import base64
import hashlib
import json
import logging
import math
import random
from collections.abc import Callable, Generator
from functools import partial
from io import BufferedIOBase
from time import monotonic, perf_counter, sleep, time
from typing import Any, NamedTuple, cast

from PyNetioConf.constants import (
    HTTPS_DELAY_FACTOR,
    LATENCY_DELAY_STEPS,
    UPLOAD_CHUNK_PAUSE,
    UPLOAD_CHUNK_TIMEOUT,
    WIFI_DELAY_FACTOR,
    WS_EXECUTION_DELAY,
    WS_RECONNECT_INTERVAL,
    WS_RECONNECT_TIMEOUT,
)

from ..exceptions import AuthError, CommunicationError, DeviceError, UnauthorizedError
from ..netio_device import NETIODevice
from .ws_transport import Connection, WebSocketClosedError, WebSocketTimeoutError

logger = logging.getLogger(__name__)


def _check_reply(reply: dict[str, Any], host: str, ws_type: str, topic: str | None) -> None:
    """
    Raises DeviceError when the device answered the request with an error, UnauthorizedError for the code
    Unauthorized. A reply without a status passes: only firmware 5.4.0 is checked to send one on every reply.
    """
    status = reply.get("status")
    if status is None or status == "OK":
        return
    error: dict[str, Any] = reply.get("error") or {}
    code = str(error.get("code", status))
    message = str(error.get("message", "")).rstrip(" :")
    if code == "Unauthorized":
        raise UnauthorizedError(host, ws_type, topic, code, message)
    raise DeviceError(host, ws_type, topic, code, message)


class Event(NamedTuple):
    """What a device sent unasked about a topic it was subscribed to: the topic's data as it then was."""

    topic: str | None
    data: Any
    received: float  # time.monotonic() when it came
    time: float  # time.time() when it came


def _store_event(device: NETIODevice, message: dict[str, Any], received: float) -> None:
    """Adds an EVENT to the device's event queue, which drops its oldest when full, and wakes who waits for one."""
    event = Event(message.get("topic"), message.get("data"), received, time() - (monotonic() - received))
    with device._event_condition:
        if len(device._event_queue) == device._event_queue.maxlen:
            device._events_dropped += 1
        device._event_queue.append(event)
        device._event_condition.notify_all()


def _sort_message(device: NETIODevice, message: str | bytes, received: float) -> bool:
    """The connection's sorter: keeps an EVENT for the device's event queue, leaves everything else to the requests."""
    try:
        parsed = json.loads(message)
    except ValueError:
        return False
    if not isinstance(parsed, dict) or parsed.get("type") != "EVENT":
        return False
    _store_event(device, cast(dict[str, Any], parsed), received)
    return True


def connection_opened(device: NETIODevice) -> None:
    """
    For every new connection of a device: has it hand its events to the device's event queue as they come, and forgets
    the subscriptions, which the device held for the connection before it.
    """
    if device.ws is not None:
        device.ws.set_sorter(partial(_sort_message, device))
    if device._subscriptions:
        logger.debug(f"The subscriptions of {device.host} ended with its connection: {sorted(device._subscriptions)}")
        device._subscriptions.clear()


def _events(device: NETIODevice, topic: str | None = None, since: float | None = None) -> list[Event]:
    """The events in the device's queue, the oldest first: all, those of a topic, or those since a time.monotonic()."""
    with device._event_condition:
        return [
            event
            for event in device._event_queue
            if (topic is None or event.topic == topic) and (since is None or event.received >= since)
        ]


def _clear_events(device: NETIODevice) -> None:
    """Empties the device's event queue."""
    with device._event_condition:
        device._event_queue.clear()


def _wait_for_event(
    device: NETIODevice,
    topic: str,
    timeout: float,
    match: Callable[[Event], bool] | None = None,
    since: float | None = None,
) -> Event | None:
    """
    Waits for an event of a topic the device is subscribed to (_raw_request() with SUBSCRIBE) and returns it, or None
    when none came within timeout seconds. An event carries the topic's data as it was then, which can still be the
    state before a change: say with match which event counts, or read the topic afterwards.

    Parameters
    ----------
    topic : str
        The topic the event has to be of.
    timeout : float
        How long to wait, in seconds.
    match : Callable[[Event], bool] | None
        Whether an event counts. None for any event of the topic.
    since : float | None
        The time.monotonic() from which an event counts, for one that may come before this call, such as a mark taken
        before the request that causes it. None for the time of the call.
    """
    start = monotonic() if since is None else since
    deadline = monotonic() + timeout
    with device._event_condition:
        while True:
            for event in device._event_queue:
                if event.received >= start and event.topic == topic and (match is None or match(event)):
                    return event
            remaining = deadline - monotonic()
            if remaining <= 0:
                return None
            device._event_condition.wait(remaining)


def _receive(ws: Connection, req_id: int, host: str, device: NETIODevice | None = None) -> dict[str, Any]:
    """
    Reads the connection until the reply to request req_id comes, and returns it. Another request's reply, such as a
    late one or an UNSUBSCRIBE's, is passed over and kept in the device's queues. An EVENT the connection's reader
    didn't take, which is one that came before connection_opened(), goes to the device's event queue here.

    Raises
    ------
    WebSocketTimeoutError
        The reply didn't come within the connection's timeout, counted from the call, whatever else came.
    WebSocketClosedError
        The connection is closed.
    """
    timeout = ws.gettimeout()
    deadline = None if timeout is None else monotonic() + timeout
    while True:
        message = ws.recv(deadline)
        logger.debug(f"Received response from {host} with payload {message}")
        reply: dict[str, Any] = json.loads(message)
        if reply.get("type") == "EVENT":
            if device is not None:
                _store_event(device, reply, monotonic())
            continue
        if device is not None:
            (device._pong_queue if reply.get("type") == "PONG" else device._request_queue).append(reply)
        if reply.get("reqId") == req_id:
            return reply
        logger.debug(f"Passed over the reply to request {reply.get('reqId')} of {host}, waiting for {req_id}")


class _FileChunk(NamedTuple):
    base64: str
    original_len: int
    index: int
    bytes_from: int
    bytes_to: int


def _delay_factor(device: NETIODevice) -> float:
    """The factor on the pauses after a request and between upload chunks, for the device's link."""
    factor = 1.0
    reasons: list[str] = []
    if device._on_wifi:
        factor *= WIFI_DELAY_FACTOR
        reasons.append("Wi-Fi")
    smoothed = device._latency.smoothed
    if smoothed is not None:
        for threshold, step in LATENCY_DELAY_STEPS:
            if smoothed > threshold:
                factor *= step
                reasons.append(f"latency over {threshold * 1000:.0f} ms")
    if device.use_https:
        factor *= HTTPS_DELAY_FACTOR
        reasons.append("HTTPS")
    if factor != device._delay_factor:
        device._delay_factor = factor
        logger.debug(
            f"Request delay for {device.host}: {WS_EXECUTION_DELAY * factor * 1000:.0f} ms "
            f"({', '.join(reasons) or 'base'})"
        )
    return factor


def send_request(
    device: NETIODevice,
    ws_type: str,
    ws_topic: str | None = None,
    ws_data: dict[str, Any] | None = None,
    resend: bool = True,
) -> dict[str, Any]:
    """
    Send a request to the device's websocket API and return the response.
    Parameters
    ----------
    device : ESPDevice
        The ESPDevice object of the device.
    type : str
        The type of the request. Can be one of the following: "HELO", "AUTH", "SET", "SUBSCRIBE", "UNSUBSCRIBE".
    topic : str
        The target of the request if applicable.
    data : Dict
        The data to send with the request if applicable.
    resend : bool
        Whether a request that went out is sent again after the connection dropped. False for a request that may
        itself have restarted the device, which then raises CommunicationError once the device is back.

    Returns
    -------
        Upon successful communication returns the direct API response from the device to be further parsed.
    """
    # One request at a time on a device's connection: the keep-alive runs in a thread of its own
    with device._ws_lock:
        return _send_request(device, ws_type, ws_topic, ws_data, resend, raw=False)


def _raw_request(
    device: NETIODevice,
    ws_type: str,
    ws_topic: str | None = None,
    ws_data: dict[str, Any] | None = None,
    resend: bool = True,
) -> dict[str, Any]:
    """
    Sends a request exactly as given and returns the reply, where send_request() reads: a SUBSCRIBE stays a SUBSCRIBE on
    firmware 5.4.0 and newer, and no UNSUBSCRIBE follows it. The device then sends an event with the topic's data
    whenever the topic changes, which go to the device's event queue (_wait_for_event(), _events()), until an
    UNSUBSCRIBE of the topic or the end of the connection. A topic is subscribed or not: a second SUBSCRIBE reads it,
    and one UNSUBSCRIBE ends it.

    Raises what send_request() raises.
    """
    with device._ws_lock:
        reply = _send_request(device, ws_type, ws_topic, ws_data, resend, raw=True)
        if ws_topic and ws_type == "SUBSCRIBE":
            device._subscriptions.add(ws_topic)
        elif ws_topic and ws_type == "UNSUBSCRIBE":
            device._subscriptions.discard(ws_topic)
        return reply


def _send_request(
    device: NETIODevice, ws_type: str, ws_topic: str | None, ws_data: dict[str, Any] | None, resend: bool, raw: bool
) -> dict[str, Any]:
    """send_request() and _raw_request() once the device's connection is this thread's."""
    if device.ws is None:
        device.login(device.username, device.password)

    if device.version and not raw:
        if (device.version[0] > 5 or (device.version[0] == 5 and device.version[1] >= 4)) and ws_type == "SUBSCRIBE":
            ws_type = "GET"

    request: dict[str, Any] = {"type": ws_type, "reqId": device.ws_req_id}
    unsubscribe_needed = False
    expected_reqest_id = device.ws_req_id
    # A read by SUBSCRIBE ends its subscription at once, unless the topic is held: the UNSUBSCRIBE would end that too
    if ws_type == "SUBSCRIBE" and not raw and ws_topic not in device._subscriptions:
        unsubscribe_needed = True
    if ws_topic:
        request["topic"] = ws_topic
    if ws_data:
        request["data"] = ws_data
    logger.debug(f"Sending request to {device.host} with payload {request}")
    reconnect_deadline: float | None = None
    last_reconnect: float | None = None
    sent = False
    while True:
        try:
            if device.ws is None:
                device.login(device.username, device.password)
            if device.ws is None:
                raise ConnectionError("Couldn't establish a WebSocket connection")
            sent = False
            # Due to internal timers it is safer to wait after sending to not overwhelm the device
            delay = WS_EXECUTION_DELAY * _delay_factor(device)
            started = perf_counter()
            device.ws.send(json.dumps(request, ensure_ascii=False))
            sent = True
            # The pauses below aren't the device's response time
            paused = delay
            sleep(delay)
            device.ws_req_id += 1

            # Since we do not look for events we should not leave a hanging SUBSCRIBE on the websocket
            # This is best done right after the SUBSCRIBE, so as little EVENT data gets transmitted
            if unsubscribe_needed:
                unsubscribe_request: dict[str, Any] = {
                    "type": "UNSUBSCRIBE",
                    "reqId": device.ws_req_id,
                }
                if ws_topic:
                    unsubscribe_request["topic"] = ws_topic
                logger.debug(f"Sending request to {device.host} with payload {unsubscribe_request}")
                device.ws.send(json.dumps(unsubscribe_request, ensure_ascii=False))
                paused += delay
                sleep(delay)
                device.ws_req_id += 1

            reply = _receive(device.ws, expected_reqest_id, device.host, device)

            device._latency.record(max(perf_counter() - started - paused, 0.0))
            _check_reply(reply, device.host, ws_type, ws_topic)
            return reply
        except WebSocketClosedError:
            # This most likely means that the device has rebooted, or just lost connection for other reasons.
            # Keep reconnecting for WS_RECONNECT_TIMEOUT seconds, then consider the connection lost.
            if reconnect_deadline is None:
                reconnect_deadline = perf_counter() + WS_RECONNECT_TIMEOUT
            elif perf_counter() >= reconnect_deadline:
                raise CommunicationError(
                    f"Connection to {device.host} kept dropping for {WS_RECONNECT_TIMEOUT} seconds."
                )
            last_reconnect = _reconnect(device, reconnect_deadline, last_reconnect)
            # A reset that went out ends the connection without a reply. One the drop stopped from going out, on a
            # connection that was already dead, is sent again like any other request.
            if ws_topic == "system/reset" and sent:
                return {}
            if sent and not resend:
                raise CommunicationError(
                    f"The connection to {device.host} dropped after the {ws_type} of {ws_topic} was sent, so the "
                    "device probably restarted on it. The request wasn't sent again."
                )
            continue
        except (AuthError, DeviceError):
            # A refused login from reconnecting, or a request the device refused, is not a communication problem
            raise
        except WebSocketTimeoutError as e:
            device._latency.record_timeout()
            raise CommunicationError(f"Failed to send request to {device.host}", str(e))
        except Exception as e:
            raise CommunicationError(f"Failed to send request to {device.host}", str(e))


def _reconnect(device: NETIODevice, deadline: float, last_attempt: float | None) -> float:
    """
    Logs back in after the connection to the device dropped. Logins start at most every WS_RECONNECT_INTERVAL
    seconds, counted from last_attempt, and failed ones are retried until the deadline passes. Both times are
    perf_counter() values.

    Returns
    -------
        The start time of the successful login, to pass as last_attempt if the connection drops again.
    """
    while True:
        if last_attempt is not None:
            wait = min(
                last_attempt + WS_RECONNECT_INTERVAL - perf_counter(),
                deadline - perf_counter(),
            )
            if wait > 0:
                sleep(wait)
        last_attempt = perf_counter()
        try:
            device.login(device.username, device.password, logout=True)
            return last_attempt
        except CommunicationError:
            if perf_counter() >= deadline:
                raise CommunicationError(f"Couldn't reconnect to {device.host} within {WS_RECONNECT_TIMEOUT} seconds.")
            logger.debug(f"Reconnecting to {device.host} failed, retrying.")


def close_connection(ws: Connection | None, graceful: bool = True) -> None:
    """
    Closes a WebSocket connection to a device. The device keeps a session for every open connection and has room for
    only a few, so a connection that isn't needed any more has to be closed, not left to the garbage collector.

    Parameters
    ----------
    ws : Connection | None
        The connection to close. None does nothing.
    graceful : bool
        Send a close frame and wait for the device's reply. Otherwise the socket is shut down at once, which is meant
        for a connection that dropped or stopped answering. Default True.
    """
    if ws is None:
        return
    try:
        if graceful:
            ws.close()
        else:
            ws.shutdown()
    except Exception as e:
        # A connection that can't be closed cleanly has already dropped, the device ends its session either way
        logger.debug(f"Closing a WebSocket connection failed, dropping it: {e}")


def _gen_file_chunks(file_obj: BufferedIOBase, chunk_size: int = 2048) -> Generator[_FileChunk, None, None]:
    """Reads a binary file in chunks.

    Yields:
        Tuple[str, int, int, int, int]:
            (base64_string, original_chunk_len, chunk_index, bytes_from, bytes_to)
    """
    chunk_iterator = iter(lambda: file_obj.read(chunk_size), b"")
    current_byte = 0

    for index, chunk in enumerate(chunk_iterator, start=0):
        chunk_len = len(chunk)
        b64_string = base64.b64encode(chunk).decode("utf-8")

        bytes_from = current_byte
        bytes_to = current_byte + chunk_len  # Inclusive boundary

        yield _FileChunk(
            base64=b64_string,
            original_len=chunk_len,
            index=index,
            bytes_from=bytes_from,
            bytes_to=bytes_to,
        )

        current_byte += chunk_len


# What a chunk that gets no reply raises: a timeout, or a connection the device closed or reset
_NO_REPLY = (WebSocketTimeoutError, WebSocketClosedError)


def upload_file(
    device: NETIODevice, file: BufferedIOBase, upload_id: str, last_reply_timeout: float | None = None
) -> None:
    """
    Sends the file through upload/chunk. Raises CommunicationError when the device refuses or doesn't answer a chunk.
    Set last_reply_timeout when the device restarts once the upload ends: the last chunk's reply is awaited that long,
    and a missing one is taken for the restart.
    """
    # The whole upload is one use of the connection: a keep-alive between two chunks would read a chunk's reply
    with device._ws_lock:
        _upload_file(device, file, upload_id, last_reply_timeout)


def _upload_file(device: NETIODevice, file: BufferedIOBase, upload_id: str, last_reply_timeout: float | None) -> None:
    """upload_file() once the device's connection is this thread's."""
    if device.ws is None:
        raise CommunicationError("No websocket connection associated with the device")
    CHUNK_SIZE = 2048
    file_chunks = list(_gen_file_chunks(file, CHUNK_SIZE))
    chunks_total = len(file_chunks)
    total_size = sum(chunk.original_len for chunk in file_chunks)
    timeout = device.ws.gettimeout()
    try:
        for chunk in file_chunks:
            last = chunk.index == chunks_total - 1
            restarts = last and last_reply_timeout is not None
            device.ws.settimeout(last_reply_timeout if restarts else UPLOAD_CHUNK_TIMEOUT)
            position = f"chunk {chunk.index + 1} of {chunks_total}"
            try:
                reply = chunk_file_upload(
                    device,
                    chunk.base64,
                    chunk.bytes_from,
                    chunk.bytes_to,
                    total_size,
                    upload_id,
                    chunk.index,
                    chunks_total,
                    last,
                )
            except _NO_REPLY as e:
                if isinstance(e, WebSocketTimeoutError) and not restarts:
                    device._latency.record_timeout()
                if restarts:
                    logger.debug(f"Device {device.host} didn't answer the last chunk ({type(e).__name__}), restarting")
                    return
                raise CommunicationError(f"Device {device.host} didn't answer {position} ({type(e).__name__})") from e
            if reply["status"] != "OK":
                raise CommunicationError(f"Device {device.host} refused {position}: {reply}")
            if not last:
                sleep(UPLOAD_CHUNK_PAUSE * _delay_factor(device))
    finally:
        device.ws.settimeout(timeout)


def chunk_file_upload(
    device: NETIODevice,
    byte_data: str,
    bytes_from: int,
    bytes_to: int,
    bytes_total: int,
    upload_id: str,
    chunk_index: int = 0,
    chunk_total: int = 1,
    complete: bool = True,
) -> dict[str, Any]:
    chunk_topic = "upload/chunk"
    ws_type = "SET"
    chunk_data = {
        "b64Data": byte_data,
        "bytesFrom": bytes_from,
        "bytesTo": bytes_to,
        "bytesTotal": bytes_total,
        "chunkIndex": chunk_index,
        "chunksTotal": chunk_total,
        "complete": complete,
        "uploadId": upload_id,
    }
    ws_request = {
        "data": chunk_data,
        "reqId": device.ws_req_id,
        "topic": chunk_topic,
        "type": ws_type,
    }

    _debug_request = {
        **ws_request,
        "data": {
            **chunk_data,
            "b64Data": f"... [{len(byte_data)} bytes] ...",
        },
    }
    if device.ws is None:
        raise CommunicationError("No websocket connection associated with the device")
    logger.debug(f"Sending request to {device.host} with payload {_debug_request}")
    req_id = ws_request["reqId"]
    started = perf_counter()
    device.ws.send(json.dumps(ws_request, ensure_ascii=False))
    device.ws_req_id += 1
    reply = _receive(device.ws, req_id, device.host, device)
    device._latency.record(perf_counter() - started)
    return reply


def generate_salt() -> str:
    base = random.randint(0, 2**32)
    # create a sha256 hash of the base
    return hashlib.sha256(str(base).encode()).hexdigest()


def generate_password_hash(username: str, password: str, public_key: str) -> str:
    salted_hash = hashlib.sha256(f"{username}{public_key}{password}".encode()).digest()
    # convert the salted hash to base64
    return base64.b64encode(salted_hash).decode()


def generate_password_token(salt: str, password_hash: str) -> tuple[str, str]:
    # create a sha256 hash of the salt and password hash
    pwd_hash = hashlib.sha256(f"{salt}{password_hash}".encode()).hexdigest()
    return salt, pwd_hash


def generate_auth_token(password_token: tuple[str, str], local_timestamp: int) -> str:
    time_mark = str(math.floor(local_timestamp / 10))
    token_hash = hashlib.sha256(f"{time_mark}{password_token[1]}".encode()).hexdigest()
    return f"{password_token[0]}.{token_hash}"


def _check_auth_reply(reply: dict[str, Any], host: str) -> None:
    """
    Raises AuthError when the device refused the login, with the error code the device sent, such as
    InvalidCredentials or TooManyFailLogin. A reply without a status counts as a success, only firmware 5.4.0 is
    checked to send one.
    """
    status = reply.get("status")
    if status is not None and status != "OK":
        error: dict[str, Any] = reply.get("error", {})
        code = error.get("code", status)
        message = str(error.get("message", "")).rstrip(" :")
        raise AuthError(f"Login to {host} failed with {code}: {message}")


def login(device: NETIODevice, timestamp: int, public_key: str, username: str, password: str) -> dict[str, Any]:
    salt = generate_salt()
    password_hash = generate_password_hash(username, password, public_key)
    password_token = generate_password_token(salt, password_hash)
    auth_token = generate_auth_token(password_token, timestamp)
    request = {
        "type": "AUTH",
        "reqId": device.ws_req_id,
        "username": username,
        "token": auth_token,
    }
    if device.ws is None:
        raise CommunicationError("No websocket connection associated with the device")
    try:
        device.ws.send(json.dumps(request, ensure_ascii=False))
        logger.debug(f"Sending authentication request to {device.host}, payload: {request}")
        device.ws_req_id += 1
        reply = _receive(device.ws, request["reqId"], device.host, device)
    except Exception as e:
        raise CommunicationError(f"Failed to log in to {device.host}", str(e))
    _check_auth_reply(reply, device.host)
    return reply


def device_init_login(
    ws: Connection,
    ws_req_id: int,
    timestamp: int,
    public_key: str,
    username: str,
    password: str,
    host: str,
) -> dict[str, Any]:
    salt = generate_salt()
    password_hash = generate_password_hash(username, password, public_key)
    password_token = generate_password_token(salt, password_hash)
    auth_token = generate_auth_token(password_token, timestamp)
    request = {
        "type": "AUTH",
        "reqId": ws_req_id,
        "username": username,
        "token": auth_token,
    }
    ws.send(json.dumps(request, ensure_ascii=False))
    logger.debug(f"Sending authentication request to {host}, payload: {request}")
    reply = _receive(ws, ws_req_id, host)
    _check_auth_reply(reply, host)
    return reply


def device_init_request(
    ws: Connection,
    ws_req_id: int,
    type: str,
    host: str,
    topic: str | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    This is a simplified version of the send_request() function used for communication between PyNetioConf and a device
    which is yet to initialize.
    """
    request: dict[str, Any] = {"type": type, "reqId": ws_req_id}
    unsubscribe_needed = False
    expected_reqest_id = ws_req_id
    if type == "SUBSCRIBE":
        unsubscribe_needed = True
    if topic:
        request["topic"] = topic
    if data:
        request["data"] = data
    logger.debug(f"Sending request to {host} with payload {request}")
    try:
        ws.send(json.dumps(request, ensure_ascii=False))

        # Since we do not look for events we should not leave a hanging SUBSCRIBE on the websocket
        if unsubscribe_needed:
            ws_req_id += 1
            unsubscribe_request: dict[str, Any] = {
                "type": "UNSUBSCRIBE",
                "reqId": ws_req_id,
            }
            if topic:
                unsubscribe_request["topic"] = topic
            logger.debug(f"Sending request to {host} with payload {unsubscribe_request}")
            ws.send(json.dumps(unsubscribe_request, ensure_ascii=False))
        reply = _receive(ws, expected_reqest_id, host)
        _check_reply(reply, host, type, topic)
        return reply
    except DeviceError:
        raise
    except Exception as e:
        raise CommunicationError(f"Failed to send request to {host}", str(e))
