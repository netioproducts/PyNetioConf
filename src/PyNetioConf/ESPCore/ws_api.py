import base64
import hashlib
import json
import logging
import math
import random
from collections.abc import Generator
from io import BufferedIOBase
from time import sleep
from typing import Any, BinaryIO, NamedTuple, Tuple

from websocket import WebSocket, WebSocketConnectionClosedException

from PyNetioConf.constants import WS_EXECUTION_DELAY

from ..exceptions import CommunicationError
from ..netio_device import NETIODevice

logger = logging.getLogger(__name__)


class _FileChunk(NamedTuple):
    base64: str
    original_len: int
    index: int
    bytes_from: int
    bytes_to: int


def send_request(
    device: NETIODevice,
    type: str,
    topic: str | None = None,
    data: dict[str, Any] | None = None,
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

    Returns
    -------
        Upon successful communication returns the direct API response from the device to be further parsed.
    """
    if device.ws is None:
        device.login(device.username, device.password)

    request: dict[str, Any] = {"type": type, "reqId": device.ws_req_id}
    unsubscribe_needed = False
    expected_reqest_id = device.ws_req_id
    if type == "SUBSCRIBE":
        unsubscribe_needed = True
    if topic:
        request["topic"] = topic
    if data:
        request["data"] = data
    logger.debug(f"Sending request to {device.host} with payload {request}")
    while True:
        try:
            if device.ws is None:
                raise CommunicationError(
                    "No websocket connection associated with the device"
                )
            device.ws.send(json.dumps(request, ensure_ascii=False))
            sleep(
                WS_EXECUTION_DELAY  # TODO: Tie to device/NM
            )  # Due to internal timers it is safer to wait after sending to not overwhelm the device
            device.ws_req_id += 1

            # Since we do not look for events we should not leave a hanging SUBSCRIBE on the websocket
            # This is best done right after the SUBSCRIBE, so as little EVENT data gets transmitted
            if unsubscribe_needed:
                unsubscribe_request: dict[str, Any] = {
                    "type": "UNSUBSCRIBE",
                    "reqId": device.ws_req_id,
                }
                if topic:
                    unsubscribe_request["topic"] = topic
                logger.debug(
                    f"Sending request to {device.host} with payload {unsubscribe_request}"
                )
                device.ws.send(json.dumps(unsubscribe_request, ensure_ascii=False))
                sleep(
                    WS_EXECUTION_DELAY
                )  # Due to internal timers it is safer to wait after sending to not overwhelm the device
                device.ws_req_id += 1

            # Create a more proper message filtering
            waiting_for_reply = True
            while waiting_for_reply:
                message = device.ws.recv()
                logger.debug(f"Received response {message}")
                message_data = json.loads(message)
                if message_data["type"] != "EVENT":
                    if message_data["type"] == "PONG":
                        device._pong_queue.append(message_data)
                    else:
                        device._request_queue.append(message_data)
                    try:
                        if message_data["reqId"] == expected_reqest_id:
                            waiting_for_reply = False
                            logger.debug(
                                f"Processing correct request {message_data['reqId']}"
                            )
                            break
                        elif message_data["reqId"] > expected_reqest_id:
                            if message_data["type"] == "PONG":
                                match = next(
                                    (
                                        dq_req_id
                                        for dq_req_id in device._pong_queue
                                        if dq_req_id.get("reqId") == expected_reqest_id
                                    ),
                                    None,
                                )
                            else:
                                match = next(
                                    (
                                        dq_req_id
                                        for dq_req_id in device._request_queue
                                        if dq_req_id.get("reqId") == expected_reqest_id
                                    ),
                                    None,
                                )
                            if match:
                                logger.debug(
                                    f"Processing correct request {message_data['reqId']}"
                                )
                                break
                            else:
                                raise NotImplementedError

                        else:
                            logger.debug(
                                f"Processing wrong message: [{message_data['reqId']}], continuing to next one."
                            )
                    except KeyError:
                        # We shouldn't be able to get here with queuing since we filter EVENTs completely now
                        logger.debug(f"Throwing away websocket message: {message}")
                        continue

            if message_data:
                return message_data
            else:
                return json.loads(message)
        except (
            BrokenPipeError,
            WebSocketConnectionClosedException,
            ConnectionResetError,
        ):
            # This most likely means that the device has rebooted, or just lost connection for other reasons.
            # Try to reconnect first, then consider the connection lost.
            device.login(device.username, device.password, logout=True)
            if topic == "system/reset":
                return {}
            continue
        except Exception as e:
            raise CommunicationError(f"Failed to send request to {device.host}", str(e))


def _gen_file_chunks(
    file_obj: BufferedIOBase, chunk_size: int = 2048
) -> Generator[_FileChunk, None, None]:
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


def upload_file(device: NETIODevice, file: BufferedIOBase, upload_id: str):
    CHUNK_SIZE = 2048
    file_chunks = list(_gen_file_chunks(file, CHUNK_SIZE))
    chunks_total = len(file_chunks)
    total_size = sum(chunk.original_len for chunk in file_chunks)
    for chunk in file_chunks:
        uploaded_chunk = chunk_file_upload(
            device,
            chunk.base64,
            chunk.bytes_from,
            chunk.bytes_to,
            total_size,
            upload_id,
            chunk.index,
            chunks_total,
            False if chunk.index < (chunks_total - 1) else True,
        )
        sleep(0.3)


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
    import copy

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
    device.ws.send(json.dumps(ws_request, ensure_ascii=False))
    device.ws_req_id += 1
    chunk_reply = device.ws.recv()
    logger.debug(f"Received response from {device.host} with payload {chunk_reply}")
    return json.loads(chunk_reply)


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


def login(
    device: NETIODevice, timestamp: int, public_key: str, username: str, password: str
) -> dict[str, Any]:
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
    device.ws.send(json.dumps(request, ensure_ascii=False))
    logger.debug(f"Sending authentication request to {device.host}, payload: {request}")
    device.ws_req_id += 1
    message = device.ws.recv()
    logger.debug(
        f"Received authentication response from {device.host}, payload: {message}"
    )
    return json.loads(message)


def device_init_login(
    ws: WebSocket,
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
    ws_req_id += 1
    message = ws.recv()
    logger.debug(f"Received authentication response from {host}, payload: {message}")
    return json.loads(message)


def device_init_request(
    ws: WebSocket,
    ws_req_id: int,
    type: str,
    host: str,
    topic: str | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    This is a simplified version of the send_request() function used for communication between PyNetioConf and a device which is yet to initialize.
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
            logger.debug(
                f"Sending request to {host} with payload {unsubscribe_request}"
            )
            ws.send(json.dumps(unsubscribe_request, ensure_ascii=False))
        ws_req_id += 1
        message = ws.recv()
        # Create a more proper message filtering
        waiting_for_reply = True
        while waiting_for_reply:
            try:
                if json.loads(message)["reqId"] == expected_reqest_id:
                    waiting_for_reply = False
                else:
                    logger.debug(f"Throwing away websocket message: {message}")
                    message = ws.recv()
            except KeyError:
                logger.debug(f"Throwing away websocket message: {message}")
                message = ws.recv()
        logger.debug(f"Received response from {host} with payload {message}")
        return json.loads(message)
    except Exception as e:
        raise CommunicationError(f"Failed to send request to {host}", str(e))
