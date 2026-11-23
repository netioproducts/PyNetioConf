"""
The WebSocket connection to a device: the asyncio client of `websockets` behind blocking calls. Every connection of the
process runs on one event loop, in a daemon thread that starts with the first connection. A reader on that loop takes
every message of a connection as it comes, so nothing waits in the socket while no request is made.
"""

import asyncio
import logging
import os
import queue
import ssl
import threading
import time
from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, WebSocketException
from websockets.protocol import State

logger = logging.getLogger(__name__)
# What websockets logs about a connection, a DEBUG line for every frame and the handshake. Off unless this logger is set
# to DEBUG: PyNetioConf logs every request and reply itself
frame_logger = logging.getLogger(f"{__name__}.frames")
if frame_logger.level == logging.NOTSET:
    frame_logger.setLevel(logging.INFO)

_T = TypeVar("_T")

OPEN_TIMEOUT = 10  # Seconds a connection may take to open
CLOSE_TIMEOUT = 3  # Seconds a close waits for the device's close frame


# Takes a message and its time.monotonic() of arrival on the event loop's thread, and returns whether it kept the
# message; one it didn't keep goes to recv(). It has to be quick and safe to call from that thread.
Sorter = Callable[[str | bytes, float], bool]


class _Closed:
    """In a connection's inbox: the reader ended, with what ended it."""

    def __init__(self, reason: str) -> None:
        self.reason = reason


class WebSocketError(Exception):
    """A WebSocket connection couldn't be opened or used."""


class WebSocketClosedError(WebSocketError):
    """The connection is closed: the device closed it, restarted or can't be reached."""


class WebSocketTimeoutError(WebSocketError):
    """No message came within the connection's timeout."""


_loop: asyncio.AbstractEventLoop | None = None
_loop_thread: threading.Thread | None = None
_loop_lock = threading.Lock()


def _forget_loop() -> None:
    """In a forked child: the parent's loop thread doesn't exist here, the next connection starts a new one."""
    global _loop, _loop_thread, _loop_lock
    _loop = None
    _loop_thread = None
    _loop_lock = threading.Lock()


os.register_at_fork(after_in_child=_forget_loop)


def _event_loop() -> asyncio.AbstractEventLoop:
    """The process's event loop for device connections, started on first use."""
    global _loop, _loop_thread
    with _loop_lock:
        if _loop is None or _loop_thread is None or not _loop_thread.is_alive():
            _loop = asyncio.new_event_loop()
            _loop_thread = threading.Thread(target=_loop.run_forever, name="PyNetioConf-websockets", daemon=True)
            _loop_thread.start()
            logger.debug("Started the event loop for WebSocket connections")
        return _loop


def ssl_context_of(ssl_options: dict[str, Any]) -> ssl.SSLContext:
    """
    The TLS settings of a wss:// connection from a device's ssl_options: its "context" when it has one, else a context
    built from the keys cert_reqs, check_hostname, ca_certs, ca_cert_path, certfile, keyfile, password, ciphers and
    ecdh_curve. Without any of them the certificate and the host name are verified.
    """
    context = ssl_options.get("context")
    if isinstance(context, ssl.SSLContext):
        return context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cert_reqs: ssl.VerifyMode = ssl_options.get("cert_reqs", ssl.CERT_REQUIRED)
    # The host name can only be checked while the certificate is, and has to be switched off first
    context.check_hostname = cert_reqs != ssl.CERT_NONE and bool(ssl_options.get("check_hostname", True))
    context.verify_mode = cert_reqs
    if ssl_options.get("ca_certs") or ssl_options.get("ca_cert_path"):
        context.load_verify_locations(cafile=ssl_options.get("ca_certs"), capath=ssl_options.get("ca_cert_path"))
    elif cert_reqs != ssl.CERT_NONE:
        context.load_default_certs()
    if ssl_options.get("certfile"):
        context.load_cert_chain(ssl_options["certfile"], ssl_options.get("keyfile"), ssl_options.get("password"))
    if ssl_options.get("ciphers"):
        context.set_ciphers(ssl_options["ciphers"])
    if ssl_options.get("ecdh_curve"):
        context.set_ecdh_curve(ssl_options["ecdh_curve"])
    return context


def connect_device(host: str, use_https: bool, ssl_options: dict[str, Any] | None = None) -> "Connection":
    """
    Opens the WebSocket connection to a device, wss://<host>/emweb with the TLS settings of ssl_options or
    ws://<host>/emweb. Its recv() waits OPEN_TIMEOUT seconds until settimeout() says otherwise.

    Raises
    ------
    WebSocketError
        The connection couldn't be opened.
    """
    if use_https:
        return Connection(f"wss://{host}/emweb", ssl_context_of(ssl_options or {}), timeout=OPEN_TIMEOUT)
    return Connection(f"ws://{host}/emweb", timeout=OPEN_TIMEOUT)


class Connection:
    """
    One WebSocket connection to a device, with blocking calls for use from any thread but the event loop's. A timeout
    of None waits without limit.
    """

    def __init__(self, url: str, ssl_context: ssl.SSLContext | None = None, timeout: float | None = None) -> None:
        """
        Opens the connection.

        Parameters
        ----------
        url : str
            The device's WebSocket URL, ws://<host>/emweb or wss://<host>/emweb.
        ssl_context : ssl.SSLContext | None
            The TLS settings of a wss:// connection. None takes Python's defaults, which verify the certificate.
        timeout : float | None
            How long recv() waits for a message, in seconds; settimeout() changes it.

        Raises
        ------
        WebSocketError
            The connection couldn't be opened within OPEN_TIMEOUT seconds.
        """
        self.url = url
        self._timeout = timeout
        self._loop = _event_loop()
        # What the reader took and no sorter kept, for recv(); a _Closed once the reader has ended
        self._inbox: queue.SimpleQueue[str | bytes | _Closed] = queue.SimpleQueue()
        self._sorter: Sorter | None = None
        self._reader: asyncio.Task[None] | None = None
        try:
            self._ws: ClientConnection = self._run(self._open(url, ssl_context))
        except (OSError, WebSocketException) as error:
            raise WebSocketError(f"Couldn't open {url}: {error!r}") from error

    async def _open(self, url: str, ssl_context: ssl.SSLContext | None) -> ClientConnection:
        # Compression isn't negotiated by the devices. The devices' sessions are kept alive by PyNetioConf's own PING
        # requests, and their replies have no size limit.
        ws = await connect(
            url,
            ssl=ssl_context,
            compression=None,
            ping_interval=None,
            max_size=None,
            open_timeout=OPEN_TIMEOUT,
            close_timeout=CLOSE_TIMEOUT,
            logger=frame_logger,
        )
        self._reader = asyncio.create_task(self._read(ws))
        return ws

    async def _read(self, ws: ClientConnection) -> None:
        """Takes every message as it comes: to the sorter, and to the inbox when there is none or it doesn't keep it."""
        reason = "closed"
        try:
            async for message in ws:
                received = time.monotonic()
                sorter = self._sorter
                try:
                    kept = sorter is not None and sorter(message, received)
                except Exception:
                    logger.exception(f"Sorting a message from {self.url} failed, it goes to the next recv()")
                    kept = False
                if not kept:
                    self._inbox.put(message)
        except ConnectionClosed as error:
            reason = repr(error)
        finally:
            self._inbox.put(_Closed(reason))

    def set_sorter(self, sorter: Sorter | None) -> None:
        """Sets what the reader offers every message to before recv() gets it; None for nothing."""
        self._sorter = sorter

    def _run(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        """Runs a coroutine on the event loop and returns its result."""
        if threading.current_thread() is _loop_thread:
            coroutine.close()
            raise RuntimeError("A blocking call on a device connection was made from its event loop")
        return asyncio.run_coroutine_threadsafe(coroutine, self._loop).result()

    @property
    def connected(self) -> bool:
        """Whether the connection is open."""
        return self._ws.state is State.OPEN

    def gettimeout(self) -> float | None:
        return self._timeout

    def settimeout(self, timeout: float | None) -> None:
        self._timeout = timeout

    def send(self, message: str) -> None:
        """
        Sends a text message.

        Raises
        ------
        WebSocketClosedError
            The connection is closed.
        """
        try:
            self._run(self._ws.send(message))
        except (ConnectionClosed, OSError) as error:
            raise WebSocketClosedError(f"The connection to {self.url} is closed: {error!r}") from error

    def recv(self, deadline: float | None = None) -> str | bytes:
        """
        Waits for the next message the sorter didn't keep and returns it, text as str: for the connection's timeout, or
        until deadline, a time.monotonic() value, when one is given. Two threads waiting each get a message of their
        own.

        Raises
        ------
        WebSocketTimeoutError
            No message came within the timeout. The connection stays usable.
        WebSocketClosedError
            The connection is closed.
        """
        timeout = self._timeout if deadline is None else max(deadline - time.monotonic(), 0.0)
        try:
            message = self._inbox.get(timeout=timeout)
        except queue.Empty as error:
            raise WebSocketTimeoutError(f"No message from {self.url} in {timeout} s") from error
        if isinstance(message, _Closed):
            # Stays in the inbox for every later recv()
            self._inbox.put(message)
            raise WebSocketClosedError(f"The connection to {self.url} is closed: {message.reason}")
        return message

    def close(self) -> None:
        """Closes the connection with a close frame and waits up to CLOSE_TIMEOUT seconds for the device's."""
        self._run(self._ws.close())

    def shutdown(self) -> None:
        """Drops the connection at once, without a close frame: for one that is dead or stopped answering."""
        self._run(self._abort())

    async def _abort(self) -> None:
        self._ws.transport.abort()
        await self._ws.wait_closed()
