"""
Implementation specifics for ESP devices with the firmware 5.0.x.
"""

import atexit
import base64
import io
import json
import os
import re
import sys
from collections import deque
from collections.abc import Callable
from enum import StrEnum
from time import perf_counter, sleep
from xml.etree.ElementTree import Element

from PyNetioConf.constants import (
    CLOUD_ACTION_COMMUNICATION_DELAY,
    CLOUD_DEFAULT_CONNECTION_WAIT,
    WS_DEFAULT_TIMEOUT,
)

if sys.version_info >= (3, 12):
    from typing import Any, override
else:
    from typing import Any

    from typing_extensions import override

import logging
import threading
import warnings

import requests

from .. import NetioManager
from ..constants import (
    BLOCK_CONFIG_MAX,
    BLOCK_CREATE_SETTLE,
    BLOCK_LISTED_INTERVAL,
    BLOCK_LISTED_TIMEOUT,
    BLOCK_NAME_MAX,
    CONFIG_IMPORT_RESTART_TIMEOUT,
    DEFAULT_KEEP_ALIVE_QUEUE_LEN,
    DEFAULT_PASSWORD,
    DEFAULT_REQUEST_QUEUE_LEN,
    DEFAULT_USERNAME,
    FIRMWARE_LIST_CACHE_TIME,
    FIRMWARE_LIST_INTERVAL,
    FIRMWARE_LIST_SETTLE,
    FIRMWARE_LIST_TIMEOUT,
    LOAD_DEFAULTS_GRACE_PERIOD,
    LOAD_DEFAULTS_RETRY_INTERVAL,
    LOAD_DEFAULTS_SETTLE_UPTIME,
    LOAD_DEFAULTS_TIMEOUT,
    MQTT_APPLY_INTERVAL,
    MQTT_APPLY_TIMEOUT,
    MQTT_BROKER_REQUIRED,
    MQTT_CLIENT_ID_MAX,
    MQTT_CONFIG_MAX,
    MQTT_EVENT_TYPES,
    MQTT_LOG_TYPES,
    MQTT_PROTOCOLS,
    MQTT_TIMER_PERIOD_MIN,
    NBUS_DISCOVER_TIMEOUT,
    ONLINE_UPDATE_ATTEMPTS,
    ONLINE_UPDATE_INTERVAL,
    ONLINE_UPDATE_RETRY_INTERVAL,
    ONLINE_UPDATE_RETRY_WAIT,
    ONLINE_UPDATE_START_TIMEOUT,
    ONLINE_UPDATE_TIMEOUT,
    OUTPUT_DELAY_MAX,
    OUTPUT_POWER_UP_INTERVAL_MIN,
    OUTPUT_RESET_DELAY_MIN,
    PAB_CONFIG_REQUIRED,
    PEM_CERTIFICATE,
    PEM_FILE_MAX,
    PEM_KEY_EXTRAS,
    PEM_PRIVATE_KEY,
    RULE_CONFIG_REQUIRED,
    SCHEDULE_DAYS,
    SCHEDULE_FROM_MAX,
    SCHEDULE_TO_MAX,
    UPLOAD_RESTART_REPLY_TIMEOUT,
    USER_LIST_SYNC_INTERVAL,
    USER_LIST_SYNC_TIMEOUT,
    USER_PRIVILEGES,
    WATCHDOG_CONFIG_REQUIRED,
    WEB_SERVER_RESTART_INTERVAL,
    WEB_SERVER_RESTART_TIMEOUT,
    NbusRole,
    NetworkMode,
    OutputAction,
    OutputPowerUpState,
    PushProtocol,
    SnmpAuthProtocol,
    SnmpPrivProtocol,
    SnmpSecurityLevel,
    TemperatureUnit,
)
from ..exceptions import (
    AuthError,
    CommunicationError,
    DeviceError,
    ElementAlreadyExists,
    ElementNotFound,
    FeatureNotSupported,
    InvalidParameterValueError,
    InvalidSocketIndex,
    UnauthorizedError,
)
from ..latency import LatencyStats
from ..netio_device import NETIODevice
from . import esp_api, ws_api
from .ws_transport import Connection, connect_device


def _value_or_current(value: Any, current: dict[str, Any], key: str) -> Any:
    """Returns value, or the device's current value for key when value is None."""
    return value if value is not None else current[key]


def _choice_value(choices: type[StrEnum], value: str | None, name: str) -> str | None:
    """Returns the plain string of a choice given as a member of choices or as its value, None stays None."""
    if value is None:
        return None
    try:
        return choices(value).value
    except ValueError:
        raise InvalidParameterValueError(
            f"Unknown {name} {value!r}, the possible ones are {[choice.value for choice in choices]}"
        ) from None


def _load_config_file(file: Any) -> dict[str, Any]:
    """The configuration in a file opened in binary or text mode. Anything but a JSON object is refused."""
    if not isinstance(file, (io.BufferedIOBase, io.TextIOBase)):
        raise InvalidParameterValueError(
            f"The configuration has to be a path or a file opened in binary or text mode, not {type(file).__name__}"
        )
    try:
        data: Any = json.load(file)
    except ValueError:
        raise InvalidParameterValueError("The configuration file isn't valid JSON") from None
    if not isinstance(data, dict):
        raise InvalidParameterValueError(f"The configuration has to be a JSON object, not {type(data).__name__}")
    return data


_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)


def _check_pem(content: Any, private_key: bool, name: str) -> bytes:
    """
    The content of a certificate file, or with private_key of a key file, as bytes. Raises
    InvalidParameterValueError unless it is PEM text of that kind and at most PEM_FILE_MAX bytes: the device stores
    whatever it is sent, and a file it can't read leaves it without the key or certificate. Only the PEM frame is
    checked, not what the blocks hold.
    """
    if not isinstance(content, (str, bytes)):
        raise InvalidParameterValueError(f"The {name} has to be PEM text, not {type(content).__name__}")
    data = content.encode("utf-8") if isinstance(content, str) else content
    if not data.strip():
        raise InvalidParameterValueError(f"The {name} is empty")
    if len(data) > PEM_FILE_MAX:
        raise InvalidParameterValueError(f"The {name} has {len(data)} bytes, the device takes {PEM_FILE_MAX}")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise InvalidParameterValueError(f"The {name} isn't PEM text") from None
    wanted = PEM_PRIVATE_KEY if private_key else PEM_CERTIFICATE
    allowed = wanted + PEM_KEY_EXTRAS if private_key else wanted
    labels: list[str] = []
    for label, body in _PEM_BLOCK.findall(text):
        try:
            _ = base64.b64decode("".join(body.split()), validate=True)
        except ValueError:
            raise InvalidParameterValueError(f"The {name} has a {label} block that isn't base64") from None
        labels.append(label)
    unexpected = [label for label in labels if label not in allowed]
    found = [label for label in labels if label in wanted]
    if unexpected or not found or (private_key and len(found) != 1):
        expected = "one unencrypted private key" if private_key else "certificates"
        raise InvalidParameterValueError(
            f"The {name} has to hold {expected} as PEM, it holds {labels or 'no PEM block'}"
        )
    return data


def _check_milliseconds(value: int, minimum: int, name: str) -> None:
    """Raises InvalidParameterValueError unless value is a whole number from minimum to OUTPUT_DELAY_MAX."""
    # bool is an int as well, but True as 1 ms is surely a mistake
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= OUTPUT_DELAY_MAX:
        raise InvalidParameterValueError(
            f"The {name} is in milliseconds and has to be a whole number from {minimum} to {OUTPUT_DELAY_MAX}, "
            f"not {value!r}"
        )


def _check_enabled(value: Any) -> None:
    """Raises InvalidParameterValueError unless value is a bool: the firmware stores anything else as sent or as off."""
    if not isinstance(value, bool):
        raise InvalidParameterValueError(f"enabled has to be a bool, not {value!r}")


def _check_block_name(name: Any, kind: str) -> None:
    """
    Raises InvalidParameterValueError unless name is a string of 1 to BLOCK_NAME_MAX bytes as UTF-8 without a slash. The
    firmware stores other names, and one with a slash can't be read or changed through its name topic.
    """
    if not isinstance(name, str) or not 1 <= len(name.encode()) <= BLOCK_NAME_MAX or "/" in name:
        raise InvalidParameterValueError(
            f"The {kind} name has to be a string of 1 to {BLOCK_NAME_MAX} characters without '/', not {name!r}"
        )


def _block_config_text(config: Any, kind: str) -> str:
    """
    The config of a rule, PAB or watchdog as the JSON string to send. Raises InvalidParameterValueError for one that
    isn't a dict, lacks a key without which the firmware drops it or never acts on it, or is longer than the topic
    takes.
    """
    if not isinstance(config, dict):
        raise InvalidParameterValueError(f"The config has to be a dict, not {config!r}")
    required: tuple[str, ...]
    if kind == "PAB":
        if "type" not in config or not isinstance(config["type"], str) or config["type"] not in PAB_CONFIG_REQUIRED:
            raise InvalidParameterValueError(f"A PAB's config needs a 'type' of {list(PAB_CONFIG_REQUIRED)}")
        required = PAB_CONFIG_REQUIRED[config["type"]]
    else:
        required = RULE_CONFIG_REQUIRED if kind == "rule" else WATCHDOG_CONFIG_REQUIRED
    missing = [key for key in required if key not in config]
    if missing:
        raise InvalidParameterValueError(f"The {kind}'s config lacks {missing}")
    text = json.dumps(config, ensure_ascii=False)
    size = len(text.encode())
    if size > BLOCK_CONFIG_MAX:
        raise InvalidParameterValueError(
            f"The {kind}'s config is {size} bytes long as JSON, the device takes {BLOCK_CONFIG_MAX}"
        )
    return text


def _intervals_cover(intervals: list[dict[str, Any]], device_time: int) -> bool:
    """Whether one of a schedule's intervals covers device_time, the device's local time as seconds since the epoch."""
    second = device_time % 86400
    day = SCHEDULE_DAYS[(device_time // 86400 + 3) % 7]  # 1970-01-01 was a Thursday
    return any(interval[day] and interval["from"] <= second < interval["to"] for interval in intervals)


def _check_intervals(intervals: Any) -> None:
    """
    Raises InvalidParameterValueError unless intervals is a non-empty list of dicts, each with a whole number of seconds
    as 'from' (0 to SCHEDULE_FROM_MAX) and 'to' (0 to SCHEDULE_TO_MAX) and a bool for each day, as the firmware needs.
    """
    if not isinstance(intervals, list):
        raise InvalidParameterValueError(f"The intervals have to be a list of dicts, not {intervals!r}")
    # The firmware up to 5.4.0 doesn't handle a schedule without intervals: accept an empty list on the firmware that
    # does
    if not intervals:
        raise InvalidParameterValueError("A schedule needs at least one interval on this firmware")
    for number, interval in enumerate(intervals, 1):
        if not isinstance(interval, dict):
            raise InvalidParameterValueError(f"Interval {number} has to be a dict, not {interval!r}")
        missing = [key for key in ("from", "to", *SCHEDULE_DAYS) if key not in interval]
        if missing:
            raise InvalidParameterValueError(f"Interval {number} lacks {missing}")
        for key, maximum in (("from", SCHEDULE_FROM_MAX), ("to", SCHEDULE_TO_MAX)):
            value = interval[key]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise InvalidParameterValueError(
                    f"Interval {number}: {key!r} has to be a whole number of seconds from 0 to {maximum}, not {value!r}"
                )
        not_bool = [day for day in SCHEDULE_DAYS if not isinstance(interval[day], bool)]
        if not_bool:
            raise InvalidParameterValueError(f"Interval {number}: {not_bool} have to be bools")


def _mqtt_number(value: Any) -> float | None:
    """value as a number when it is one or a string of one, as the firmware takes both. None otherwise."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _mqtt_entries(parent: dict[str, Any], key: str, where: str) -> list[dict[str, Any]]:
    """The objects of the list under key, none when the key is missing. The firmware skips other entries silently."""
    if key not in parent:
        return []
    entries: Any = parent[key]
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise InvalidParameterValueError(f"MQTT config, {where}: {key!r} has to be a list of objects")
    return entries


def _mqtt_text(parent: dict[str, Any], key: str, where: str) -> None:
    """Raises InvalidParameterValueError unless parent has a non-empty string under key."""
    if key not in parent or not isinstance(parent[key], str) or not parent[key]:
        raise InvalidParameterValueError(f"MQTT config, {where}: {key!r} has to be a non-empty string")


def _check_mqtt_qos(entry: dict[str, Any], where: str) -> None:
    if "qos" in entry and _mqtt_number(entry["qos"]) not in (0, 1, 2):
        raise InvalidParameterValueError(f"MQTT config, {where}: 'qos' has to be 0, 1 or 2, not {entry['qos']!r}")


def _check_mqtt_events(entry: dict[str, Any], where: str) -> None:
    for number, event in enumerate(_mqtt_entries(entry, "events", where), 1):
        at = f"{where}, event {number}"
        # The firmware needs a type
        if "type" not in event or event["type"] not in MQTT_EVENT_TYPES:
            raise InvalidParameterValueError(f"MQTT config, {at}: 'type' has to be one of {MQTT_EVENT_TYPES}")
        if event["type"] == "timer":
            period = _mqtt_number(event["period"]) if "period" in event else None
            if period is None or period < MQTT_TIMER_PERIOD_MIN:
                raise InvalidParameterValueError(
                    f"MQTT config, {at}: a timer needs a 'period' of at least {MQTT_TIMER_PERIOD_MIN} seconds"
                )
            continue
        _mqtt_text(event, "source", at)
        if event["type"] == "delta" and ("delta" not in event or _mqtt_number(event["delta"]) is None):
            raise InvalidParameterValueError(f"MQTT config, {at}: a delta event needs a number as 'delta'")


def _check_mqtt_broker(broker: Any) -> None:
    where = "broker"
    if not isinstance(broker, dict):
        raise InvalidParameterValueError("MQTT config: 'broker' has to be an object")
    missing = [key for key in MQTT_BROKER_REQUIRED if key not in broker]
    if missing:
        raise InvalidParameterValueError(f"MQTT config, {where}: {missing} missing")
    _mqtt_text(broker, "url", where)
    if "://" in broker["url"]:
        raise InvalidParameterValueError(f"MQTT config, {where}: 'url' is the host alone, without a scheme")
    for key in ("ssl", "clientcert"):
        if key in broker and not isinstance(broker[key], bool):
            raise InvalidParameterValueError(f"MQTT config, {where}: {key!r} has to be true or false")
    if broker["protocol"] not in MQTT_PROTOCOLS:
        raise InvalidParameterValueError(f"MQTT config, {where}: 'protocol' has to be one of {MQTT_PROTOCOLS}")
    # The firmware adds an "s" for ssl, and "mqttss" connects nowhere
    if broker["protocol"] == "mqtts" and "ssl" in broker and broker["ssl"]:
        raise InvalidParameterValueError(f"MQTT config, {where}: use the protocol 'mqtts' or 'ssl' true, not both")
    if "clientid" in broker and (
        not isinstance(broker["clientid"], str) or len(broker["clientid"]) > MQTT_CLIENT_ID_MAX
    ):
        raise InvalidParameterValueError(
            f"MQTT config, {where}: 'clientid' has to be a string of at most {MQTT_CLIENT_ID_MAX} characters"
        )


def _mqtt_config_text(config: Any) -> str:
    """
    The MQTT config as the JSON string to send, without spaces, as the device stores it. Raises
    InvalidParameterValueError for a config the checks refuse or that is longer than the topic takes.
    """
    _check_mqtt_config(config)
    text = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    size = len(text.encode())
    if size > MQTT_CONFIG_MAX:
        raise InvalidParameterValueError(f"The MQTT config is {size} bytes long, the device takes {MQTT_CONFIG_MAX}")
    return text


def _mqtt_difference(sent: Any, held: Any, where: str) -> str | None:
    """
    Where the MQTT config the device holds differs from the one sent, or None when they are the same. A string of
    digits that the device returns as that number counts as the same: the firmware stores it so.
    """
    if isinstance(sent, dict) and isinstance(held, dict):
        for key in sent.keys() | held.keys():
            if key not in sent or key not in held:
                return f"{where}.{key} is {'missing' if key in sent else 'added'}"
            difference = _mqtt_difference(sent[key], held[key], f"{where}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(sent, list) and isinstance(held, list):
        if len(sent) != len(held):
            return f"{where} has {len(held)} entries, not {len(sent)}"
        for index, (sent_item, held_item) in enumerate(zip(sent, held)):
            difference = _mqtt_difference(sent_item, held_item, f"{where}[{index}]")
            if difference is not None:
                return difference
        return None
    if isinstance(sent, bool) or isinstance(held, bool):
        same = sent is held
    elif isinstance(sent, str) and isinstance(held, (int, float)):
        same = sent == str(held)
    else:
        same = sent == held
    # Without the values: the config holds the broker's password
    return None if same else f"{where} isn't the value that was sent"


def _check_mqtt_config(config: Any) -> None:
    """
    Raises InvalidParameterValueError for an MQTT config that the firmware can't handle or doesn't apply. The device
    answers OK to any config, so nothing else would tell. Variable names and unknown keys aren't checked.
    """
    if not isinstance(config, dict) or "broker" not in config:
        raise InvalidParameterValueError("The MQTT config has to be an object with a 'broker'")
    _check_mqtt_broker(config["broker"])
    for number, entry in enumerate(_mqtt_entries(config, "publish", "config"), 1):
        where = f"publish entry {number}"
        _mqtt_text(entry, "topic", where)
        if "payload" not in entry and "payloaddef" not in entry:
            raise InvalidParameterValueError(f"MQTT config, {where}: 'payload' or 'payloaddef' is needed")
        if "payloaddef" in entry:
            definition: Any = entry["payloaddef"]
            if not isinstance(definition, dict) or "source" not in definition or "translate" not in definition:
                raise InvalidParameterValueError(
                    f"MQTT config, {where}: 'payloaddef' has to be an object with 'source' and 'translate'"
                )
        _check_mqtt_qos(entry, where)
        _check_mqtt_events(entry, where)
    for number, entry in enumerate(_mqtt_entries(config, "subscribe", "config"), 1):
        where = f"subscribe entry {number}"
        _mqtt_text(entry, "topic", where)
        _mqtt_text(entry, "target", where)
        # The firmware needs an action to remove the entry. A number is what the ACTION targets take, and what the
        # device returns for a string of digits
        if (
            "action" not in entry
            or isinstance(entry["action"], bool)
            or not isinstance(entry["action"], (str, int, float))
        ):
            raise InvalidParameterValueError(
                f"MQTT config, {where}: 'action' has to be a string or a number, '${{payload}}' to pass the message on"
            )
        for mapping in _mqtt_entries(entry, "actiondef", where):
            if "payload" not in mapping or "action" not in mapping:
                raise InvalidParameterValueError(
                    f"MQTT config, {where}: every 'actiondef' entry needs 'payload' and 'action'"
                )
        _check_mqtt_qos(entry, where)
    for number, entry in enumerate(_mqtt_entries(config, "groupEvents", "config"), 1):
        _check_mqtt_events(entry, f"group event {number}")


def _auth_or_current(auth: tuple[str, str] | None, current: dict[str, Any], prefix: str) -> tuple[str, str]:
    """Returns auth, or the device's current (username, password) when auth is None."""
    if auth is not None:
        return auth
    return current[f"{prefix}Username"], current[f"{prefix}Password"]


def _port_in_host(host: str) -> int | None:
    """Returns the port written into host, such as 8080 in 192.168.1.10:8080 or [fe80::1]:8080, None without one."""
    after_address = host.rsplit("]", 1)[-1]
    if after_address.count(":") != 1:
        return None
    return int(after_address.split(":")[1])


class ESP500Device(NETIODevice):
    """
    A class to control ESP devices with the firmware 5.1.x.
    """

    @override
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        sn_number: str,
        hostname: str,
        keep_alive: bool = True,
        netio_manager: NetioManager | None = None,
        use_https: bool = False,
        **kwargs: Any,
    ):
        """
        Creates the device object for a NETIO device running firmware 5.1.x. This is normally not called
        directly: NetioManager.init_device detects the firmware version, opens and authenticates the WebSocket
        connection, and passes that connection state in through kwargs.

        The 5.x.x versions of Netio firmware have been severely redesigned, which includes the entirety of the API
        used to communicate with the device. Therefore this init is completely separate from the base classes and
        does not call super().__init__. If the base NETIODevice class gets updated, this has to be updated
        accordingly.

        Parameters
        ----------
        host : str
            IP address or hostname of the device, without any URL parts such as 'http://'.
        username : str
            Username to log in with. Note that many actions require administrator privileges.
        password : str
            Password for the user.
        sn_number : str
            Serial number of the device. NetioManager passes an empty string; the 5.x classes don't use it.
        hostname : str
            Network hostname of the device. NetioManager passes an empty string; the 5.x classes don't use it.
        keep_alive : bool
            Start the keep-alive thread. On 5.1.x firmware the keep-alive is a stub that only logs a debug
            message; devices running 5.2.x and up ping the device every 120 seconds.
        netio_manager : NetioManager | None
            The NetioManager instance the device belongs to. Used after a firmware update to replace the object
            with the class that matches the new firmware version.
        use_https : bool
            Communicate over HTTPS and secure WebSockets (wss://) instead of HTTP and ws://. HTTPS must be enabled
            on the device. Also silences urllib3's InsecureRequestWarning, since devices use self-signed
            certificates.
        **kwargs : Any
            Connection state handed over by NetioManager. None of these are required when creating the object by
            hand, but without them the init opens and authenticates a new connection itself.

            ws_connection : ws_transport.Connection | None
                An open WebSocket connection to the device. If None, a new connection is opened on login.
                Default None.
            is_ws_auth : bool
                Whether ws_connection is already authenticated. If True the login step is skipped, otherwise the
                init logs in with username and password. Default False.
            ws_req_id : int
                The next request ID to use, so that IDs continue from the requests already sent on
                ws_connection. Default 0.
            ws_helo_data : dict[str, Any]
                The device's full reply to the initial HELO request, which carries the public key used for password
                hashing. If not given, a new HELO request is sent. Default None.
            device_version : tuple[int, int, int]
                Firmware version of the device as (major, minor, patch). Also selects the API dialect: on 5.4.x and
                newer, requests use GET instead of SUBSCRIBE. Default (5, 1, 3).
            ssl_options : dict[str, Any]
                The TLS settings whenever the connection is (re)opened over wss://: "context", an ssl.SSLContext,
                or without it the keys ws_transport.ssl_context_of() takes.
                NetioManager builds this from the ssl_* keyword arguments of init_device. Default {}.
        """
        self.host = host
        self.username = username
        self.password = password
        self.sn_number = sn_number
        self.hostname = hostname
        self.session_id = ""
        self.supported_features: dict[str, Any] = dict()
        self.output_count = 4
        self.user_permissions: list[str] = list()
        self._keep_alive_flag = keep_alive
        self.ws_req_id = kwargs.get("ws_req_id", 0)
        self.use_https = use_https
        self.version = kwargs.get("device_version", (5, 1, 3))
        if use_https:
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning

            disable_warnings(category=InsecureRequestWarning)

        # Before we start dealing with websocket communication past initiation we create a deque for the responses.
        # This is mainly to mitigate potential desynchronization between the device requests and the library posting
        # them.
        # This is mostly due to SUBSCRIBE topics sending events which we don't react to given the request-response
        # architecture
        # of PyNetioConf. PING PONG topics also cause potential desynchronization
        self._request_queue = deque(maxlen=DEFAULT_REQUEST_QUEUE_LEN)
        self._pong_queue = deque(maxlen=DEFAULT_KEEP_ALIVE_QUEUE_LEN)
        self._ws_lock = threading.RLock()
        self._latency = LatencyStats()
        self._on_wifi = False
        self._delay_factor = 1.0
        # Last answer of get_firmware_updates_list() and its perf_counter() time, reused for FIRMWARE_LIST_CACHE_TIME
        self._firmware_list: list[dict[str, Any]] | None = None
        self._firmware_list_time = 0.0

        # Init from base ESP Device
        self.ws: Connection | None = kwargs.get("ws_connection", None)
        self.logger = logging.getLogger(__name__)
        self.ssl_options: dict[str, Any] = kwargs.get("ssl_options") or {}
        if kwargs.get("is_ws_auth", False):
            self.session_id = "TODO AUTH"
        else:
            self.session_id = self.login(username, password)
        # self.supported_features = self.get_features()
        # self.output_count: int = self.supported_features["outputCount"]
        try:
            self.user_permissions = self.get_user_privileges(username)
        except (CommunicationError, DeviceError, ElementNotFound):
            self.logger.warning(
                f"Couldn't read the privileges of user {username} on device {self.host}, user_permissions is empty."
            )
        self._ka_thread: threading.Timer | None = None
        if keep_alive:
            self._ka_thread = threading.Timer(120, self._keep_alive)
            self._ka_thread.daemon = True
            self._ka_thread.start()
        atexit.register(self._cleanup)

        # New Init
        # Logger of the module the class is defined in, so it stays under the package hierarchy for subclasses too
        self.logger = logging.getLogger(type(self).__module__)
        self.netio_manager = netio_manager
        # self.fw_version = self.get_version()

        _system_info = self.get_system_info()
        self.output_count = _system_info["outputCount"]
        self.input_count = _system_info["inputCount"]
        self.supported_features["wifi"] = _system_info["wifiSupport"]
        self.supported_features["eth"] = _system_info["ethSupport"]
        self._on_wifi = bool(_system_info["wifiSupport"]) and self._detect_wifi()
        self._ws_helo_data = kwargs.get("ws_helo_data") or ws_api.send_request(self, "HELO")

    def _detect_wifi(self) -> bool:
        """Whether the device reaches the network over Wi-Fi: its Ethernet isn't connected and its Wi-Fi is."""
        self.logger.debug(f"Checking whether device {self.host} is on Wi-Fi")
        try:
            ethernet = bool(self.supported_features["eth"]) and (
                self.get_ethernet_status()["connectionStatus"] == "Connected"
            )
            wifi = self.get_wifi_status()["connectionStatus"] == "Connected"
        except (CommunicationError, DeviceError):
            # Taken for Wi-Fi, so the delays err on the long side
            self.logger.debug(f"Couldn't read the network status of device {self.host}, taking it for Wi-Fi")
            return True
        return wifi and not ethernet

    def _keep_alive(self) -> None:
        self.logger.debug(
            f"Keep-alive stub called for device {self.host}, keep-alive functianolity is restored on devices running "
            "5.2.x and up, please update."
        )

    @override
    def login(self, username: str, password: str, logout: bool = False) -> str:
        # The connection is replaced here: no other thread's request may be on it meanwhile
        with self._ws_lock:
            return self._login(username, password, logout)

    def _login(self, username: str, password: str, logout: bool) -> str:
        """login() once the device's connection is this thread's."""
        if logout:
            # Drops the current connection, which usually ended with a device restart, and logs in on a new one
            ws_api.close_connection(self.ws, graceful=False)
            self.ws = None

        # Each attempt connects if needed, then sends HELO and AUTH. The AUTH token is built from the HELO reply, so a
        # dropped connection needs the whole sequence again. HELO doesn't go through send_request, which would call
        # login again when there is no connection.
        reconnected = False
        try_count = 3
        for attempt in range(try_count):
            if self.ws is None:
                # If the KA thread is alive it can send requests while the device is reconnecting on the old pipe.
                if self._ka_thread:
                    self._ka_thread.cancel()
                    self._ka_thread.join()
                    self.logger.debug("Disabled keep-alive thread due to new login process.")

                self.logger.debug(f"{self.host} websocket connection attempt {attempt + 1}/{try_count}")
                try:
                    self.ws = connect_device(self.host, self.use_https, self.ssl_options)
                except Exception:
                    self.logger.debug(f"Connection to {self.host} failed on {attempt + 1}/{try_count}")
                    sleep(1)
                    continue

                self.logger.debug(f"Succesfully connected to {self.host}")
                self.ws.settimeout(WS_DEFAULT_TIMEOUT)
                self.ws_req_id = 0
                reconnected = True

            try:
                hello_response = ws_api.device_init_request(self.ws, self.ws_req_id, "HELO", self.host)
                self.ws_req_id += 1
                ws_api.login(
                    self,
                    hello_response["data"]["localTimestamp"],
                    hello_response["data"]["publicKey"],
                    username,
                    password,
                )
            except CommunicationError:
                self.logger.debug(f"Login to {self.host} failed on {attempt + 1}/{try_count}")
                # The next attempt opens a new connection, the device would keep a session for this one
                ws_api.close_connection(self.ws, graceful=False)
                self.ws = None
                sleep(1)
                continue
            except AuthError:
                # Not retried, the credentials stay wrong and every attempt counts towards the device's lockout
                ws_api.close_connection(self.ws)
                self.ws = None
                raise

            if reconnected and self._keep_alive_flag:
                self._ka_thread = threading.Timer(120, self._keep_alive)
                self._ka_thread.daemon = True
                self._ka_thread.start()

            # change_password and the logins after a dropped connection use the credentials of the last login
            user_changed = username != self.username
            self.username = username
            self.password = password
            if user_changed:
                try:
                    self.user_permissions = self.get_user_privileges(username)
                except (CommunicationError, DeviceError, ElementNotFound):
                    self.logger.warning(
                        f"Couldn't read the privileges of user {username} on device {self.host}, "
                        "user_permissions is empty."
                    )
                    self.user_permissions = []

            return "TODO: Authenticate Session ID on 5.x.x"

        raise CommunicationError(f"Couldn't log in to device {self.host} after {try_count} attempts.")

    @override
    def logout(self) -> None:
        self.logger.debug(f"Logging out of device {self.host}")
        self.logger.debug(f"Latency of {self.host}: {self._latency.summary()}")
        # The keep-alive would log in again and open a new session. The next login starts it again.
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
        # The device keeps the session until the connection closes
        ws_api.close_connection(self.ws)
        self.ws = None
        self.ws_req_id = 0

    @override
    def get_current_user(self) -> dict[str, Any]:
        self.logger.debug(f"Fetching current user ({self.username}) data from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{self.username}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    @override
    def get_user_privileges(self, username: str) -> list[str]:
        self.logger.debug(f"Fetching privileges for user {username} on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{username}/config"
        self._require_user(username)
        response = ws_api.send_request(self, ws_type, ws_topic)
        data = response.get("data")
        if not data:
            raise ElementNotFound(f"User {username} not found on device {self.host}")
        priv_dict = data.get("privileges", {})
        return [key for key, val in priv_dict.items() if val is True]

    @override
    def get_users(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "users/list"

        self.logger.debug(f"Fetching users list on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        items = response.get("data", {}).get("items", [])
        return {item["name"]: item for item in items if "name" in item}

    @override
    def create_user(self, username: str, password: str, privileges: list[str] | None = None) -> None:
        self.logger.debug(f"Creating user {username} on device {self.host}")
        if privileges is None or len(privileges) == 0:
            privileges = ["can_login"]
        privileges_dict = self._privileges_dict(privileges)
        # The device replies OK to creating an existing user and leaves that user unchanged
        if username in self.get_users():
            raise ElementAlreadyExists(f"User {username} already exists on device {self.host}")

        hello_response = ws_api.send_request(self, "HELO")
        public_key = hello_response["data"]["publicKey"]
        password_hash = ws_api.generate_password_hash(username, password, public_key)

        ws_type = "SET"
        ws_topic = "users/create"
        ws_data = {
            "name": username,
            "password": "",
            "passwordHash": password_hash,
            "privileges": privileges_dict,
        }
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        self._wait_for_user_list(username, listed=True)

    @override
    def remove_user(self, username: str) -> None:
        self.logger.debug(f"Removing user {username} on device {self.host}")
        ws_type = "SET"
        ws_topic = "users/delete"
        ws_data = {"name": username}
        # The device replies OK to deleting a user that doesn't exist
        self._require_user(username)
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        self._wait_for_user_list(username, listed=False)

    @override
    def set_user_privileges(self, username: str, privileges: list[str]) -> None:
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{username}/config"
        self.logger.debug(f"Setting privileges of user {username} on device {self.host}")
        privileges_dict = self._privileges_dict(privileges)
        self._require_user(username)
        ws_data = self._require_config(
            ws_api.send_request(self, ws_type, ws_topic).get("data", {}),
            f"user {username}",
        )
        ws_data["privileges"] = privileges_dict
        ws_type = "SET"
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def set_user_privilege(self, username: str, privilege: str, state: bool) -> None:
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{username}/config"
        self.logger.debug(f"Setting privilege {privilege} of user {username} to {state} on device {self.host}")
        self._check_privileges([privilege])
        self._require_user(username)
        ws_data = self._require_config(
            ws_api.send_request(self, ws_type, ws_topic).get("data", {}),
            f"user {username}",
        )
        ws_data["privileges"][privilege] = state
        ws_type = "SET"
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def get_system_info(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "system/info"
        self.logger.debug(f"Fetching system info on {self.host}")
        return ws_api.send_request(self, ws_type, ws_topic)["data"]

    @override
    def get_uptime(self) -> int:
        self.logger.debug(f"Fetching system uptime from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "system/uptime"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return int(response.get("data", {}).get("uptime", 0))

    @override
    def get_version_detailed(self) -> str:
        self.logger.debug(f"Fetching detailed firmware version from device {self.host}")
        return self.get_system_info()["fwVersion"]

    @override
    def get_version(self) -> str:
        self.logger.debug(f"Fetching firmware version from device {self.host}")
        return self.get_version_detailed().split("-")[0].strip()

    @override
    def get_output_data(self, output_id: int) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = f"outputs/id/{output_id}/config"
        self.logger.debug(f"Fetching output configuration data for output id {output_id} on {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    def _set_output_config(
        self,
        output_id: int,
        default_state: str | None = None,
        is_schedule_active: bool | None = None,
        output_name: str | None = None,
        power_up_interval: int | None = None,
        reset_delay: int | None = None,
        schedule_id: int | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = f"outputs/id/{output_id}/config"

        self.logger.debug(f"Setting output {output_id} config on device {self.host}")
        current = self._require_config(self.get_output_data(output_id), f"output {output_id}")
        ws_data = {
            "default": _value_or_current(default_state, current, "default"),
            "isScheduleActive": _value_or_current(is_schedule_active, current, "isScheduleActive"),
            "name": _value_or_current(output_name, current, "name"),
            "powerUpInterval": _value_or_current(power_up_interval, current, "powerUpInterval"),
            "resetDelay": _value_or_current(reset_delay, current, "resetDelay"),
            "scheduleId": _value_or_current(schedule_id, current, "scheduleId"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    def _require_user(self, username: str) -> None:
        """
        Raises ElementNotFound when the user is not on the device. The check goes through users/list, because
        requesting the config of a user that doesn't exist restarts firmware 5.4.0. The logged-in user is not
        checked.
        """
        if username != self.username and username not in self.get_users():
            raise ElementNotFound(f"User {username} not found on device {self.host}")

    def _wait_for_user_list(self, username: str, listed: bool) -> None:
        """
        Waits until users/list shows the user as listed or not listed. The device confirms users/create and
        users/delete before users/list shows the change, so checks right after them would see the old state.
        """
        deadline = perf_counter() + USER_LIST_SYNC_TIMEOUT
        while (username in self.get_users()) != listed:
            if perf_counter() >= deadline:
                state = "still not listed" if listed else "still listed"
                raise CommunicationError(
                    f"User {username} is {state} on device {self.host} {USER_LIST_SYNC_TIMEOUT} seconds after "
                    "the device confirmed the change"
                )
            sleep(USER_LIST_SYNC_INTERVAL)

    def _check_privileges(self, privileges: list[str]) -> None:
        """
        Raises InvalidParameterValueError when one of the privileges doesn't exist.
        """
        unknown = [privilege for privilege in privileges if privilege not in USER_PRIVILEGES]
        if unknown:
            raise InvalidParameterValueError(
                f"Unknown privileges {unknown}, the possible ones are {list(USER_PRIVILEGES)}"
            )

    def _privileges_dict(self, privileges: list[str]) -> dict[str, bool]:
        """
        Turns a list of privileges into the dict the device expects, with every privilege in it.
        """
        self._check_privileges(privileges)
        return {privilege: privilege in privileges for privilege in USER_PRIVILEGES}

    def _require_config(self, current: dict[str, Any], config_name: str) -> dict[str, Any]:
        if not current:
            message = f"Device {self.host} returned no {config_name} configuration, settings were left unchanged"
            self.logger.error(message)
            raise CommunicationError(message)
        return current

    def _check_socket_index(self, socket_index: int) -> None:
        if socket_index < 1 or socket_index > self.output_count:
            raise InvalidSocketIndex(
                f"You tried to access socket with id {socket_index}, the device supports <1;{self.output_count}>."
            )

    @override
    def rename_output(self, output_id: int, output_name: str) -> None:
        if not isinstance(output_name, str):
            raise InvalidParameterValueError(f"The output name has to be a string, not {output_name!r}")
        self.logger.debug(f"Renaming output {output_id} to new name: {output_name}")
        self._set_output_config(output_id, output_name=output_name)

    @override
    def set_output_action(self, output_id: int, action: OutputAction) -> None:
        try:
            request = OutputAction(action)
        except ValueError:
            raise InvalidParameterValueError(
                f"Unknown output action {action!r}, the possible ones are {[a.value for a in OutputAction]}"
            ) from None
        ws_type = "SET"
        ws_topic = f"outputs/id/{output_id}/ctrl"
        ws_data = {"request": request.value}

        self._check_socket_index(output_id)
        self.logger.debug(f"Setting output {output_id} to {request.name} on device {self.host}")
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def set_output(self, output_id: int, state: bool) -> None:
        self.logger.debug(f"Switching output {output_id} {'on' if state else 'off'} on device {self.host}")
        self.set_output_action(output_id, OutputAction.ON if state else OutputAction.OFF)

    @override
    def short_on_output(self, output_id: int) -> None:
        self.logger.debug(f"Switching output {output_id} on for its reset delay on device {self.host}")
        self.set_output_action(output_id, OutputAction.SHORT_ON)

    @override
    def toggle_output(self, output_id: int) -> None:
        self.logger.debug(f"Toggling output {output_id} on device {self.host}")
        self.set_output_action(output_id, OutputAction.TOGGLE)

    @override
    def set_output_reset_delay(self, output_id: int, reset_delay: int) -> None:
        _check_milliseconds(reset_delay, OUTPUT_RESET_DELAY_MIN, "reset delay")
        self._check_socket_index(output_id)
        self.logger.debug(f"Setting the reset delay of output {output_id} to {reset_delay} ms on device {self.host}")
        self._set_output_config(output_id, reset_delay=reset_delay)

    @override
    def set_output_power_up_state(self, output_id: int, state: OutputPowerUpState) -> None:
        try:
            default_state = OutputPowerUpState(state).value
        except ValueError:
            raise InvalidParameterValueError(
                f"Unknown power-up state {state!r}, the possible ones are {[s.value for s in OutputPowerUpState]}"
            ) from None
        self._check_socket_index(output_id)
        self.logger.debug(f"Setting the power-up state of output {output_id} to {default_state} on device {self.host}")
        self._set_output_config(output_id, default_state=default_state)

    @override
    def set_output_power_up_interval(self, output_id: int, power_up_interval: int) -> None:
        _check_milliseconds(power_up_interval, OUTPUT_POWER_UP_INTERVAL_MIN, "power-up interval")
        self._check_socket_index(output_id)
        self.logger.debug(
            f"Setting the power-up interval of output {output_id} to {power_up_interval} ms on device {self.host}"
        )
        self._set_output_config(output_id, power_up_interval=power_up_interval)

    @override
    def set_outputs_unified(self, state: bool) -> None:
        self.logger.debug(f"Setting all outputs unified to {state} on device {self.host}")
        for output in range(1, self.output_count + 1):
            self.set_output(output, state)

    @override
    def reset_output(self, output_id: int) -> None:
        self.logger.debug(f"Resetting output {output_id} (short off) on device {self.host}")
        self.set_output_action(output_id, OutputAction.SHORT_OFF)

    @override
    def reset_output_consumption_counter(self, output_id: int) -> None:
        ws_type = "SET"
        ws_topic = f"outputs/id/{output_id}/resetOutputConsumption"
        ws_data = {"request": True}

        self._check_socket_index(output_id)
        self.logger.debug(f"Resetting power consumption counters for output {output_id} on device {self.host}")
        ws_api.send_request(
            self,
            ws_type,
            ws_topic,
            ws_data,
        )

    @override
    def reset_power_consumption_counters(self) -> None:
        self.logger.debug(f"Resetting power consumption counters for all outputs on device {self.host}")
        for output in range(1, self.output_count + 1):
            self.reset_output_consumption_counter(output)
            sleep(0.1)

    @override
    def reset_global_consumption_counter(self) -> None:
        ws_type = "SET"
        ws_topic = "outputs/globalMeasure/resetOutputConsumption"
        ws_data = {"request": True}

        self.logger.debug(f"Resetting the global consumption counter on device {self.host}")
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def get_output_schedule(self, output_id: int) -> dict[str, Any]:
        self.logger.debug(f"Fetching output {output_id} schedule from device {self.host}")
        output_data = self.get_output_data(output_id)
        return {
            "id": output_data.get("scheduleId", 0),
            "on": output_data.get("isScheduleActive", False),
        }

    @override
    def get_output_schedule_id(self, output_id: int) -> int:
        self.logger.debug(f"Fetching output {output_id} schedule ID from device {self.host}")
        return int(self.get_output_schedule(output_id)["id"])

    @override
    def set_output_schedule(self, output_id: int, schedule_id: int, enabled: bool | None = None) -> None:
        self.logger.debug(
            f"Setting output {output_id} schedule to schedule ID {schedule_id} (active={enabled}) on {self.host}"
        )
        self._set_output_config(output_id, schedule_id=schedule_id, is_schedule_active=enabled)

    @override
    def set_output_schedule_state(self, output_id: int, schedule_enabled: bool) -> None:
        self.logger.debug(f"Setting output {output_id} schedule state to {schedule_enabled} on {self.host}")
        self._set_output_config(output_id, is_schedule_active=schedule_enabled)

    @override
    def set_output_schedule_by_name(self, output_id: int, schedule_name: str, enabled: bool | None = None) -> None:
        self.logger.debug(f"Setting output {output_id} schedule to '{schedule_name}' on {self.host}")
        schedule_id = self.get_schedule_id(schedule_name)
        self.set_output_schedule(output_id, schedule_id, enabled)

    def _create_block(
        self,
        kind: str,
        topic: str,
        data: dict[str, Any],
        get: Callable[[str], Any],
        listed: Callable[[], list[dict[str, Any]]],
    ) -> None:
        """
        Sends the create of a rule, PAB, watchdog or schedule once none of its name exists, and returns when the device
        lists the new one and gives it by name: 5.4.0 answers before either. The first read waits BLOCK_CREATE_SETTLE.
        """
        name: str = data["name"]
        try:
            get(name)
        except ElementNotFound:
            pass
        else:
            raise ElementAlreadyExists(f"{kind[0].upper()}{kind[1:]} {name} already exists on device {self.host}")
        self.logger.debug(f"Creating {kind} {name} via {topic} on device {self.host}")
        _ = ws_api.send_request(self, "SET", topic, data)
        sent = perf_counter()
        sleep(BLOCK_CREATE_SETTLE)
        while True:
            if any(item["name"] == name for item in listed()):
                try:
                    get(name)
                    return
                except ElementNotFound:
                    pass
            if perf_counter() - sent > BLOCK_LISTED_TIMEOUT:
                raise CommunicationError(
                    f"Device {self.host} answered the create of {kind} {name} but doesn't give it "
                    f"{BLOCK_LISTED_TIMEOUT} s later"
                )
            sleep(BLOCK_LISTED_INTERVAL)

    def _create_configurable_block(
        self,
        kind: str,
        topic: str,
        enable: bool,
        name: str,
        config: dict[str, Any],
        get: Callable[[str], Any],
        listed: Callable[[], list[dict[str, Any]]],
    ) -> None:
        """Creates a rule, PAB or watchdog after checking what the firmware would store as sent."""
        _check_enabled(enable)
        _check_block_name(name, kind)
        text = _block_config_text(config, kind)
        self.logger.debug(f"{kind} {name} configuration: {text}")
        self._create_block(kind, topic, {"enabled": enable, "name": name, "config": text}, get, listed)

    def _get_configurable_block(self, ws_topic: str, kind: str, name: str) -> dict[str, Any]:
        """A rule, PAB or watchdog with its config parsed. The device sends it as a JSON string."""
        ws_type = "SUBSCRIBE"
        data = ws_api.send_request(self, ws_type, ws_topic)["data"]
        if not data:
            raise ElementNotFound(f"{kind} {name} not found on device {self.host}")
        data["config"] = json.loads(data["config"])
        return data

    def _set_configurable_block(
        self, ws_topic: str, kind: str, name: str, enabled: bool | None, config: dict[str, Any] | None
    ) -> None:
        """Changes an existing rule, PAB or watchdog through its config topic. The device refuses another name."""
        if enabled is not None:
            _check_enabled(enabled)
        text = _block_config_text(config, kind) if config is not None else None
        current = self._get_configurable_block(ws_topic, kind, name)
        ws_type = "SET"
        ws_data = {
            "name": name,
            "enabled": _value_or_current(enabled, current, "enabled"),
            "config": text if text is not None else json.dumps(current["config"], ensure_ascii=False),
        }
        self.logger.debug(f"Setting {kind} {name} on device {self.host}")
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def create_rule(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        self._create_configurable_block(
            "rule", "/rules/create", enable, name, config, self.get_rule_by_name, self.get_rules
        )

    @override
    def get_rules(self) -> list[dict[str, Any]]:
        self.logger.debug(f"Getting rules from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "rules/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]["items"]

    @override
    def get_rule_by_name(self, rule_name: str) -> dict[str, Any]:
        ws_topic = f"rules/name/{rule_name}/config"
        self.logger.debug(f"Filtering for rule {rule_name} on device {self.host}")
        return self._get_configurable_block(ws_topic, "Rule", rule_name)

    @override
    def set_rule(self, name: str, enabled: bool | None = None, config: dict[str, Any] | None = None) -> None:
        ws_topic = f"rules/name/{name}/config"
        self._set_configurable_block(ws_topic, "rule", name, enabled, config)

    @override
    def get_enabled_rules(self) -> list[dict[str, Any]]:
        rules = self.get_rules()
        self.logger.debug(f"Filtering for enabled rules from device {self.host}")
        return [rule for rule in rules if rule["enabled"] is True]

    @override
    def get_disabled_rules(self) -> list[dict[str, Any]]:
        rules = self.get_rules()
        self.logger.debug(f"Filtering for disabled rules from device {self.host}")
        return [rule for rule in rules if rule["enabled"] is False]

    @override
    def create_pab(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        self._create_configurable_block("PAB", "/pab/create", enable, name, config, self.get_pab_by_name, self.get_pabs)

    @override
    def get_pabs(self) -> list[dict[str, Any]]:
        self.logger.debug(f"Getting PABs from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "pab/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]["items"]

    @override
    def get_pab_by_name(self, pab_name: str) -> dict[str, Any]:
        ws_topic = f"pab/name/{pab_name}/config"
        self.logger.debug(f"Filtering for PAB {pab_name} on device {self.host}")
        return self._get_configurable_block(ws_topic, "PAB", pab_name)

    @override
    def set_pab(self, name: str, enabled: bool | None = None, config: dict[str, Any] | None = None) -> None:
        ws_topic = f"pab/name/{name}/config"
        self._set_configurable_block(ws_topic, "PAB", name, enabled, config)

    @override
    def get_enabled_pabs(self) -> list[dict[str, Any]]:
        pabs = self.get_pabs()
        self.logger.debug(f"Filtering for enabled PABs from device {self.host}")
        return [pab for pab in pabs if pab["enabled"] is True]

    @override
    def get_disabled_pabs(self) -> list[dict[str, Any]]:
        pabs = self.get_pabs()
        self.logger.debug(f"Filtering for disabled PABs from device {self.host}")
        return [pab for pab in pabs if pab["enabled"] is False]

    @override
    def create_watchdog(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        self._create_configurable_block(
            "watchdog", "/wdtpingers/create", enable, name, config, self.get_watchdog_by_name, self.get_watchdogs
        )

    @override
    def get_watchdogs(self) -> list[dict[str, Any]]:
        self.logger.debug(f"Getting watchdogs from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "wdtpingers/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]["items"]

    @override
    def get_watchdog_by_name(self, watchdog_name: str) -> dict[str, Any]:
        ws_topic = f"wdtpingers/name/{watchdog_name}/config"
        self.logger.debug(f"Filtering for watchdog {watchdog_name} on device {self.host}")
        return self._get_configurable_block(ws_topic, "Watchdog", watchdog_name)

    @override
    def set_watchdog(self, name: str, enabled: bool | None = None, config: dict[str, Any] | None = None) -> None:
        ws_topic = f"wdtpingers/name/{name}/config"
        self._set_configurable_block(ws_topic, "watchdog", name, enabled, config)

    @override
    def delete_watchdog_by_name(self, name: str) -> None:
        topic = "wdtpingers/delete"
        ws_type = "SET"
        ws_data = {"name": name}
        self.get_watchdog_by_name(name)
        self.logger.debug(f"Attempting to delete watchdog {name} on device {self.host}.")
        _ = ws_api.send_request(self, ws_type, topic, ws_data)

    @override
    def get_enabled_watchdogs(self) -> list[dict[str, Any]]:
        watchdogs = self.get_watchdogs()
        self.logger.debug(f"Filtering for enabled watchdogs from device {self.host}")
        return [w for w in watchdogs if w["enabled"] is True]

    @override
    def get_disabled_watchdogs(self) -> list[dict[str, Any]]:
        watchdogs = self.get_watchdogs()
        self.logger.debug(f"Filtering for disabled watchdogs from device {self.host}")
        return [w for w in watchdogs if w["enabled"] is False]

    @override
    def create_schedule(self, name: str, intervals: list[dict[str, Any]]) -> None:
        _check_block_name(name, "schedule")
        _check_intervals(intervals)
        self.logger.debug(f"schedule {name} intervals: {intervals}")
        self._create_block(
            "schedule",
            "/schedules/create",
            {"name": name, "intervals": intervals},
            self.get_schedule_by_name,
            self.get_schedules,
        )

    @override
    def set_schedule(self, name: str, intervals: list[dict[str, Any]]) -> None:
        ws_topic = f"schedules/name/{name}/config"
        ws_type = "SET"
        _check_intervals(intervals)
        ws_data = {"name": name, "intervals": intervals}
        self.get_schedule_by_name(name)
        self.logger.debug(f"Setting the intervals of schedule {name} on device {self.host}")
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def get_schedules(self) -> list[dict[str, Any]]:
        self.logger.debug(f"Getting a schedule list from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "schedules/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]["items"]

    @override
    def get_schedule_by_name(self, schedule_name: str) -> dict[str, Any]:
        self.logger.debug(f"Filtering for schedule {schedule_name} on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = f"schedules/name/{schedule_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        data = response["data"]
        if not data:
            raise ElementNotFound(f"Schedule {schedule_name} not found on device {self.host}")
        return data

    @override
    def get_schedule_id(self, schedule_name: str) -> int:
        self.logger.debug(f"Fetching ID of schedule {schedule_name} from device {self.host}")
        schedules = self.get_schedules()
        for schedule in schedules:
            if schedule["name"] == schedule_name:
                return int(schedule["id"])
        raise ElementNotFound(f"Schedule {schedule_name} not found on device {self.host}")

    @override
    def get_schedule_names(self) -> list[str]:
        schedules = self.get_schedules()
        self.logger.debug(f"Filtering for schedule names on device {self.host}")
        return [schedule["name"] for schedule in schedules]

    @override
    def get_active_schedules(self) -> list[dict[str, Any]]:
        schedules = self.get_schedules()
        self.logger.debug(f"Filtering for active schedules on device {self.host}")
        if all("active" in schedule for schedule in schedules):
            return [schedule for schedule in schedules if schedule["active"] is True]
        # The list has no "active" on firmware up to 5.4.0: work it out from the intervals and the device's clock
        now = int(self.get_system_datetime()["time"])
        return [
            schedule
            for schedule in schedules
            if _intervals_cover(self.get_schedule_by_name(schedule["name"])["intervals"], now)
        ]

    @override
    def delete_schedule(self, schedule_id: int) -> None:
        self.logger.debug(f"Deleting schedule {schedule_id} from device {self.host}")
        schedules = self.get_schedules()
        schedule_name = None
        for schedule in schedules:
            if schedule["id"] == schedule_id:
                schedule_name = schedule["name"]
                break

        if not schedule_name:
            raise ElementNotFound(f"Schedule with ID {schedule_id} not found on device {self.host}")

        self.delete_schedule_by_name(schedule_name)

    @override
    def delete_schedule_by_name(self, schedule_name: str) -> None:
        # Check for schedule existing, error out if it doesn't
        try:
            self.get_schedule_by_name(schedule_name)
        except ElementNotFound:
            raise ElementNotFound(f"Schedule {schedule_name} not found on device {self.host}")

        topic = "schedules/delete"
        ws_type = "SET"
        ws_data = {"name": schedule_name}
        self.logger.debug(f"Attempting to delete schedule {schedule_name} on device {self.host}.")
        ws_api.send_request(self, ws_type, topic, ws_data)

    @override
    def delete_rule_by_name(self, name: str) -> None:
        # Check for rule existing, error out if it doesn't
        try:
            self.get_rule_by_name(name)
        except ElementNotFound:
            raise ElementNotFound(f"Rule {name} not found on device {self.host}")
        topic = "/rules/delete"
        ws_type = "SET"
        ws_data = {"name": name}
        self.logger.debug(f"Attempting to delete rule {name} on device {self.host}.")
        ws_api.send_request(self, ws_type, topic, ws_data)

    @override
    def delete_pab_by_name(self, pab_name: str) -> None:
        # Check for PAB existing, error out if it doesn't
        try:
            self.get_pab_by_name(pab_name)
        except ElementNotFound:
            raise ElementNotFound(f"PAB {pab_name} not found on device {self.host}")
        topic = "/pab/delete"
        ws_type = "SET"
        ws_data = {"name": pab_name}
        self.logger.debug(f"Attempting to delete PAB {pab_name} on device {self.host}.")
        ws_api.send_request(self, ws_type, topic, ws_data)

    @override
    def get_active_protocols(self) -> list[int]:
        self.logger.debug(f"Fetching active protocols on {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/info"
        response = ws_api.send_request(self, ws_type, ws_topic)

        active_dict = response.get("data", {}).get("active", {})
        active_ids = []
        protocol_map = {
            "xml": 103,
            "json": 104,
            "url": 105,
            "telnet": 106,
            "modbus": 107,
            "mqtt": 108,
            "push": 109,
            "snmp": 110,
        }
        for name, is_active in active_dict.items():
            if is_active and name in protocol_map:
                active_ids.append(protocol_map[name])
        return active_ids

    @override
    def get_supported_protocols(self) -> list[int]:
        self.logger.debug(f"Fetching supported protocols on {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/info"
        response = ws_api.send_request(self, ws_type, ws_topic)

        active_dict = response.get("data", {}).get("active", {})
        protocol_map = {
            "xml": 103,
            "json": 104,
            "url": 105,
            "telnet": 106,
            "modbus": 107,
            "mqtt": 108,
            "push": 109,
            "snmp": 110,
        }
        supported_ids = []
        for name in active_dict.keys():
            if name in protocol_map:
                supported_ids.append(protocol_map[name])
        return supported_ids

    @override
    def get_xml_api_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting XML API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/xml/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]

    @override
    def set_xml_api_state(
        self,
        protocol_enabled: bool | None = None,
        read_enable: bool | None = None,
        write_enable: bool | None = None,
        read_auth: tuple[str, str] | None = None,
        write_auth: tuple[str, str] | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/xml/config"

        self.logger.debug(f"Setting XML API state on device {self.host}")
        current = self._require_config(self.get_xml_api_state(), "XML API")
        read_username, read_password = _auth_or_current(read_auth, current, "read")
        write_username, write_password = _auth_or_current(write_auth, current, "write")
        protocol_data = {
            "enable": _value_or_current(protocol_enabled, current, "enable"),
            "port": current["port"],
            "readOnlyEnable": _value_or_current(read_enable, current, "readOnlyEnable"),
            "readUsername": read_username,
            "readPassword": read_password,
            "readWriteEnable": _value_or_current(write_enable, current, "readWriteEnable"),
            "writeUsername": write_username,
            "writePassword": write_password,
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, protocol_data)

    @override
    def get_json_api_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting JSON API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/json/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]

    @override
    def get_json(self, json_auth: tuple[str, str]) -> dict[str, Any]:
        # TODO: Implement get_json for 5.0.0+ firmware
        raise NotImplementedError("get_json is not yet implemented for 5.0.0+ firmware")

    @override
    def get_xml(self, xml_auth: tuple[str, str]) -> Element:
        # TODO: Implement get_xml for 5.0.0+ firmware
        raise NotImplementedError("get_xml is not yet implemented for 5.0.0+ firmware")

    @override
    def get_telnet_api_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting Telnet API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/telnet/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]

    @override
    def set_telnet_api_state(
        self,
        protocol_enabled: bool | None = None,
        port: int | None = None,
        read_enabled: bool | None = None,
        read_auth: tuple[str, str] | None = None,
        write_enabled: bool | None = None,
        write_auth: tuple[str, str] | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/telnet/config"

        self.logger.debug(f"Setting Telnet API state on device {self.host}")
        current = self._require_config(self.get_telnet_api_state(), "Telnet API")
        read_username, read_password = _auth_or_current(read_auth, current, "read")
        write_username, write_password = _auth_or_current(write_auth, current, "write")
        protocol_data = {
            "enable": _value_or_current(protocol_enabled, current, "enable"),
            "port": _value_or_current(port, current, "port"),
            "readOnlyEnable": _value_or_current(read_enabled, current, "readOnlyEnable"),
            "readUsername": read_username,
            "readPassword": read_password,
            "readWriteEnable": _value_or_current(write_enabled, current, "readWriteEnable"),
            "writeUsername": write_username,
            "writePassword": write_password,
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, protocol_data)

    @override
    def get_modbus_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting Modbus M2M API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/modbus/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]

    @override
    def set_modbus_state(
        self,
        protocol_enabled: bool | None = None,
        port: int | None = None,
        ip_filter_enabled: bool | None = None,
        ip_from: str | None = None,
        ip_to: str | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/modbus/config"

        self.logger.debug(f"Setting Modbus M2M API state on device {self.host}")
        current = self._require_config(self.get_modbus_state(), "Modbus M2M API")
        protocol_data = {
            "enable": _value_or_current(protocol_enabled, current, "enable"),
            "port": _value_or_current(port, current, "port"),
            "lastIp": current["lastIp"],
            "ipFilterEnable": _value_or_current(ip_filter_enabled, current, "ipFilterEnable"),
            "ipFrom": _value_or_current(ip_from, current, "ipFrom"),
            "ipTo": _value_or_current(ip_to, current, "ipTo"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, protocol_data)

    @override
    def get_netio_push_api_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting Netio Push API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/push/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]

    @override
    def set_netio_push_api_state(
        self,
        protocol_enabled: bool | None = None,
        url: str | None = None,
        push_protocol: PushProtocol | str | None = None,
        delta: int | None = None,
        period: int | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/push/config"

        self.logger.debug(f"Setting Netio Push API state on device {self.host}")
        if push_protocol is not None:
            push_protocol = _choice_value(PushProtocol, push_protocol.upper(), "push_protocol")
        current = self._require_config(self.get_netio_push_api_state(), "Netio Push API")
        protocol_data: dict[str, Any] = {
            "enable": _value_or_current(protocol_enabled, current, "enable"),
            "url": _value_or_current(url, current, "url"),
            "delta": _value_or_current(delta, current, "delta"),
            "period": _value_or_current(period, current, "period"),
        }
        # The device doesn't report the push format, so only send it when given.
        if push_protocol is not None:
            protocol_data["protocol"] = push_protocol
        _ = ws_api.send_request(self, ws_type, ws_topic, protocol_data)

    @override
    def get_snmp_api_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting SNMP API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/snmp/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]

    @override
    def _set_snmp_api_state(
        self,
        protocol_enabled: bool | None,
        version: str,
        location: str | None = None,
        community_read: str | None = None,
        community_write: str | None = None,
        security_name: str | None = None,
        security_level: str | None = None,
        auth_protocol: str | None = None,
        auth_key: str | None = None,
        priv_protocol: str | None = None,
        priv_key: str | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/snmp/config"

        self.logger.debug(f"Setting SNMP API state on device {self.host}")
        current = self._require_config(self.get_snmp_api_state(), "SNMP API")
        ver = "v1-2" if version in ("v1,2c", "v1-2") else "v3"

        request_data = {
            "enable": _value_or_current(protocol_enabled, current, "enable"),
            "location": _value_or_current(location, current, "location"),
            "communityRead": _value_or_current(community_read, current, "communityRead"),
            "communityWrite": _value_or_current(community_write, current, "communityWrite"),
            "version": ver,
            "securityName": _value_or_current(security_name, current, "securityName"),
            "authAlgo": _value_or_current(auth_protocol, current, "authAlgo"),
            "authKey": _value_or_current(auth_key, current, "authKey"),
            "encryptAlgo": _value_or_current(priv_protocol, current, "encryptAlgo"),
            "encryptKey": _value_or_current(priv_key, current, "encryptKey"),
            "securityLevel": _value_or_current(security_level, current, "securityLevel"),
        }

        _ = ws_api.send_request(self, ws_type, ws_topic, request_data)

    @override
    def set_snmp_v1_2_api_state(
        self,
        protocol_enabled: bool | None = None,
        location: str | None = None,
        community_read: str | None = None,
        community_write: str | None = None,
    ) -> None:
        self.logger.debug(f"Setting SNMP v1,2c API state on device {self.host}")
        self._set_snmp_api_state(
            protocol_enabled=protocol_enabled,
            version="v1-2",
            location=location,
            community_read=community_read,
            community_write=community_write,
        )

    @override
    def set_snmp_v3_api_state(
        self,
        protocol_enabled: bool | None = None,
        location: str | None = None,
        security_name: str | None = None,
        security_level: SnmpSecurityLevel | str | None = None,
        auth_protocol: SnmpAuthProtocol | str | None = None,
        auth_key: str | None = None,
        priv_protocol: SnmpPrivProtocol | str | None = None,
        priv_key: str | None = None,
    ) -> None:
        self.logger.debug(f"Setting SNMP v3 API state on device {self.host}")
        self._set_snmp_api_state(
            protocol_enabled=protocol_enabled,
            version="v3",
            location=location,
            security_name=security_name,
            security_level=_choice_value(SnmpSecurityLevel, security_level, "security_level"),
            auth_protocol=_choice_value(SnmpAuthProtocol, auth_protocol, "auth_protocol"),
            auth_key=auth_key,
            priv_protocol=_choice_value(SnmpPrivProtocol, priv_protocol, "priv_protocol"),
            priv_key=priv_key,
        )

    def set_json_api_state(
        self,
        protocol_enabled: bool | None = None,
        read_enable: bool | None = None,
        write_enable: bool | None = None,
        read_auth: tuple[str, str] | None = None,
        write_auth: tuple[str, str] | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/json/config"
        current = self._require_config(self.get_json_api_state(), "JSON API")
        read_username, read_password = _auth_or_current(read_auth, current, "read")
        write_username, write_password = _auth_or_current(write_auth, current, "write")

        protocol_data = {
            "enable": _value_or_current(protocol_enabled, current, "enable"),
            "port": current["port"],
            "readOnlyEnable": _value_or_current(read_enable, current, "readOnlyEnable"),
            "readUsername": read_username,
            "readPassword": read_password,
            "readWriteEnable": _value_or_current(write_enable, current, "readWriteEnable"),
            "writeUsername": write_username,
            "writePassword": write_password,
        }
        self.logger.debug(f"Setting json api state on device {self.host}.")
        logged_data = {key: "***" if "Password" in key else value for key, value in protocol_data.items()}
        self.logger.debug(f"JSON configuration: {json.dumps(logged_data, ensure_ascii=False, indent=4)}")
        _ = ws_api.send_request(self, ws_type, ws_topic, protocol_data)

    @override
    def get_urlapi_state(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/url/config"

        self.logger.debug(f"Getting urlapi state on device {self.host}.")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]

    def set_urlapi_state(
        self,
        protocol_enabled: bool | None = None,
        write_enable: bool | None = None,
        write_password: str | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/url/config"

        self.logger.debug(f"Setting urlapi state on device {self.host}.")
        current = self._require_config(self.get_urlapi_state(), "URL API")
        protocol_data = {
            "enable": _value_or_current(protocol_enabled, current, "enable"),
            "port": current["port"],
            "writeEnable": _value_or_current(write_enable, current, "writeEnable"),
            "password": _value_or_current(write_password, current, "password"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, protocol_data)

    def get_measurement(self) -> list[dict[str, Any]]:
        """
        Deprecated, use get_outputs_data(), which this returns. It used to return the device's whole reply to
        outputs/measure. Removed in PyNetioConf 1.0.
        """
        warnings.warn(
            "get_measurement() is deprecated and will be removed in PyNetioConf 1.0, use get_outputs_data()",
            DeprecationWarning,
            stacklevel=2,
        )
        self.logger.debug(f"Fetching measurements through the deprecated get_measurement() on device {self.host}")
        return self.get_outputs_data()

    def upload_mqtt_client_key(self, key: str) -> None:
        content = _check_pem(key, True, "MQTT client key")
        ws_type = "SET"
        ws_topic = "protocols/mqtt/clientkeyupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT client key to device {self.host}.")
        upload_path = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]["uploadPath"]
        _ = esp_api.send_file(self, upload_path, content)
        sleep(0.1)

    def upload_mqtt_client_certificate(self, cert: str) -> None:
        content = _check_pem(cert, False, "MQTT client certificate")
        ws_type = "SET"
        ws_topic = "protocols/mqtt/clientcertupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT client certificate to device {self.host}.")
        upload_path = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]["uploadPath"]
        _ = esp_api.send_file(self, upload_path, content)
        sleep(0.1)

    def upload_mqtt_ca_certificate(self, ca: str) -> None:
        content = _check_pem(ca, False, "MQTT CA certificate")
        ws_type = "SET"
        ws_topic = "protocols/mqtt/cacertupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT CA certificate to device {self.host}.")
        upload_path = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]["uploadPath"]
        _ = esp_api.send_file(self, upload_path, content)
        sleep(0.1)

    def get_mqttflex_state(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/mqtt/config"

        self.logger.debug(f"Getting MQTT flex state on device {self.host}")
        state: dict[str, Any] = ws_api.send_request(self, ws_type, ws_topic)["data"]
        if not state:
            return state
        try:
            config: Any = json.loads(state["config"])
        except (TypeError, ValueError):
            # TypeError: short of memory the device returns null in place of the config
            raise CommunicationError(f"Device {self.host} returned an MQTT config that isn't JSON") from None
        return {**state, "config": config}

    @override
    def get_outputs_data(self) -> list[dict[str, Any]]:
        ws_type = "SUBSCRIBE"
        ws_topic = "outputs/measure"

        self.logger.debug(f"Fetching outputs measurement data from device {self.host}")
        return ws_api.send_request(self, ws_type, ws_topic)["data"]["items"]

    @override
    def get_output_states(self) -> list[tuple[int, bool]]:
        self.logger.debug(f"Fetching output states from device {self.host}")
        output_data = self.get_outputs_data()
        output_states = []
        for output in output_data:
            output_states.append((int(output["id"]), True if output["state"] == "on" else False))
        return output_states

    @override
    def get_output_state(self, output_id: int) -> bool:
        self.logger.debug(f"Fetching output {output_id} state from device {self.host}")
        # Looked up in the reply rather than checked against output_count, which doesn't count the outputs of NBUS
        # clients
        states = dict(self.get_output_states())
        if output_id not in states:
            raise InvalidSocketIndex(
                f"You tried to access output {output_id}, the device {self.host} has the outputs {sorted(states)}."
            )
        return states[output_id]

    def set_mqttflex_state(self, state: bool | None = None, config: dict[str, Any] | None = None) -> None:
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/mqtt/config"

        self.logger.debug(f"Setting MQTT flex state to {state} on device {self.host}")
        config_text = _mqtt_config_text(config) if config is not None else None
        # Read unparsed: the config the device has goes back as the string it sent
        current = self._require_config(ws_api.send_request(self, ws_type, ws_topic)["data"], "MQTT flex")
        if config_text is None and not isinstance(current["config"], str):
            raise CommunicationError(f"Device {self.host} returned no MQTT config to send back with the state")
        ws_type = "SET"
        ws_data = {
            "enable": _value_or_current(state, current, "enable"),
            "config": config_text if config_text is not None else current["config"],
        }
        # Sent once: a config the device can't handle would restart it again with every repeat
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data, resend=False)
        sleep(1)
        if config is not None:
            self._require_mqtt_stored(config)
        if ws_data["enable"]:
            self._require_mqtt_applied()

    def _require_mqtt_stored(self, config: dict[str, Any]) -> None:
        """
        Raises DeviceError with the code ConfigNotApplied when the device holds another config than the one sent. It
        answers OK to a config it then fails to write, and keeps the one before.
        """
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/mqtt/config"
        deadline = perf_counter() + MQTT_APPLY_TIMEOUT
        while True:
            state = self._require_config(ws_api.send_request(self, ws_type, ws_topic)["data"], "MQTT flex")
            held_text = state["config"]
            if isinstance(held_text, str) and held_text:
                break
            # Short of memory the device returns null or nothing for the config: for a moment while it stores the
            # config, or for good when it failed to
            if perf_counter() >= deadline:
                reason = "The device answered OK, but returns no config"
                raise DeviceError(self.host, "SET", ws_topic, "ConfigNotApplied", reason)
            sleep(1)
        try:
            held: Any = json.loads(held_text)
        except ValueError:
            # The device returns strings unescaped, so a config with a quote in one, such as a JSON payload, reads
            # back as text that can't be parsed or compared
            self.logger.warning(
                f"Device {self.host} returned its MQTT config as text that isn't JSON, so whether it stored the "
                "config that was set can't be checked"
            )
            return
        difference = _mqtt_difference(config, held, "config")
        if difference is not None:
            reason = f"The device answered OK, but doesn't hold the config that was sent: {difference}"
            raise DeviceError(self.host, "SET", ws_topic, "ConfigNotApplied", reason)

    def _require_mqtt_applied(self) -> None:
        """
        Raises DeviceError with the code ConfigNotApplied when MQTT is enabled and not running. The device answers OK
        to a config it then doesn't apply, and says why only in its log.
        """
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/info"
        deadline = perf_counter() + MQTT_APPLY_TIMEOUT
        while True:
            if ws_api.send_request(self, ws_type, ws_topic)["data"]["active"]["mqtt"]:
                return
            if perf_counter() >= deadline:
                break
            sleep(MQTT_APPLY_INTERVAL)
        reason = "MQTT is enabled, but the device didn't apply its config"
        entries: list[dict[str, Any]] = []
        try:
            entries = [entry for entry in self.get_system_log() if entry["type"] in MQTT_LOG_TYPES]
        except UnauthorizedError:
            # Without can_browse_logs the reason stays unknown
            pass
        if entries:
            reason = f"{reason}. Its log says: {entries[-1]['message']}"
        raise DeviceError(self.host, "SET", "protocols/mqtt/config", "ConfigNotApplied", reason)

    def upload_https_private_key(self, keyfile: str) -> None:
        topic = "system/srvkeyupload"
        ws_type = "SET"
        ws_data: dict[str, Any] = {}
        with open(keyfile, "rb") as f:
            content = _check_pem(f.read(), True, "HTTPS private key")
        self.logger.debug(f"Uploading https private key for https to device {self.host}.")
        endpoint_data = ws_api.send_request(self, ws_type, topic, ws_data)
        endpoint = endpoint_data["data"]["uploadPath"]
        esp_api.send_file(self, endpoint, content)

    def upload_https_certificate(self, certfile: str) -> None:
        topic = "system/srvcertupload"
        ws_type = "SET"
        ws_data = {}
        with open(certfile, "rb") as f:
            content = _check_pem(f.read(), False, "HTTPS certificate")
        self.logger.debug("Uploading https certificate for https.")
        endpoint_data = ws_api.send_request(self, ws_type, topic, ws_data)
        endpoint = endpoint_data["data"]["uploadPath"]
        esp_api.send_file(self, endpoint, content)

    def export_config(self, save_file: str | None = None) -> dict[str, Any]:
        ws_type = "SET"
        ws_topic = "system/cfgexport"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Exporting configuration from device {self.host}")
        # 5.1.x sends the configuration as a JSON string
        config: dict[str, Any] = json.loads(ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]["config"])
        if save_file:
            with open(save_file, "w", encoding="utf-8") as file:
                json.dump(config, file, ensure_ascii=False, indent=4)
        return config

    def import_config(self, file: str | os.PathLike[str] | io.BufferedIOBase | io.TextIOBase, **kwargs: Any) -> None:
        ws_type = "SET"
        ws_topic = "system/cfgimport"
        ws_data: dict[str, Any] = {}

        if isinstance(file, (str, os.PathLike)):
            with open(file, "rb") as config_file:
                return self.import_config(config_file, **kwargs)
        data = _load_config_file(file)
        if "can_alter_settings" not in self.user_permissions:
            raise PermissionError("You don't have permission to alter settings on this device.")
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
        self.logger.debug(f"Importing configuration to device {self.host}")
        # UTF-8, not \u escapes, which the firmware doesn't handle when about 150 characters follow
        encoded_data = json.dumps(data, ensure_ascii=False).encode("utf-8")
        upload_path = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]["uploadPath"]
        requested = perf_counter()
        try:
            _ = esp_api.send_file(self, upload_path, encoded_data, timeout=UPLOAD_RESTART_REPLY_TIMEOUT)
        except (requests.exceptions.Timeout, CommunicationError) as e:
            # 5.1.3 restarts without replying
            self.logger.debug(f"Device {self.host} didn't reply to the import ({type(e).__name__}), it is restarting")
        self._log_in_after_import(requested, **kwargs)

    def _log_in_after_import(self, requested: float, **kwargs: Any) -> None:
        """
        Logs in again once the device has restarted with the imported configuration, with the username and password
        keywords when given. login=False skips that. requested is the perf_counter() time the upload started.
        """
        # The device restarts on its own, this connection ends with it
        ws_api.close_connection(self.ws, graceful=False)
        self.ws = None
        if not kwargs.get("login", True):
            return
        self.username = kwargs.get("username", self.username)
        self.password = kwargs.get("password", self.password)
        self._log_in_after_restart(
            requested, CONFIG_IMPORT_RESTART_TIMEOUT, "with the imported configuration", "the configuration import"
        )

    @override
    def update_firmware(self, file: str | os.PathLike[str] | io.BufferedIOBase) -> NETIODevice:
        ws_type = "SET"
        ws_topic = "system/fwupdate"
        ws_data: dict[str, Any] = {}

        if isinstance(file, (str, os.PathLike)):
            with open(file, "rb") as firmware_file:
                return self.update_firmware(firmware_file)
        if "can_alter_settings" not in self.user_permissions:
            raise PermissionError("You don't have permission to alter settings on this device.")
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()

        pre_reconnect_wait = 20
        if self.supported_features["wifi"] == "yes":
            wifi_settings = self.get_wifi_settings()
            if wifi_settings["mode"] == "client" and wifi_settings["client"]["status"] == "Connected":
                pre_reconnect_wait = 50
                self.logger.debug("Increased wait time after fimrware update due to active Wi-Fi connection.")

        if esp_api.check_connectivity(self) > (pre_reconnect_wait / 10.0):
            pre_reconnect_wait = pre_reconnect_wait * 2
            self.logger.debug("Increased wait time after firmware update due to poor connection quality.")

        self.logger.debug(f"Uploading firmware to device {self.host}")
        # The device closes this session after replying and restarts when the upload ends
        upload_path = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]["uploadPath"]
        _ = esp_api.send_file(self, upload_path, file)
        self.logger.debug(
            f"Uploaded firmware {getattr(file, 'name', 'in-memory file')}, device {self.host} might be unresponsive "
            "for a while."
        )

        sleep(pre_reconnect_wait)

        self.logger.debug(
            f"Retrying connection to device {self.host} after updating firmware to "
            f"{getattr(file, 'name', 'in-memory file')}."
        )
        device_response_time = esp_api.check_connectivity(self)
        retry_limit = 3 if device_response_time == -1 else 0
        for _ in range(0, retry_limit):
            device_response_time = esp_api.check_connectivity(self)

        if device_response_time == -1:
            raise CommunicationError("Device couldn't establish connection after firmware update.")

        updated_instance = None
        if isinstance(self.netio_manager, NetioManager):
            updated_instance = self.netio_manager.update_device(self, ws_expected=True)

        if not updated_instance:
            raise CommunicationError("Coudln't get updated instance.")

        return updated_instance

    def get_features(self) -> dict[str, Any]:
        self.logger.debug(f"Fetching supported features from device {self.host}")
        return self.get_system_info()

    @override
    def ping(self) -> bool:
        self.logger.warning("Device pinging is not supported on 5.0.x to 5.1.x, please update your device.")
        return True

    @override
    def get_system_log(self) -> list[dict[str, Any]]:
        ws_topic = "log/messages"
        ws_type = "SUBSCRIBE"
        ws_data = None
        self.logger.debug(f"Fetching system log messages from device {self.host}.")

        log_messages: list[dict[str, Any]] = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]
        return log_messages

    @override
    def set_wifi_settings(self, ssid: str, password: str) -> None:
        ws_topic = "network/wifi/config"
        ws_type = "SET"
        ws_data = {
            "ssid": ssid,
            "secured": True if password else False,
            "password": password,
        }
        self.logger.debug(f"Sending Wi-Fi configuration to {self.host}")
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def get_wifi_settings(self) -> dict[str, Any]:
        ws_topic = "network/wifi/config"
        ws_type = "SUBSCRIBE"
        ws_data = None
        self.logger.debug(f"Fetching Wi-Fi configuration from {self.host}")
        return ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]

    @override
    def set_wifi_static_address(
        self,
        address: str | None = None,
        net_mask: str | None = None,
        gateway: str | None = None,
        dns_server: str | None = None,
        hostname: str | None = None,
    ) -> None:
        ws_type = "SUBSCRIBE"
        ws_topic = "network/netwifi/config"

        self.logger.debug(f"Setting Wi-Fi static address on device {self.host}")
        if hostname is not None:
            self.logger.warning(
                f"The hostname of device {self.host} is taken from the device name "
                "on 5.0.0+ firmware and was not changed, use rename_device to change it"
            )
        netwifi_res = ws_api.send_request(self, ws_type, ws_topic)
        netwifi_data = self._require_config(netwifi_res.get("data", {}), "Wi-Fi network")
        if netwifi_data["networkMode"] != "static" and None in (
            address,
            net_mask,
            gateway,
        ):
            raise InvalidParameterValueError(
                "address, net_mask and gateway are required when switching Wi-Fi from DHCP to a static address"
            )
        netwifi_data["networkMode"] = "static"
        if address is not None:
            netwifi_data["ip"] = address
        if net_mask is not None:
            netwifi_data["netmask"] = net_mask
        if gateway is not None:
            netwifi_data["gateway"] = gateway
        if dns_server is not None:
            netwifi_data["dns"] = dns_server

        ws_type = "SET"
        _ = ws_api.send_request(self, ws_type, ws_topic, netwifi_data)

    @override
    def get_version_revision(self) -> str:
        self.logger.debug(f"Fetching firmware revision from device {self.host}")
        return self.get_system_info()["fwRevision"]

    @override
    def set_periodic_restart(self, enable: bool | None = None, restart_period: int | None = None) -> None:
        self.logger.debug(f"Setting periodic restart on device {self.host}")
        self.set_system_settings(periodic_restart=enable, restart_period=restart_period)

    @override
    def rename_device(self, device_name: str) -> None:
        self.logger.debug(f"Renaming device {self.host} to {device_name}")
        self.set_system_settings(device_name=device_name)

    @override
    def set_system_settings(
        self,
        device_name: str | None = None,
        port: int | None = None,
        periodic_restart: bool | None = None,
        restart_period: int | None = None,
        syslog_enable: bool | None = None,
        syslog_server: str | None = None,
        syslog_port: int | None = None,
    ) -> None:
        ws_type = "SUBSCRIBE"
        ws_topic = "system/config"

        self.logger.debug(f"Setting system settings on device {self.host}")
        if port is not None:
            self.logger.warning(
                f"The port of device {self.host} is not part of the system settings "
                "on 5.0.0+ firmware and was not changed, "
                "use set_server_settings to change it"
            )
        if syslog_server is not None and not isinstance(syslog_server, str):
            raise InvalidParameterValueError(f"The syslog server must be a string, got {syslog_server!r}")
        if syslog_port is not None and (
            isinstance(syslog_port, bool) or not isinstance(syslog_port, int) or not 1 <= syslog_port <= 65535
        ):
            raise InvalidParameterValueError(
                f"The syslog port must be a whole number from 1 to 65535, got {syslog_port!r}"
            )
        cfg_res = ws_api.send_request(self, ws_type, ws_topic)
        cfg_data = self._require_config(cfg_res.get("data", {}), "system")
        if device_name is not None:
            cfg_data["devname"] = device_name
        if periodic_restart is not None:
            cfg_data["periodRestartEnable"] = periodic_restart
        if restart_period is not None:
            cfg_data["periodRestartPeriod"] = restart_period
        if syslog_enable is not None:
            cfg_data["syslogEnable"] = syslog_enable
        if syslog_server is not None:
            cfg_data["syslogServer"] = syslog_server
        if syslog_port is not None:
            cfg_data["syslogPort"] = syslog_port

        ws_type = "SET"
        _ = ws_api.send_request(self, ws_type, ws_topic, cfg_data)

    @override
    def get_system_settings(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "system/config"
        self.logger.debug(f"Fetching system settings on device {self.host}")
        cfg_res = ws_api.send_request(self, ws_type, ws_topic)
        return self._require_config(cfg_res.get("data", {}), "system")

    @override
    def locate(self) -> None:
        raise FeatureNotSupported("Locating the device is only supported on firmware 5.2.0 and newer.")

    @override
    def clear_system_log(self) -> None:
        ws_type = "SET"
        ws_topic = "log/clear"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Clearing system log on device {self.host}")
        ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def change_user_password(self, username: str, old_password: str, new_password: str) -> None:
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{username}/config"

        self.logger.debug(f"Changing password for user {username} on device {self.host}")
        self._require_user(username)
        user_cfg_res = ws_api.send_request(self, ws_type, ws_topic)
        user_data = user_cfg_res["data"]
        hello_response = ws_api.send_request(self, "HELO")
        public_key = hello_response["data"]["publicKey"]
        password_hash = ws_api.generate_password_hash(username, new_password, public_key)
        user_data["passwordHash"] = password_hash
        user_data["password"] = ""

        ws_type = "SET"
        ws_api.send_request(self, ws_type, ws_topic, user_data)
        # Logins after a dropped connection have to use the new password
        if username == self.username:
            self.password = new_password

    @override
    def change_password(self, new_password: str) -> None:
        self.logger.debug(f"Changing password of the current user on {self.host}")
        self.change_user_password(self.username, "", new_password)

    @override
    def get_cloud_state(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/cloud"

        self.logger.debug(f"Getting cloud state on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response["data"]

    @override
    def set_cloud_state(self, state: bool) -> None:
        ws_type = "SET"
        ws_topic = "protocols/cloud"

        self.logger.debug(f"Setting cloud state to {state} on device {self.host}")
        ws_data = self.get_cloud_state()
        ws_data["enabled"] = state
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        if state:
            sleep(CLOUD_DEFAULT_CONNECTION_WAIT)

    @override
    def register_to_cloud(self, token: str) -> None:
        ws_type = "SET"
        ws_topic = "protocols/cloud/cmd"
        ws_data = {"action": "register", "token": token, "server": ""}

        self.logger.debug(f"Registering to cloud with token {token} on device {self.host}")
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        sleep(CLOUD_ACTION_COMMUNICATION_DELAY)

    @override
    def set_on_premise(self, url: str) -> None:
        ws_type = "SET"
        ws_topic = "protocols/cloud/cmd"
        ws_data = {"action": "setOnPremis", "token": "", "server": url}

        self.logger.debug(f"Setting on-premise cloud server to {url} on device {self.host}")
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        sleep(CLOUD_ACTION_COMMUNICATION_DELAY)

    @override
    def netio_push_api_push_now(self) -> None:
        raise FeatureNotSupported("Netio Push on demand is not supported on firmware 5.1.0 and newer.")

    def _cleanup(self) -> None:
        try:
            if self._ka_thread:
                self._ka_thread.cancel()
                self._ka_thread.join()
                self.logger.debug("Disabled keep-alive thread.")
        except AttributeError:
            pass  # No need to clean up a non existant thread
        # Shut down without waiting for the device's reply, so exiting isn't held up by a device that stopped answering
        ws_api.close_connection(self.ws, graceful=False)
        self.ws = None

    @override
    def get_input_list(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "inputs/list"

        self.logger.debug(f"Fetching input list from device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)["data"]
        return response

    @override
    def get_input_data(self, input_id: int) -> dict[str, Any]:
        self._check_input_index(input_id)
        self.logger.debug(f"Fetching input {input_id} data from device {self.host}")
        return self.get_input_list()["items"][input_id - 1]

    def _check_input_index(self, input_id: int) -> None:
        if input_id < 1 or input_id > self.input_count:
            raise InvalidSocketIndex(
                f"You tried to access input with id {input_id}, the device supports <1;{self.input_count}>."
            )

    def _set_input_config(self, input_id: int, name: str | None = None, temperature_unit: str | None = None) -> None:
        ws_topic = f"inputs/inputs/{input_id}/config"
        ws_type = "SUBSCRIBE"

        self.logger.debug(f"Setting input {input_id} config on device {self.host}")
        current = self._require_config(ws_api.send_request(self, ws_type, ws_topic)["data"], f"input {input_id}")
        ws_type = "SET"
        ws_data = {
            "name": _value_or_current(name, current, "name"),
            "temperatureUnit": _value_or_current(temperature_unit, current, "temperatureUnit"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def rename_input(self, input_id: int, name: str) -> None:
        if not isinstance(name, str):
            raise InvalidParameterValueError(f"The input name has to be a string, not {name!r}")
        self._check_input_index(input_id)
        self.logger.debug(f"Renaming input {input_id} to {name} on device {self.host}")
        self._set_input_config(input_id, name=name)

    @override
    def set_input_temperature_unit(self, input_id: int, unit: TemperatureUnit) -> None:
        try:
            temperature_unit = TemperatureUnit(unit).value
        except ValueError:
            raise InvalidParameterValueError(
                f"Unknown temperature unit {unit!r}, the possible ones are {[u.value for u in TemperatureUnit]}"
            ) from None
        self._check_input_index(input_id)
        self.logger.debug(f"Setting input {input_id} temperature unit to {temperature_unit} on device {self.host}")
        self._set_input_config(input_id, temperature_unit=temperature_unit)

    @override
    def get_system_datetime(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "system/datetime"

        self.logger.debug(f"Fetching system date/time on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    # TODO: Timezone documentation
    @override
    def set_system_datetime(
        self,
        ntp_enabled: bool | None = None,
        ntp_server: str | None = None,
        timezone: str | None = None,
        time: int | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "system/datetime"

        self.logger.debug(f"Setting system date/time on device {self.host}")
        current = self._require_config(self.get_system_datetime(), "date/time")
        ws_data: dict[str, Any] = {
            "ntpEnabled": _value_or_current(ntp_enabled, current, "ntpEnabled"),
            "ntpServer": _value_or_current(ntp_server, current, "ntpServer"),
            "timezone": _value_or_current(timezone, current, "timezone"),
            "time": _value_or_current(time, current, "time"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def system_reset(self) -> None:
        raise FeatureNotSupported("Restarting the device is only supported on firmware 5.2.0 and newer.")

    @override
    def load_defaults(self) -> None:
        ws_type = "SET"
        ws_topic = "system/loaddefaults"
        ws_data = {"loadDefaults": True}

        self.logger.debug(f"Loading the default configuration on device {self.host}")
        # The keep-alive would log in again with the old credentials while the device restarts
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)
        requested = perf_counter()
        # The device restarts on its own, this connection ends with it
        ws_api.close_connection(self.ws, graceful=False)
        self.ws = None
        # The default network settings run the HTTP server on port 80 and switch HTTPS off. Logins over HTTP fail until
        # the restart, which the wait counts as the device going down.
        self.use_https = False
        self._log_in_after_defaults(requested)

    def _log_in_after_defaults(self, requested: float) -> None:
        """
        Waits until the device has restarted with the default configuration and logs in as admin with the default
        password. requested is the perf_counter() time at which the device accepted the request.

        The first boot with the default configuration isn't the last one: once the device has a network address it marks
        itself installed and restarts again. It is done when it reports installed and has either restarted since it was
        seen not installed, or has been up for LOAD_DEFAULTS_SETTLE_UPTIME seconds.
        """
        sleep(LOAD_DEFAULTS_GRACE_PERIOD)
        went_down = False
        last_error: Exception | None = None
        seen_not_installed: float | None = None
        while True:
            try:
                self.login(DEFAULT_USERNAME, DEFAULT_PASSWORD)
            except CommunicationError as e:
                went_down = True
                last_error = e
            except DeviceError as e:
                # A device still writing the defaults answers the login's HELO with an error (5.1.3)
                last_error = e
            except AuthError as e:
                # Until the restart the device still has the old configuration, where admin can have another password.
                # These logins are retried on purpose, a refusal only counts once the device has been down.
                if went_down:
                    raise
                last_error = e
            else:
                # Without a restart since a point in time, the uptime is at least the time since then, less up to 1 s
                # because the device counts whole seconds. A busy device reports it late, which only makes it smaller.
                uptime = self.get_uptime()
                # A login before the first restart reaches the old configuration
                if uptime < perf_counter() - requested - 1:
                    if not self.get_system_info()["installed"]:
                        seen_not_installed = perf_counter()
                    elif (
                        seen_not_installed is not None and uptime < perf_counter() - seen_not_installed - 1
                    ) or uptime >= LOAD_DEFAULTS_SETTLE_UPTIME:
                        self.user_permissions = self.get_user_privileges(DEFAULT_USERNAME)
                        # The device can come back with its old configuration, when it restarted before loading the
                        # defaults
                        users = self.get_users()
                        if set(users) != {DEFAULT_USERNAME}:
                            raise CommunicationError(
                                f"Device {self.host} came back without the default configuration, its users are {users}"
                            )
                        self.logger.info(f"Device {self.host} is back with the default configuration")
                        return
                self.logout()
                last_error = None
            if perf_counter() - requested > LOAD_DEFAULTS_TIMEOUT:
                detail = (
                    f"last login attempt: {last_error}"
                    if last_error
                    else "it still had the old configuration or hadn't finished installing the default one"
                )
                raise CommunicationError(
                    f"Device {self.host} wasn't back with the default configuration {LOAD_DEFAULTS_TIMEOUT} seconds "
                    f"after loading it, {detail}"
                )
            sleep(LOAD_DEFAULTS_RETRY_INTERVAL)

    @override
    def get_ethernet_settings(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "network/ethernet/config"

        self.logger.debug(f"Fetching Ethernet settings on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    @override
    def set_ethernet_settings(
        self,
        network_mode: NetworkMode | str | None = None,
        ip: str | None = None,
        netmask: str | None = None,
        gateway: str | None = None,
        dns: str | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "network/ethernet/config"

        self.logger.debug(f"Setting Ethernet configuration on device {self.host}")
        network_mode = _choice_value(NetworkMode, network_mode, "network_mode")
        current = self._require_config(self.get_ethernet_settings(), "Ethernet")
        if network_mode == "static" and current["networkMode"] != "static" and None in (ip, netmask, gateway):
            raise InvalidParameterValueError(
                "ip, netmask and gateway are required when switching Ethernet from DHCP to a static address"
            )
        ws_data: dict[str, Any] = {
            "mac": current["mac"],
            "networkMode": _value_or_current(network_mode, current, "networkMode"),
            "ip": _value_or_current(ip, current, "ip"),
            "netmask": _value_or_current(netmask, current, "netmask"),
            "gateway": _value_or_current(gateway, current, "gateway"),
            "dns": _value_or_current(dns, current, "dns"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def get_ethernet_status(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "network/ethernet/status"

        self.logger.debug(f"Fetching Ethernet status on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    @override
    def get_wifi_status(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "network/wifi/status"

        self.logger.debug(f"Fetching Wi-Fi status on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    @override
    def get_server_settings(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "network/servers/config"

        self.logger.debug(f"Fetching web server settings on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    @override
    def set_server_settings(
        self,
        http_enable: bool | None = None,
        http_port: int | None = None,
        https_enable: bool | None = None,
        https_port: int | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "network/servers/config"

        self.logger.debug(f"Setting web server settings on device {self.host}")
        if http_enable is not None and http_enable == https_enable:
            raise InvalidParameterValueError(
                f"Device {self.host} runs either HTTP or HTTPS, http_enable and https_enable can't both be "
                f"{http_enable}."
            )
        current = self._require_config(self.get_server_settings(), "web server")
        # The device turns one server off when the other one is turned on, so the request names exactly one of them
        if https_enable is not None:
            use_https = https_enable
        elif http_enable is not None:
            use_https = not http_enable
        else:
            use_https = bool(current["httpsEnable"])
        ws_data: dict[str, Any] = {
            "httpEnable": not use_https,
            "httpPort": _value_or_current(http_port, current, "httpPort"),
            "httpsEnable": use_https,
            "httpsPort": _value_or_current(https_port, current, "httpsPort"),
        }
        if all(ws_data[key] == current[key] for key in ws_data):
            # Any change restarts the device, so settings it already has aren't sent
            self.logger.debug(f"Device {self.host} already has these web server settings, nothing sent")
            return

        scheme = "HTTPS" if use_https else "HTTP"
        server_port = ws_data["httpsPort"] if use_https else ws_data["httpPort"]
        connection_port = _port_in_host(self.host) or (443 if use_https else 80)
        if server_port != connection_port:
            raise NotImplementedError(
                f"The device object connects to {self.host} on port {connection_port}, PyNetioConf can't follow the "
                f"{scheme} server to port {server_port} yet."
            )

        # The keep-alive would log in again while the device restarts
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)
        requested = perf_counter()
        # The device restarts on its own, this connection ends with it
        ws_api.close_connection(self.ws, graceful=False)
        self.ws = None
        if use_https and not self.use_https:
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning

            disable_warnings(category=InsecureRequestWarning)
        self.use_https = use_https
        self._log_in_after_restart(
            requested, WEB_SERVER_RESTART_TIMEOUT, f"with its {scheme} server", "the change of its web server settings"
        )

    def _log_in_after_restart(self, requested: float, timeout: float, back: str, cause: str) -> None:
        """
        Waits until the device has restarted after requested, a perf_counter() time, and logs in again. back and cause
        complete the messages, such as "with its HTTPS server" and "the change of its web server settings".
        """
        last_error: Exception | None = None
        while perf_counter() - requested < timeout:
            sleep(WEB_SERVER_RESTART_INTERVAL)
            try:
                self.login(self.username, self.password)
            except CommunicationError as e:
                last_error = e
                continue
            # Without a restart since the request, the uptime is at least the time since then, less up to 1 s because
            # the device counts whole seconds
            if self.get_uptime() < perf_counter() - requested - 1:
                self.logger.info(f"Device {self.host} is back {back}")
                return
            # This login reached the device before it restarted
            self.logout()
            last_error = None
        detail = f"last login attempt: {last_error}" if last_error else "it hadn't restarted"
        raise CommunicationError(f"Device {self.host} wasn't back {back} {timeout} seconds after {cause}, {detail}")

    @override
    def get_global_measurement(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "outputs/globalmeasure"

        self.logger.debug(f"Fetching global measurements on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {}).get("measure", {})

    @override
    def get_outputs_list(self) -> list[dict[str, Any]]:
        ws_type = "SUBSCRIBE"
        ws_topic = "outputs/list"

        self.logger.debug(f"Fetching outputs overview list on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {}).get("items", [])

    @override
    def get_output_groups(self) -> list[dict[str, Any]]:
        raise FeatureNotSupported("Output groups are only supported on firmware 5.4.0 and newer.")

    @override
    def get_output_group(self, group_id: int) -> dict[str, Any]:
        raise FeatureNotSupported("Output groups are only supported on firmware 5.4.0 and newer.")

    @override
    def set_output_group(
        self,
        group_id: int,
        name: str | None = None,
        power_up_state: OutputPowerUpState | None = None,
        reset_delay: int | None = None,
        outputs: dict[int, int] | None = None,
    ) -> None:
        raise FeatureNotSupported("Output groups are only supported on firmware 5.4.0 and newer.")

    @override
    def set_output_group_id(self, output_id: int, group_id: int) -> None:
        raise FeatureNotSupported("Output groups are only supported on firmware 5.4.0 and newer.")

    @override
    def set_output_group_action(self, group_id: int, action: OutputAction) -> None:
        raise FeatureNotSupported("Output groups are only supported on firmware 5.4.0 and newer.")

    @override
    def switch_output_group(self, group_id: int, state: bool) -> None:
        raise FeatureNotSupported("Output groups are only supported on firmware 5.4.0 and newer.")

    @override
    def has_nbus(self) -> bool:
        self.logger.debug(f"Checking for NBUS on device {self.host}, its firmware has none")
        return False

    @override
    def get_nbus_settings(self) -> dict[str, Any]:
        raise FeatureNotSupported("NBUS is only supported on firmware 5.4.0 and newer.")

    @override
    def set_nbus_settings(self, enabled: bool | None = None, role: NbusRole | None = None) -> None:
        raise FeatureNotSupported("NBUS is only supported on firmware 5.4.0 and newer.")

    @override
    def discover_nbus_devices(self, timeout: float = NBUS_DISCOVER_TIMEOUT) -> list[dict[str, Any]]:
        raise FeatureNotSupported("NBUS is only supported on firmware 5.4.0 and newer.")

    @override
    def get_nbus_devices(self) -> list[dict[str, Any]]:
        raise FeatureNotSupported("NBUS is only supported on firmware 5.4.0 and newer.")

    @override
    def delete_nbus_device(self, device_sn: str) -> None:
        raise FeatureNotSupported("NBUS is only supported on firmware 5.4.0 and newer.")

    @override
    def locate_nbus_device(self, device_sn: str) -> None:
        raise FeatureNotSupported("NBUS is only supported on firmware 5.4.0 and newer.")

    @override
    def set_nbus_device_order(self, device_sns: list[str]) -> None:
        raise FeatureNotSupported("NBUS is only supported on firmware 5.4.0 and newer.")

    @override
    def get_nbus_mapping(self) -> list[dict[str, Any]]:
        raise FeatureNotSupported("NBUS is only supported on firmware 5.4.0 and newer.")

    @override
    def get_firmware_updates_list(self) -> list[dict[str, Any]]:
        ws_type = "SET"
        ws_topic = "system/firmwarelist"
        ws_data = {"getFirmwareList": True, "updateFw": ""}

        # A check takes a few seconds, so a recent answer is reused, for example by update_firmware_online() right
        # after is_update_available(). Copies, so a caller changing them doesn't change the stored answer
        age = perf_counter() - self._firmware_list_time
        if self._firmware_list is not None and age < FIRMWARE_LIST_CACHE_TIME:
            self.logger.debug(f"Using the firmware updates device {self.host} got {age:.0f} seconds ago")
            return [dict(item) for item in self._firmware_list]
        self.logger.debug(f"Checking for firmware updates on device {self.host}")
        before = self._get_firmware_list()
        sleep(FIRMWARE_LIST_INTERVAL)
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)
        items: list[dict[str, Any]] = self._wait_for_firmware_list(before)
        # Without newer firmware the device lists one item, "No new firmware available", without version or links
        if all(not item["version"] and not item["downloadUrl"] and not item["downloadUrlNoMcu"] for item in items):
            items = []
        self._firmware_list = items
        self._firmware_list_time = perf_counter()
        return [dict(item) for item in items]

    def _get_firmware_list(self) -> list[dict[str, Any]]:
        ws_type = "SUBSCRIBE"
        ws_topic = "fwupdate/list"

        data: dict[str, Any] = ws_api.send_request(self, ws_type, ws_topic)["data"]
        # 5.1.3 leaves out items while it rebuilds the list
        return data["items"] if "items" in data else []

    def _wait_for_firmware_list(self, before: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Waits until fwupdate/list holds the update server's answer to a getFirmwareList request and returns it. before
        is the list from just before the request.

        The device locks system/lock while it asks the server, unlocks when the request ends and rebuilds the list
        about 0.4 s later, so a read around the unlock can get the previous list, a partial one, or on 5.1.3 none. Until
        the first answer since the device started, the list holds one item with empty fields. A list that differs from
        before counts once two reads in a row agree. A list that doesn't differ counts as the same answer once it stayed
        unchanged for FIRMWARE_LIST_SETTLE seconds after the unlock.
        """
        fields = ("name", "version", "downloadUrl", "downloadUrlNoMcu", "releaseNoteEn")
        deadline = perf_counter() + FIRMWARE_LIST_TIMEOUT
        locked = False
        unlocked_at: float | None = None
        previous: list[dict[str, Any]] | None = None
        while perf_counter() < deadline:
            sleep(FIRMWARE_LIST_INTERVAL)
            if self.get_system_lock()["op"] == "lock":
                locked = True
            elif locked and unlocked_at is None:
                unlocked_at = perf_counter()
            sleep(FIRMWARE_LIST_INTERVAL)
            items = self._get_firmware_list()
            complete = len(items) > 0 and all(field in item for item in items for field in fields)
            complete = complete and all(item["name"] for item in items)
            if complete and items != before:
                if items == previous:
                    return items
                previous = items
                continue
            previous = None
            if unlocked_at is not None and perf_counter() - unlocked_at >= FIRMWARE_LIST_SETTLE:
                if complete:
                    return items
                raise CommunicationError(
                    f"Device {self.host} finished asking the firmware update server without getting an answer"
                )
        raise CommunicationError(
            f"Device {self.host} got no answer from the firmware update server within {FIRMWARE_LIST_TIMEOUT} seconds"
        )

    @override
    def is_update_available(self) -> bool:
        self.logger.debug(f"Checking whether newer firmware is available for device {self.host}")
        return len(self.get_firmware_updates_list()) > 0

    @override
    def update_firmware_online(self, include_low_level_system: bool = False, version: str | None = None) -> NETIODevice:
        ws_type = "SET"
        ws_topic = "system/firmwarelist"

        self.logger.debug(f"Starting the online firmware update on device {self.host}")
        offers = self.get_firmware_updates_list()
        # Only firmware the update server offers is installed, nothing is sent for a version it doesn't offer
        if version is not None:
            matching = [item for item in offers if item["version"].split()[0] == version]
            if not matching:
                offered = ", ".join(item["version"] for item in offers) or "nothing"
                raise ElementNotFound(
                    f"The update server doesn't offer firmware {version} for device {self.host}, it offers {offered}"
                )
            offer = matching[0]
        elif not offers:
            self.logger.info(f"The update server offers no newer firmware for device {self.host}, nothing to update")
            return self
        else:
            # The server lists the newest firmware first
            offer = offers[0]
        target = offer["version"].split()[0]
        ws_data = {
            "getFirmwareList": False,
            "updateFw": offer["downloadUrl"] if include_low_level_system else offer["downloadUrlNoMcu"],
        }
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()

        sleep(FIRMWARE_LIST_INTERVAL)
        uptime = self.get_uptime()
        sleep(FIRMWARE_LIST_INTERVAL)
        self.logger.info(f"Updating device {self.host} to {offer['name']} from {ws_data['updateFw']}")
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)
        self._wait_for_online_update(target, uptime)

        if not isinstance(self.netio_manager, NetioManager):
            raise CommunicationError(
                f"Device {self.host} runs firmware {target} now, but has no NetioManager to create its device object"
            )
        return self.netio_manager.update_device(self)

    @override
    def update_firmware_incl_low_level_online(self, version: str | None = None) -> NETIODevice:
        self.logger.debug(f"Starting the online firmware update including the low-level system on device {self.host}")
        return self.update_firmware_online(include_low_level_system=True, version=version)

    def _wait_for_online_update(self, target: str, uptime: int) -> None:
        """
        Waits until the device runs firmware version target after the online update was started. uptime is the
        device's uptime from just before.

        The device locks system/lock while it downloads and restarts when the download ends, also after a failed one.
        The firmware is written to try again after the restart, ONLINE_UPDATE_ATTEMPTS attempts in all, but with NETIO
        Cloud disabled 5.4.0 didn't, so a failed attempt counts as the last one unless the device starts another within
        ONLINE_UPDATE_RETRY_WAIT seconds. A restart shows as a later boot time worked out from the uptime. A busy
        device reports its uptime a few seconds late, so the boot time has to move by more than two intervals.
        """
        deadline = perf_counter() + ONLINE_UPDATE_START_TIMEOUT
        while self.get_system_lock()["op"] != "lock":
            if perf_counter() >= deadline:
                raise CommunicationError(f"Device {self.host} didn't start the online firmware update")
            sleep(FIRMWARE_LIST_INTERVAL)

        booted_at = perf_counter() - uptime
        restarts = 0
        deadline = perf_counter() + ONLINE_UPDATE_TIMEOUT
        while perf_counter() < deadline:
            sleep(ONLINE_UPDATE_INTERVAL)
            try:
                current = self.get_uptime()
                if perf_counter() - current - booted_at <= 2 * ONLINE_UPDATE_INTERVAL:
                    continue
                booted_at = perf_counter() - current
                restarts += 1
                running = self.get_system_info()["fwVersion"].split()[0]
            except CommunicationError:
                # Down for longer than ws_api keeps reconnecting, the next round tries again
                continue
            if running == target:
                self.logger.info(f"Device {self.host} runs firmware {target} after {restarts} restart(s)")
                return
            self.logger.warning(
                f"Device {self.host} restarted with firmware {running}, attempt {restarts} of {ONLINE_UPDATE_ATTEMPTS} "
                f"to update to {target} failed"
            )
            if restarts >= ONLINE_UPDATE_ATTEMPTS:
                raise CommunicationError(
                    f"Device {self.host} still runs firmware {running} after {restarts} attempts to update to {target}"
                )
            if not self._online_update_retried(booted_at):
                raise CommunicationError(
                    f"Device {self.host} restarted with firmware {running} and didn't try the update to {target} again "
                    f"within {ONLINE_UPDATE_RETRY_WAIT} seconds"
                )
        raise CommunicationError(
            f"Device {self.host} doesn't run firmware {target} {ONLINE_UPDATE_TIMEOUT} seconds after the online update "
            "started"
        )

    def _online_update_retried(self, booted_at: float) -> bool:
        """
        Whether the device starts another attempt of the online update within ONLINE_UPDATE_RETRY_WAIT seconds after it
        came back from a failed one: it locks system/lock again, can't be reached, or restarted in between. booted_at
        is the boot time _wait_for_online_update worked out from the uptime.
        """
        deadline = perf_counter() + ONLINE_UPDATE_RETRY_WAIT
        while perf_counter() < deadline:
            sleep(ONLINE_UPDATE_RETRY_INTERVAL)
            try:
                if self.get_system_lock()["op"] == "lock":
                    return True
            except CommunicationError:
                return True
        # An attempt that failed between two reads has restarted the device again
        try:
            return perf_counter() - self.get_uptime() - booted_at > 2 * ONLINE_UPDATE_INTERVAL
        except CommunicationError:
            return True

    @override
    def get_system_lock(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "system/lock"
        # TODO: Use for cloud communication verification timing

        self.logger.debug(f"Fetching system lock state on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    @override
    def get_system_notifications(self) -> list[dict[str, Any]]:
        ws_type = "SUBSCRIBE"
        ws_topic = "system/notifications"

        self.logger.debug(f"Fetching system notifications on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        data = response.get("data", [])
        return data if isinstance(data, list) else []
