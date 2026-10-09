"""
Implementation specifics for ESP devices with the firmware 5.0.x.
"""

import atexit
import json
import os
import ssl
import sys
from collections import deque
from io import BytesIO
from time import sleep
from xml.etree.ElementTree import Element

from PyNetioConf.constants import (
    CLOUD_ACTION_COMMUNICATION_DELAY,
    CLOUD_DEFAULT_CONNECTION_WAIT,
    DEVICE_RESET_GRACE_PERIOD,
    WS_DEFAULT_TIMEOUT,
)

if sys.version_info >= (3, 12):
    from typing import IO, Any, AnyStr, Dict, List, Tuple, override
else:
    from typing import IO, Any, AnyStr, Dict, List, Tuple

    from typing_extensions import override

import logging
import threading

import websocket
from websocket import WebSocket

from .. import NetioManager
from ..constants import DEFAULT_KEEP_ALIVE_QUEUE_LEN, DEFAULT_REQUEST_QUEUE_LEN
from ..exceptions import (
    CommunicationError,
    ElementNotFound,
    InvalidParameterValueError,
    InvalidSocketIndex,
)
from ..netio_device import NETIODevice
from . import esp_api, ws_api
from .esp_400_device import ESP400Device


def _value_or_current(value: Any, current: dict[str, Any], key: str) -> Any:
    """Returns value, or the device's current value for key when value is None."""
    return value if value is not None else current[key]


def _auth_or_current(
    auth: tuple[str, str] | None, current: dict[str, Any], prefix: str
) -> tuple[str, str]:
    """Returns auth, or the device's current (username, password) when auth is None."""
    if auth is not None:
        return auth
    return current[f"{prefix}Username"], current[f"{prefix}Password"]


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

            ws_connection : websocket.WebSocket | None
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
                SSL options passed to websocket-client as sslopt whenever the connection is (re)opened over wss://.
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
        # This is mainly to mitigate potential desynchronization between the device requests and the library posting them.
        # This is mostly due to SUBSCRIBE topics sending events which we don't react to given the request-response architecture
        # of PyNetioConf. PING PONG topics also cause potential desynchronization
        self._request_queue = deque(maxlen=DEFAULT_REQUEST_QUEUE_LEN)
        self._pong_queue = deque(maxlen=DEFAULT_KEEP_ALIVE_QUEUE_LEN)

        # Init from base ESP Device
        self.ws: WebSocket | None = kwargs.get("ws_connection", None)
        self.logger = logging.getLogger(__name__)
        self.ssl_options: dict[str, Any] | None = kwargs.get("ssl_options", dict())
        if kwargs.get("is_ws_auth", False):
            self.session_id = "TODO AUTH"
        else:
            self.session_id = self.login(username, password)
        # self.supported_features = self.get_features()
        # self.output_count: int = self.supported_features["outputCount"]
        try:
            self.user_permissions = self.get_user_privileges(username)
        except (CommunicationError, ElementNotFound):
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
        self._ws_helo_data = kwargs.get("ws_helo_data") or ws_api.send_request(
            self, "HELO"
        )

    def _keep_alive(self) -> None:
        self.logger.debug(
            f"Keep-alive stub called for device {self.host}, keep-alive functianolity is restored on devices running 5.2.x and up, please update."
        )

    @override
    def login(self, username: str, password: str, logout: bool = False) -> str:
        if logout:
            self.ws = None  # Disables a connection if one was present, the device handles the logout automatically

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
                    self.logger.debug(
                        "Disabled keep-alive thread due to new login process."
                    )

                self.logger.debug(
                    f"{self.host} websocket connection attempt {attempt + 1}/{try_count}"
                )
                try:
                    if self.use_https:
                        self.ws = websocket.create_connection(
                            f"wss://{self.host}/emweb",
                            sslopt=self.ssl_options,
                            timeout=10,
                        )  # pyright: ignore[reportUnknownMemberType]
                    else:
                        self.ws = websocket.create_connection(
                            f"ws://{self.host}/emweb", timeout=10
                        )  # pyright: ignore[reportUnknownMemberType]
                except Exception:
                    self.logger.debug(
                        f"Connection to {self.host} failed on {attempt + 1}/{try_count}"
                    )
                    sleep(1)
                    continue

                self.logger.debug(f"Succesfully connected to {self.host}")
                self.ws.settimeout(WS_DEFAULT_TIMEOUT)
                self.ws_req_id = 0
                reconnected = True

            try:
                hello_response = ws_api.device_init_request(
                    self.ws, self.ws_req_id, "HELO", self.host
                )
                self.ws_req_id += 1
                ws_api.login(
                    self,
                    hello_response["data"]["localTimestamp"],
                    hello_response["data"]["publicKey"],
                    username,
                    password,
                )
            except CommunicationError:
                self.logger.debug(
                    f"Login to {self.host} failed on {attempt + 1}/{try_count}"
                )
                self.ws = None
                sleep(1)
                continue

            if reconnected and self._keep_alive_flag:
                self._ka_thread = threading.Timer(120, self._keep_alive)
                self._ka_thread.daemon = True
                self._ka_thread.start()

            return "TODO: Authenticate Session ID on 5.x.x"

        raise CommunicationError(
            f"Couldn't log in to device {self.host} after {try_count} attempts."
        )

    @override
    def logout(self) -> None:
        self.logger.debug(f"Logging out of device {self.host}")
        self.ws = None
        self.ws_req_id = 0

    @override
    def get_current_user(self) -> dict[str, Any]:
        self.logger.debug(
            f"Fetching current user ({self.username}) data from device {self.host}"
        )
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{self.username}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {})

    @override
    def get_user_privileges(self, username: str) -> list[str]:
        self.logger.debug(
            f"Fetching privileges for user {username} on device {self.host}"
        )
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{username}/config"
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
    def create_user(
        self, username: str, password: str, privileges: list[str] | None = None
    ) -> None:
        self.logger.debug(f"Creating user {username} on device {self.host}")
        hello_response = ws_api.send_request(self, "HELO")
        public_key = hello_response["data"]["publicKey"]
        password_hash = ws_api.generate_password_hash(username, password, public_key)

        all_privileges = [
            "can_alter_rules",
            "can_alter_settings",
            "can_alter_users",
            "can_login",
            "can_control_outputs",
            "can_alter_outputs",
            "can_view_settings",
            "can_alter_devices",
            "can_view_history",
            "can_control_user_buttons",
            "can_browse_logs",
            "can_use_tunnels",
        ]
        if privileges is None or len(privileges) == 0:
            privileges = ["can_login"]

        privileges_dict = {key: (key in privileges) for key in all_privileges}

        ws_type = "SET"
        ws_topic = "users/create"
        ws_data = {
            "name": username,
            "password": "",
            "passwordHash": password_hash,
            "privileges": privileges_dict,
        }
        ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def remove_user(self, username: str) -> None:
        self.logger.debug(f"Removing user {username} on device {self.host}")
        ws_type = "SET"
        ws_topic = "users/delete"
        ws_data = {"name": username}
        ws_api.send_request(self, ws_type, ws_topic, ws_data)

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
        self.logger.debug(
            f"Fetching output configuration data for output id {output_id} on {self.host}"
        )
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
        current = self._require_config(
            self.get_output_data(output_id), f"output {output_id}"
        )
        ws_data = {
            "default": _value_or_current(default_state, current, "default"),
            "isScheduleActive": _value_or_current(
                is_schedule_active, current, "isScheduleActive"
            ),
            "name": _value_or_current(output_name, current, "name"),
            "powerUpInterval": _value_or_current(
                power_up_interval, current, "powerUpInterval"
            ),
            "resetDelay": _value_or_current(reset_delay, current, "resetDelay"),
            "scheduleId": _value_or_current(schedule_id, current, "scheduleId"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    def _require_config(
        self, current: dict[str, Any], config_name: str
    ) -> dict[str, Any]:
        if not current:
            message = (
                f"Device {self.host} returned no {config_name} configuration, "
                "settings were left unchanged"
            )
            self.logger.error(message)
            raise CommunicationError(message)
        return current

    def _check_socket_index(self, socket_index: int) -> None:
        if socket_index < 1 or socket_index > self.output_count:
            raise InvalidSocketIndex(
                f"You tried to access socket with id {socket_index},"
                f" the device supports <1;{self.output_count}>."
            )

    @override
    def rename_output(self, output_id: int, output_name: str) -> None:
        self.logger.debug(f"Renaming output {output_id} to new name: {output_name}")
        self._set_output_config(output_id, output_name=output_name)

    @override
    def set_output(self, output_id: int, state: bool) -> None:
        ws_type = "SET"
        ws_topic = f"outputs/id/{output_id}/ctrl"
        ws_data = {"request": "on" if state else "off"}

        self._check_socket_index(output_id)
        self.logger.debug(
            f"Setting output {output_id} to {state} on device {self.host}"
        )
        ws_api.send_request(
            self,
            ws_type,
            ws_topic,
            ws_data,
        )
        self.logger.debug(
            f"Setting output {output_id} on device {self.host} to {state}."
        )

    @override
    def set_outputs_unified(self, state: bool) -> None:
        self.logger.debug(
            f"Setting all outputs unified to {state} on device {self.host}"
        )
        for output in range(1, self.output_count + 1):
            self.set_output(output, state)

    @override
    def reset_output(self, output_id: int) -> None:
        raise NotImplementedError("reset_output is not supported on 5.0.0+ firmware")

    @override
    def reset_output_consumption_counter(self, output_id: int) -> None:
        ws_type = "SET"
        ws_topic = f"outputs/id/{output_id}/resetOutputConsumption"
        ws_data = {"request": True}

        self._check_socket_index(output_id)
        self.logger.debug(
            f"Resetting power consumption counters for output {output_id} on device {self.host}"
        )
        ws_api.send_request(
            self,
            ws_type,
            ws_topic,
            ws_data,
        )

    @override
    def reset_power_consumption_counters(self) -> None:
        self.logger.debug(
            f"Resetting power consumption counters for all outputs on device {self.host}"
        )
        for output in range(1, self.output_count + 1):
            self.reset_output_consumption_counter(output)
            sleep(0.1)

    @override
    def get_output_schedule(self, output_id: int) -> dict[str, Any]:
        self.logger.debug(
            f"Fetching output {output_id} schedule from device {self.host}"
        )
        output_data = self.get_output_data(output_id)
        return {
            "id": output_data.get("scheduleId", 0),
            "on": output_data.get("isScheduleActive", False),
        }

    @override
    def get_output_schedule_id(self, output_id: int) -> int:
        self.logger.debug(
            f"Fetching output {output_id} schedule ID from device {self.host}"
        )
        return int(self.get_output_schedule(output_id)["id"])

    @override
    def set_output_schedule(
        self, output_id: int, schedule_id: int, enabled: bool | None = None
    ) -> None:
        self.logger.debug(
            f"Setting output {output_id} schedule to schedule ID {schedule_id} (active={enabled}) on {self.host}"
        )
        self._set_output_config(
            output_id, schedule_id=schedule_id, is_schedule_active=enabled
        )

    @override
    def set_output_schedule_state(self, output_id: int, schedule_enabled: bool) -> None:
        self.logger.debug(
            f"Setting output {output_id} schedule state to {schedule_enabled} on {self.host}"
        )
        self._set_output_config(output_id, is_schedule_active=schedule_enabled)

    @override
    def set_output_schedule_by_name(
        self, output_id: int, schedule_name: str, enabled: bool | None = None
    ) -> None:
        self.logger.debug(
            f"Setting output {output_id} schedule to '{schedule_name}' on {self.host}"
        )
        schedule_id = self.get_schedule_id(schedule_name)
        self.set_output_schedule(output_id, schedule_id, enabled)

    def _create_configurable_block(
        self, enable: bool, name: str, config: dict[str, Any], topic: str
    ) -> None:
        ws_type = "SET"

        self.logger.debug(f"Creating '{name}' via {topic} on device {self.host}")
        rule_data = {
            "enabled": enable,
            "name": name,
            "config": json.dumps(config),
        }

        ws_api.send_request(self, ws_type, topic, rule_data)

    def create_rule(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        topic = "/rules/create"
        try:
            self.get_rule_by_name(name)
            raise
        except ElementNotFound:
            pass
        self.logger.debug(f"Attempting to create rule {name} on device {self.host}.")
        self.logger.debug(f"Rule configuration: {json.dumps(config)}")
        self._create_configurable_block(enable, name, config, topic)

    @override
    def get_rules(self) -> list[dict[str, Any]]:
        self.logger.debug(f"Getting rules from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "rules/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {}).get("items", [])

    @override
    def get_rule_by_name(self, rule_name: str) -> dict[str, Any]:
        self.logger.debug(f"Filtering for rule {rule_name} on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = f"rules/name/{rule_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        data = response.get("data")
        if not data:
            raise ElementNotFound(f"Rule {rule_name} not found on device {self.host}")
        return data

    @override
    def get_enabled_rules(self) -> list[dict[str, Any]]:
        rules = self.get_rules()
        self.logger.debug(f"Filtering for enabled rules from device {self.host}")
        return [rule for rule in rules if rule.get("enabled") is True]

    @override
    def get_disabled_rules(self) -> list[dict[str, Any]]:
        rules = self.get_rules()
        self.logger.debug(f"Filtering for disabled rules from device {self.host}")
        return [rule for rule in rules if rule.get("enabled") is False]

    def create_pab(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        topic = "/pab/create"
        try:
            self.get_pab_by_name(name)
            raise
        except ElementNotFound:
            pass
        self.logger.debug(f"Attempting to create PAB {name} on device {self.host}.")
        self.logger.debug(f"PAB configuration: {json.dumps(config)}")
        self._create_configurable_block(enable, name, config, topic)

    @override
    def get_pabs(self) -> list[dict[str, Any]]:
        self.logger.debug(f"Getting PABs from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "pab/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {}).get("items", [])

    @override
    def get_pab_by_name(self, pab_name: str) -> dict[str, Any]:
        self.logger.debug(f"Filtering for PAB {pab_name} on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = f"pab/name/{pab_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        data = response.get("data")
        if not data:
            raise ElementNotFound(f"PAB {pab_name} not found on device {self.host}")
        return data

    @override
    def get_enabled_pabs(self) -> list[dict[str, Any]]:
        pabs = self.get_pabs()
        self.logger.debug(f"Filtering for enabled PABs from device {self.host}")
        return [pab for pab in pabs if pab.get("enabled") is True]

    @override
    def get_disabled_pabs(self) -> list[dict[str, Any]]:
        pabs = self.get_pabs()
        self.logger.debug(f"Filtering for disabled PABs from device {self.host}")
        return [pab for pab in pabs if pab.get("enabled") is False]

    def create_watchdog(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        topic = "/wdtpingers/create"
        try:
            self.get_watchdog_by_name(name)
            raise
        except ElementNotFound:
            pass
        self.logger.debug(
            f"Attempting to create watchdog {name} on device {self.host}."
        )
        self.logger.debug(f"Watchdog configuration: {json.dumps(config)}")
        self._create_configurable_block(enable, name, config, topic)

    @override
    def get_watchdogs(self) -> list[dict[str, Any]]:
        self.logger.debug(f"Getting watchdogs from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "wdtpingers/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {}).get("items", [])

    @override
    def get_watchdog_by_name(self, watchdog_name: str) -> dict[str, Any]:
        self.logger.debug(
            f"Filtering for watchdog {watchdog_name} on device {self.host}"
        )
        ws_type = "SUBSCRIBE"
        ws_topic = f"wdtpingers/name/{watchdog_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        data = response.get("data")
        if not data:
            raise ElementNotFound(
                f"Watchdog {watchdog_name} not found on device {self.host}"
            )
        return data

    @override
    def get_enabled_watchdogs(self) -> list[dict[str, Any]]:
        watchdogs = self.get_watchdogs()
        self.logger.debug(f"Filtering for enabled watchdogs from device {self.host}")
        return [w for w in watchdogs if w.get("enabled") is True]

    @override
    def get_disabled_watchdogs(self) -> list[dict[str, Any]]:
        watchdogs = self.get_watchdogs()
        self.logger.debug(f"Filtering for disabled watchdogs from device {self.host}")
        return [w for w in watchdogs if w.get("enabled") is False]

    def create_schedule(self, name: str, intervals: list[dict[int, Any]]) -> None:
        topic = "/schedules/create"
        ws_type = "SET"
        ws_data = {
            "name": name,
            "intervals": intervals,
        }
        try:
            self.get_schedule_by_name(name)
            raise
        except ElementNotFound:
            pass
        self.logger.debug(
            f"Attempting to create schedule {name} on device {self.host}."
        )
        self.logger.debug(f"Schedule configuration: {intervals}")
        ws_api.send_request(self, ws_type, topic, ws_data)

    @override
    def get_schedules(self) -> list[dict[str, Any]]:
        self.logger.debug(f"Getting a schedule list from device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "schedules/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {}).get("items", [])

    @override
    def get_schedule_by_name(self, schedule_name: str) -> dict[str, Any]:
        self.logger.debug(
            f"Filtering for schedule {schedule_name} on device {self.host}"
        )
        ws_type = "SUBSCRIBE"
        ws_topic = f"schedules/name/{schedule_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        data = response.get("data")
        if not data:
            raise ElementNotFound(
                f"Schedule {schedule_name} not found on device {self.host}"
            )
        return data

    @override
    def get_schedule_id(self, schedule_name: str) -> int:
        self.logger.debug(
            f"Fetching ID of schedule {schedule_name} from device {self.host}"
        )
        schedules = self.get_schedules()
        for schedule in schedules:
            if schedule.get("name") == schedule_name:
                return int(schedule["id"])
        raise ElementNotFound(
            f"Schedule {schedule_name} not found on device {self.host}"
        )

    @override
    def get_schedule_names(self) -> list[str]:
        schedules = self.get_schedules()
        self.logger.debug(f"Filtering for schedule names on device {self.host}")
        return [schedule["name"] for schedule in schedules if "name" in schedule]

    @override
    def get_active_schedules(self) -> list[dict[str, Any]]:
        schedules = self.get_schedules()
        self.logger.debug(f"Filtering for active schedules on device {self.host}")
        return [schedule for schedule in schedules if schedule.get("active") is True]

    @override
    def delete_schedule(self, schedule_id: int) -> None:
        self.logger.debug(f"Deleting schedule {schedule_id} from device {self.host}")
        schedules = self.get_schedules()
        schedule_name = None
        for schedule in schedules:
            if schedule.get("id") == schedule_id:
                schedule_name = schedule.get("name")
                break

        if not schedule_name:
            raise ElementNotFound(
                f"Schedule with ID {schedule_id} not found on device {self.host}"
            )

        self.delete_schedule_by_name(schedule_name)

    @override
    def delete_schedule_by_name(self, schedule_name: str) -> None:
        # Check for schedule existing, error out if it doesn't
        try:
            self.get_schedule_by_name(schedule_name)
        except ElementNotFound:
            raise ElementNotFound(
                f"Schedule {schedule_name} not found on device {self.host}"
            )

        topic = "schedules/delete"
        ws_type = "SET"
        ws_data = {"name": schedule_name}
        self.logger.debug(
            f"Attempting to delete schedule {schedule_name} on device {self.host}."
        )
        ws_api.send_request(self, ws_type, topic, ws_data)

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
            "readWriteEnable": _value_or_current(
                write_enable, current, "readWriteEnable"
            ),
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
            "readOnlyEnable": _value_or_current(
                read_enabled, current, "readOnlyEnable"
            ),
            "readUsername": read_username,
            "readPassword": read_password,
            "readWriteEnable": _value_or_current(
                write_enabled, current, "readWriteEnable"
            ),
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
            "ipFilterEnable": _value_or_current(
                ip_filter_enabled, current, "ipFilterEnable"
            ),
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
        push_protocol: str | None = None,
        delta: int | None = None,
        period: int | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/push/config"

        self.logger.debug(f"Setting Netio Push API state on device {self.host}")
        if push_protocol is not None and push_protocol.upper() not in ("JSON", "XML"):
            raise InvalidParameterValueError(
                f"push_protocol must be 'json' or 'xml', got {push_protocol!r}"
            )
        current = self._require_config(
            self.get_netio_push_api_state(), "Netio Push API"
        )
        protocol_data: dict[str, Any] = {
            "enable": _value_or_current(protocol_enabled, current, "enable"),
            "url": _value_or_current(url, current, "url"),
            "delta": _value_or_current(delta, current, "delta"),
            "period": _value_or_current(period, current, "period"),
        }
        # The device doesn't report the push format, so only send it when given.
        if push_protocol is not None:
            protocol_data["protocol"] = push_protocol.upper()
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
            "communityRead": _value_or_current(
                community_read, current, "communityRead"
            ),
            "communityWrite": _value_or_current(
                community_write, current, "communityWrite"
            ),
            "version": ver,
            "securityName": _value_or_current(security_name, current, "securityName"),
            "authAlgo": _value_or_current(auth_protocol, current, "authAlgo"),
            "authKey": _value_or_current(auth_key, current, "authKey"),
            "encryptAlgo": _value_or_current(priv_protocol, current, "encryptAlgo"),
            "encryptKey": _value_or_current(priv_key, current, "encryptKey"),
            "securityLevel": _value_or_current(
                security_level, current, "securityLevel"
            ),
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
        security_level: str | None = None,
        auth_protocol: str | None = None,
        auth_key: str | None = None,
        priv_protocol: str | None = None,
        priv_key: str | None = None,
    ) -> None:
        self.logger.debug(f"Setting SNMP v3 API state on device {self.host}")
        self._set_snmp_api_state(
            protocol_enabled=protocol_enabled,
            version="v3",
            location=location,
            security_name=security_name,
            security_level=security_level,
            auth_protocol=auth_protocol,
            auth_key=auth_key,
            priv_protocol=priv_protocol,
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
            "readWriteEnable": _value_or_current(
                write_enable, current, "readWriteEnable"
            ),
            "writeUsername": write_username,
            "writePassword": write_password,
        }
        self.logger.debug(f"Setting json api state on device {self.host}.")
        logged_data = {
            key: "***" if "Password" in key else value
            for key, value in protocol_data.items()
        }
        self.logger.debug(f"JSON configuration: {json.dumps(logged_data, indent=4)}")
        _ = ws_api.send_request(self, ws_type, ws_topic, protocol_data)

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

    def get_measurement(self):
        ws_type = "SUBSCRIBE"
        ws_topic = "outputs/measure"

        self.logger.debug(f"Fetching raw measurements from device {self.host}")
        return ws_api.send_request(self, ws_type, ws_topic)

    def upload_mqtt_client_key(self, key: str) -> None:
        ws_type = "SET"
        ws_topic = "protocols/mqtt/clientkeyupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT client key to device {self.host}.")
        upload_path = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"][
            "uploadPath"
        ]
        _ = esp_api.send_file(self, upload_path, key)
        sleep(0.1)

    def upload_mqtt_client_certificate(self, cert: str) -> None:
        ws_type = "SET"
        ws_topic = "protocols/mqtt/clientcertupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT client certificate to device {self.host}.")
        upload_path = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"][
            "uploadPath"
        ]
        _ = esp_api.send_file(self, upload_path, cert)
        sleep(0.1)

    def upload_mqtt_ca_certificate(self, ca: str) -> None:
        ws_type = "SET"
        ws_topic = "protocols/mqtt/cacertupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT CA certificate to device {self.host}.")
        upload_path = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"][
            "uploadPath"
        ]
        _ = esp_api.send_file(self, upload_path, ca)
        sleep(0.1)

    def get_mqttflex_state(self) -> dict:
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/mqtt/config"

        self.logger.debug(f"Getting MQTT flex state on device {self.host}")
        return ws_api.send_request(self, ws_type, ws_topic)["data"]

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
            output_states.append(
                (int(output["id"]), True if output["state"] == "on" else False)
            )
        return output_states

    @override
    def get_output_state(self, output_id: int) -> bool:
        self.logger.debug(f"Fetching output {output_id} state from device {self.host}")
        return self.get_output_states()[output_id - 1][1]  # TODO: Polish

    def set_mqttflex_state(
        self, state: bool | None = None, config: dict[str, Any] | None = None
    ) -> None:
        ws_type = "SET"
        ws_topic = "protocols/mqtt/config"

        self.logger.debug(f"Setting MQTT flex state to {state} on device {self.host}")
        current = self._require_config(self.get_mqttflex_state(), "MQTT flex")
        ws_data = {
            "enable": _value_or_current(state, current, "enable"),
            # The device returns the config JSON-encoded; only encode a given dict.
            "config": json.dumps(config) if config is not None else current["config"],
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)
        sleep(1)

    def upload_https_private_key(self, keyfile: str) -> None:
        topic = "system/srvkeyupload"
        ws_type = "SET"
        ws_data: dict[str, Any] = {}
        self.logger.debug(
            f"Uploading https private key for https to device {self.host}."
        )
        with open(keyfile, "rb") as f:
            endpoint_data = ws_api.send_request(self, ws_type, topic, ws_data)
            endpoint = endpoint_data["data"]["uploadPath"]
            esp_api.send_file(self, endpoint, f)

    def upload_https_certificate(self, certfile: str) -> None:
        topic = "system/srvcertupload"
        ws_type = "SET"
        ws_data = {}
        self.logger.debug("Uploading https certificate for https.")
        with open(certfile, "rb") as f:
            endpoint_data = ws_api.send_request(self, ws_type, topic, ws_data)
            endpoint = endpoint_data["data"]["uploadPath"]
            esp_api.send_file(self, endpoint, f)

    def export_config(self, save_file: str | None = None) -> dict[str, Any]:
        ws_type = "SET"
        ws_topic = "system/cfgexport"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Exporting configuration from device {self.host}")
        config = ws_api.send_request(self, ws_type, ws_topic, ws_data)
        if save_file:
            with open(save_file, "w") as file:
                json.dump(config["data"]["config"], file)
        return config["data"]["config"]

    def import_config(self, file, **kwargs) -> None:
        ws_type = "SET"
        ws_topic = "system/cfgimport"
        ws_data: dict[str, Any] = {}

        if "can_alter_settings" not in self.user_permissions:
            raise PermissionError(
                "You don't have permission to alter settings on this device."
            )
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
        self.logger.debug(f"Importing configuration to device {self.host}")
        data = json.load(file)
        encoded_data = json.dumps(data).encode("utf-8")
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        esp_api.send_file(self, "/cfgimport", encoded_data)
        self.logger.info(
            f"Imported configuration from {getattr(file, 'name', 'in-memory file')}, device {self.host} is restarting..."
        )
        sleep(kwargs.get("sleep_time", 15))
        username = kwargs.get("username", self.username)
        password = kwargs.get("password", self.password)

        if kwargs.get("login", True):
            # logout=True drops the connection that ended with the device restart, login also restarts the keep-alive
            self.login(username, password, logout=True)

    @override
    def update_firmware(self, file: os.PathLike[AnyStr] | BytesIO) -> NETIODevice:
        if "can_alter_settings" not in self.user_permissions:
            raise PermissionError(
                "You don't have permission to alter settings on this device."
            )
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()

        pre_reconnect_wait = 20
        if self.supported_features["wifi"] == "yes":
            wifi_settings = self.get_wifi_settings()
            if (
                wifi_settings["mode"] == "client"
                and wifi_settings["client"]["status"] == "Connected"
            ):
                pre_reconnect_wait = 50
                self.logger.debug(
                    "Increased wait time after fimrware update due to active Wi-Fi connection."
                )

        if esp_api.check_connectivity(self) > (pre_reconnect_wait / 10.0):
            pre_reconnect_wait = pre_reconnect_wait * 2
            self.logger.debug(
                "Increased wait time after firmware update due to poor connection quality."
            )

        _ = esp_api.send_request(self, "prepFwUpgrade")
        _ = esp_api.send_file(self, "/upload/firmware", file)
        try:
            _ = esp_api.send_request(self, "startUpgrade", close=True)
        except CommunicationError:
            self.logger.warn(
                f"Device {self.host} couldn't verify firmware update process beginning, this should be harmless if the device connects, waiting for connection."
            )
        self.logger.debug(
            f"Uploaded firmware {getattr(file, 'name', 'in-memory file')}, device {self.host} might be unresponsive for a while."
        )

        sleep(pre_reconnect_wait)

        self.logger.debug(
            f"Retrying connection to device {self.host} after updating firmware to {getattr(file, 'name', 'in-memory file')}."
        )
        device_response_time = esp_api.check_connectivity(self)
        retry_limit = 3 if device_response_time == -1 else 0
        for _ in range(0, retry_limit):
            device_response_time = esp_api.check_connectivity(self)

        if device_response_time == -1:
            raise CommunicationError(
                "Device couldn't establish connection after firmware update."
            )

        updated_instance = None
        if isinstance(self.netio_manager, NetioManager):
            updated_instance = self.netio_manager.update_device(self)

        if not updated_instance:
            raise CommunicationError("Coudln't get updated instance.")

        return updated_instance

    def get_features(self) -> dict[str, Any]:
        self.logger.debug(f"Fetching supported features from device {self.host}")
        return self.get_system_info()

    @override
    def ping(self) -> bool:
        self.logger.warning(
            "Device pinging is not supported on 5.0.x to 5.1.x, please update your device."
        )
        return True

    @override
    def get_system_log(self) -> list[dict[str, Any]]:
        ws_topic = "log/messages"
        ws_type = "SUBSCRIBE"
        ws_data = None
        self.logger.debug(f"Fetching system log messages from device {self.host}.")

        log_messages: list[dict[str, Any]] = ws_api.send_request(
            self, ws_type, ws_topic, ws_data
        )["data"]
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
        netwifi_data = self._require_config(
            netwifi_res.get("data", {}), "Wi-Fi network"
        )
        if netwifi_data["networkMode"] != "static" and None in (
            address,
            net_mask,
            gateway,
        ):
            raise InvalidParameterValueError(
                "address, net_mask and gateway are required when switching Wi-Fi "
                "from DHCP to a static address"
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
    def set_periodic_restart(
        self, enable: bool | None = None, restart_period: int | None = None
    ) -> None:
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
        cfg_res = ws_api.send_request(self, ws_type, ws_topic)
        cfg_data = self._require_config(cfg_res.get("data", {}), "system")
        if device_name is not None:
            cfg_data["devname"] = device_name
        if periodic_restart is not None:
            cfg_data["periodRestartEnable"] = periodic_restart
        if restart_period is not None:
            cfg_data["periodRestartPeriod"] = restart_period

        ws_type = "SET"
        _ = ws_api.send_request(self, ws_type, ws_topic, cfg_data)

    @override
    def locate(self) -> None:
        ws_type = "SET"
        ws_topic = "system/locate"
        ws_data = {"locate": True}

        self.logger.debug(f"Locating device {self.host}")
        ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def clear_system_log(self) -> None:
        ws_type = "SET"
        ws_topic = "log/clear"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Clearing system log on device {self.host}")
        ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    def change_user_password(
        self, username: str, old_password: str, new_password: str
    ) -> None:
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{username}/config"

        self.logger.debug(
            f"Changing password for user {username} on device {self.host}"
        )
        user_cfg_res = ws_api.send_request(self, ws_type, ws_topic)
        user_data = user_cfg_res["data"]
        hello_response = ws_api.send_request(self, "HELO")
        public_key = hello_response["data"]["publicKey"]
        password_hash = ws_api.generate_password_hash(
            username, new_password, public_key
        )
        user_data["passwordHash"] = password_hash
        user_data["password"] = ""

        ws_type = "SET"
        ws_api.send_request(self, ws_type, ws_topic, user_data)

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

        self.logger.debug(
            f"Registering to cloud with token {token} on device {self.host}"
        )
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        sleep(CLOUD_ACTION_COMMUNICATION_DELAY)

    @override
    def set_on_premise(self, url: str) -> None:
        ws_type = "SET"
        ws_topic = "protocols/cloud/cmd"
        ws_data = {"action": "setOnPremis", "token": "", "server": url}

        self.logger.debug(
            f"Setting on-premise cloud server to {url} on device {self.host}"
        )
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        sleep(CLOUD_ACTION_COMMUNICATION_DELAY)

    @override
    def netio_push_api_push_now(self) -> None:
        raise NotImplementedError(
            "netio_push_api_push_now is not implemented on 5.0.0+ devices"
        )

    def _cleanup(self) -> None:
        try:
            if self._ka_thread:
                self._ka_thread.cancel()
                self._ka_thread.join()
                self.logger.debug("Disabled keep-alive thread.")
        except AttributeError:
            pass  # No need to clean up a non existant thread
        # TODO: Logout to be sure here even though destroying the connection should be sufficient
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
        self.logger.debug(f"Fetching input {input_id} data from device {self.host}")
        input_list = self.get_input_list()
        if input_id > len(input_list["items"]):
            raise InvalidSocketIndex(
                f"The device doesn't support {input_id} inputs. The input range is <0;{len(input_list['items'])}>"
            )
        else:
            return input_list["items"][input_id - 1]

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
        ws_type = "SET"
        ws_topic = "system/reset"
        ws_data = {"reset": True}

        self.logger.debug(f"Triggering system reset (reboot) on device {self.host}")
        ws_api.send_request(self, ws_type, ws_topic, ws_data)
        sleep(DEVICE_RESET_GRACE_PERIOD)

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
        network_mode: str | None = None,
        ip: str | None = None,
        netmask: str | None = None,
        gateway: str | None = None,
        dns: str | None = None,
    ) -> None:
        ws_type = "SET"
        ws_topic = "network/ethernet/config"

        self.logger.debug(f"Setting Ethernet configuration on device {self.host}")
        current = self._require_config(self.get_ethernet_settings(), "Ethernet")
        if (
            network_mode == "static"
            and current["networkMode"] != "static"
            and None in (ip, netmask, gateway)
        ):
            raise InvalidParameterValueError(
                "ip, netmask and gateway are required when switching Ethernet "
                "from DHCP to a static address"
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
        # TODO: make sure to change the https settings if it's toggled to https and vice versa

        self.logger.debug(f"Setting web server settings on device {self.host}")
        current = self._require_config(self.get_server_settings(), "web server")
        ws_data: dict[str, Any] = {
            "httpEnable": _value_or_current(http_enable, current, "httpEnable"),
            "httpPort": _value_or_current(http_port, current, "httpPort"),
            "httpsEnable": _value_or_current(https_enable, current, "httpsEnable"),
            "httpsPort": _value_or_current(https_port, current, "httpsPort"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

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
    def get_firmware_updates_list(self) -> list[dict[str, Any]]:
        ws_type = "SET"
        ws_topic = "system/firmwarelist"
        ws_data = {"getFirmwareList": True, "updateFw": ""}

        self.logger.debug(f"Fetching available firmware updates on device {self.host}")
        ws_api.send_request(self, ws_type, ws_topic, ws_data)

        ws_type = "SUBSCRIBE"
        ws_topic = "fwupdate/list"
        response = ws_api.send_request(self, ws_type, ws_topic)
        return response.get("data", {}).get("items", [])

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
