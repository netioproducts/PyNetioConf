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
from ..exceptions import CommunicationError, ElementNotFound, InvalidSocketIndex
from ..netio_device import NETIODevice
from . import esp_api, ws_api
from .esp_400_device import ESP400Device


class ESP500Device(NETIODevice):
    """
    A class to control ESP devices with the firmware 5.0.x.
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
        The 5.x.x versions of Netio firmware have been severely redesigned which includes the entirety of the API that is used for communication with the device therefore this init is completely separated from the base classes and does not call super().__init__ but instead makes a new class from scratch. If the base NETIODevice class gets updated this has to be done accordingly here.

        Parameters
        ----------
        host : str

        username : str

        password : str

        sn_number : str

        hostname : str

         : Any

        keep_alive : bool

        netio_manager : NetioManager | None

        use_https : bool


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
        if kwargs.get("is_ws_auth", False):
            self.session_id = "TODO AUTH"
        else:
            self.session_id = self.login(username, password)
        # self.supported_features = self.get_features()
        # self.output_count: int = self.supported_features["outputCount"]
        # self.user_permissions = self.get_current_user()["privileges"]
        if keep_alive:
            self._ka_thread = threading.Timer(120, self._keep_alive)
            self._ka_thread.daemon = True
            self._ka_thread.start()
        atexit.register(self._cleanup)

        # New Init
        self.ssl_options: dict[str, Any] | None = kwargs.get("ssl_options", dict())
        self.logger = logging.getLogger(self.__class__.__name__)
        self.netio_manager = netio_manager
        # self.fw_version = self.get_version()

        _system_info = self.get_system_info()
        self.output_count = _system_info["outputCount"]
        self.input_count = _system_info["inputCount"]
        self.supported_features["wifi"] = _system_info["wifiSupport"]
        self.supported_features["eth"] = _system_info["ethSupport"]

    def _keep_alive(self) -> None:
        # TODO: Implement WebSocket keep-alive logic for 5.0.0+ firmware
        self.logger.debug(f"Keep-alive stub called for device {self.host}")

    def login(self, username: str, password: str, logout: bool = False) -> str:
        if logout:
            self.ws = None  # Disables a connection if one was present, the device handles the logout automatically

        if self.ws is None:
            if self.use_https:
                self.ws = websocket.create_connection(
                    f"wss://{self.host}/emweb", sslopt=self.ssl_options
                )  # pyright: ignore[reportUnknownMemberType]
            else:
                self.ws = websocket.create_connection(f"ws://{self.host}/emweb")  # pyright: ignore
            self.ws_req_id = 0

        hello_response = ws_api.send_request(self, "HELO")

        ws_api.login(
            self,
            hello_response["data"]["localTimestamp"],
            hello_response["data"]["publicKey"],
            username,
            password,
        )

        return "TODO: Authenticate Session ID on 5.x.x"

    @override
    def logout(self) -> None:
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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get current user data: {error_msg}")
        return response.get("data", {})

    @override
    def get_user_privileges(self, username: str) -> list[str]:
        self.logger.debug(
            f"Fetching privileges for user {username} on device {self.host}"
        )
        ws_type = "SUBSCRIBE"
        ws_topic = f"users/name/{username}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            if (
                "not found" in error_msg.lower()
                or "does not exist" in error_msg.lower()
            ):
                raise ElementNotFound(
                    f"User {username} not found on device {self.host}"
                )
            raise CommunicationError(
                f"Failed to get user privileges for {username}: {error_msg}"
            )
        data = response.get("data")
        if not data:
            raise ElementNotFound(f"User {username} not found on device {self.host}")
        priv_dict = data.get("privileges", {})
        return [key for key, val in priv_dict.items() if val is True]

    @override
    def get_users(self) -> dict[str, Any]:
        self.logger.debug(f"Fetching users list on device {self.host}")
        current_user_data = self.get_current_user()
        if current_user_data:
            return {self.username: current_user_data}
        return {}

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
        response = ws_api.send_request(self, ws_type, ws_topic, ws_data)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to create user {username}: {error_msg}")

    @override
    def remove_user(self, username: str) -> None:
        self.logger.debug(f"Removing user {username} on device {self.host}")
        ws_type = "SET"
        ws_topic = "users/delete"
        ws_data = {"name": username}
        response = ws_api.send_request(self, ws_type, ws_topic, ws_data)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to remove user {username}: {error_msg}")

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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get uptime: {error_msg}")
        return int(response.get("data", {}).get("uptime", 0))

    def get_version_detailed(self) -> str:
        return self.get_system_info()["fwVersion"]

    def get_version(self) -> str:
        return self.get_version_detailed().split("-")[0].strip()

    @override
    def get_output_data(self, output_id: int) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = f"outputs/id/{output_id}/config"
        self.logger.debug(
            f"Fetching output configuration data for output id {output_id} on {self.host}"
        )
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(
                f"Failed to get output data for output {output_id}: {error_msg}"
            )
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
        old_output_data = self.get_output_data(output_id)
        ws_data = {
            "default": default_state
            if default_state is not None
            else old_output_data["default"],
            "isScheduleActive": is_schedule_active
            if is_schedule_active is not None
            else old_output_data["isScheduleActive"],
            "name": output_name if output_name is not None else old_output_data["name"],
            "powerUpInterval": power_up_interval
            if power_up_interval is not None
            else old_output_data["powerUpInterval"],
            "resetDelay": reset_delay
            if reset_delay is not None
            else old_output_data["resetDelay"],
            "scheduleId": schedule_id
            if schedule_id is not None
            else old_output_data["scheduleId"],
        }
        ws_api.send_request(self, ws_type, ws_topic, ws_data)

    def _check_socket_index(self, socket_index: int) -> None:
        if socket_index < 1 or socket_index > self.output_count:
            raise InvalidSocketIndex(
                f"You tried to access socket with id {socket_index},"
                f" the device supports <1;{self.output_count}>."
            )

    def rename_output(self, output_id: int, output_name: str) -> None:
        self.logger.debug(f"Renaming output {output_id} to new name: {output_name}")
        self._set_output_config(output_id, output_name=output_name)

    def set_output(self, output_id: int, state: bool) -> None:
        self._check_socket_index(output_id)
        ws_api.send_request(
            self,
            "SET",
            f"outputs/id/{output_id}/ctrl",
            {"request": "on" if state else "off"},
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
        self._check_socket_index(output_id)
        self.logger.debug(
            f"Resetting power consumption counters for output {output_id} on device {self.host}"
        )
        response = ws_api.send_request(
            self,
            "SET",
            f"outputs/id/{output_id}/resetOutputConsumption",
            {"request": True},
        )
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(
                f"Failed to reset power consumption counters for output {output_id}: {error_msg}"
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
        output_data = self.get_output_data(output_id)
        return {
            "id": output_data.get("scheduleId", 0),
            "on": output_data.get("isScheduleActive", False),
        }

    @override
    def get_output_schedule_id(self, output_id: int) -> int:
        return int(self.get_output_schedule(output_id)["id"])

    @override
    def set_output_schedule(
        self, output_id: int, schedule_id: int, enabled: bool = True
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
        self, output_id: int, schedule_name: str, enabled: bool = True
    ) -> None:
        schedule_id = self.get_schedule_id(schedule_name)
        self.set_output_schedule(output_id, schedule_id, enabled)

    def _create_configurable_block(
        self, enable: bool, name: str, config: dict[str, Any], topic: str
    ) -> None:
        ws_type = "SET"
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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get rules: {error_msg}")
        return response.get("data", {}).get("items", [])

    @override
    def get_rule_by_name(self, rule_name: str) -> dict[str, Any]:
        self.logger.debug(f"Filtering for rule {rule_name} on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = f"rules/name/{rule_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            if (
                "not found" in error_msg.lower()
                or "does not exist" in error_msg.lower()
            ):
                raise ElementNotFound(
                    f"Rule {rule_name} not found on device {self.host}"
                )
            raise CommunicationError(f"Failed to get rule {rule_name}: {error_msg}")

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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get PABs: {error_msg}")
        return response.get("data", {}).get("items", [])

    @override
    def get_pab_by_name(self, pab_name: str) -> dict[str, Any]:
        self.logger.debug(f"Filtering for PAB {pab_name} on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = f"pab/name/{pab_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            if (
                "not found" in error_msg.lower()
                or "does not exist" in error_msg.lower()
            ):
                raise ElementNotFound(f"PAB {pab_name} not found on device {self.host}")
            raise CommunicationError(f"Failed to get PAB {pab_name}: {error_msg}")

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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get watchdogs: {error_msg}")
        return response.get("data", {}).get("items", [])

    @override
    def get_watchdog_by_name(self, watchdog_name: str) -> dict[str, Any]:
        self.logger.debug(
            f"Filtering for watchdog {watchdog_name} on device {self.host}"
        )
        ws_type = "SUBSCRIBE"
        ws_topic = f"wdtpingers/name/{watchdog_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            if (
                "not found" in error_msg.lower()
                or "does not exist" in error_msg.lower()
            ):
                raise ElementNotFound(
                    f"Watchdog {watchdog_name} not found on device {self.host}"
                )
            raise CommunicationError(
                f"Failed to get watchdog {watchdog_name}: {error_msg}"
            )

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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get schedules: {error_msg}")
        return response.get("data", {}).get("items", [])

    @override
    def get_schedule_by_name(self, schedule_name: str) -> dict[str, Any]:
        self.logger.debug(
            f"Filtering for schedule {schedule_name} on device {self.host}"
        )
        ws_type = "SUBSCRIBE"
        ws_topic = f"schedules/name/{schedule_name}/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            if (
                "not found" in error_msg.lower()
                or "does not exist" in error_msg.lower()
            ):
                raise ElementNotFound(
                    f"Schedule {schedule_name} not found on device {self.host}"
                )
            raise CommunicationError(
                f"Failed to get schedule {schedule_name}: {error_msg}"
            )

        data = response.get("data")
        if not data:
            raise ElementNotFound(
                f"Schedule {schedule_name} not found on device {self.host}"
            )
        return data

    @override
    def get_schedule_id(self, schedule_name: str) -> int:
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
        response = ws_api.send_request(self, ws_type, topic, ws_data)

        # Check response for failure
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(
                f"Failed to delete schedule {schedule_name}: {error_msg}"
            )

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
        response = ws_api.send_request(self, ws_type, topic, ws_data)

        # Check response for failure
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to delete rule {name}: {error_msg}")

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
        response = ws_api.send_request(self, ws_type, topic, ws_data)

        # Check response for failure
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to delete PAB {pab_name}: {error_msg}")

    @override
    def get_active_protocols(self) -> list[int]:
        self.logger.debug(f"Fetching active protocols on {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/info"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get active protocols: {error_msg}")

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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get supported protocols: {error_msg}")

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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get XML API state: {error_msg}")
        return response["data"]

    @override
    def set_xml_api_state(
        self,
        protocol_enabled: bool,
        read_enable: bool,
        write_enable: bool,
        read_auth: tuple[str, str],
        write_auth: tuple[str, str],
    ) -> None:
        self.logger.debug(f"Setting XML API state on device {self.host}")
        protocol_data = {
            "enable": protocol_enabled,
            "port": 80,
            "readOnlyEnable": read_enable,
            "readUsername": read_auth[0],
            "readPassword": read_auth[1],
            "readWriteEnable": write_enable,
            "writeUsername": write_auth[0],
            "writePassword": write_auth[1],
        }
        response = ws_api.send_request(
            self, "SET", "protocols/xml/config", protocol_data
        )
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to set XML API state: {error_msg}")

    @override
    def get_json_api_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting JSON API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/json/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get JSON API state: {error_msg}")
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
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get Telnet API state: {error_msg}")
        return response["data"]

    @override
    def set_telnet_api_state(
        self,
        protocol_enabled: bool,
        port: int | None = None,
        read_enabled: bool | None = None,
        read_auth: tuple[str, str] | None = None,
        write_enabled: bool | None = None,
        write_auth: tuple[str, str] | None = None,
    ) -> None:
        self.logger.debug(f"Setting Telnet API state on device {self.host}")
        current = self.get_telnet_api_state()
        protocol_data = {
            "enable": protocol_enabled,
            "port": port if port is not None else current.get("port", 23),
            "readOnlyEnable": read_enabled
            if read_enabled is not None
            else current.get("readOnlyEnable", True),
            "readUsername": read_auth[0]
            if read_auth is not None
            else current.get("readUsername", ""),
            "readPassword": read_auth[1]
            if read_auth is not None
            else current.get("readPassword", ""),
            "readWriteEnable": write_enabled
            if write_enabled is not None
            else current.get("readWriteEnable", True),
            "writeUsername": write_auth[0]
            if write_auth is not None
            else current.get("writeUsername", "netio"),
            "writePassword": write_auth[1]
            if write_auth is not None
            else current.get("writePassword", "netio"),
        }
        response = ws_api.send_request(
            self, "SET", "protocols/telnet/config", protocol_data
        )
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to set Telnet API state: {error_msg}")

    @override
    def get_modbus_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting Modbus M2M API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/modbus/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get Modbus API state: {error_msg}")
        return response["data"]

    @override
    def set_modbus_state(
        self,
        protocol_enabled: bool,
        port: int = 502,
        ip_filter_enabled: bool = False,
        ip_from: str = "0.0.0.0",
        ip_to: str = "0.0.0.0",
    ) -> None:
        self.logger.debug(f"Setting Modbus M2M API state on device {self.host}")
        protocol_data = {
            "enable": protocol_enabled,
            "port": port,
            "lastIp": "0.0.0.0",
            "ipFilterEnable": ip_filter_enabled,
            "ipFrom": ip_from,
            "ipTo": ip_to,
        }
        response = ws_api.send_request(
            self, "SET", "protocols/modbus/config", protocol_data
        )
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to set Modbus state: {error_msg}")

    @override
    def get_netio_push_api_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting Netio Push API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/push/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get Push API state: {error_msg}")
        return response["data"]

    @override
    def set_netio_push_api_state(
        self,
        protocol_enabled: bool,
        url: str | None = None,
        push_protocol: str | None = None,
        delta: int | None = None,
        period: int | None = None,
    ) -> None:
        self.logger.debug(f"Setting Netio Push API state on device {self.host}")
        current = self.get_netio_push_api_state()
        protocol_data = {
            "enable": protocol_enabled,
            "url": url
            if url is not None
            else current.get("url", "http://test.example.com:80/push"),
            "protocol": (
                push_protocol.upper()
                if push_protocol is not None
                else current.get("protocol", "JSON")
            ),
            "delta": delta if delta is not None else current.get("delta", 0),
            "period": period if period is not None else current.get("period", 60),
        }
        response = ws_api.send_request(
            self, "SET", "protocols/push/config", protocol_data
        )
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to set Push API state: {error_msg}")

    @override
    def get_snmp_api_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting SNMP API state on device {self.host}")
        ws_type = "SUBSCRIBE"
        ws_topic = "protocols/snmp/config"
        response = ws_api.send_request(self, ws_type, ws_topic)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get SNMP API state: {error_msg}")
        return response["data"]

    @override
    def _set_snmp_api_state(
        self,
        protocol_enabled: bool,
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
        self.logger.debug(f"Setting SNMP API state on device {self.host}")
        current_state = self.get_snmp_api_state()
        ver = "v1-2" if version in ("v1,2c", "v1-2") else "v3"

        request_data = {
            "enable": protocol_enabled,
            "location": location
            if location is not None
            else current_state.get("location", "Unknown"),
            "communityRead": community_read
            if community_read is not None
            else current_state.get("communityRead", "public"),
            "communityWrite": community_write
            if community_write is not None
            else current_state.get("communityWrite", "private"),
            "version": ver,
            "securityName": security_name
            if security_name is not None
            else current_state.get("securityName", "netio"),
            "authAlgo": auth_protocol
            if auth_protocol is not None
            else current_state.get("authAlgo", "SHA"),
            "authKey": auth_key
            if auth_key is not None
            else current_state.get("authKey", "netio"),
            "encryptAlgo": priv_protocol
            if priv_protocol is not None
            else current_state.get("encryptAlgo", "AES"),
            "encryptKey": priv_key
            if priv_key is not None
            else current_state.get("encryptKey", "netio"),
            "securityLevel": security_level
            if security_level is not None
            else current_state.get("securityLevel", "authPriv"),
        }

        response = ws_api.send_request(
            self, "SET", "protocols/snmp/config", request_data
        )
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to set SNMP API state: {error_msg}")

    @override
    def set_snmp_v1_2_api_state(
        self,
        protocol_enabled: bool,
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
        protocol_enabled: bool,
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
        protocol_enabled: bool,
        read_enable: bool | None = None,
        write_enable: bool | None = None,
        read_auth: tuple[str, str] | None = None,
        write_auth: tuple[str, str] | None = None,
    ) -> None:
        old_protocol_data = self.get_json_api_state()

        protocol_data = {
            "enable": protocol_enabled,
            "port": 80,
            "readOnlyEnable": read_enable
            if read_enable is not None
            else old_protocol_data["read"]["enable"],
            "readUsername": read_auth[0]
            if read_auth is not None
            else old_protocol_data["read"]["username"],
            "readPassword": read_auth[1]
            if read_auth is not None
            else old_protocol_data["read"]["password"],
            "readWriteEnable": write_enable
            if write_enable is not None
            else old_protocol_data["write"]["enable"],
            "writeUsername": write_auth[0]
            if write_auth is not None
            else old_protocol_data["write"]["username"],
            "writePassword": write_auth[1]
            if write_auth is not None
            else old_protocol_data["write"]["password"],
        }
        self.logger.debug(f"Setting json api state on device {self.host}.")
        self.logger.debug(f"JSON configuration: {json.dumps(protocol_data, indent=4)}")
        ws_api.send_request(self, "SET", "protocols/json/config", protocol_data)

    def get_urlapi_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting urlapi state on device {self.host}.")
        response = ws_api.send_request(self, "SUBSCRIBE", "protocols/url/config")
        return response["data"]

    def set_urlapi_state(
        self, protocol_enabled: bool, write_enable: bool, write_password: str
    ) -> None:
        old_protocol_data = self.get_urlapi_state()
        protocol_data = {
            "enable": protocol_enabled,
            "port": 80,
            "writeEnable": write_enable,
            "password": write_password,
        }
        ws_api.send_request(self, "SET", "protocols/url/config", protocol_data)

    def get_output_states(self) -> list[tuple[int, bool]]:
        socket_list = ws_api.send_request(self, "SUBSCRIBE", "outputs/measure")
        return [
            (socket["id"], socket["state"] == "on")
            for socket in socket_list["data"]["items"]
        ]

    def get_measurement(self):
        return ws_api.send_request(self, "SUBSCRIBE", "outputs/measure")

    def upload_mqtt_client_key(self, key: str) -> None:
        upload_path = ws_api.send_request(
            self, "SET", "protocols/mqtt/clientkeyupload", {}
        )["data"]["uploadPath"]
        _ = esp_api.send_file(self, upload_path, key)
        sleep(0.1)

    def upload_mqtt_client_certificate(self, cert: str) -> None:
        upload_path = ws_api.send_request(
            self, "SET", "protocols/mqtt/clientcertupload", {}
        )["data"]["uploadPath"]
        _ = esp_api.send_file(self, upload_path, cert)
        sleep(0.1)

    def upload_mqtt_ca_certificate(self, ca: str) -> None:
        upload_path = ws_api.send_request(
            self, "SET", "protocols/mqtt/cacertupload", {}
        )["data"]["uploadPath"]
        _ = esp_api.send_file(self, upload_path, ca)
        sleep(0.1)

    def get_mqttflex_state(self) -> dict:
        return ws_api.send_request(self, "SUBSCRIBE", "protocols/mqtt/config")["data"]

    @override
    def get_outputs_data(self) -> list[dict[int, dict[str, Any]]]:
        return ws_api.send_request(self, "SUBSCRIBE", "outputs/measure")["data"][
            "items"
        ]

    @override
    def get_output_states(self) -> list[tuple[int, bool]]:
        output_data = self.get_outputs_data()
        output_states = []
        for output in output_data:
            output_states.append(
                (int(output["id"]), True if output["state"] == "on" else False)
            )
        return output_states

    @override
    def get_output_state(self, output_id: int) -> bool:
        return self.get_output_states()[output_id - 1][1]  # TODO: Polish

    def set_mqttflex_state(
        self, state: bool, config: dict[str, Any] | None = None
    ) -> None:
        if config is None:
            config = self.get_mqttflex_state()["config"]
        ws_api.send_request(
            self,
            "SET",
            "protocols/mqtt/config",
            {"enable": state, "config": json.dumps(config)},
        )
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

    def export_config(self, save_file: str = None) -> dict:
        config = ws_api.send_request(self, "SET", "system/cfgexport", data={})
        if save_file:
            with open(save_file, "w") as file:
                json.dump(config["data"]["config"], file)
        return config["data"]["config"]

    def import_config(self, file, **kwargs) -> None:
        if "can_alter_settings" not in self.user_permissions:
            raise PermissionError(
                "You don't have permission to alter settings on this device."
            )
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
        data = json.load(file)
        encoded_data = json.dumps(data).encode("utf-8")
        ws_api.send_request(self, "SET", "system/cfgimport", data={})
        esp_api.send_file(self, "/cfgimport", encoded_data)
        self.logger.info(
            f"Imported configuration from {file.name}, device {self.host} is restarting..."
        )
        sleep(kwargs.get("sleep_time", 15))
        username = kwargs.get("username", self.username)
        password = kwargs.get("password", self.password)

        if kwargs.get("login", True):
            self._login_new(username, password)
            if self._ka_thread:
                self._keep_alive()

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
            f"Uploaded firmware {file.name}, device {self.host} might be unresponsive for a while."
        )

        sleep(pre_reconnect_wait)

        self.logger.debug(
            f"Retrying connection to device {self.host} after updating firmware to {file.name}."
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
        if type(self.netio_manager) is NetioManager:
            updated_instance = self.netio_manager.update_device(self)

        if not updated_instance:
            raise CommunicationError("Coudln't get updated instance.")

        return updated_instance

    def get_features(self) -> dict[str, Any]:
        return self.get_system_info()

    @override
    def ping(self) -> bool:
        # TODO: Make a proper ping like utility to not force new HTTP connection
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
        self, address: str, net_mask: str, gateway: str, dns_server: str, hostname: str
    ) -> None:
        self.logger.debug(f"Setting Wi-Fi static address on device {self.host}")
        netwifi_res = ws_api.send_request(self, "SUBSCRIBE", "network/netwifi/config")
        netwifi_data = netwifi_res.get("data", {})
        netwifi_data["networkMode"] = "static"
        netwifi_data["ip"] = address
        netwifi_data["netmask"] = net_mask
        netwifi_data["gateway"] = gateway
        netwifi_data["dns"] = dns_server
        response = ws_api.send_request(
            self, "SET", "network/netwifi/config", netwifi_data
        )
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to set Wi-Fi static address: {error_msg}")

    @override
    def get_version_revision(self) -> str:
        return self.get_system_info()["fwRevision"]

    @override
    def set_periodic_restart(
        self, enable: bool, restart_period: int | None = None
    ) -> None:
        self.logger.debug(f"Setting periodic restart on device {self.host}")
        cfg_res = ws_api.send_request(self, "SUBSCRIBE", "system/config")
        cfg_data = cfg_res.get("data", {})
        cfg_data["periodRestartEnable"] = enable
        if restart_period is not None:
            cfg_data["periodRestartPeriod"] = restart_period
        ws_api.send_request(self, "SET", "system/config", cfg_data)

    @override
    def rename_device(self, device_name: str) -> None:
        self.logger.debug(f"Renaming device {self.host} to {device_name}")
        cfg_res = ws_api.send_request(self, "SUBSCRIBE", "system/config")
        cfg_data = cfg_res.get("data", {})
        cfg_data["devname"] = device_name
        ws_api.send_request(self, "SET", "system/config", cfg_data)

    @override
    def set_system_settings(
        self,
        device_name: str | None = None,
        port: int | None = None,
        periodic_restart: bool | None = None,
        restart_period: int | None = None,
    ) -> None:
        self.logger.debug(f"Setting system settings on device {self.host}")
        cfg_res = ws_api.send_request(self, "SUBSCRIBE", "system/config")
        cfg_data = cfg_res.get("data", {})
        if device_name is not None:
            cfg_data["devname"] = device_name
        if periodic_restart is not None:
            cfg_data["periodRestartEnable"] = periodic_restart
        if restart_period is not None:
            cfg_data["periodRestartPeriod"] = restart_period
        response = ws_api.send_request(self, "SET", "system/config", cfg_data)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to set system settings: {error_msg}")

    @override
    def locate(self) -> None:
        self.logger.debug(f"Locating device {self.host}")
        ws_api.send_request(self, "SET", "system/locate", {"locate": True})

    @override
    def clear_system_log(self) -> None:
        self.logger.debug(f"Clearing system log on device {self.host}")
        ws_api.send_request(self, "SET", "log/clear", {})

    @override
    def change_user_password(
        self, username: str, old_password: str, new_password: str
    ) -> None:
        self.logger.debug(
            f"Changing password for user {username} on device {self.host}"
        )
        user_cfg_res = ws_api.send_request(
            self, "SUBSCRIBE", f"users/name/{username}/config"
        )
        if user_cfg_res.get("status") == "failed" or "error" in user_cfg_res:
            error_msg = user_cfg_res.get("error", f"User {username} not found")
            raise CommunicationError(
                f"Failed to fetch user config for {username}: {error_msg}"
            )

        user_data = user_cfg_res["data"]
        public_key = self.ws_helo_data.get("publicKey", "")
        password_hash = ws_api.generate_password_hash(
            username, new_password, public_key
        )
        user_data["passwordHash"] = password_hash
        user_data["password"] = ""

        response = ws_api.send_request(
            self, "SET", f"users/name/{username}/config", user_data
        )
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(
                f"Failed to change password for user {username}: {error_msg}"
            )

    @override
    def change_password(self, new_password: str) -> None:
        self.change_user_password(self.username, "", new_password)

    @override
    def get_cloud_state(self) -> dict[str, Any]:
        self.logger.debug(f"Getting cloud state on device {self.host}")
        response = ws_api.send_request(self, "SUBSCRIBE", "protocols/cloud")
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to get cloud state: {error_msg}")
        return response["data"]

    @override
    def set_cloud_state(self, state: bool) -> None:
        self.logger.debug(f"Setting cloud state to {state} on device {self.host}")
        cloud_data = self.get_cloud_state()
        cloud_data["enabled"] = state
        response = ws_api.send_request(self, "SET", "protocols/cloud", cloud_data)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to set cloud state: {error_msg}")

    @override
    def register_to_cloud(self, token: str) -> None:
        self.logger.debug(
            f"Registering to cloud with token {token} on device {self.host}"
        )
        payload = {"action": "register", "token": token, "server": ""}
        response = ws_api.send_request(self, "SET", "protocols/cloud/cmd", payload)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(f"Failed to register to cloud: {error_msg}")

    @override
    def set_on_premise(self, url: str) -> None:
        self.logger.debug(
            f"Setting on-premise cloud server to {url} on device {self.host}"
        )
        payload = {"action": "setOnPremis", "token": "", "server": url}
        response = ws_api.send_request(self, "SET", "protocols/cloud/cmd", payload)
        if response.get("status") == "failed" or "error" in response:
            error_msg = response.get("error", "Unknown error occurred on device")
            raise CommunicationError(
                f"Failed to set on-premise cloud server: {error_msg}"
            )

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
