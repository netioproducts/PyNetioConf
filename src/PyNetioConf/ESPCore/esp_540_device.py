"""
Implementation specifics for ESP devices with the firmware 5.4.x.
"""

import atexit
import sys
from collections import deque

if sys.version_info >= (3, 12):
    from typing import Any, override
else:
    from typing import Any

    from typing_extensions import override

import logging
import threading

from websocket import WebSocket

from .. import NetioManager
from ..constants import (
    DEFAULT_KEEP_ALIVE_QUEUE_LEN,
    DEFAULT_REQUEST_QUEUE_LEN,
    OUTPUT_GROUP_COUNT,
    OUTPUT_POWER_UP_INTERVAL_MIN,
    OUTPUT_RESET_DELAY_MIN,
    OutputAction,
    OutputPowerUpState,
)
from ..exceptions import (
    CommunicationError,
    DeviceError,
    ElementNotFound,
    InvalidParameterValueError,
)
from ..experimental import experimental
from . import ws_api
from .esp_500_device import _check_milliseconds, _choice_value, _value_or_current
from .esp_520_device import ESP520Device


class ESP540Device(ESP520Device):
    """
    A class to control ESP devices with the firmware 5.4.x and newer.
    """

    # NBUS and the output groups came with 5.4.0
    _export_groups: tuple[str, ...] = (*ESP520Device._export_groups, "nbus", "outGroups")

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
        Creates the device object for a NETIO device running firmware 5.4.x and newer. This is normally not called
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
            If True, a background thread pings the device every 120 seconds to keep the WebSocket session open.
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
                newer, requests use GET instead of SUBSCRIBE. Default (5, 4, 0).
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
        self.version = kwargs.get("device_version", (5, 4, 0))
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
        # Last answer of get_firmware_updates_list() and its perf_counter() time, reused for FIRMWARE_LIST_CACHE_TIME
        self._firmware_list: list[dict[str, Any]] | None = None
        self._firmware_list_time = 0.0

        # Init from base ESP Device
        self.ws: WebSocket | None = kwargs.get("ws_connection", None)
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
        self._ws_helo_data = kwargs.get("ws_helo_data") or ws_api.send_request(self, "HELO")

    @override
    def get_output_states(self) -> list[tuple[int, bool]]:
        # outputs/state came with firmware 5.4.0, older 5.x firmware has the states only in outputs/measure
        ws_type = "SUBSCRIBE"
        ws_topic = "outputs/state"

        self.logger.debug(f"Fetching output states from device {self.host}")
        items = ws_api.send_request(self, ws_type, ws_topic)["data"]["items"]
        return [(int(item["id"]), item["state"] == "on") for item in items]

    @override
    def _set_output_config(
        self,
        output_id: int,
        default_state: str | None = None,
        is_schedule_active: bool | None = None,
        output_name: str | None = None,
        power_up_interval: int | None = None,
        reset_delay: int | None = None,
        schedule_id: int | None = None,
        group_id: int | None = None,
    ) -> None:
        # 5.4.0 has groupId in the output config. A SET without it keeps the group, but the table lists it as required
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
            "groupId": _value_or_current(group_id, current, "groupId"),
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    def _check_group_index(self, group_id: int, minimum: int = 1) -> None:
        """The device stores any groupId (F12), so the range is checked here."""
        if isinstance(group_id, bool) or not isinstance(group_id, int) or not minimum <= group_id <= OUTPUT_GROUP_COUNT:
            raise InvalidParameterValueError(
                f"The group id has to be a whole number from {minimum} to {OUTPUT_GROUP_COUNT}, not {group_id!r}"
            )

    @override
    @experimental("output groups", "5.4.0")
    def get_output_groups(self) -> list[dict[str, Any]]:
        ws_type = "SUBSCRIBE"
        ws_topic = "groups/list"

        self.logger.debug(f"Fetching the output groups on device {self.host}")
        return ws_api.send_request(self, ws_type, ws_topic)["data"]["items"]

    @override
    @experimental("output groups", "5.4.0")
    def get_output_group(self, group_id: int) -> dict[str, Any]:
        self._check_group_index(group_id)
        ws_type = "SUBSCRIBE"
        ws_topic = f"groups/id/{group_id}/config"

        self.logger.debug(f"Fetching output group {group_id} on device {self.host}")
        response = ws_api.send_request(self, ws_type, ws_topic)
        return self._require_config(response.get("data", {}), f"output group {group_id}")

    @override
    @experimental("output groups", "5.4.0")
    def set_output_group(
        self,
        group_id: int,
        name: str | None = None,
        power_up_state: OutputPowerUpState | None = None,
        reset_delay: int | None = None,
        outputs: dict[int, int] | None = None,
    ) -> None:
        self._check_group_index(group_id)
        if name is not None and not isinstance(name, str):
            raise InvalidParameterValueError(f"The group name has to be a string, not {name!r}")
        state = _choice_value(OutputPowerUpState, power_up_state, "power-up state")
        if reset_delay is not None:
            _check_milliseconds(reset_delay, OUTPUT_RESET_DELAY_MIN, "reset delay")
        members: list[dict[str, int]] = []
        if outputs is not None:
            if not isinstance(outputs, dict):
                raise InvalidParameterValueError(
                    f"The outputs have to be a dict of output id to power-up interval, not {outputs!r}"
                )
            for output_id, interval in outputs.items():
                if isinstance(output_id, bool) or not isinstance(output_id, int):
                    raise InvalidParameterValueError(f"An output id has to be a whole number, not {output_id!r}")
                self._check_socket_index(output_id)
                _check_milliseconds(interval, OUTPUT_POWER_UP_INTERVAL_MIN, f"power-up interval of output {output_id}")
                members.append({"id": output_id, "powerUpInterval": interval})
        ws_type = "SET"
        ws_topic = f"groups/id/{group_id}/config"

        self.logger.debug(f"Setting output group {group_id} on device {self.host}")
        current = self.get_output_group(group_id)
        # An empty list keeps the members: the list only puts outputs in
        ws_data = {
            "name": _value_or_current(name, current, "name"),
            "powerUpState": _value_or_current(state, current, "powerUpState"),
            "resetDelay": _value_or_current(reset_delay, current, "resetDelay"),
            "outputs": members,
        }
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    @experimental("output groups", "5.4.0")
    def set_output_group_id(self, output_id: int, group_id: int) -> None:
        self._check_group_index(group_id, minimum=0)
        self._check_socket_index(output_id)
        self.logger.debug(f"Setting the group of output {output_id} to {group_id} on device {self.host}")
        self._set_output_config(output_id, group_id=group_id)

    @override
    @experimental("output groups", "5.4.0")
    def set_output_group_action(self, group_id: int, action: OutputAction) -> None:
        try:
            request = OutputAction(action)
        except ValueError:
            raise InvalidParameterValueError(
                f"Unknown output action {action!r}, the possible ones are {[a.value for a in OutputAction]}"
            ) from None
        if request is OutputAction.TOGGLE:
            raise InvalidParameterValueError("An output group takes on, off, son and soff, not toggle")
        self._check_group_index(group_id)
        ws_type = "SET"
        ws_topic = f"groups/id/{group_id}/ctrl"
        ws_data = {"request": request.value}

        self.logger.debug(f"Setting output group {group_id} to {request.name} on device {self.host}")
        _ = ws_api.send_request(self, ws_type, ws_topic, ws_data)

    @override
    @experimental("output groups", "5.4.0")
    def switch_output_group(self, group_id: int, state: bool) -> None:
        self.logger.debug(f"Switching output group {group_id} {'on' if state else 'off'} on device {self.host}")
        self.set_output_group_action(group_id, OutputAction.ON if state else OutputAction.OFF)
