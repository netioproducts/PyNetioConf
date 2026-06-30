"""
Implementation specifics for ESP devices with the firmware 5.0.x.
"""

import atexit
import json
import os
import ssl
from time import sleep
from typing import IO, Any, AnyStr, Dict, List, Tuple, override

import websocket

from . import esp_api, ws_api
import logging
from .esp_400_device import ESP400Device
from .. import NetioManager
from ..exceptions import CommunicationError, ElementNotFound
from ..netio_device import NETIODevice
from websocket import WebSocket
import threading


class ESP500Device(
    ESP400Device 
    #NETIODevice
):  # TODO: Make sure we inherit from ESP400Device on release
    """
    A class to control ESP devices with the firmware 5.0.x.
    """

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

        # Init from base ESP Device
        self.ws: WebSocket | None = kwargs.get("ws_connection", None)
        self.logger = logging.getLogger(__name__)
        if kwargs.get("is_ws_auth", False):
            self.session_id = "TODO AUTH"
        else:
            self.session_id = self.login(username, password)
        #self.supported_features = self.get_features()
        #self.output_count: int = self.supported_features["outputCount"]
        #self.user_permissions = self.get_current_user()["privileges"]
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


    def login(self, username: str, password: str, logout: bool = False) -> str:
        if logout:
            self.ws = None  # Disables a connection if one was present, the device handles the logout automatically

        if self.ws is None:
            if self.use_https:
                self.ws = websocket.create_connection(f"wss://{self.host}/emweb", sslopt=self.ssl_options)  # pyright: ignore[reportUnknownMemberType]
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

    def logout(self) -> None:
        self.ws = None
        self.ws_req_id = 0

    def get_system_info(self) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = "system/info"
        self.logger.debug(f"Fetching system info on {self.host}")
        return ws_api.send_request(self, ws_type, ws_topic)

    def get_version_detailed(self) -> str:
        return self.get_system_info()["fwversion"]

    def get_version(self) -> str:
        return self.get_version_detailed().split("-")[0].strip()

    def get_output_data(self, output_id: int) -> dict[str, Any]:
        ws_type = "SUBSCRIBE"
        ws_topic = f"outputs/id/{output_id}/config"
        self.logger.debug(
            f"Fetching output configuration data for output id {output_id} on {self.host}"
        )
        return ws_api.send_request(self, ws_type, ws_topic)

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

    def delete_rule_by_name(self, name: str) -> None:
        # Check for rule existing, error out if it doesn't
        try:
            self.get_rule_by_name(name)
        except ElementNotFound:
            raise ElementNotFound(f"Rule {name} not found on device {self.host}")
        topic = "/rules/delete"
        ws_type = "SET"
        ws_data = {"name": name}
        self.logger.debug(f"Attempting to delete {name} on device {self.host}.")
        ws_api.send_request(self, ws_type, topic, ws_data)

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

    def set_json_api_state(
        self,
        protocol_enabled: bool,
        read_enable: bool | None = None,
        write_enable: bool | None = None,
        read_auth: Tuple[str, str] | None = None,
        write_auth: Tuple[str, str] | None = None,
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

    def get_urlapi_state(self) -> Dict[str, Any]:
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

    def get_output_states(self) -> List[Tuple[int, bool]]:
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
    def get_outputs_data(self) -> List[dict[int, dict[str, Any]]]:
        return ws_api.send_request(self, "SUBSCRIBE", "outputs/measure")["data"]["items"]

    @override
    def get_output_states(self) -> List[Tuple[int, bool]]:
        output_data = self.get_outputs_data()
        output_states = []
        for output in output_data:
            output_states.append((int(output["id"]), True if output["state"] == "on" else False))
        return output_states

    @override
    def get_output_state(self, output_id: int) -> bool:
        return self.get_output_states()[output_id - 1][1] #TODO: Polish

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

    def export_config(self, save_file: str = None) -> Dict:
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

    def update_firmware(
        self, file: str | bytes | os.PathLike[AnyStr] | IO[bytes]
    ) -> NETIODevice:
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
        #TODO: Make a proper ping like utility to not force new HTTP connection
        return True

    @override
    def get_system_log(self) -> list[dict[str, Any]]:
        ws_topic = "log/messages"
        ws_type = "SUBSCRIBE"
        ws_data = None
        self.logger.debug(f"Fetching system log messages from device {self.host}.")

        log_messages: list[dict[str, Any]] = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"]
        return log_messages


