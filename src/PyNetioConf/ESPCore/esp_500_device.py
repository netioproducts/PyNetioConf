"""
Implementation specifics for ESP devices with the firmware 5.0.x.
"""
import json
import ssl
from time import sleep
from typing import Dict, List, Tuple

import websocket

from . import esp_api, ws_api
from .esp_400_device import ESP400Device
from .. import NetioManager
from ..exceptions import CommunicationError


class ESP500Device(ESP400Device):
    """
    A class to control ESP devices with the firmware 5.0.x.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str,
                 keep_alive: bool = True, netio_manager: NetioManager = None, use_https: bool = False):
        self.use_https = use_https
        super().__init__(host, username, password, sn_number, hostname, keep_alive, netio_manager)
        self.fw_version = self.get_version()
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        if self.use_https:
            self.ws = websocket.create_connection(f"wss://{host}/emweb", sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            self.ws = websocket.create_connection(f"ws://{host}/emweb")
        self.ws_req_id = 0
        self._login_new(username, password)

    def _login_new(self, username: str, password: str, logout=False) -> str:
        if self.use_https:
            self.ws = websocket.create_connection(f"wss://{self.host}/emweb", sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            self.ws = websocket.create_connection(f"ws://{self.host}/emweb")
        self.ws_req_id = 0
        hello_response = ws_api.send_request(self, "HELO")

        ws_api.login(self, hello_response["data"]["localTimestamp"],
                     hello_response["data"]["publicKey"], username, password)

    def set_output(self, output_id: int, state: bool) -> None:
        self._check_socket_index(output_id)
        ws_api.send_request(self, "SET", f"outputs/id/{output_id}/ctrl", {"request": "on" if state else "off"})
        self.logger.debug(f"Setting output {output_id} on device {self.host} to {state}.")

    def set_json_api_state(
            self,
            protocol_enabled: bool,
            read_enable: bool = None,
            write_enable: bool = None,
            read_auth: Tuple[str, str] = None,
            write_auth: Tuple[str, str] = None,
    ) -> None:
        old_protocol_data = self.get_json_api_state()

        protocol_data = {
            "enable":          protocol_enabled,
            "port":            80,
            "readOnlyEnable":  read_enable if read_enable is not None else old_protocol_data["read"]["enable"],
            "readUsername":    read_auth[0] if read_auth is not None else old_protocol_data["read"]["username"],
            "readPassword":    read_auth[1] if read_auth is not None else old_protocol_data["read"]["password"],
            "readWriteEnable": write_enable if write_enable is not None else old_protocol_data["write"]["enable"],
            "writeUsername":   write_auth[0] if write_auth is not None else old_protocol_data["write"]["username"],
            "writePassword":   write_auth[1] if write_auth is not None else old_protocol_data["write"]["password"],
        }

        ws_api.send_request(self, "SET", "protocols/json/config", protocol_data)

    def get_output_states(self) -> List[Tuple[int, bool]]:
        socket_list = ws_api.send_request(self, "UNSUBSCRIBE", "outputs/measure")
        return [(socket["id"], socket["state"] == "on") for socket in socket_list["data"]["items"]]

    def get_measurement(self):
        return ws_api.send_request(self, "UNSUBSCRIBE", "outputs/measure")

    def upload_mqtt_client_key(self, key: str) -> None:
        upload_path = ws_api.send_request(self, "SET", "protocols/mqtt/clientkeyupload", {})["data"]["uploadPath"]
        response = esp_api.send_file(self, upload_path, key)
        sleep(0.1)

    def upload_mqtt_client_certificate(self, cert: str) -> None:
        upload_path = ws_api.send_request(self, "SET", "protocols/mqtt/clientcertupload", {})["data"]["uploadPath"]
        response = esp_api.send_file(self, upload_path, cert)
        sleep(0.1)

    def upload_mqtt_ca_certificate(self, ca: str) -> None:
        upload_path = ws_api.send_request(self, "SET", "protocols/mqtt/cacertupload", {})["data"]["uploadPath"]
        response = esp_api.send_file(self, upload_path, ca)
        sleep(0.1)

    def get_mqttflex_state(self) -> dict:
        return ws_api.send_request(self, "UNSUBSCRIBE", "protocols/mqtt/config")['data']

    def set_mqttflex_state(self, state: bool, config: dict = None) -> None:
        if config is None:
            config = self.get_mqttflex_state()["config"]
        ws_api.send_request(self, "SET", "protocols/mqtt/config", {"enable": state, "config": json.dumps(config)})
        sleep(1)

    def export_config(self, save_file: str = None) -> Dict:
        config = ws_api.send_request(self, "SET", "system/cfgexport", data={})
        if save_file:
            with open(save_file, 'w') as file:
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

        self._login_new(username, password)
        if self._ka_thread:
            self._keep_alive()

    def update_firmware(self, file) -> None:
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
            if wifi_settings["mode"] == "client" and wifi_settings["client"]["status"] == "Connected":
                pre_reconnect_wait = 50
                self.logger.debug(f"Increased wait time after fimrware update due to active Wi-Fi connection.")

        if esp_api.check_connectivity(self) > (pre_reconnect_wait / 10.0):
            pre_reconnect_wait = pre_reconnect_wait * 2
            self.logger.debug("Increased wait time after firmware update due to poor connection quality.")

        _ = esp_api.send_request(self, "prepFwUpgrade")
        _ = esp_api.send_file(self, "/upload/firmware", file)
        try:
            _ = esp_api.send_request(self, "startUpgrade", close=True)
        except CommunicationError:
            self.logger.warn(
                f"Device {self.host} couldn't verify firmware update process beginning, this should be harmless if the device connects, waiting for connection.")
        self.logger.debug(
            f"Uploaded firmware {file.name}, device {self.host} might be unresponsive for a while."
        )

        sleep(pre_reconnect_wait)

        self.logger.debug(f"Retrying connection to device {self.host} after updating firmware to {file.name}.")
        device_response_time = esp_api.check_connectivity(self)
        retry_limit = 3 if device_response_time == -1 else 0
        for _ in range(0, retry_limit):
            device_response_time = esp_api.check_connectivity(self)

        if device_response_time == -1:
            raise CommunicationError("Device couldn't establish connection after firmware update.")

        updated_instance = self.netio_manager.update_device(self)

        return updated_instance
