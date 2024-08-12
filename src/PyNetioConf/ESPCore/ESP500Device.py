"""
Implementation specifics for ESP devices with the firmware 5.0.x.
"""
import json
import ssl
from typing import Dict, List, Tuple
from time import sleep

import websocket

from .ESP400Device import ESP400Device
from . import ws_api, esp_api


class ESP500Device(ESP400Device):
    """
    A class to control ESP devices with the firmware 5.0.x.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str,
                 keep_alive: bool = True, use_https: bool = False):
        self.use_https = use_https
        super().__init__(host, username, password, sn_number, hostname, keep_alive)
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

    def get_socket_states(self) -> List[Tuple[int, bool]]:
        socket_list = ws_api.send_request(self, "UNSUBSCRIBE", "outputs/measure")
        return [(socket["id"], socket["state"] == "on") for socket in socket_list["data"]["items"]]

    def get_measurement(self):
        return ws_api.send_request(self, "UNSUBSCRIBE", "outputs/measure")

    def upload_mqtt_client_key(self, cert: str) -> None:
        ws_api.send_request(self, "SET", "protocols/mqtt/clientkeyupload", {})
        response = esp_api.send_file(self, "/upload/ssl/mqtt_client_key.pem", cert)

    def upload_mqtt_client_certificate(self, key: str) -> None:
        ws_api.send_request(self, "SET", "protocols/mqtt/clientcertupload", {})
        response = esp_api.send_file(self, "/upload/ssl/mqtt_client_cert.pem", key)

    def upload_mqtt_ca_certificate(self, ca: str) -> None:
        ws_api.send_request(self, "SET", "protocols/mqtt/cacertupload", {})
        response = esp_api.send_file(self, "/upload/ssl/mqtt_root_ca.pem", ca)

    def get_mqttflex_state(self) -> dict:
        return ws_api.send_request(self, "UNSUBSCRIBE", "protocols/mqtt/config")['data']

    def set_mqttflex_state(self, state: bool, config: dict = None) -> None:
        if config is None:
            config = self.get_mqttflex_state()["config"]
        ws_api.send_request(self, "SET", "protocols/mqtt/config", {"enable": state, "config": json.dumps(config)})

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
        esp_api.send_request(self, "prepFwUpgrade")
        esp_api.send_file(self, "/upload/firmware", file)
        esp_api.send_request(self, "startUpgrade", close=True)
        self.logger.debug(
            f"Uploaded firmware {file.name}, device {self.host} might be unresponsive for a while."
        )
        sleep(10)
        _ = self.login(self.username, self.password)
        _ = self._login_new(self.username, self.password)
        if self._ka_thread:
            self._keep_alive()


