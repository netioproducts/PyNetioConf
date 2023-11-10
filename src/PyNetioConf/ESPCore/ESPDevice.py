"""
The implementation of the NETIODevice class for ESP firmware based devices.
"""
import atexit
import json
import logging
import threading
from time import sleep
from typing import Dict, List, Tuple
from xml.etree import ElementTree as ET

import requests

from . import esp_api
from .. import NETIODevice
from ..exceptions import *


class ESPDevice(NETIODevice):
    """
    A base class for ESPDevices based on the 3.x.x firmware.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str,
                 keep_alive: bool) -> None:
        super().__init__(host, username, password, sn_number, hostname)
        self.logger = logging.getLogger(__name__)
        self.session_id = self.login(username, password)
        self.supported_features = self.get_features()
        self.output_count = self.supported_features['outputCount']
        self.user_permissions = self.get_current_user()['privileges']
        if keep_alive:
            self._ka_thread = threading.Timer(120, self._keep_alive)
            self._ka_thread.daemon = True
            self._ka_thread.start()
        atexit.register(self._cleanup)

    # region Session

    def login(self, username: str, password: str, logout=False) -> str:
        if logout:
            self.logger.debug("Logging out of the current session.")
            self.logout()

        response = esp_api.send_request(self, 'login', {'username': username, 'password': password}, timeout=10)
        if "data" in response.json():
            self.session_id = response.json()['data']['sessionId']
            self.logger.debug(f"Logged in to device {self.host} with session ID {self.session_id}")
        else:
            raise CommunicationError("Cannot login to device")
        return self.session_id

    def logout(self) -> None:
        if self.session_id == '':
            self.logger.debug(f"Device {self.host} is not logged in, ignoring logout request.")
            pass
        esp_api.send_request(self, 'logout')
        self.session_id = ''
        self.logger.debug(f"Logged out of device {self.host}")

    def ping(self) -> bool:
        response = esp_api.send_request(self, 'ping')
        status = "OK" if response.status_code == 200 else response.json()
        self.logger.debug(f"Pinging device {self.host}, response: {status}. This should be empty if ok.")
        if response.status_code == 200:
            return True
        else:
            return False

    def _keep_alive(self) -> None:
        self.logger.debug(f"Sending keep-alive to device {self.host}")
        self._ka_thread = threading.Timer(120, self._keep_alive)
        self._ka_thread.daemon = True
        self._ka_thread.start()
        self.ping()

    # endregion

    # region Device Information
    def get_version(self) -> str:
        response = esp_api.send_request(self, 'getVersion').json()['data']['version']
        response = response.split(" ")[0]
        self.logger.debug(f"Received device version: {response}")
        return response

    def get_version_detailed(self) -> Dict:
        response = esp_api.send_request(self, 'getVersion').json()['data']
        self.logger.debug(f"Received device version information: {response}")
        return response

    def get_features(self) -> Dict:
        response = esp_api.send_request(self, 'getFeatures').json()['data']
        self.logger.debug(f"Received device supported features: {response}")
        return response

    # endregion

    # region Sockets
    # region Socket Control
    def set_output(self, output_id: int, state: bool) -> None:
        if "can_control_outputs" not in self.user_permissions:
            raise PermissionError("You don't have permission to control outputs on this device.")
        self._check_socket_index(output_id)
        esp_api.send_request(self, 'setOutputState', {'output': output_id, 'value': state})
        self.logger.debug(f"Setting output {output_id} on device {self.host} to {state}.")

    def set_outputs_unified(self, state: bool) -> None:
        for output in range(1, self.output_count + 1):
            self.set_output(output, state)

    def rename_output(self, output_id: int, output_name: str) -> None:
        if "can_alter_outputs" not in self.user_permissions:
            raise PermissionError("You don't have permission to alter outputs on this device.")
        self._check_socket_index(output_id)
        response = esp_api.send_request(self, 'getOutputDetailList')
        json_data = response.json()['data'][output_id - 1]
        interrupt_delay = json_data['interruptDelay']
        default = json_data['default']
        pui = json_data['powerUpInterval']
        request_data = {"id":      output_id, "name": output_name, "resetDelay": interrupt_delay,
                        "default": default, "powerUpInterval": pui}
        self.logger.debug(f"Renaming output {output_id} to {output_name} on device {self.host}")
        esp_api.send_request(self, "setOutputBase", request_data)

    def reset_output(self, output_id: int) -> None:
        if "can_control_outputs" not in self.user_permissions:
            raise PermissionError("You don't have permission to control outputs on this device.")
        self._check_socket_index(output_id)
        esp_api.send_request(self, 'resetOutputState', {'output': output_id})
        self.logger.debug(f"Resetting output {output_id} on device {self.host}.")

    # endregion

    # region Socket Information
    def get_output_data(self, output_id: int) -> Dict:
        self._check_socket_index(output_id)
        output_info = self.get_outputs_data()[output_id - 1]
        return output_info

    def get_outputs_data(self) -> List[Dict]:
        output_data = esp_api.send_request(self, "getOutputDetailList").json()['data']
        self.logger.debug(f"Received output list form device {self.host}: {output_data}")
        return output_data

    def get_socket_states(self) -> List[Tuple[int, bool]]:
        outputs = self.get_outputs_data()
        value_list = [(output['outputId'], output['on']) for output in outputs]
        self.logger.debug(f"Received socket states from device {self.host}: {value_list}")
        return value_list

    # endregion

    # endregion

    # region Device Configuration
    # region Network
    def get_wifi_settings(self) -> Dict:
        if self.supported_features['wifi'] == "no":
            raise FeatureNotSupported("Wi-Fi is not supported on this device.")
        response = esp_api.send_request(self, "getWifiSettings")
        self.logger.debug(f"Wi-Fi settings on {self.host}: {response.json()['data']}")
        return response.json()['data']

    def set_wifi_settings(self, ssid: str, password: str) -> None:
        if self.supported_features['wifi'] == "no":
            raise FeatureNotSupported("Wi-Fi is not supported on this device.")
        request_data = {"ssid": ssid, "password": password}
        response = esp_api.send_request(self, "setWifiSettings", request_data)
        if response.status_code == 200:
            self.logger.debug(f"Successfully connected to {ssid} on device {self.host}")
        else:
            self.logger.warning(f"Unable to connect to {ssid} on device {self.host}")

    def set_wifi_static_address(self, address: str, net_mask: str, gateway: str, dns_server: str,
                                hostname: str) -> None:
        if self.supported_features['wifi'] == "no":
            raise FeatureNotSupported("Wi-Fi is not supported on this device.")
        mac_address = self.get_wifi_settings()['mac']
        request_data = {"networkMode": "manual",
                        "mac":         mac_address,
                        "status":      "Connected",
                        "ipAddress":   address,
                        "netMask":     net_mask,
                        "gateway":     gateway,
                        "dnsServer":   dns_server,
                        "hostname":    hostname}
        response = esp_api.send_request(self, 'setNetworkWifi', request_data)
        self.logger.debug(f"Setting static address on device {self.host} to {address}, full info: {request_data}")
        if response.status_code == 200:
            self.logger.debug(f"Successfully set static address on device {self.host}")
        else:
            self.logger.debug(f"Unable to set static address on device {self.host}")

    # endregion

    def import_config(self, file, **kwargs) -> None:
        if "can_alter_settings" not in self.user_permissions:
            raise PermissionError("You don't have permission to alter settings on this device.")
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
        data = json.load(file)
        encoded_data = json.dumps(data).encode('utf-8')
        esp_api.send_file(self, '/upload/config', encoded_data)
        self.logger.info(f"Imported configuration from {file.name}, device {self.host} is restarting...")
        sleep(kwargs.get("sleep_time", 15))
        username = kwargs.get("username", self.username)
        password = kwargs.get("password", self.password)

        self.login(username, password)
        if self._ka_thread:
            self._keep_alive()

    def export_config(self, save_file: str = None) -> Dict:
        response = esp_api.get_file(self, '/files/config.json')
        self.logger.debug(f"Exported configuration from device {self.host}, response: {response.json()}")
        if save_file is not None:
            with open(save_file, 'w') as f:
                f.write(response.text)
            self.logger.debug(f"Saved configuration to {save_file}")
        return response.json()

    def update_firmware(self, file) -> None:
        if "can_alter_settings" not in self.user_permissions:
            raise PermissionError("You don't have permission to alter settings on this device.")
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
        esp_api.send_request(self, 'prepFwUpgrade')
        esp_api.send_file(self, '/upload/firmware', file)
        esp_api.send_request(self, 'startUpgrade', close=True)
        self.logger.debug(f"Uploaded firmware {file.name}, device {self.host} might be unresponsive for a while.")
        if self._ka_thread:
            self._keep_alive()

    def rename_device(self, device_name: str) -> None:
        response = esp_api.send_request(self, "getSystemInfo")
        json_data = response.json()["data"]
        port = json_data["port"]
        pr_enable = json_data["periodicRestart"]["enable"]
        pr_period = json_data["periodicRestart"]["period"]
        request_data = {"deviceName":      device_name, "port": port,
                        "periodicRestart": {"enable": pr_enable, "period": pr_period}}
        self.logger.debug(f"Renaming device to {device_name} on url {self.host}")
        esp_api.send_request(self, "setSystemConfig", request_data)

    # endregion

    # region User Management
    def get_current_user(self) -> Dict:
        response = esp_api.send_request(self, 'getCurrentUser')
        self.logger.debug(f"Received current user information: {response.json()['data']} from device {self.host}")
        return response.json()['data']

    def change_password(self, new_password: str) -> None:
        self.change_user_password(new_password, self.username, self.password)

    def change_user_password(self, username: str, old_password: str, new_password: str, ) -> None:
        current_user = esp_api.send_request(self, 'getCurrentUser').json()
        if "can_alter_users" not in current_user['data']['privileges']:
            raise PermissionError("You don't have permission to manage users on this device.")
        request_data = {"username": username, "password": {"old": old_password, "new": new_password}}
        self.logger.debug(f"Changing password of user {username} to {new_password} on device {self.host}")
        esp_api.send_request(self, "setUser", request_data)
        if username == current_user['data']['username']:
            self.password = new_password

    # endregion

    # region Protocols
    def get_active_protocols(self) -> List[int]:
        response = esp_api.send_request(self, 'getActiveProtocols')
        self.logger.debug(f"Received active protocols: {response.json()['data']['protocols']} from device {self.host}")
        return response.json()['data']['protocols']

    def get_supported_protocols(self) -> List[int]:
        response = esp_api.send_request(self, "getSupportedProtocols")
        protocols = response.json()['data']['protocols']
        self.logger.debug(f"Received supported protocols: {protocols} from device {self.host}")
        return protocols

    # region NETIO Cloud
    def set_cloud_state(self, state: bool) -> None:
        string_state = "true" if state else "false"

        response = esp_api.send_request(self, 'setProtocol', {"id": 111, "action": "set", "enable": string_state})
        self.logger.debug(f"Setting cloud state of device {self.host} to {state}, response: {response.json()}")

    def get_cloud_state(self) -> Dict:
        response = esp_api.send_request(self, 'getProtocol', {"id": 111, "action": "getStatus"})
        self.logger.debug(f"Received cloud state: {response.json()['data']} from device {self.host}")
        return response.json()

    def set_on_premise(self, url: str) -> None:
        response = esp_api.send_request(self, "setProtocol", {"id": 111, "action": "setOnPremis", "server": url})
        self.logger.debug(f"Setting on-premise server of device {self.host} to {url}, response: {response.json()}")

    def register_to_cloud(self, token: str) -> None:
        response = esp_api.send_request(self, "setProtocol", {"id": 111, "action": "register", "token": token})
        self.logger.debug(f"Registering device {self.host} to cloud using token {token}, response: {response.json()}")

    # endregion

    # region URLAPI
    def set_urlapi_state(self, protocol_enabled: bool, write_enable: bool, write_password: str) -> None:
        json_data = {"enable": protocol_enabled,
                     "write":  {"enable": write_enable, "password": write_password},
                     "id":     105}
        response = esp_api.send_request(self, "setProtocol", data=json_data)
        self.logger.debug(
            f"Setting URL API state on device {self.host} to {protocol_enabled}, response: {response.json()}")

    # endregion

    # region Modbus

    def get_modbus_state(self) -> Dict:
        response = esp_api.send_request(self, 'getProtocol', {"id": 107, "action": "getStatus"})
        self.logger.debug(f"Received Modbus M2M state: {response.json()['data']} from device {self.host}")
        return response.json()['data']

    def set_modbus_state(self, protocol_enabled: bool, port: int = 502, ip_filter_enabled: bool = False,
                         ip_from: str = None, ip_to: str = None) -> None:
        modbus_data = self.get_modbus_state()
        json_data = {"enable": protocol_enabled,
                     "port":   port,
                     "id":     107}
        if ip_filter_enabled:
            if ip_from is None:
                ip_from = modbus_data['ipFilter']['ipFrom']
            if ip_to is None:
                ip_to = modbus_data['ipFilter']['ipTo']
            json_data['ipFilter'] = {"enable": ip_filter_enabled, "ipFrom": ip_from, "ipTo": ip_to}  # noqa
        else:
            json_data['ipFilter'] = {"enable": ip_filter_enabled}
        response = esp_api.send_request(self, "setProtocol", data=json_data)
        self.logger.debug(
            f"Setting Modbus M2M state on device {self.host} to {protocol_enabled}, response: {response.json()}")

    # endregion

    # region JSON
    def get_json_api_state(self) -> Dict:
        response = esp_api.send_request(self, 'getProtocol', {"id": 104, "action": "getStatus"})
        self.logger.debug(f"Received JSON API state: {response.json()['data']} from device {self.host}")
        return response.json()['data']

    def set_json_api_state(self, protocol_enabled: bool, read_enable: bool = None, write_enable: bool = None,
                           read_auth: Tuple[str, str] = None, write_auth: Tuple[str, str] = None) -> None:
        # TODO: Make the parameters optional, so only a specific setting can be changed.
        current_config = self.get_json_api_state()

        if read_enable is None:
            read_enable = current_config['read']['enable']
        if write_enable is None:
            write_enable = current_config['write']['enable']
        if read_auth is None:
            read_auth = (current_config['read']['username'], current_config['read']['password'])
        if write_auth is None:
            write_auth = (current_config['write']['username'], current_config['write']['password'])

        request_data = {"enable": protocol_enabled,
                        "read":   {"enable": read_enable, "username": read_auth[0], "password": read_auth[1]},
                        "write":  {"enable": write_enable, "username": write_auth[0], "password": write_auth[1]},
                        "id":     104}

        response = esp_api.send_request(self, "setProtocol", request_data)
        self.logger.debug(
            f"Setting JSON API state on device {self.host} to {protocol_enabled}, full info: {request_data}")
        if response.status_code == 200:
            ap = self.get_active_protocols()
            if 104 in ap:
                self.logger.debug(f"Successfully set JSON API state on device {self.host}")
            else:
                self.logger.debug(f"Unable to set JSON API state on device {self.host}")

    def get_json(self, json_auth: Tuple[str, str]) -> Dict:
        if 104 not in self.get_active_protocols():
            raise ProtocolNotEnabled("JSON API is not enabled on the device.")
        try:
            response = requests.get("http://" + self.host + f"/netio.json", auth=json_auth, timeout=10)
            if response.status_code == 200:
                self.logger.debug(f"Received JSON information from device {self.host}: {response.json()}")
                return response.json()
            else:
                raise requests.ConnectionError
        except (requests.ConnectionError, requests.ReadTimeout):
            self.logger.critical(f"Unable to reach host {self.host}")
            raise CommunicationError

    # endregion

    # region XML
    def set_xml_api_state(self, protocol_enabled: bool, read_enable: bool, write_enable: bool,
                          read_auth: Tuple[str, str], write_auth: Tuple[str, str]) -> None:
        # TODO: Make the parameters optional, so only a specific setting can be changed.
        request_data = {"enable": protocol_enabled,
                        "read":   {"enable": read_enable, "username": read_auth[0], "password": read_auth[1]},
                        "write":  {"enable": write_enable, "username": write_auth[0], "password": write_auth[1]},
                        "id":     103}

        response = esp_api.send_request(self, "setProtocol", request_data)
        self.logger.debug(
            f"Setting XML API state on device {self.host} to {protocol_enabled}, full info: {request_data}")
        if response.status_code == 200:
            ap = self.get_active_protocols()
            if 103 in ap:
                self.logger.debug(f"Successfully set XML API state on device {self.host}")
            else:
                self.logger.debug(f"Unable to set XML API state on device {self.host}")

    def get_xml(self, xml_auth: Tuple[str, str]):
        if 103 not in self.get_active_protocols():
            raise ProtocolNotEnabled("XML API is not enabled on the device.")
        try:
            response = requests.get("http://" + self.host + f"/netio.xml", auth=xml_auth, timeout=10)
            if response.status_code == 200:
                self.logger.debug(f"Received XML information from device {self.host}: {response.content}")
                return ET.fromstring(response.content)
            else:
                self.logger.critical(f"Unable to reach host {self.host}")
                raise CommunicationError
        except requests.ConnectionError:
            raise CommunicationError

    # endregion

    # endregion

    # region Private Functions
    def _check_socket_index(self, socket_index: int) -> None:
        if socket_index < 1 or socket_index > self.output_count:
            raise InvalidSocketIndex(f"You tried to access socket with id {socket_index},"
                                     f" the device supports <1;{self.output_count}>.")

    def _cleanup(self) -> None:
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
            self.logger.debug("Disabled keep-alive thread.")
        if self.session_id != '':
            self.logout()

    # endregion
