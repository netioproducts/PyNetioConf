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
from .. import NetioManager
from ..exceptions import *
from ..netio_device import NETIODevice


class ESPDevice(NETIODevice):
    """
    A base class for ESPDevices based on the 3.x.x firmware.
    """

    def __init__(
            self,
            host: str,
            username: str,
            password: str,
            sn_number: str,
            hostname: str,
            keep_alive: bool,
            netio_manager: NetioManager = None,
            use_https: bool = False,
    ) -> None:
        super().__init__(host, username, password, sn_number, hostname, keep_alive, netio_manager, use_https)
        self.logger = logging.getLogger(__name__)
        self.session_id = self.login(username, password)
        self.supported_features = self.get_features()
        self.output_count = self.supported_features["outputCount"]
        self.user_permissions = self.get_current_user()["privileges"]
        if keep_alive:
            self._ka_thread = threading.Timer(120, self._keep_alive)
            self._ka_thread.daemon = True
            self._ka_thread.start()
        atexit.register(self._cleanup)

    # region Session

    def login(self, username: str, password: str, logout: bool = False) -> str:
        if logout:
            self.logger.debug("Logging out of the current session.")
            self.logout()

        response = esp_api.send_request(
            self, "login", {"username": username, "password": password}, timeout=10
        )
        if "data" in response.json():
            self.session_id = response.json()["data"]["sessionId"]
            self.logger.debug(
                f"Logged in to device {self.host} with session ID {self.session_id}"
            )
        else:
            raise CommunicationError("Cannot login to device")
        return self.session_id

    def logout(self) -> None:
        if self.session_id == "":
            self.logger.debug(
                f"Device {self.host} is not logged in, ignoring logout request."
            )
            pass
        esp_api.send_request(self, "logout")
        self.session_id = ""
        self.logger.debug(f"Logged out of device {self.host}")

    def ping(self) -> bool:
        response = esp_api.send_request(self, "ping")
        status = "OK" if response.status_code == 200 else response.json()
        self.logger.debug(
            f"Pinging device {self.host}, response: {status}. This should be empty if ok."
        )
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
        response = esp_api.send_request(self, "getVersion").json()["data"]["version"]
        response = response.split(" ")[0]
        self.logger.debug(f"Received device version: {response}")
        return response

    def get_version_detailed(self) -> Dict:
        response = esp_api.send_request(self, "getVersion").json()["data"]
        self.logger.debug(f"Received device version information: {response}")
        return response

    def get_features(self) -> Dict:
        response = esp_api.send_request(self, "getFeatures").json()["data"]
        self.logger.debug(f"Received device supported features: {response}")
        return response

    # endregion

    # region Sockets
    # region Socket Control

    def set_output(self, output_id: int, state: bool) -> None:
        if "can_control_outputs" not in self.user_permissions:
            raise PermissionError(
                "You don't have permission to control outputs on this device."
            )
        self._check_socket_index(output_id)
        esp_api.send_request(
            self, "setOutputState", {"output": output_id, "value": state}
        )
        self.logger.debug(
            f"Setting output {output_id} on device {self.host} to {state}."
        )

    def set_outputs_unified(self, state: bool) -> None:
        for output in range(1, self.output_count + 1):
            self.set_output(output, state)
            sleep(0.1)

    def rename_output(self, output_id: int, output_name: str) -> None:
        if "can_alter_outputs" not in self.user_permissions:
            raise PermissionError(
                "You don't have permission to alter outputs on this device."
            )
        self._check_socket_index(output_id)
        response = esp_api.send_request(self, "getOutputDetailList")
        json_data = response.json()["data"][output_id - 1]
        interrupt_delay = json_data["interruptDelay"]
        default = json_data["default"]
        pui = json_data["powerUpInterval"]
        request_data = {
            "id":              output_id,
            "name":            output_name,
            "resetDelay":      interrupt_delay,
            "default":         default,
            "powerUpInterval": pui,
        }
        self.logger.debug(
            f"Renaming output {output_id} to {output_name} on device {self.host}"
        )
        esp_api.send_request(self, "setOutputBase", request_data)

    def reset_output(self, output_id: int) -> None:
        if "can_control_outputs" not in self.user_permissions:
            raise PermissionError(
                "You don't have permission to control outputs on this device."
            )
        self._check_socket_index(output_id)
        esp_api.send_request(self, "resetOutputState", {"output": output_id})
        self.logger.debug(f"Resetting output {output_id} on device {self.host}.")

    def set_output_schedule(self, output_id: int, schedule_id: int, enabled: bool = True) -> None:
        if "can_control_outputs" not in self.user_permissions:
            raise PermissionError(
                "You don't have permission to control outputs on this device."
            )
        self._check_socket_index(output_id)
        request_data = {"id": output_id, "scheduleId": f"{schedule_id}", "enable": enabled}
        esp_api.send_request(self, "setOutputSchedule", request_data)
        self.logger.debug(f"Setting schedule {schedule_id} on output {output_id}, netio_device: {self.host}.")

    def get_output_schedule(self, output_id: int) -> Dict:
        output_data = self.get_output_schedule(output_id)
        schedule = output_data["schedule"]
        return schedule

    def get_output_schedule_id(self, output_id: int) -> int:
        output_schedule = self.get_output_schedule(output_id)
        return output_schedule["id"]

    def set_output_schedule_state(self, output_id: int, schedule_enabled: bool) -> None:
        self.logger.debug(f"Setting schedule state {schedule_enabled} on output {output_id} to {schedule_enabled}, "
                          f"device {self.host}.")
        current_output_schedule = self.get_output_schedule_id(output_id)
        self.set_output_schedule(current_output_schedule, current_output_schedule, schedule_enabled)

    def set_output_schedule_by_name(self, output_id: int, schedule_name: str, enabled: bool = True) -> None:
        schedule_id = self.get_schedule_id(schedule_name)
        self.set_output_schedule(output_id, schedule_id, enabled)

    # endregion

    # region Socket Information

    def get_output_data(self, output_id: int) -> Dict:
        self._check_socket_index(output_id)
        output_info = self.get_outputs_data()[output_id - 1]
        return output_info

    def get_outputs_data(self) -> List[Dict]:
        output_data = esp_api.send_request(self, "getOutputDetailList").json()["data"]
        self.logger.debug(
            f"Received output list form device {self.host}: {output_data}"
        )
        return output_data

    def get_output_states(self) -> List[Tuple[int, bool]]:
        outputs = self.get_outputs_data()
        value_list = [(output["outputId"], output["on"]) for output in outputs]
        self.logger.debug(
            f"Received socket states from device {self.host}: {value_list}"
        )
        return value_list

    # endregion

    # endregion

    # region Device Configuration
    # region Network

    def get_wifi_settings(self) -> Dict:
        if self.supported_features["wifi"] == "no":
            raise FeatureNotSupported("Wi-Fi is not supported on this device.")
        response = esp_api.send_request(self, "getWifiSettings")
        self.logger.debug(f"Wi-Fi settings on {self.host}: {response.json()['data']}")
        return response.json()["data"]

    def set_wifi_settings(self, ssid: str, password: str) -> None:
        if self.supported_features["wifi"] == "no":
            raise FeatureNotSupported("Wi-Fi is not supported on this device.")
        request_data = {"ssid": ssid, "password": password}
        response = esp_api.send_request(self, "setWifiSettings", request_data)
        if response.status_code == 200:
            self.logger.debug(f"Successfully connected to {ssid} on device {self.host}")
        else:
            self.logger.warning(f"Unable to connect to {ssid} on device {self.host}")

    def set_wifi_static_address(
            self, address: str, net_mask: str, gateway: str, dns_server: str, hostname: str
    ) -> None:
        if self.supported_features["wifi"] == "no":
            raise FeatureNotSupported("Wi-Fi is not supported on this device.")
        mac_address = self.get_wifi_settings()["mac"]
        request_data = {
            "networkMode": "manual",
            "mac":         mac_address,
            "status":      "Connected",
            "ipAddress":   address,
            "netMask":     net_mask,
            "gateway":     gateway,
            "dnsServer":   dns_server,
            "hostname":    hostname,
        }
        response = esp_api.send_request(self, "setNetworkWifi", request_data)
        self.logger.debug(
            f"Setting static address on device {self.host} to {address}, full info: {request_data}"
        )
        if response.status_code == 200:
            self.logger.debug(f"Successfully set static address on device {self.host}")
        else:
            self.logger.debug(f"Unable to set static address on device {self.host}")

    # endregion

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
        esp_api.send_file(self, "/upload/config", encoded_data)
        self.logger.info(
            f"Imported configuration from {file.name}, device {self.host} is restarting..."
        )
        sleep(kwargs.get("sleep_time", 15))
        username = kwargs.get("username", self.username)
        password = kwargs.get("password", self.password)

        self.login(username, password)
        if self._ka_thread:
            self._keep_alive()

    def export_config(self, save_file: str = None) -> Dict:
        response = esp_api.get_file(self, "/files/config.json")
        self.logger.debug(
            f"Exported configuration from device {self.host}, response: {response.json()}"
        )
        if save_file is not None:
            with open(save_file, "w") as f:
                f.write(response.text)
            self.logger.debug(f"Saved configuration to {save_file}")
        return response.json()

    def update_firmware(self, file) -> NETIODevice:
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

        if esp_api.check_connectivity(self) > (pre_reconnect_wait / 10.0):
            pre_reconnect_wait = pre_reconnect_wait * 2

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

        device_response_time = esp_api.check_connectivity(self)
        retry_limit = 3 if device_response_time == -1 else 0
        for _ in range(0, retry_limit):
            device_response_time = esp_api.check_connectivity(self)

        if device_response_time == -1:
            raise CommunicationError("Device couldn't establish connection after firmware update.")
        updated_instance = self.netio_manager.update_device(self)

        return updated_instance

    def get_system_info(self) -> Dict:
        action = "getSystemInfo"
        self.logger.debug(f"Getting system info for device {self.host}")
        response = esp_api.send_request(self, action)
        return response.json()["data"]

    def get_uptime(self) -> int:
        system_info = self.get_system_info()
        self.logger.debug(f"Uptime for device {self.host}")
        return system_info["uptime"]

    def reset_power_consumption_counters(self) -> None:
        action = "resetOutputConsumption"
        self.logger.debug(f"Resetting power consumption counters for device {self.host}")
        esp_api.send_request(self, action)

    def set_system_settings(self, device_name: str = None, port: int = None, periodic_restart: bool = None,
                            restart_period: int = None) -> None:
        device_system_info = esp_api.send_request(self, "getSystemInfo")
        info_json_data = device_system_info.json()["data"]
        device_name = device_name if device_name is not None else info_json_data["deviceName"]
        port = port if port is not None else info_json_data["port"]
        pr_enable = periodic_restart if periodic_restart is not None else info_json_data["periodicRestart"]["enable"]
        pr_period = restart_period if restart_period is not None else info_json_data["periodicRestart"]["period"]
        request_data = {
            "deviceName":      device_name,
            "port":            port,
            "periodicRestart": {"enable": pr_enable, "period": pr_period},
        }
        self.logger.debug(f"Setting system settings on device {device_name}, host {self.host} to {request_data}")
        esp_api.send_request(self, "setSystemConfig", request_data)

    def rename_device(self, device_name: str) -> None:
        response = esp_api.send_request(self, "getSystemInfo")
        json_data = response.json()["data"]
        port = json_data["port"]
        pr_enable = json_data["periodicRestart"]["enable"]
        pr_period = json_data["periodicRestart"]["period"]
        request_data = {
            "deviceName":      device_name,
            "port":            port,
            "periodicRestart": {"enable": pr_enable, "period": pr_period},
        }
        self.logger.debug(f"Renaming device to {device_name} on url {self.host}")
        esp_api.send_request(self, "setSystemConfig", request_data)

    def set_periodic_restart(self, enable: bool, restart_period: int = None) -> None:
        self.set_system_settings(periodic_restart=enable, restart_period=restart_period)

    def locate(self) -> None:
        self.logger.debug(f"Blinking LED on device {self.host}")
        esp_api.send_request(self, "locate")

    # endregion

    # region User Management

    def get_current_user(self) -> Dict:
        response = esp_api.send_request(self, "getCurrentUser")
        self.logger.debug(
            f"Received current user information: {response.json()['data']} from device {self.host}"
        )
        return response.json()["data"]

    def get_user_privileges(self, username: str) -> List[str]:
        device_users = self.get_users()
        self.logger.debug(f"Checking for user privileges of user {username} on device {self.host}")
        for user in device_users:
            if user["username"] == username:
                return user["permissions"]
        self.logger.warning(f"Couldn't find the specified user in the user list.")

    def get_users(self) -> Dict:
        action = "getUserList"
        return esp_api.send_request(self, action).json()["data"]

    def change_password(self, new_password: str) -> None:
        self.change_user_password(new_password, self.username, self.password)

    def change_user_password(
            self,
            username: str,
            old_password: str,
            new_password: str,
    ) -> None:
        current_user = esp_api.send_request(self, "getCurrentUser").json()
        if "can_alter_users" not in current_user["data"]["privileges"]:
            raise PermissionError(
                "You don't have permission to manage users on this device."
            )
        request_data = {
            "username": username,
            "password": {"old": old_password, "new": new_password},
        }
        self.logger.debug(
            f"Changing password of user {username} to {new_password} on device {self.host}"
        )
        esp_api.send_request(self, "setUser", request_data)
        if username == current_user["data"]["username"]:
            self.password = new_password

    def create_user(self, username: str, password: str, privileges: List[str] = None) -> None:
        if "can_alter_users" not in self.user_permissions:
            raise PermissionError("You don't have permission to manage users on this device.")
        possible_priviledges = (
            "can_login", "can_alter_users", "can_alter_settings", "can_use_tunnels", "can_browse_logs",
            "can_alter_outputs",
            "can_control_outputs", "can_view_settings", "can_alter_rules")
        if privileges is None:
            privileges = ["can_login"]
        for privilege in privileges:
            if privilege not in possible_priviledges:
                raise ValueError(f"List of priviledges contains an invalid value: {privileges}")
        action = "addUser"
        request_data = {"username": username, "password": password, "permissions": privileges}
        self.logger.debug(f"Creating user {username} on device {self.host}")
        esp_api.send_request(self, action, request_data)

    def remove_user(self, username: str) -> None:
        requst_data = {"username": username}
        action = "deleteUser"
        self.logger.debug(f"Removing user {username} on device {self.host}")
        esp_api.send_request(self, action, requst_data)

        # endregion

    # region Protocols

    def get_active_protocols(self) -> List[int]:
        response = esp_api.send_request(self, "getActiveProtocols")
        self.logger.debug(
            f"Received active protocols: {response.json()['data']['protocols']} from device {self.host}"
        )
        return response.json()["data"]["protocols"]

    def get_supported_protocols(self) -> List[int]:
        response = esp_api.send_request(self, "getSupportedProtocols")
        protocols = response.json()["data"]["protocols"]
        self.logger.debug(
            f"Received supported protocols: {protocols} from device {self.host}"
        )
        return protocols

    # region NETIO Cloud

    def set_cloud_state(self, state: bool) -> None:
        string_state = "true" if state else "false"

        response = esp_api.send_request(
            self, "setProtocol", {"id": 111, "action": "set", "enable": string_state}
        )
        self.logger.debug(
            f"Setting cloud state of device {self.host} to {state}, response: {response.json()}"
        )

    def get_cloud_state(self) -> Dict:
        response = esp_api.send_request(
            self, "getProtocol", {"id": 111, "action": "getStatus"}
        )
        self.logger.debug(
            f"Received cloud state: {response.json()['data']} from device {self.host}"
        )
        return response.json()

    def set_on_premise(self, url: str) -> None:
        response = esp_api.send_request(
            self, "setProtocol", {"id": 111, "action": "setOnPremis", "server": url}
        )
        self.logger.debug(
            f"Setting on-premise server of device {self.host} to {url}, response: {response.json()}"
        )

    def register_to_cloud(self, token: str) -> None:
        response = esp_api.send_request(
            self, "setProtocol", {"id": 111, "action": "register", "token": token}
        )
        self.logger.debug(
            f"Registering device {self.host} to cloud using token {token}, response: {response.json()}"
        )

    # endregion

    # region URLAPI

    def set_urlapi_state(
            self, protocol_enabled: bool, write_enable: bool, write_password: str
    ) -> None:
        json_data = {
            "enable": protocol_enabled,
            "write":  {"enable": write_enable, "password": write_password},
            "id":     105,
        }
        response = esp_api.send_request(self, "setProtocol", data=json_data)
        self.logger.debug(
            f"Setting URL API state on device {self.host} to {protocol_enabled}, response: {response.json()}"
        )

    # endregion

    # region Modbus

    def get_modbus_state(self) -> Dict:
        response = esp_api.send_request(
            self, "getProtocol", {"id": 107, "action": "getStatus"}
        )
        self.logger.debug(
            f"Received Modbus M2M state: {response.json()['data']} from device {self.host}"
        )
        return response.json()["data"]

    def set_modbus_state(
            self,
            protocol_enabled: bool,
            port: int = 502,
            ip_filter_enabled: bool = False,
            ip_from: str = None,
            ip_to: str = None,
    ) -> None:
        modbus_data = self.get_modbus_state()
        json_data = {"enable": protocol_enabled, "port": port, "id": 107}
        if ip_filter_enabled:
            if ip_from is None:
                ip_from = modbus_data["ipFilter"]["ipFrom"]
            if ip_to is None:
                ip_to = modbus_data["ipFilter"]["ipTo"]
            json_data["ipFilter"] = {
                "enable": ip_filter_enabled,
                "ipFrom": ip_from,
                "ipTo":   ip_to,
            }  # noqa
        else:
            json_data["ipFilter"] = {"enable": ip_filter_enabled}
        response = esp_api.send_request(self, "setProtocol", data=json_data)
        self.logger.debug(
            f"Setting Modbus M2M state on device {self.host} to {protocol_enabled}, response: {response.json()}"
        )

    # endregion

    # region JSON

    def get_json_api_state(self) -> Dict:
        response = esp_api.send_request(
            self, "getProtocol", {"id": 104, "action": "getStatus"}
        )
        self.logger.debug(
            f"Received JSON API state: {response.json()['data']} from device {self.host}"
        )
        return response.json()["data"]

    def set_json_api_state(
            self,
            protocol_enabled: bool,
            read_enable: bool = None,
            write_enable: bool = None,
            read_auth: Tuple[str, str] = None,
            write_auth: Tuple[str, str] = None,
    ) -> None:
        # TODO: Make the parameters optional, so only a specific setting can be changed.
        current_config = self.get_json_api_state()

        if read_enable is None:
            read_enable = current_config["read"]["enable"]
        if write_enable is None:
            write_enable = current_config["write"]["enable"]
        if read_auth is None:
            read_auth = (
                current_config["read"]["username"],
                current_config["read"]["password"],
            )
        if write_auth is None:
            write_auth = (
                current_config["write"]["username"],
                current_config["write"]["password"],
            )

        request_data = {
            "enable": protocol_enabled,
            "read":   {
                "enable":   read_enable,
                "username": read_auth[0],
                "password": read_auth[1],
            },
            "write":  {
                "enable":   write_enable,
                "username": write_auth[0],
                "password": write_auth[1],
            },
            "id":     104,
        }

        response = esp_api.send_request(self, "setProtocol", request_data)
        self.logger.debug(
            f"Setting JSON API state on device {self.host} to {protocol_enabled}, full info: {request_data}"
        )
        if response.status_code == 200:
            ap = self.get_active_protocols()
            if (protocol_enabled and 104 in ap) or (not protocol_enabled and 104 not in ap):
                self.logger.debug(
                    f"Successfully set JSON API state on device {self.host}"
                )
            else:
                self.logger.debug(f"Unable to set JSON API state on device {self.host}")

    def get_json(self, json_auth: Tuple[str, str]) -> Dict:
        if 104 not in self.get_active_protocols():
            raise ProtocolNotEnabled("JSON API is not enabled on the device.")
        try:
            response = requests.get(
                "http://" + self.host + f"/netio.json", auth=json_auth, timeout=10
            )
            if response.status_code == 200:
                self.logger.debug(
                    f"Received JSON information from device {self.host}: {response.json()}"
                )
                return response.json()
            else:
                raise requests.ConnectionError
        except (requests.ConnectionError, requests.ReadTimeout):
            self.logger.critical(f"Unable to reach host {self.host}")
            raise CommunicationError

    # endregion

    def get_telnet_api_state(self) -> Dict:
        action = "getProtocol"
        response = esp_api.send_request(
            self, action, {"id": 106, "action": "getStatus"}
        )
        self.logger.debug(
            f"Received telnet API state: {response.json()['data']} from device {self.host}"
        )
        return response.json()["data"]

    def set_telnet_api_state(self, protocol_enabled: bool, port: int = None, read_enabled: bool = None, read_auth:
    Tuple[str, str] = None, write_enabled: bool = None, write_auth: Tuple[str, str] = None) -> None:
        action = "setProtocol"
        current_state = self.get_telnet_api_state()
        request_data = {"enable": protocol_enabled,
                        "port":   port if port else current_state["port"],
                        "read":   {"enable":   read_enabled if read_enabled else current_state["read"]["enable"],
                                   "username": read_auth[0] if read_auth else current_state["read"]["username"],
                                   "password": read_auth[1] if read_auth else current_state["read"]["password"], },
                        "write":  {"enable":   write_enabled if write_enabled else current_state["write"]["enable"],
                                   "username": write_auth[0] if write_auth else current_state["write"]["username"],
                                   "password": write_auth[1] if write_auth else current_state["write"]["password"], },
                        "id":     106}
        self.logger.debug(f"Setting telnet API state on device {self.host} to new settings: {request_data}")
        response = esp_api.send_request(self, action, request_data)
        if response.status_code == 200:
            ap = self.get_active_protocols()
            if (protocol_enabled and 106 in ap) or (not protocol_enabled and 106 not in ap):
                self.logger.debug(
                    f"Successfully set new telnet state on device {self.host}"
                )
            else:
                self.logger.debug(f"Unable to set telnet state on device {self.host}, check debug log.")

    def get_netio_push_api_state(self) -> Dict:
        action = "getProtocol"
        response = esp_api.send_request(
            self, action, {"id": 109, "action": "getStatus"}
        )
        self.logger.debug(
            f"Received Netio Push API state: {response.json()['data']} from device {self.host}"
        )
        return response.json()["data"]

    def set_netio_push_api_state(self, protocol_enabled: bool, url: str = None, push_protocol: str = None,
                                 delta: int = None, period: int = None) -> None:
        action = "setProtocol"
        current_state = self.get_netio_push_api_state()
        request_data = {"enable":       protocol_enabled,
                        "url":          url if url else current_state["url"],
                        "pushProtocol": push_protocol if push_protocol else current_state["pushProtocol"],
                        "delta":        delta if delta else current_state["delta"],
                        "period":       period if period else current_state["period"],
                        "value":        "current",
                        "id":           109}
        self.logger.debug(f"Setting Netio Push API state on device {self.host} to settings: {request_data}")
        response = esp_api.send_request(self, action, request_data)
        if response.status_code == 200:
            ap = self.get_active_protocols()
            if (protocol_enabled and 109 in ap) or (not protocol_enabled and 109 not in ap):
                self.logger.debug(f"Successfully set new Netio Push API state on device {self.host}")
            else:
                self.logger.debug(f"Unable to set the Netio Push API state on device {self.host}, check debug log.")

    def netio_push_api_push_now(self) -> None:
        action = "pushNow"
        ap = self.get_active_protocols()
        if 109 not in ap:
            self.logger.warning(f"Tried to push on device with Push protocol disabled: {self.host}")
            raise ProtocolNotEnabled(f"Netio Push API is not enabled on the device. Current protocols: {ap}")
        self.logger.debug(f"Pushing Netio Push API now on device {self.host}")
        esp_api.send_request(self, action)

    def get_snmp_api_state(self) -> Dict:
        action = "getProtocol"
        response = esp_api.send_request(self, action, {"id": 110, "action": "getStatus"})
        self.logger.debug(f"Received SNMP API state: {response.json()['data']} from device {self.host}")
        return response.json()["data"]

    def _set_snmp_api_state(self, protocol_enabled: bool, version: str, location: str = None,
                            community_read: str = None, community_write: str = None, security_name: str = None,
                            security_level: str = None, auth_protocol: str = None, auth_key: str = None,
                            priv_protocol: str = None, priv_key: str = None) -> None:
        action = "setProtocol"
        current_state = self.get_snmp_api_state()
        if version == "v1,2c":
            request_data = {"enable":         protocol_enabled,
                            "id":             110,
                            "version":        "v1-2",
                            "location":       location if location else current_state["location"],
                            "communityRead":  community_read if community_read else current_state["communityRead"],
                            "communityWrite": community_write if community_write else current_state["communityWrite"]}
            _ = esp_api.send_request(self, action, request_data)
        elif version == "v3":
            request_data = {"enable":         protocol_enabled,
                            "id":             110,
                            "version":        "v3",
                            "location":       location if location else current_state["location"],
                            "communityRead":  community_read if community_read else current_state["communityRead"],
                            "communityWrite": community_write if community_write else current_state["communityWrite"]}
            security_level = security_level if security_level else current_state["snmpV3Users"][0]["securityLevel"]
            user_object = {
                "username":      security_name if security_name else current_state["snmpV3Users"][0]["username"],
                "accessLevel":   "rw",
                "securityLevel": security_level,
            }
            if security_level == "authNoPriv" or security_level == "authPriv":
                print(current_state["snmpV3Users"])
                user_object["authAlgo"] = auth_protocol if auth_protocol else current_state["snmpV3Users"][0][
                    "authAlgo"]
                user_object["authKey"] = auth_key if auth_key else current_state["snmpV3Users"][0]["authKey"]
            if security_level == "authPriv":
                user_object["encryptAlgo"] = priv_protocol if priv_protocol else current_state["snmpV3Users"][0][
                    "encryptAlgo"]
                user_object["encryptKey"] = priv_key if priv_key else current_state["snmpV3Users"][0]["encryptKey"]
            request_data["snmpV3Users"] = [user_object]
            _ = esp_api.send_request(self, action, request_data)
        else:
            raise InvalidParameterValueError

    def set_snmp_v1_2_api_state(self, protocol_enabled: bool, location: str = None, community_read: str = None,
                                community_write: str = None) -> None:
        self.logger.debug(f"Setting SNMP v1,2c API state on device {self.host}")
        if not protocol_enabled:
            self.logger.debug(f"The protocol is being disabled, the device will restart.")
        self._set_snmp_api_state(protocol_enabled, "v1,2c", location, community_read, community_write)

    def set_snmp_v3_api_state(self, protocol_enabled: bool, location: str = None, security_name: str = None,
                              security_level: str = None, auth_protocol: str = None, auth_key: str = None,
                              priv_protocol: str = None, priv_key: str = None) -> None:
        self.logger.debug(f"Setting SNMP v3 API state on device {self.host}")
        if not protocol_enabled:
            self.logger.debug(f"The protocol is being disabled, the device will restart.")
        self._set_snmp_api_state(protocol_enabled, "v3", location, None, None, security_name, security_level,
                                 auth_protocol, auth_key, priv_protocol, priv_key)

    # region XML

    def set_xml_api_state(
            self,
            protocol_enabled: bool,
            read_enable: bool,
            write_enable: bool,
            read_auth: Tuple[str, str],
            write_auth: Tuple[str, str],
    ) -> None:
        # TODO: Make the parameters optional, so only a specific setting can be changed.
        request_data = {
            "enable": protocol_enabled,
            "read":   {
                "enable":   read_enable,
                "username": read_auth[0],
                "password": read_auth[1],
            },
            "write":  {
                "enable":   write_enable,
                "username": write_auth[0],
                "password": write_auth[1],
            },
            "id":     103,
        }

        response = esp_api.send_request(self, "setProtocol", request_data)
        self.logger.debug(
            f"Setting XML API state on device {self.host} to {protocol_enabled}, full info: {request_data}"
        )
        if response.status_code == 200:
            ap = self.get_active_protocols()
            if 103 in ap:
                self.logger.debug(
                    f"Successfully set XML API state on device {self.host}"
                )
            else:
                self.logger.debug(f"Unable to set XML API state on device {self.host}")

    def get_xml(self, xml_auth: Tuple[str, str]) -> ET.Element:
        if 103 not in self.get_active_protocols():
            raise ProtocolNotEnabled("XML API is not enabled on the device.")
        try:
            response = requests.get(
                "http://" + self.host + f"/netio.xml", auth=xml_auth, timeout=10
            )
            if response.status_code == 200:
                self.logger.debug(
                    f"Received XML information from device {self.host}: {response.content}"
                )
                return ET.fromstring(response.content)
            else:
                self.logger.critical(f"Unable to reach host {self.host}")
                raise CommunicationError
        except requests.ConnectionError:
            raise CommunicationError

    # endregion

    # endregion

    def get_rules(self) -> List[Dict]:
        action = "getRules"
        self.logger.debug(f"Getting a rule list from device {self.host}")
        response = esp_api.send_request(self, action, {})
        rule_list = response.json()["data"]
        return rule_list

    def get_enabled_rules(self) -> List[Dict]:
        rule_list = self.get_rules()
        enabled_rules = []
        self.logger.debug(f"Filtering for enabled rules from device {self.host}")
        for rule in rule_list:
            if rule["enabled"]:
                enabled_rules.append(rule)
        return enabled_rules

    def get_disabled_rules(self) -> List[Dict]:
        rule_list = self.get_rules()
        disabled_rules = []
        self.logger.debug(f"Filtering for disabled rules from device {self.host}")
        for rule in rule_list:
            if not rule["enabled"]:
                disabled_rules.append(rule)
        return disabled_rules

    def get_rule_by_name(self, rule_name: str) -> Dict:
        rule_list = self.get_rules()
        self.logger.debug(f"Filtering for rule {rule_name} from device {self.host}")
        for rule in rule_list:
            if rule["name"] == rule_name:
                return rule
        self.logger.warning(f"Unable to find rule {rule_name} on device {self.host}")
        raise ElementNotFound

    def get_watchdogs(self) -> List[Dict]:
        action = "getWatchdogs"
        self.logger.debug(f"Getting a watchdog list from device {self.host}")
        response = esp_api.send_request(self, action, {})
        watchdog_list = response.json()["data"]
        return watchdog_list

    def get_enabled_watchdogs(self) -> List[Dict]:
        watchdogs = self.get_watchdogs()
        enabled_watchdogs = []
        self.logger.debug(f"Filtering for enabled watchdogs from device {self.host}")
        for watchdog in watchdogs:
            if watchdog["enabled"]:
                enabled_watchdogs.append(watchdog)
        return enabled_watchdogs

    def get_disabled_watchdogs(self) -> List[Dict]:
        watchdogs = self.get_watchdogs()
        disabled_watchdogs = []
        self.logger.debug(f"Filtering for disabled watchdogs from device {self.host}")
        for watchdog in watchdogs:
            if not watchdog["enabled"]:
                disabled_watchdogs.append(watchdog)
        return disabled_watchdogs

    def get_watchdog_by_name(self, watchdog_name: str) -> Dict:
        watchdogs = self.get_watchdogs()
        self.logger.debug(f"Filtering for watchdog {watchdog_name} on device {self.host}")
        for watchdog in watchdogs:
            if watchdog["name"] == watchdog_name:
                return watchdog
        self.logger.warning(f"Unable to find watchdog {watchdog_name} on device {self.host}")
        raise ElementNotFound

    def get_schedules(self) -> List[Dict]:
        action = "getScheduleList"
        self.logger.debug(f"Getting a schedule list from device {self.host}")
        response = esp_api.send_request(self, action, {})
        schedule_list = response.json()["data"]
        return schedule_list

    def get_schedule_by_name(self, schedule_name: str) -> Dict:
        scheduels = self.get_schedules()
        self.logger.debug(f"Filtering for schedule {schedule_name} on  device {self.host}")
        for schedule in scheduels:
            if schedule["name"] == schedule_name:
                return schedule
        self.logger.warning(f"Unable to find schedule {schedule_name} on device {self.host}")
        raise ElementNotFound

    def get_schedule_id(self, schedule_name: str) -> int:
        schedule = self.get_schedule_by_name(schedule_name)
        return schedule["id"]

    def get_schedule_names(self) -> List[str]:
        schedules = self.get_schedules()
        schedule_names = []
        self.logger.debug(f"Filtering for schedule names on device {self.host}")
        for schedule in schedules:
            schedule_names.append(schedule["name"])
        return schedule_names

    def get_active_schedules(self) -> List[Dict]:
        schedules = self.get_schedules()
        active_schedules = []
        self.logger.debug(f"Filtering for active schedules on device {self.host}")
        for schedule in schedules:
            if schedule["active"]:
                active_schedules.append(schedule)
        return active_schedules

    def delete_schedule(self, schedule_id: id) -> None:
        action = "deleteSchedule"
        self.logger.debug(f"Deleting schedule {schedule_id} from device {self.host}")
        try:
            esp_api.send_request(self, action, {"id": schedule_id})
        except CommunicationError as e:
            if "Invalid parameter" in str(e):
                raise ElementNotFound

    def delete_schedule_by_name(self, schedule_name: str) -> None:
        schedule_id = self.get_schedule_id(schedule_name)
        self.delete_schedule(schedule_id)

    def get_system_log(self) -> List[Dict]:
        action = "loadSystemLog"
        self.logger.debug(f"Getting system log from device {self.host}")
        response = esp_api.send_request(self, action, {})
        return response.json()["data"]

    def clear_system_log(self) -> None:
        action = "clearUserLog"
        self.logger.debug(f"Clearing system log from device {self.host}")
        _ = esp_api.send_request(self, action, {})

    def get_pabs(self) -> List[Dict]:
        action = "getPABList"
        self.logger.debug(f"Getting PABs from device {self.host}")
        response = esp_api.send_request(self, action, {})
        pab_list = response.json()["data"]
        return pab_list

    def get_enabled_pabs(self) -> List[Dict]:
        pab_list = self.get_pabs()
        enabled_pabs = []
        self.logger.debug(f"Filtering for enabled PABs from device {self.host}")
        for pab in pab_list:
            if pab["enabled"]:
                enabled_pabs.append(pab)
        return enabled_pabs

    def get_disabled_pabs(self) -> List[Dict]:
        pab_list = self.get_pabs()
        disabled_pabs = []
        self.logger.debug(f"Filtering for disabled PABs from device {self.host}")
        for pab in pab_list:
            if not pab["enabled"]:
                disabled_pabs.append(pab)
        return disabled_pabs

    def get_pab_by_name(self, pab_name: str) -> Dict:
        pabs = self.get_pabs()
        self.logger.debug(f"Filtering for PAB {pab_name} on device {self.host}")
        for pab in pabs:
            if pab["name"] == pab_name:
                return pab
        raise ElementNotFound

    def delete_pab_by_name(self, pab_name: str) -> None:
        action = "deletePAB"
        request_data = {"name": pab_name}
        self.logger.debug(f"Deleting PAB {pab_name} from device {self.host}")
        esp_api.send_request(self, action, request_data)

    # region Private Functions
    def _check_socket_index(self, socket_index: int) -> None:
        if socket_index < 1 or socket_index > self.output_count:
            raise InvalidSocketIndex(
                f"You tried to access socket with id {socket_index},"
                f" the device supports <1;{self.output_count}>."
            )

    def _cleanup(self) -> None:
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()
            self.logger.debug("Disabled keep-alive thread.")
        if self.session_id != "":
            self.logout()

    # endregion

    def get_mqttflex_state(self) -> None:
        raise FeatureNotSupported("MQTT with certificates is only supported on firmware 5.0.0 and newer.")

    def set_mqttflex_state(self, state: bool, config: dict | None = None) -> None:
        raise FeatureNotSupported("MQTT with certificates is only supported on firmware 5.0.0 and newer.")

    def upload_mqtt_ca_certificate(self) -> None:
        raise FeatureNotSupported("MQTT with certificates is only supported on firmware 5.0.0 and newer.")

    def upload_mqtt_client_certificate(self) -> None:
        raise FeatureNotSupported("MQTT with certificates is only supported on firmware 5.0.0 and newer.")

    def upload_mqtt_client_key(self) -> None:
        raise FeatureNotSupported("MQTT with certificates is only supported on firmware 5.0.0 and newer.")
