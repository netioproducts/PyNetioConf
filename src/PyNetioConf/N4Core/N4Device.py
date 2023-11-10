"""
Implementation details for NETIO4 devices with Linux based firmware.
"""
import atexit
import logging
import re
import threading
from typing import Dict, List, Tuple

from . import n4_api
from .. import NETIODevice
from ..exceptions import *


class N4Device(NETIODevice):

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str,
                 keep_alive: bool = True) -> None:
        super().__init__(host, username, password, sn_number, hostname, keep_alive)
        self.logger = logging.getLogger(__name__)
        self.session_id = self.login(username, password)
        self.output_count = len(self.get_socket_states())  # TODO: Handle better during implementation
        if keep_alive:
            self._ka_thread = threading.Timer(30, self._keep_alive)
            self._ka_thread.daemon = True
            self._ka_thread.start()
        atexit.register(self._cleanup)

    def login(self, username: str, password: str, logout=False) -> str:
        """
        Log in to the device, returns the session ID.

        Parameters
        ----------
        username: str
            Username that will be used to log in to the device. (Note many actions require administrator privileges)
        password: str
            Password for the user.
        logout: bool
            If True, the device will be logged out after the login.

        Returns
        -------
            Session ID string.
        """
        # Create the root element
        if logout:
            self.logout()

        xml_login_request = (f'<request sessionID=""><session action="login">'
                             f'<credentials>'
                             f'<username>{username}</username><password>{password}</password>'
                             f'</credentials>'
                             f'<usedAddress>{self.host}</usedAddress></session></request>')

        response = n4_api.send_request(self, xml_login_request)
        self.session_id = response.find('./sessionID').text
        self.logger.debug(f"Logged in to device {self.host} with session ID {self.session_id}")
        return self.session_id

    def logout(self) -> None:
        """
        Log out of the device.
        """
        if self.session_id == '':
            self.logger.debug(f"Host {self.host} is already logged out. Skipping logout request.")
            return
        xml_logout_request = f'<request sessionID="{self.session_id}"><session action="logout"></session></request>'
        n4_api.send_request(self, xml_logout_request)
        self.session_id = ""
        self.logger.debug(f"Logged out of device {self.host}")

    def _keep_alive(self) -> None:
        pass

    def ping(self) -> bool:
        pass

    # region Device Information
    def get_version(self) -> str:
        xml_get_version_request = (f'<request sessionID="{self.session_id}">'
                                   f'<system action="getVersion"></system></request>')
        response = n4_api.send_request(self, xml_get_version_request).find('./system/version').text
        self.logger.debug(f"Received device version: {response}")
        return response

    def get_version_detailed(self) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def get_features(self) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # region Sockets
    # region Socket Control
    def set_output(self, output_id: int, state: bool) -> None:
        self._check_socket_index(output_id)
        xml_output_set_request = (f'<request sessionID="{self.session_id}">'
                                  f'<device action="doAction" deviceName="system" actionName="SetOut">'
                                  f'<param name="output" type="integer">{output_id}</param>'
                                  f'<param name="value" type="integer">{int(state)}</param></device>'
                                  f'</request>')
        n4_api.send_request(self, xml_output_set_request)
        self.logger.debug(f"Setting output {output_id} on device {self.host} to {state}.")

    def set_outputs_unified(self, state: bool) -> None:
        for output in range(1, self.output_count + 1):
            self.set_output(output, state)

    def rename_output(self, output_id: int, output_name: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def reset_output(self, output_id: int) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # region Socket Information
    def get_output_data(self, output_id: int) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def get_outputs_data(self) -> List[Dict]:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def get_socket_states(self) -> List[Tuple[int, bool]]:
        xml_get_output_data_request = (f'<request sessionID="{self.session_id}">'
                                       f'<device action="get"><selector><name>system</name>'
                                       f'</selector><sections><digitalOutputs/><variables/></sections></device>'
                                       f'</request>')
        out_data_xml = n4_api.send_request(self, xml_get_output_data_request)
        out_var_data = out_data_xml.findall('.//var')
        value_list = list()
        for var in out_var_data:
            match = re.match(r'output(\d)_state', var.get('key'))
            if match:
                value_list.append((int(match.group(1)), True if var.text == "on" else False))
        return sorted(value_list, key=lambda x: x[0])

    # endregion

    # endregion

    # region Device Configuration
    # region Network
    def get_wifi_settings(self) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def set_wifi_settings(self, ssid: str, password: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def set_wifi_static_address(self, address: str, net_mask: str, gateway: str, dns_server: str,
                                hostname: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    def import_config(self, file, **kwargs) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def export_config(self, save_file: str = None) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def update_firmware(self, file) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def rename_device(self, device_name: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # region User Management
    def get_current_user(self) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def change_password(self, new_password: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def change_user_password(self, username: str, old_password: str, new_password: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # region Protocols
    def get_active_protocols(self) -> List[int]:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def get_supported_protocols(self) -> List[int]:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # region NETIO Cloud
    def set_cloud_state(self, state: bool) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def get_cloud_state(self) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def set_on_premise(self, url: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def register_to_cloud(self, token: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # region URLAPI
    def set_urlapi_state(self, protocol_enabled: bool, write_enable: bool, write_auth: Tuple[str, str]) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # region JSON
    def get_json_api_state(self) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def set_json_api_state(self, protocol_enabled: bool, read_enable: bool = None, write_enable: bool = None,
                           read_auth: Tuple[str, str] = None, write_auth: Tuple[str, str] = None) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def get_json(self, json_auth: Tuple[str, str]) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # region XML
    def set_xml_api_state(self, protocol_enabled: bool, read_enable: bool, write_enable: bool,
                          read_auth: Tuple[str, str], write_auth: Tuple[str, str]) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def get_xml(self, xml_auth: Tuple[str, str]):
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # region Modbus
    def get_modbus_state(self) -> Dict:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    def set_modbus_state(self, protocol_enabled: bool, port: int, ip_filter_enabled: bool, ip_from: str,
                         ip_to: str) -> None:
        raise DeviceNotYetSupported("This device is not yet supported, support coming in future versions.")

    # endregion

    # endregion

    # region Private Methods
    def _check_socket_index(self, output_id: int) -> None:
        if output_id < 1 or output_id > self.output_count:
            raise InvalidSocketIndex(f"You tried to access socket with id {output_id},"
                                     f" the device supports <1;{self.output_count}>.")

    def _cleanup(self) -> None:
        if self.session_id != '':
            self.logout()
        if self._ka_thread:
            self._ka_thread.cancel()

    # endregion
