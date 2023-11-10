"""
Module containing the base class for all NETIO devices. This module is not meant to be used directly, but rather
extended by the device-specific classes.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple


class NETIODevice(ABC):
    """
    A base class for ESPDevices based on the 3.x.x firmware.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str, keep_alive: bool = True):
        self.host = host
        self.username = username
        self.password = password
        self.sn_number = sn_number
        self.hostname = hostname
        self.session_id = ""
        self.supported_features = dict()
        self.output_count = 0
        self.user_permissions = list()
        self._keep_alive_flag = keep_alive
        self._ka_thread = None

    # region Session
    @abstractmethod
    def login(self, username: str, password: str, logout=False) -> str:
        """
        Login to the device, generating a session ID to be used for the requests across the session.

        Parameters
        ----------
        username: str
        password: str
        logout: bool
            Log out of the current session before logging into a new one.
        Returns
        -------
            Session ID of the new session.
        """
        pass

    @abstractmethod
    def logout(self) -> None:
        """
        Log out of the device, clearing the session.

        Returns
        -------
            The response of the request.
        """
        pass

    @abstractmethod
    def ping(self) -> bool:
        """
        Ping the device to see if it is accessible.

        Returns
        -------
            True if the device is online, False if not.
        """
        pass

    # endregion

    # region Device Information
    @abstractmethod
    def get_version(self) -> str:
        """
        Get the version information of the device.

        Returns
        -------
            The device version as string.
        """
        pass

    @abstractmethod
    def get_version_detailed(self) -> Dict:
        """
        Get the detailed version information of the device.

        Returns
        -------
            JSON of the recived data.
        """
        pass

    @abstractmethod
    def get_features(self) -> Dict:
        """
        Get the features of the device.

        Returns
        -------
            JSON of the recived data.
        """
        pass

    # endregion

    # region Sockets
    # region Socket Control
    @abstractmethod
    def set_output(self, output_id: int, state: bool) -> None:
        """
        Set a state of an output given its ID and the desired state.

        Parameters
        ----------
        output_id: int
            The number of the output.
        state: bool
            The state you want to put the device into.
        Returns
        -------
            Dict object of the api request's response.
        """
        pass

    @abstractmethod
    def set_outputs_unified(self, state: bool) -> None:
        """
        Set all outputs to the same state.

        Parameters
        ----------
        state: bool
            The state you want to put the device into.
        """
        pass

    @abstractmethod
    def reset_output(self, output_id: int) -> None:
        """
        Reset the output given its ID.

        Parameters
        ----------
        output_id: int
            The number of the output.
        """
        pass

    @abstractmethod
    def rename_output(self, output_id: int, output_name: str) -> None:
        """
        Rename the output given its ID.

        Parameters
        ----------
        output_id: int
            The number of the output.
        output_name
            The desired name of the output.

        Returns
        -------
            None
        """
        pass

    # endregion

    # region Socket Information

    @abstractmethod
    def get_output_data(self, output_id: int) -> Dict:
        """
        Produces all relevant information about the output given its ID.

        Parameters
        ----------
        output_id: int
            The id of the output.

        Returns
        -------
            Dict of all the available output information and their current values.
        """
        pass

    @abstractmethod
    def get_outputs_data(self) -> List[Dict]:
        """
        Produces a list of all the outputs on the device and relevant information about it. The information might
        differ between device types.

        Returns
        -------
        List containing a list of all the outputs on the device and any relevant information the device keeps
        about these outputs.
        """
        pass

    @abstractmethod
    def get_socket_states(self) -> List[Tuple[int, bool]]:
        """
        Generates a list of the socket states currently on the device.

        Returns
        -------
            A list containing the on/off values for all the available socket ids.
        """
        pass

    # endregion

    # endregion

    # region Device Configuration

    # region Network
    @abstractmethod
    def get_wifi_settings(self) -> Dict:
        """
        Produces all relevant information about the Wi-Fi settings on the device.

        Returns
        -------
            Dict of all the available Wi-Fi settings and their current values.
        """
        pass

    @abstractmethod
    def set_wifi_settings(self, ssid: str, password: str) -> None:
        """
        Connects the device to a specified Wi-Fi network provided the SSID and password.

        Parameters
        ----------
        ssid: str
            The name of the network to connect to, this can be a hidden network.
        password: str
            Password of the target network.

        Returns
        -------
            True if the device accepted the new settings, False if the network could not be set.
        """
        pass

    @abstractmethod
    def set_wifi_static_address(self, address: str, net_mask: str, gateway: str, dns_server: str,
                                hostname: str) -> None:
        """
        Sets the device static address on the currently connected Wi-Fi network. All the arguments are required.

        Parameters
        ----------
        address: str
            The IPv4 address the device should use.
        net_mask: str
            The network mask for the subnet.
        gateway: str
            Gateway IPv4 for the device.
        dns_server: str
            The DNS server the device will use for domain resolution.
        hostname: str
            The hostname of the device. The device will appear on the network under this name.

        Returns
        -------
            Bool signalizing the success of the device settings.
        """
        pass

    # endregion

    @abstractmethod
    def import_config(self, file, **kwargs) -> None:
        """
        Import configuration to the device from a JSON file.
        Parameters
        ----------
        file
            Python file object of the JSON configuration.
        Returns
        -------
            The response generated by the api request.
        """
        pass

    @abstractmethod
    def export_config(self, save_file: str = None) -> Dict:
        """
        Export the device's configuration to a JSON file.

        Parameters
        ----------
        save_file: str
            The path to the file you want to save the configuration to. Default is None, which returns the JSON,
             but doesn't save a file.
        Returns
        -------
            The JSON configuration.
        """
        pass

    @abstractmethod
    def update_firmware(self, file) -> None:
        """
        Upload a firmware file to the device and begin the upgrade. Note this locks the device out for a time.

        Parameters
        ----------
        file
            Python file object of the firmware package.

        Returns
        -------
            The response generated by the post request.
        """
        pass

    @abstractmethod
    def rename_device(self, device_name: str) -> None:
        """
            Rename the device to the provided name, requried to be administrator to change settings.

        Parameters
        ----------
        device_name
            The desired name of the device

        Returns
        -------
            None
        """
        pass

    # endregion

    # region User Management
    @abstractmethod
    def get_current_user(self) -> Dict:
        """
        Gets the logged-in user that corresponds to the session id used in this request.

        Returns
        -------
        JSON containing the current user information.
        """
        pass

    @abstractmethod
    def change_password(self, new_password: str) -> None:
        """
        Change the password of the currently logged-in user. Requires you to be logged in as administrator.

        Parameters
        ----------
        new_password: str
            The desired password for the account.
        """
        pass

    @abstractmethod
    def change_user_password(self, username: str, old_password: str, new_password: str) -> None:
        """
        Change the administrator password. Requires you to be logged in as administrator.

        Parameters
        ----------
        username: str
            The username of the account you want to change the password for.
        old_password: str
            The current password of the account.
        new_password: str
            The desired password for the account.
        """
        pass

    # endregion

    # region Protocols

    @abstractmethod
    def get_active_protocols(self) -> List[int]:
        """
        Produces a list of the currently active protocols.

        Returns
        -------
            List of IDs of the currently active protocols. Can be None if there is no enabled protocol.
        """
        pass

    @abstractmethod
    def get_supported_protocols(self) -> List[int]:
        """
        Produces a list of all the protocols supported by the current device, also contains relevant information about
        those protocols.

        Returns
        -------
        List containing a list of all the protocols available on the device and relevant information, such as the
        enabled protocols and setting details.
        """
        pass

    # region NETIO Cloud

    @abstractmethod
    def set_cloud_state(self, state: bool) -> None:
        """
        Set the cloud state of the device.

        Parameters
        ----------
        state: bool
            The desired state of the cloud connection.

        Returns
        -------
            None
        """
        pass

    @abstractmethod
    def get_cloud_state(self) -> Dict:
        """
        Get the cloud state of the device.

        Returns
        -------
            Dict object of the api request's response.
        """
        pass

    @abstractmethod
    def set_on_premise(self, url: str) -> None:
        """
        Set the on-premise server of the device.

        Parameters
        ----------
        url: str
            The URL of the on-premise server.

        Returns
        -------
            None
        """
        pass

    @abstractmethod
    def register_to_cloud(self, token: str) -> None:
        """
        Register the device to the cloud using the provided token.

        Parameters
        ----------
        token: str
            The token for the device.

        Returns
        -------
            None
        """
        pass

    # endregion

    # region URLAPI
    @abstractmethod
    def set_urlapi_state(self, protocol_enabled: bool, write_enable: bool, write_auth: Tuple[str, str]) -> None:
        """
        Configures the modbus M2M protocol with the provided parameters.

        Parameters
        ----------
        protocol_enabled: bool
            Toggle of the enabled protocol. Not that if any other protocols are enabled, this one is to take precedence.
        write_enable: bool
            Enable Write portion of the API. URLAPI doesn't have a read-only part such as JSON or XML.
        write_auth: tuple[str, str]
            A tuple of the authentication pair for the Write portion of the API.
        """
        pass

    # endregion

    # region Modbus
    @abstractmethod
    def get_modbus_state(self) -> Dict:
        """
        Get the Modbus M2M API state of the device.

        Returns
        -------
            JSON object containing the Modbus M2M API information.
        """
        pass

    @abstractmethod
    def set_modbus_state(self, protocol_enabled: bool, port: int,
                         ip_filter_enabled: bool, ip_from: str, ip_to: str) -> None:
        """
        Configures the modbus M2M protocol with the provided parameters.

        Parameters
        ----------
        protocol_enabled: bool
            Toggle of the enabled protocol. Not that if any other protocols are enabled, this one is to take precedence.
        port: int
            The port the protocol will be listening on.
        ip_filter_enabled: bool
            Toggle of the IP filter. If enabled, only the IP addresses in the range will be able to access the protocol.
        ip_from: str
            The start of the IP range.
        ip_to: str
            The end of the IP range.
        """
        pass

    # endregion

    # region JSON
    @abstractmethod
    def get_json_api_state(self) -> Dict:
        """
        Get the JSON M2M API state of the device.

        Returns
        -------
            JSON object containing the JSON API information.
        """
        pass

    @abstractmethod
    def set_json_api_state(self, protocol_enabled: bool, read_enable: bool, write_enable: bool,
                           read_auth: Tuple[str, str], write_auth: Tuple[str, str]) -> None:
        """
        Function for configuring the JSON M2M on the device. All parameters are required and will be set to the ones
        provided.

        Parameters
        ----------
        protocol_enabled: bool
            Toggle of the enabled protocol. Not that if any other protocols are enabled, this one is to take precedence.
        read_enable: bool
            Enable Read-Only portion of the API. This uses a different authentication from the Read-Write permissions.
        write_enable: bool
            Enable Read-Write portion of the API. Can be enabled regardless of Read-Only.
        read_auth: tuple[str, str]
            A tuple of the authentication pair for the Read-Only portion of the API. This does not have to be same as
            the write_auth.
        write_auth: tuple[str, str]
            A tuple of the authentication pair for the Read-Write portion of the API. This does not have to be same as
            the read_auth.

        Returns
        -------
            Bool representing the success of the operation.
        """
        pass

    @abstractmethod
    def get_json(self, json_auth: Tuple[str, str]) -> Dict:
        """
        Gets the JSON information from the device. This contains full information about the device.

        Parameters
        ----------
        json_auth: tuple
            Authentication pair tuple

        Returns
        -------
            JSON containing the device information and related values.
        """
        pass

    # endregion

    # region XML
    @abstractmethod
    def set_xml_api_state(self, protocol_enabled: bool, read_enable: bool, write_enable: bool,
                          read_auth: Tuple[str, str], write_auth: Tuple[str, str]) -> None:
        """
        Function for configuring the XML M2M on the device. All parameters are required and will be set to the ones
        provided.

        Parameters
        ----------
        protocol_enabled: bool
            Toggle of the enabled protocol. Not that if any other protocols are enabled, this one is to take precedence.
        read_enable: bool
            Enable Read-Only portion of the API. This uses a different authentication from the Read-Write permissions.
        write_enable: bool
            Enable Read-Write portion of the API. Can be enabled regardless of Read-Only.
        read_auth: tuple[str, str]
            A tuple of the authentication pair for the Read-Only portion of the API. This does not have to be same as
            the write_auth.
        write_auth: tuple[str, str]
            A tuple of the authentication pair for the Read-Write portion of the API. This does not have to be same as
            the read_auth.

        Returns
        -------
            Bool representing the success of the operation.
        """
        pass

    @abstractmethod
    def get_xml(self, xml_auth: Tuple[str, str]):
        """
        Gets the XML information from the device. This contains full information about the device.

        Parameters
        ----------
        xml_auth: tuple
            Authentication pair tuple

        Returns
        -------
            XML as ElementTree containing the device information and related values.
        """
        pass

    # endregion

    # endregion

    # def __del__(self):
    # This method has caused insane pain.
