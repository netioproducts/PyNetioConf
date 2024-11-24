"""
Module containing the base class for all NETIO devices. This module is not meant to be used directly, but rather
extended by the device-specific classes.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple
from xml.etree.ElementTree import Element

from websocket import WebSocket

from . import NetioManager


class NETIODevice(ABC):
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
            keep_alive: bool = True,
            netio_manager: NetioManager = None,
            use_https: bool = False,
            **kwargs
    ):
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
        self.ws: Optional[WebSocket] = None
        self.ws_req_id = 0
        self.use_https = use_https

        # Keep an instace of NetioManager for updating device classes during
        # firmware updates.
        self.netio_manager = netio_manager

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

    @abstractmethod
    def set_output_schedule(self, output_id: int, schedule_id: int, enabled: bool = True) -> None:
        """
        Activate or deactivate a specific schedule on a given output provided the schedule's ID.

        Parameters
        ----------
        output_id: int
            The number of the output.
        schedule_id: int
            The ID of the schedule.
        enabled: bool
            Whether the schedule should be enabled.

        Returns
        -------
            None
        """
        pass

    @abstractmethod
    def get_output_schedule(self, output_id: int) -> Dict:
        """
        Gets the schedule id and its state based on the output ID.

        Parameters
        ----------
        output_id : int
            The number of the output.

        Returns
        -------
            The schedule id, and it's state in {"id": x, "on": True/False} format.
        """
        pass

    @abstractmethod
    def get_output_schedule_id(self, output_id: int) -> int:
        """
        Gets the ID of the schedule currently set on the output given its ID.

        Parameters
        ----------
        output_id : int
            The number of the output.

        Returns
        -------
            An integer representing the schedule ID.
        """
        pass

    @abstractmethod
    def set_output_schedule_state(self, output_id: int, schedule_enabled: bool) -> None:
        """
        Enables or disables the currently set schedule on an output.

        Parameters
        ----------
        output_id : int
            The number of the output.
        schedule_enabled : bool
            Whether the schedule should be enabled.

        Returns
        -------
        """
        pass

    @abstractmethod
    def set_output_schedule_by_name(self, output_id: int, schedule_name: str, enabled: bool = True) -> None:
        """
        Activate or deactivate a specific schedule on a given output provided the schedule's name. If the schedule
        with such name isn't available raises ElementNotFound.

        Parameters
        ----------
        output_id : int
            The number of the output.
        schedule_name : str
            The name of the schedule.
        enabled : bool
            Whether the schedule should be enabled.

        Returns
        -------
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
    def get_output_states(self) -> List[Tuple[int, bool]]:
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
    def set_wifi_static_address(
            self, address: str, net_mask: str, gateway: str, dns_server: str, hostname: str
    ) -> None:
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
    def update_firmware(self, file) -> "NETIODevice":
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

    @abstractmethod
    def set_system_settings(self, device_name: str = None, port: int = None, periodic_restart: bool = None,
                            restart_period: int = None) -> None:
        """
        Sets the system settings on device given the provided parameters.
        Parameters
        ----------
        device_name : str
            The desired name of the device.
        port : int
            The port on which the device communication will run.
        periodic_restart : bool
            Toggle for the periodic restart feature.
        restart_period : int
            The period at which the device will restart. Can be changed regardless of periodic restart being toggled
            on or off.

        Returns
        -------

        """
        pass

    @abstractmethod
    def get_system_info(self) -> Dict:
        """
        Gets the system info on the device.

        Returns
        -------
            System info on the device in JSON format.
        """
        pass

    @abstractmethod
    def get_uptime(self) -> int:
        """
        Gets the device's current uptime in seconds.

        Returns
        -------
            An integer representing the uptime in seconds.
        """
        pass

    @abstractmethod
    def reset_power_consumption_counters(self) -> None:
        """
        Resets the power consumption counters on the device for all metered outputs.

        Returns
        -------
        """
        pass

    @abstractmethod
    def set_periodic_restart(self, enable: bool, restart_period: int = None) -> None:
        """
        Sets the periodic restart feature toggle and optionally changes the restart period.
        Parameters
        ----------
        enable : bool
            Should the restart feature be enabled.
        restart_period : int
            Time in minutes for the periodic restart feature.

        Returns
        -------

        """
        pass

    @abstractmethod
    def locate(self) -> None:
        """
        Blinks the LED on the device for a period of time.
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
    def get_users(self) -> Dict:
        """
        Gets the users and their details.
        Returns
        -------
            A dictionary containing the user information and thir priviledges.
        """
        pass

    @abstractmethod
    def get_user_privileges(self, username: str) -> List[str]:
        """
        Gets a list of privileges for the specified user.

        Parameters
        ----------
        username : str
            The username of the user. Usernames can be found by get_current_user() or get_users().

        Returns
        -------
            A list of string priviledges associated with the specified user.
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
    def change_user_password(
            self, username: str, old_password: str, new_password: str
    ) -> None:
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

    @abstractmethod
    def create_user(self, username: str, password: str, privileges: List[str] = None) -> None:
        """
        Creates a new user on the device with the given parameters.

        Parameters
        ----------
        username : str
            The username of the account you want to create.
        password : str
            The password for the account.
        privileges : List[str]
            List of privileges required to create the account.
            An empty list means no privileges, the user can only observe. (or more precisely a log-in priviledge gets added automatically)
            Possible privileges include: ["can_login","can_alter_users","can_alter_settings","can_use_tunnels",
            "can_browse_logs","can_alter_outputs","can_control_outputs","can_view_settings","can_alter_rules"]
        """
        pass

    @abstractmethod
    def remove_user(self, username: str) -> None:
        """
        Removes the specified user, requires your account to have a privilege to edit users.

        Parameters
        ----------
        username : str
            The username of the account you want to remove.
        Returns
        -------

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
    def set_urlapi_state(
            self, protocol_enabled: bool, write_enable: bool, write_auth: Tuple[str, str]
    ) -> None:
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
    def set_modbus_state(
            self,
            protocol_enabled: bool,
            port: int,
            ip_filter_enabled: bool,
            ip_from: str,
            ip_to: str,
    ) -> None:
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

    # region MQTT

    @abstractmethod
    def upload_mqtt_client_key(self, key: str) -> None:
        """
        Upload a MQTT client private key to the device.

        Parameters
        ----------
        key: str
            The private key to upload to the device. 
        """
        pass

    @abstractmethod
    def upload_mqtt_client_certificate(self, cert: str) -> None:
        """
        Uploads the MQTT client certificate to the device.

        Parameters
        ----------
        cert: str
            The client certificate to upload to the device.
        """
        pass

    @abstractmethod
    def upload_mqtt_ca_certificate(self, ca: str) -> None:
        """
        Uploads the root CA certificate to the device.

        Parameters
        ----------
        ca: str
            The root CA certificate to upload.
        """
        pass

    @abstractmethod
    def get_mqttflex_state(self) -> Dict:
        """
        Gets the state of the MQTT Flex protocol currently set on the device.

        Returns
        -------
            JSON/dict object containing the current state of MQTT Flex and its configuration.
        """
        pass

    @abstractmethod
    def set_mqttflex_state(self, state: bool, config: dict = None) -> None:
        """
        Sets the state and if provided configuration of the MQTT Flex protocol.

        Enables or disables the protocol based on the state given. If a state is
        given, but not configuration is given, the method will only apply changes
        to the state and keep the configuration that is present on device.

        Parameters
        ----------
        state: bool
            A boolean to determine if the protocol should be enabled or disabled.
        config: dict
            A dict object containing the desired MQTT configuration to upload to the device.
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
    def set_json_api_state(
            self,
            protocol_enabled: bool,
            read_enable: bool,
            write_enable: bool,
            read_auth: Tuple[str, str],
            write_auth: Tuple[str, str],
    ) -> None:
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

    @abstractmethod
    def get_netio_push_api_state(self) -> Dict:
        """
        Gets the state and settings of the M2M Netio Push protocol currently set on the device.

        Returns
        -------

        """
        pass

    @abstractmethod
    def set_netio_push_api_state(self, protocol_enabled: bool, url: str = None, push_protocol: str = None,
                                 delta: int = None, period: int = None) -> None:
        """
        Sets the state and settings of the M2M Netio Push protocol currently set on the device.

        Parameters
        ----------
        protocol_enabled : bool
            Whether the protocol should be enabled or disabled.
        url : str
            On what URL should the protocol push its messages. If None, keeps the setting already set on the device.
        push_protocol : str
            Which format should the push protocol use. Can be either 'json' or 'xml'. If None, keeps the setting already set on the device.
        delta : int
            The current delta for auto push. If None, keeps the setting already set on the device.
        period : int
            Push period in seconds. If None, keeps the setting already set on the device.

        Returns
        -------

        """
        pass

    @abstractmethod
    def get_snmp_api_state(self) -> Dict:
        """
        Gets the state and settings of the M2M SNMP protocol currently set on the device.

        Returns
        -------

        """

    @abstractmethod
    def _set_snmp_api_state(self, protocol_enabled: bool, version: str, location: str = None,
                            community_read: str = None, community_write: str = None, security_name: str = None,
                            security_level: str = None, auth_protocol: str = None, auth_key: str = None,
                            priv_protocol: str = None, priv_key: str = None) -> None:
        # TODO: Finish SNMP before 0.1.0
        pass

    @abstractmethod
    def set_snmp_v1_2_api_state(self, protocol_enabled: bool, location: str = None, community_read: str = None,
                                community_write: str = None) -> None:
        """
        Sets the state and settings of the M2M SNMP v1,2c protocol currently set on the device. Enabling this,
        disables the v3 version of SNMP if it's active. Disabling SNMP requires a device restart.
        Parameters
        ----------
        protocol_enabled : bool
            Whether the protocol should be enabled or disabled. If disabling the protocol the device will restart.
        location : str
            The location of the SNMP v1,2c protocol to set on the device. If None, keeps the setting already set on the device.
        community_read : str
            The community read of the SNMP v1,2c protocol to set on the device. If None, keeps the setting already set on the device.
        community_write : str
            The community write of the SNMP v1,2c protocol to set on the device. If None, keeps the setting already set on the device.

        Returns
        -------

        """

    @abstractmethod
    def set_snmp_v3_api_state(self, protocol_enabled: bool, location: str = None, security_name: str = None,
                              security_level: str = None, auth_protocol: str = None, auth_key: str = None,
                              priv_protocol: str = None, priv_key: str = None) -> None:
        """
        Sets the state and settings of the M2M SNMP v3 protocol currently set on the device. Enabling this will
        disable the v1,2c version of the protocol if it's active. Disabling SNMP requires a device restart.
        Parameters
        ----------
        protocol_enabled : bool
            Whether the protocol should be enabled or disabled. If disabling the protocol, the device will restart.
        location : str
            The location of the SNMP v3 protocol, if None, keeps the setting already set on the device.
        security_name : str
            The security name of the SNMP v3 protocol, if None, keeps the setting already set on the device.
        security_level : str
            The security level of the SNMP v3, any of ["authPriv", "authNoPriv", "noAuthNoPriv"], if None,
            keeps the setting already set on the device.
        auth_protocol : str
            The authentication protocol of the SNMP v3, if None, keeps the setting already set on the device. If the
            security level is "noAuthNoPriv" this setting will not be set.
        auth_key : str
            The authentication key of the SNMP v3, if None, keeps the setting already set on the device. If the security
            level is "noAuthNoPriv" this setting will not be set.
        priv_protocol : str
            The private protocol of the SNMP v3, currently supports "AES" only, if None, keeps the setting already
            set on the device. If the security level is "noAuthNoPriv" or "authNoPriv" this setting will not be set.
        priv_key : str
            The private key of the SNMP v3, if None, keeps the setting already set on the device. If the security
            level is "noAuthNoPriv" or "authNoPriv" this setting will not be set.

        Returns
        -------
        """

    @abstractmethod
    def netio_push_api_push_now(self) -> None:
        """
        Manually use the push protocol if enabled.
        Returns
        -------

        """
        pass

    @abstractmethod
    def get_telnet_api_state(self) -> Dict:
        """
        Gets the state and settings of the telnet M2M protocol currently set on the device.

        Returns
        -------
            JSON object containing the current state of the telnet M2M protocol.
        """
        pass

    @abstractmethod
    def set_telnet_api_state(self, protocol_enabled: bool, port: int = None, read_enabled: bool = None, read_auth:
    Tuple[
        str, str] = None, write_enabled: bool = None, write_auth: Tuple[str, str] = None) -> None:
        """
        Sets the state and settings of the telnet M2M protocol currently set on the device.

        Parameters
        ----------
        protocol_enabled : bool
            Whether the protocol should be enabled or disabled.
        port: int
            The port on which the protocol will communicate. If None, keeps the settins already on device.
        read_enabled : bool
            Whether the read only portion of the protocol should be enabled or disabled. If None, keeps the settins
            already on device.
        read_auth : Tuple[str, str]
            Authentication pair tuple for read only in the format ("username", "password") If None, keeps the settins already on device.
        write_enabled: bool
            Whether the write only portion of the protocol should be enabled or disabled. If None, keeps the settins
            already on device.
        write_auth : Tuple[str, str]
            Authentication pair tuple for write only in the format ("username", "password") If None,
            keeps the settins already on device.

        Returns
        -------

        """
        pass

    # region XML
    @abstractmethod
    def set_xml_api_state(
            self,
            protocol_enabled: bool,
            read_enable: bool,
            write_enable: bool,
            read_auth: Tuple[str, str],
            write_auth: Tuple[str, str],
    ) -> None:
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
    def get_xml(self, xml_auth: Tuple[str, str]) -> Element:
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

    @abstractmethod
    def get_rules(self) -> List[Dict]:
        """
        Gets the list of all rules on the device and their configuration.

        Returns
        -------
            A list of all rules, enabled or disabled on the device in JSON format.
        """
        pass

    @abstractmethod
    def get_enabled_rules(self) -> List[Dict]:
        """
        Gets the list of all enabled rules on the device and their configuration.

        Returns
        -------
            A list of all enabled rules on the device in JSON formate.
        """
        pass

    @abstractmethod
    def get_disabled_rules(self) -> List[Dict]:
        """
        Gets the list of all disabled rules on the device and their configuration.

        Returns
        -------
            A list of all disabled rules on the device in JSON format.
        """
        pass

    @abstractmethod
    def get_rule_by_name(self, rule_name: str) -> Dict:
        """
        Gets a rule based on its name.

        Parameters
        ----------
        rule_name : str
            The name of the rule to fetch.

        Returns
        -------
            A JSON object containing the rule information.
        """
        pass

    @abstractmethod
    def get_watchdogs(self) -> List[Dict]:
        """
        Gets the list of all watchdogs, enabled or disabled on the device.

        Returns
        -------
            List of all watchdogs, enabled or disabled on the device in JSON format.
        """
        pass

    @abstractmethod
    def get_enabled_watchdogs(self) -> List[Dict]:
        """
        Gets all enabled watchdogs  on the device.

        Returns
        -------
            List of all enabled watchdogs on the device in JSON format.
        """
        pass

    @abstractmethod
    def get_disabled_watchdogs(self) -> List[Dict]:
        """
        Gets all disabled watchdogs on the device.

        Returns
        -------
            List of all disabled watchdogs on the device in JSON format.
        """
        pass

    @abstractmethod
    def get_watchdog_by_name(self, watchdog_name: str) -> Dict:
        """
        Gets a watchdog based on its name.

        Parameters
        ----------
        watchdog_name : str
            The name of the watchdog to fetch.

        Returns
        -------
            A JSON object containing the watchdog information.
        """

    @abstractmethod
    def get_schedules(self) -> List[Dict]:
        """
        Gets the list of all the schedules available on the device.

        Returns
        -------
            Returns a list of all schedules on the device in JSON format.
        """
        pass

    @abstractmethod
    def get_schedule_by_name(self, schedule_name: str) -> Dict:
        """
        Gets a schedule based on its name. Raises ElementNotFound if the schedule isn't found.

        Parameters
        ----------
        schedule_name : str
            The name of the schedule to fetch.

        Returns
        -------
            A JSON object containing the schedule information.
        """
        pass

    @abstractmethod
    def get_schedule_id(self, schedule_name: str) -> int:
        """
        Gets the schedule ID for a schedule based on its name. Raises ElementNotFound if schedule isn't found.

        Parameters
        ----------
        schedule_name : str
            The name of the schedule to fetch.

        Returns
        -------
            An integer representing the schedule ID.
        """
        pass

    @abstractmethod
    def get_schedule_names(self) -> List[str]:
        """
        Gets all the schedules available on the device.

        Returns
        -------
            A list containing only the names of the available schedules.
        """
        pass

    @abstractmethod
    def get_active_schedules(self) -> List[Dict]:
        """
        Gets all the schedules that are currently active on the device.

        Returns
        -------
            A list of all active schedules on the device in JSON format.
        """
        pass

    @abstractmethod
    def delete_schedule(self, schedule_id: id) -> None:
        """
        Deletes a schedule from the device.

        Parameters
        ----------
        schedule_id : int
            The schedule ID to delete.

        Returns
        -------
        """
        pass

    @abstractmethod
    def delete_schedule_by_name(self, schedule_name: str) -> None:
        """
        Deletes a schedule from the device given its name.

        Parameters
        ----------
        schedule_name : str
            The name of the schedule to delete. Raises ElementNotFound if schedule isn't found.

        Returns
        -------
        """

    @abstractmethod
    def get_system_log(self) -> List[Dict]:
        """
        Gets the system log of the device.

        Returns
        -------
        List[Dict]
            A list of JSON objects, where each dictionary contains details of a single system log entry. In the
            format of {"timestamp": "x", "type": "y", "message": "z"}
        """
        pass

    @abstractmethod
    def clear_system_log(self) -> None:
        """
        Clears the system log of the device.
        Returns
        -------
        """
        pass

    @abstractmethod
    def get_pabs(self) -> List[Dict]:
        """
        Gets the list of PABs, enabled or disabled on the device.
        Returns
        -------
            A list of JSON objects, where each dictionary contains details of a single PAB entry from the device.
        """
        pass

    @abstractmethod
    def get_pab_by_name(self, pab_name: str) -> Dict:
        """
        Gets a PAB and its configuration based on its name. Raises ElementNotFound if the PAB isn't found.

        Parameters
        ----------
        pab_name : str
            The name of the PAB to fetch.

        Returns
        -------
            A JSON object containing the PAB information.
        """
        pass

    @abstractmethod
    def get_enabled_pabs(self) -> List[Dict]:
        """
        Gets the list of enabled PABs on the device.

        Returns
        -------
            A list of JSON objects, where each dictionary contains details of a single enabled PAB entry from the device.
        """
        pass

    @abstractmethod
    def get_disabled_pabs(self) -> List[Dict]:
        """
        Gets the list of disabled PABs on the device.

        Returns
        -------
            A list of JSON objects, where each dictionary contains details of a single disabled PAB entry from the device.
        """
        pass

    @abstractmethod
    def delete_pab_by_name(self, pab_name: str) -> None:
        """
        Deletes a PAB from the device given its name. Raises ElementNotFound if the PAB isn't found.

        Parameters
        ----------
        pab_name : str
            The name of the PAB to delete.

        Returns
        -------

        """
        pass
