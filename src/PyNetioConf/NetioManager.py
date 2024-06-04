"""
Module for managing NETIO devices across a session without creating multiple connections to the same device.
"""
import atexit
import re
from typing import Dict, List, Tuple
from xml.etree import ElementTree as ET  # noqa

import requests

from . import NETIODevice
from .ESPCore import ESP200Device, ESP300Device, ESP400Device
from .N4Core import N4Device, n4_api
from .exceptions import *


class NetioManager:
    """
    A class to create and manage NETIO devices across a session.
    """

    def __init__(self) -> None:
        self._connected_devices: List[NETIODevice] = list()
        atexit.register(self.logout_all)

    def logout_all(self) -> None:
        """
        Logs out of all connected devices, keeps the device list, but invalidates the sessions, if a request will be
        sent to any of the devices, a new session will be created.
        """
        for device in self._connected_devices:
            if device.session_id != '':
                device.logout()

    def assign_esp_device(self, host: str, username: str, password: str, keep_alive: bool) -> NETIODevice:
        """
        Creates a NETIODevice object based on the platform of the connected device. Supports EPS 4.0.x firmware.
        Parameters
        ----------
        host : str
            The URL of the device.
        username : str
            The username to log in with.
        password : str
            The password to log in with.
        keep_alive : bool
            A flag to keep the connection alive by sending a keep alive packet every 30 seconds.

        Returns
        -------
            A ESPDevice object for the connected device.
        """
        fw_version = self.parse_fw_version(host)  # noqa
        version_info = self.get_info(host)
        platform = version_info["data"]["platform"]  # noqa
        device_sn = version_info["data"]["deviceSN"]
        revision = version_info["data"]["revision"]  # noqa
        hostname = version_info["data"]["hostname"]

        for device in self._connected_devices:
            if device.sn_number == device_sn:
                return device

        if fw_version[0] < 2:
            raise FirmwareVersionNotSupported("Firmware version not supported, please upgrade to fw 2.x.x or newer.")

        if fw_version[0] == 2:
            netio_device = ESP200Device(host, username, password, device_sn, hostname, keep_alive)
            return netio_device

        if fw_version[0] == 3:
            netio_device = ESP300Device(host, username, password, device_sn, hostname, keep_alive)
            return netio_device

        if fw_version[0] == 4:
            netio_device = ESP400Device(host, username, password, device_sn, hostname, keep_alive)
            return netio_device

    def assign_n4_device(self, host: str, username: str, password: str, keep_alive: bool) -> NETIODevice:
        """
        Creates a NETIODevice object based on the platform of the connected device. Supports NETIO4 firmware.

        Parameters
        ----------
        host : str
            The URL of the device.
        username : str
            The username to log in with.
        password : str
            The password to log in with.
        keep_alive : bool
            A flag to keep the connection alive by sending a keep alive packet every 30 seconds.

        Returns
        -------
            A N4Device object for the connected device.
        """
        fw_version = self.parse_fw_version_n4(host)  # noqa
        version_info = ET.fromstring(n4_api.get_info(host))
        platform = version_info.find("./platform").text  # noqa
        device_sn = version_info.find("./serialNumber").text
        revision = version_info.find("./revision").text  # noqa
        hostname = version_info.find("./hostname").text

        for device in self._connected_devices:
            if device.sn_number == device_sn:
                return device

        netio_device = N4Device(host, username, password, device_sn, hostname, keep_alive)
        return netio_device

    def init_device(self, host: str, username: str, password: str, keep_alive: bool = True) -> NETIODevice:
        """
            Initialize a Netio device object, create a connection to the device, get its platform type and return
            an object based on that platform.

            Parameters
            ----------
            host: str
                Device IP address (just the IP address, without any URL parts such as 'http://')
            username: str
                Username that will be used to log in to the device. (Note many actions require administrator privileges)
            password: str
                Password for the user.
            keep_alive: bool
                If True, the connection will be kept alive by sending a keep alive packet every 30 seconds.

            Returns
            -------
                NETIODevice compatible object based on the platform of the connected device.
            """
        try:
            version_info = self.parse_fw_version(host)  # noqa
            netio_device = self.assign_esp_device(host, username, password, keep_alive)
        except requests.exceptions.ConnectionError:
            version_info = self.parse_fw_version_n4(host)  # noqa
            netio_device = self.assign_n4_device(host, username, password, keep_alive)

        self._connected_devices.append(netio_device)
        return netio_device

    @staticmethod
    def parse_fw_version(host: str) -> Tuple[int, int, int]:
        """
        Parse the firmware info string and return the version numbers.

        Parameters
        ----------
        host: str
            The URL of the device.

        Returns
        -------
            A tuple containing the major, minor and bugfix version numbers.
        """
        fw_info = NetioManager.get_info(host)["data"]["version"]
        fw_version = fw_info.split("-")[0]
        version_info = re.search(r"(\d+)\.(\d+)\.(\d+)", fw_version)

        if version_info:
            return int(version_info.group(1)), int(version_info.group(2)), int(version_info.group(3))
        else:
            raise ValueError("Invalid firmware version string")

    @staticmethod
    def parse_fw_version_n4(host: str) -> Tuple[int, int, int]:
        """
        Parse the firmware info string and return the version numbers.

        Parameters
        ----------
        host: str
            The URL of the device.

        Returns
        -------
            A tuple containing the major, minor and bugfix version numbers.
        """
        device_info = n4_api.get_info(host)
        response_xml = ET.fromstring(device_info)
        fw_version = response_xml.find("./version").text
        version_info = re.search(r"(\d+)\.(\d+)\.(\d+)", fw_version)

        if version_info:
            return int(version_info.group(1)), int(version_info.group(2)), int(version_info.group(3))
        else:
            raise ValueError("Invalid firmware version string")

    @staticmethod
    def get_info(host: str) -> Dict:
        """
        Get version information from the device.

        Parameters
        ----------
        host: str
            IP address of the device.
        Returns
        -------
            Dictionary containing the version info from the device
        """
        session = requests.Session()
        json_payload = {"sessionId": "", "action": "getVersion"}
        response = session.post(f"http://{host}/api", json=json_payload)  # noqa

        if 'data' not in response.json():
            raise ConnectionError('Invalid response from device')
        return response.json()

    @staticmethod
    def esp_get_platform(host) -> Tuple[str, str]:
        """
        Get platform information from the device, as well as the serial number.

        Parameters
        ----------
        host: str
            URL of the device.

        Returns
        -------
            A tuple containing the platform type and the serial number.
        """
        json_response = NetioManager.get_info(host)

        if "platform" not in json_response["data"]:
            raise ValueError("Invalid response from device")  # todo custom exception

        return json_response["data"]["platform"], json_response["data"]["deviceSN"]
