"""
Module for managing NETIO devices across a session without creating multiple connections to the same device.
"""

import atexit
import re
from typing import Any, Dict, List, Tuple

import requests

from PyNetioConf.exceptions import CommunicationError, FirmwareVersionNotSupported

from .ESPCore import esp_device_init
from .netio_device import NETIODevice


class NetioManager:
    """
    A class to create and manage NETIO devices across a session.
    """

    def __init__(self) -> None:
        self._connected_devices: list[NETIODevice] = list()
        atexit.register(self.logout_all)

    def logout_all(self) -> None:
        """
        Logs out of all connected devices, keeps the device list, but invalidates the sessions, if a request will be
        sent to any of the devices, a new session will be created.
        """
        for device in self._connected_devices:
            if device.session_id != "" or device.ws is not None:
                device.logout()

    def init_device(
        self,
        host: str,
        username: str,
        password: str,
        keep_alive: bool = True,
        use_https: bool = False,
        **kwargs: dict[str, Any],
    ) -> NETIODevice:
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
            If True, the connection will be kept alive by sending a keep alive packet every 120 seconds.
        use_https: bool
            Makes the communication with the device based on HTTPs, the protocol must be enabled on the device
            in the security settings.
        kwargs: dict[str, Any]
            Used mainly for setting up custom SSL options while using HTTPS

        Returns
        -------
            NETIODevice compatible object based on the platform of the connected device.
        """
        try:
            netio_device = esp_device_init.initialize_esp(
                host, username, password, keep_alive, self, use_https, **kwargs
            )  # pyright: ignore[reportUnknownMemberType]
        except requests.exceptions.ConnectionError:
            raise NotImplementedError
        self._connected_devices.append(netio_device)
        return netio_device

    def update_device(self, netio_device: NETIODevice, **kwargs) -> NETIODevice:
        """
        Update the device object in the device list and return its new instance,
        main use for updating firmware between major versions.

        Parameters
        ----------
        netio_device: NETIODevice
            The device object to update.

        Returns
        -------
            The updated device object.
        """
        for index, device in enumerate(self._connected_devices):
            if device is netio_device:
                updated_device = esp_device_init.initialize_esp(
                    device.host,
                    device.username,
                    device.password,
                    device._keep_alive_flag,
                    self,
                    device.use_https,
                    **kwargs,
                )
                self._connected_devices[index] = updated_device
                return updated_device
        raise CommunicationError("Device could not be reinstated after update.")

    @staticmethod
    def parse_fw_version(host: str) -> tuple[int, int, int]:
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
            return (
                int(version_info.group(1)),
                int(version_info.group(2)),
                int(version_info.group(3)),
            )
        else:
            raise ValueError("Invalid firmware version string")

    @staticmethod
    def get_info(host: str) -> dict:
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
        from urllib3.exceptions import MaxRetryError

        try:
            response = session.post(
                f"http://{host}/api", json=json_payload, timeout=300
            )  # noqa
        except MaxRetryError:
            from time import sleep

            sleep(5)
            response = session.get(f"http://{host}/api", json=json_payload, timeout=300)

        if "data" not in response.json():
            raise ConnectionError("Invalid response from device")
        return response.json()

    @staticmethod
    def esp_get_platform(host) -> tuple[str, str]:
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
