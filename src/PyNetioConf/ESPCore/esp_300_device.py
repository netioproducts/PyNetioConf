"""
Implementation specifics for ESP devices with the firmware 3.x.x.
"""
from .esp_200_device import ESP200Device
from .. import NetioManager


class ESP300Device(ESP200Device):
    """
    A class to control ESP devices with the firmware 3.x.x.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str, keep_alive: bool =
    True, netio_manager: NetioManager = None, use_https: bool = False):
        super().__init__(host, username, password, sn_number, hostname, keep_alive, netio_manager, use_https)
        self.fw_version = self.get_version()
