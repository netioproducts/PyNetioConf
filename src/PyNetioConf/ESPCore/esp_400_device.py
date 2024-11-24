"""
Implementation specifics for ESP devices with the firmware 4.0.x.
"""
from .esp_300_device import ESP300Device
from .. import NetioManager


class ESP400Device(ESP300Device):
    """
    A class to control ESP devices with the firmware 4.0.x.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str, keep_alive: bool =
    True, netio_manager: NetioManager = None, use_https: bool = False):
        super().__init__(host, username, password, sn_number, hostname, keep_alive, netio_manager, use_https)
        self.fw_version = self.get_version()
