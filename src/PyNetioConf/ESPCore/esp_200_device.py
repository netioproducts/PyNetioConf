"""
Implementation specifics for ESP devices with the firmware 2.x.x.
"""
from .esp_device import ESPDevice
from .. import NetioManager


class ESP200Device(ESPDevice):
    """
    A class to control ESP devices with the firmware 2.x.x.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str, keep_alive: bool =
    True, netio_manager: NetioManager = None, use_https: bool = False):
        super().__init__(host, username, password, sn_number, hostname, keep_alive, netio_manager, use_https)
        self.fw_version = self.get_version()
