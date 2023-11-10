"""
Implementation specifics for ESP devices with the firmware 4.0.x.
"""
from .ESPDevice import ESPDevice


class ESP400Device(ESPDevice):
    """
    A class to control ESP devices with the firmware 4.0.x.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str, keep_alive: bool = True):
        super().__init__(host, username, password, sn_number, hostname, keep_alive)
        self.fw_version = self.get_version()
