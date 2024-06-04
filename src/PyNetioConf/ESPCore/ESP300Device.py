"""
Implementation specifics for ESP devices with the firmware 3.x.x.
"""
from .ESP200Device import ESP200Device


class ESP300Device(ESP200Device):
    """
    A class to control ESP devices with the firmware 3.x.x.
    """

    def __init__(self, host: str, username: str, password: str, sn_number: str, hostname: str, keep_alive: bool = True):
        super().__init__(host, username, password, sn_number, hostname, keep_alive)
        self.fw_version = self.get_version()
