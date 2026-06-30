"""
Implementation specifics for ESP devices with the firmware 5.0.x.
"""

import atexit
import json
import os
import ssl
from time import sleep
from typing import IO, Any, AnyStr, Dict, List, Tuple, override

import websocket

from . import esp_api, ws_api
import logging
from .esp_500_device import ESP500Device
from .. import NetioManager
from ..exceptions import CommunicationError, ElementNotFound
from ..netio_device import NETIODevice
from websocket import WebSocket
import threading


class ESP520Device(
    ESP500Device 
    #NETIODevice
):  # TODO: Make sure we inherit from ESP400Device on release
    """
    A class to control ESP devices with the firmware 5.0.x.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        sn_number: str,
        hostname: str,
        keep_alive: bool = True,
        netio_manager: NetioManager | None = None,
        use_https: bool = False,
        **kwargs: Any,
    ):
        """
        The 5.x.x versions of Netio firmware have been severely redesigned which includes the entirety of the API that is used for communication with the device therefore this init is completely separated from the base classes and does not call super().__init__ but instead makes a new class from scratch. If the base NETIODevice class gets updated this has to be done accordingly here.

        Parameters
        ----------
        host : str
            
        username : str
            
        password : str
            
        sn_number : str
            
        hostname : str
            
         : Any
            
        keep_alive : bool
            
        netio_manager : NetioManager | None
            
        use_https : bool
            

        """
        self.host = host
        self.username = username
        self.password = password
        self.sn_number = sn_number
        self.hostname = hostname
        self.session_id = ""
        self.supported_features: dict[str, Any] = dict()
        self.output_count = 4
        self.user_permissions: list[str] = list()
        self._keep_alive_flag = keep_alive
        self.ws_req_id = kwargs.get("ws_req_id", 0)
        self.use_https = use_https
        if use_https:
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning

            disable_warnings(category=InsecureRequestWarning)

        # Init from base ESP Device
        self.ws: WebSocket | None = kwargs.get("ws_connection", None)
        self.logger = logging.getLogger(__name__)
        if kwargs.get("is_ws_auth", False):
            self.session_id = "TODO AUTH"
        else:
            self.session_id = self.login(username, password)
        #self.supported_features = self.get_features()
        #self.output_count: int = self.supported_features["outputCount"]
        #self.user_permissions = self.get_current_user()["privileges"]
        if keep_alive:
            self._ka_thread = threading.Timer(120, self._keep_alive)
            self._ka_thread.daemon = True
            self._ka_thread.start()
        atexit.register(self._cleanup)

        # New Init
        self.ssl_options: dict[str, Any] | None = kwargs.get("ssl_options", dict())
        self.logger = logging.getLogger(self.__class__.__name__)
        self.netio_manager = netio_manager
        # self.fw_version = self.get_version()

    @override
    def upload_mqtt_client_key(self, key: str) -> None:
        import base64
        upload_id = ws_api.send_request(self, "SET", "protocols/mqtt/clientkeyupload", {})["data"]["uploadId"]
        original_bytes = key.encode("utf-8")
        base64_string = base64.b64encode(original_bytes).decode("utf-8")
        ws_api.chunk_file_upload(self, base64_string, 0, len(key), len(key), upload_id)

    @override
    def upload_mqtt_ca_certificate(self, ca: str) -> None:
        import base64
        upload_id = ws_api.send_request(self, "SET", "protocols/mqtt/cacertupload", {})["data"]["uploadId"]
        original_bytes = ca.encode("utf-8")
        base64_string = base64.b64encode(original_bytes).decode("utf-8")
        ws_api.chunk_file_upload(self, base64_string, 0, len(ca), len(ca), upload_id)

    @override
    def upload_mqtt_client_certificate(self, cert: str) -> None:
        import base64
        upload_id = ws_api.send_request(self, "SET", "protocols/mqtt/clientcertupload", {})["data"]["uploadId"]
        original_bytes = cert.encode("utf-8")
        base64_string = base64.b64encode(original_bytes).decode("utf-8")
        ws_api.chunk_file_upload(self, base64_string, 0, len(cert), len(cert), upload_id)
