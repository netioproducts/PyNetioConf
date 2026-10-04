"""
Implementation specifics for ESP devices with the firmware 5.2.x.
"""

import atexit
import io
import json
import os
import ssl
import sys
from collections import deque
from io import BytesIO
from pathlib import Path
from time import sleep, time

from ..constants import (
    DEFAULT_KEEP_ALIVE_QUEUE_LEN,
    DEFAULT_REQUEST_QUEUE_LEN,
)

if sys.version_info >= (3, 12):
    from typing import IO, Any, AnyStr, Dict, List, Tuple, override
else:
    from typing import IO, Any, AnyStr, Dict, List, Tuple

    from typing_extensions import override

import logging
import threading

import websocket
from websocket import WebSocket

from .. import NetioManager
from ..exceptions import CommunicationError, ElementNotFound
from ..netio_device import NETIODevice
from . import esp_api, ws_api
from .esp_500_device import ESP500Device


class ESP520Device(ESP500Device):
    """
    A class to control ESP devices with the firmware 5.2.x.
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

        self._request_queue = deque(maxlen=DEFAULT_REQUEST_QUEUE_LEN)
        self._pong_queue = deque(maxlen=DEFAULT_KEEP_ALIVE_QUEUE_LEN)

        # Init from base ESP Device
        self.ws: WebSocket | None = kwargs.get("ws_connection", None)
        self.logger = logging.getLogger(__name__)
        if kwargs.get("is_ws_auth", False):
            self.session_id = "TODO AUTH"
        else:
            self.session_id = self.login(username, password)
        # self.supported_features = self.get_features()
        # self.output_count: int = self.supported_features["outputCount"]
        # self.user_permissions = self.get_current_user()["privileges"]
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

        _system_info = self.get_system_info()
        self.output_count = _system_info["outputCount"]
        self.input_count = _system_info["inputCount"]
        self.supported_features["wifi"] = _system_info["wifiSupport"]
        self.supported_features["eth"] = _system_info["ethSupport"]

    # TODO: Handle repeated code for uploading files using chunking
    @override
    def upload_mqtt_client_key(self, key: str) -> None:
        import base64

        ws_type = "SET"
        ws_topic = "protocols/mqtt/clientkeyupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT client key to device {self.host}.")
        upload_id = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"][
            "uploadId"
        ]
        original_bytes = key.encode("utf-8")
        base64_string = base64.b64encode(original_bytes).decode("utf-8")
        ws_api.chunk_file_upload(self, base64_string, 0, len(key), len(key), upload_id)

    @override
    def upload_mqtt_ca_certificate(self, ca: str) -> None:
        import base64

        ws_type = "SET"
        ws_topic = "protocols/mqtt/cacertupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT CA certificate to device {self.host}.")
        upload_id = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"][
            "uploadId"
        ]
        original_bytes = ca.encode("utf-8")
        base64_string = base64.b64encode(original_bytes).decode("utf-8")
        ws_api.chunk_file_upload(self, base64_string, 0, len(ca), len(ca), upload_id)

    @override
    def upload_mqtt_client_certificate(self, cert: str) -> None:
        import base64

        ws_type = "SET"
        ws_topic = "protocols/mqtt/clientcertupload"
        ws_data: dict[str, Any] = {}

        self.logger.debug(f"Uploading MQTT client certificate to device {self.host}.")
        upload_id = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"][
            "uploadId"
        ]
        original_bytes = cert.encode("utf-8")
        base64_string = base64.b64encode(original_bytes).decode("utf-8")
        ws_api.chunk_file_upload(
            self, base64_string, 0, len(cert), len(cert), upload_id
        )

    @override
    def update_firmware(self, file: os.PathLike[AnyStr] | BytesIO) -> NETIODevice:
        # TODO: Implement permission checks
        # if "can_alter_settings" not in self.user_permissions:
        #     raise PermissionError(
        #         "You don't have permission to alter settings on this device."
        #     )
        if self._ka_thread:
            self._ka_thread.cancel()
            self._ka_thread.join()

        pre_reconnect_wait = 20
        # TODO: Implement supported_features
        try:
            if self.supported_features["wifi"] == "yes":
                wifi_settings = self.get_wifi_settings()
                if (
                    wifi_settings["mode"] == "client"
                    and wifi_settings["client"]["status"] == "Connected"
                ):
                    pre_reconnect_wait = 50
                    self.logger.debug(
                        "Increased wait time after fimrware update due to active Wi-Fi connection."
                    )
        except KeyError:
            pre_reconnect_wait = 100

        # TODO: Checnk connectivity
        # if esp_api.check_connectivity(self) > (pre_reconnect_wait / 10.0):
        #     pre_reconnect_wait = pre_reconnect_wait * 2
        #     self.logger.debug(
        #         "Increased wait time after firmware update due to poor connection quality."
        #     )

        try:
            ws_type = "SET"
            ws_topic = "system/fwupdate"
            ws_data = {}
            upload_id = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"][
                "uploadId"
            ]

            if isinstance(file, io.BufferedIOBase):
                ws_api.upload_file(self, file, upload_id)
            else:
                self.logger.debug("Unsupported file format.")
        except CommunicationError:
            self.logger.warning(
                f"Device {self.host} couldn't verify firmware update process beginning, this should be harmless if the device connects, waiting for connection."
            )
        self.logger.debug(
            f"Uploaded firmware, device {self.host} might be unresponsive for a while."
        )

        # TODO: Sophisticated
        pre_reconnect_wait = 30
        sleep(pre_reconnect_wait)

        self.logger.debug(
            f"Retrying connection to device {self.host} after updating firmware to new version, the device class is now going to update."
        )

        # TODO: Check connectivity for new FW
        # device_response_time = esp_api.check_connectivity(self)
        # retry_limit = 3 if device_response_time == -1 else 0
        # for _ in range(0, retry_limit):
        #     device_response_time = esp_api.check_connectivity(self)
        #
        # if device_response_time == -1:
        #     raise CommunicationError(
        #         "Device couldn't establish connection after firmware update."
        #     )

        updated_instance = None
        if type(self.netio_manager) is NetioManager:
            updated_instance = self.netio_manager.update_device(self, ws_expected=True)

        if isinstance(updated_instance, NETIODevice):
            self.logger.info(
                f"The device has updated to {updated_instance.get_version_detailed()}, the device object is now of the {type(updated_instance)} class, check documentation for supported features and changes."
            )

        if not updated_instance:
            raise CommunicationError("Coudln't get updated instance.")

        return updated_instance

    @override
    def import_config(self, file, **kwargs):
        ws_type = "SET"
        ws_topic = "system/cfgimport"
        ws_data = {}
        upload_id = ws_api.send_request(self, ws_type, ws_topic, ws_data)["data"][
            "uploadId"
        ]

        if isinstance(file, io.BufferedIOBase):
            self.logger.debug(f"Importing configuration to host {self.host}")
            ws_api.upload_file(self, file, upload_id)
        elif isinstance(file, str):
            file_path = Path(file)
            if file_path.exists():
                with open(file, "rb") as file:
                    ws_api.upload_file(self, file, upload_id)
        else:
            self.logger.debug("Unsupported file format.")

    @override
    def ping(self) -> bool:
        ws_type = "PING"
        start_time = time()
        ws_api.send_request(self, ws_type)
        end_time = time()
        self.logger.debug(
            f"Pinging device {self.host} successful. Response time: {end_time - start_time}"
        )
        return True

    @override
    def export_config(self, save_file: str | None = None) -> dict[str, Any]:
        ws_type = "SET"
        ws_export_topics_list = [
            "export/config/inputs",
            "export/config/network",
            "export/config/outputs",
            "export/config/PAB",
            "export/config/protocols",
            "export/config/rules",
            "export/config/schedules",
            "export/config/system",
            "export/config/users",
            "export/config/wdtpingers",
            "export/config/mqtt",
            "export/config/nbus",
        ]
        ws_data: dict[str, Any] = {}

        config_export: dict[str, Any] = dict()

        for config_group in ws_export_topics_list:
            self.logger.debug(
                f"Exporting configuration for {config_group.split('/')[-1]} from device {self.host}"
            )
            group_data = ws_api.send_request(self, ws_type, config_group, ws_data).get(
                "data", {}
            )
            config_export |= {config_group.split("/")[-1]: group_data}
        if save_file is not None:
            file_path = Path(save_file)
            if file_path.exists():
                self.logger.warning("Export config file exists, overriding.")
                # TODO: Make override a method parameter

            with open(save_file, "w+") as file:
                conf_string = json.dumps(config_export, ensure_ascii=False, indent=4)
                file.write(conf_string)

        return config_export

    @override
    def _keep_alive(self) -> None:
        self.logger.debug(f"Sending keep-alive to device {self.host}")
        self._ka_thread = threading.Timer(120, self._keep_alive)
        self._ka_thread.daemon = True
        self._ka_thread.start()
        self.ping()
