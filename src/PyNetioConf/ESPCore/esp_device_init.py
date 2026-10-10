import logging
import re
import ssl
from time import perf_counter, sleep
from typing import TYPE_CHECKING, Any, Optional

import requests
import websocket
from websocket import WebSocket

from ..exceptions import AuthError, CommunicationError, InvalidParameterValueError
from ..netio_device import NETIODevice
from . import ws_api

logger = logging.getLogger(__name__)


def _setup_ssl(**kwargs: Any) -> tuple[ssl.SSLContext, dict[str, Any]]:
    _ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # Force TLS 1.2

    DEFAULT_CIPHER_SUITES = [
        # RSA
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_256_CCM",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_128_CCM",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        # ECC
        "TLS_ECDHE_ECDSA_WITH_AES_256_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
        "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    ]

    cipher_suites = ":".join(DEFAULT_CIPHER_SUITES)

    ssl_options: dict[str, Any] = {}
    if kwargs.get("ssl_ciphers", None) is not None:
        ssl_options["ciphers"] = kwargs.get("ssl_ciphers", cipher_suites)
        _ssl_context.set_ciphers(kwargs.get("ssl_ciphers", cipher_suites))
    else:
        ssl_options["ciphers"] = cipher_suites
        _ssl_context.set_ciphers(cipher_suites)

    if kwargs.get("ssl_ca_cert_path", None) is not None:
        ssl_options["ca_cert_path"] = kwargs.get("ssl_ca_cert_path")
        _ssl_context.load_verify_locations(capath=kwargs.get("ssl_ca_cert_path"))

    if kwargs.get("ssl_ecdh_curve", None) is not None:
        ecdh_curve = kwargs.get("ssl_ecdh_curve")
        if type(ecdh_curve) is str:
            ssl_options["ecdh_curve"] = ecdh_curve
            _ssl_context.set_ecdh_curve(ecdh_curve)
        else:
            raise TypeError("ssl_ecdh_curve must be a str")

    if kwargs.get("ssl_ca_certs", None) is not None:
        ssl_options["ca_certs"] = kwargs.get("ssl_ca_certs")
        _ssl_context.load_verify_locations(cafile=kwargs.get("ssl_ca_certs"))

    if kwargs.get("ssl_certfile", None) is not None:
        ssl_options["certfile"] = kwargs.get("ssl_certfile")

        if kwargs.get("ssl_keyfile", None) is not None:
            ssl_options["keyfile"] = kwargs.get("ssl_keyfile")
            if kwargs.get("ssl_password", None) is not None:
                ssl_options["password"] = kwargs.get("ssl_password")
                _ssl_context.load_cert_chain(
                    kwargs.get("ssl_certfile"),
                    kwargs.get("ssl_keyfile"),
                    kwargs.get("ssl_password"),
                )
            else:
                _ssl_context.load_cert_chain(
                    kwargs.get("ssl_certfile"), kwargs.get("ssl_keyfile")
                )
        else:
            _ssl_context.load_cert_chain(kwargs.get("ssl_certfile"))

    if kwargs.get("ssl_check_hostname", None) is not None:
        check_hostname = kwargs.get("ssl_check_hostname")
        if type(check_hostname) is bool:
            ssl_options["check_hostname"] = check_hostname
            _ssl_context.check_hostname = check_hostname
    else:
        ssl_options["check_hostname"] = False
        _ssl_context.check_hostname = False

    if kwargs.get("ssl_cert_reqs", None) is not None:
        cert_req = kwargs.get("ssl_cert_reqs")
        if type(cert_req) is ssl.VerifyMode:
            ssl_options["cert_reqs"] = cert_req
            _ssl_context.verify_mode = cert_req
    else:
        ssl_options["cert_reqs"] = ssl.CERT_NONE
        _ssl_context.verify_mode = ssl.CERT_NONE

    ssl_options["context"] = kwargs.get("ssl_context", _ssl_context)
    return (_ssl_context, ssl_options)


def _try_connect_websocket(
    host: str, use_https: bool, try_count: int, **kwargs: dict[str, Any]
) -> WebSocket:
    ssl_options: dict[str, Any] | None = None
    _ssl_context: ssl.SSLContext | None = None
    if use_https:
        _ssl_context, ssl_options = _setup_ssl(**kwargs)

    logger.debug(f"Attempting websocket connection to {host}")
    for attempt in range(try_count):
        logger.debug(f"{host} websocket connection attempt {attempt + 1}/{try_count}")
        try:
            connection_dt_start = perf_counter()
            if use_https:
                ws = websocket.create_connection(
                    f"wss://{host}/emweb", sslopt=ssl_options, timeout=10
                )  # pyright: ignore[reportUnknownMemberType]
            else:
                ws = websocket.create_connection(f"ws://{host}/emweb", timeout=10)  # pyright: ignore[reportUnknownMemberType]

            if isinstance(ws, WebSocket):
                logger.debug(f"Succesfully connected to {host}")
                break
            else:
                elapsed_time = perf_counter() - connection_dt_start
                if elapsed_time < 10:
                    logger.debug(
                        "Couldn't establish ws connection in time, waiting to reconnect."
                    )
                    sleep(10 - elapsed_time)
        except Exception as e:
            logger.debug(f"Connection to {host} failed on {attempt + 1}/{try_count}")
            sleep(1)
            continue

    if isinstance(ws, WebSocket):
        logger.debug(f"Setting default timeout for {host}.")
        ws.settimeout(60)
    return ws


def initialize_esp(
    host: str,
    username: str,
    password: str,
    keep_alive: bool = True,
    netio_manager: Optional["NetioManager"] = None,  # type: ignore # noqa
    use_https: bool = False,
    **kwargs: Any,
) -> NETIODevice:
    if netio_manager is None:
        raise InvalidParameterValueError

    ws: websocket.WebSocket | None = None
    version = 4  # TODO: Do version parsing here, not in NetioManager as this is ESP thing, not general NETIO thing
    minor = 0
    patch = 0
    try:
        try_count = 3 if not kwargs.get("ws_expected", False) else 15
        ssl_options = _setup_ssl(**kwargs)[1] if use_https else {}

        ws = _try_connect_websocket(host, use_https, try_count, **kwargs)
        ws_req_id = 0

        hello_response = ws_api.device_init_request(ws, ws_req_id, "HELO", host)
        ws_req_id += 1
        ws_api.device_init_login(
            ws,
            ws_req_id,
            hello_response["data"]["localTimestamp"],
            hello_response["data"]["publicKey"],
            username,
            password,
            host,
        )
        ws_req_id += 1
        try:
            version_str = hello_response["data"]["device"]["fwVersion"]
            version_pattern = r"(\d+)\.(\d+)\.(\d+)"
            match = re.search(version_pattern, version_str)
            if match:
                version, minor, patch = match.groups()
        except KeyError:
            logger.debug(
                "Version not found in HELO message, fetching from system/info instead"
            )
            system_info = ws_api.device_init_request(
                ws, ws_req_id, "SUBSCRIBE", host, "system/info"
            )
            ws_req_id += 2
            version_str = system_info["data"]["fwVersion"]
            version_pattern = r"(\d+)\.(\d+)\.(\d+)"
            match = re.search(version_pattern, version_str)
            if match:
                version, minor, patch = match.groups()
            else:
                logger.warn(
                    f"Websocket on {host} is connected but version couldn't be verified, defaulting to 5beta firmware"
                )
                version, minor, patch = 5, 0, 0
    except AuthError:
        # The device refused the credentials, it does have the WebSocket API, so no fallback to older firmware
        if ws is not None:
            ws.close()
        raise
    except:
        ws_req_id = 0
        ws = None

    if int(version) == 2:
        from .esp_200_device import ESP200Device

        netio_device = ESP200Device(
            host,
            username,
            password,
            "",
            "",
            keep_alive,
            netio_manager,  # pyright: ignore[reportUnknownArgumentType]
            use_https,
        )
        return netio_device

    if int(version) == 3:
        from .esp_300_device import ESP300Device

        netio_device = ESP300Device(
            host,
            username,
            password,
            "",
            "",
            keep_alive,
            netio_manager,  # pyright: ignore[reportUnknownArgumentType]
            use_https,
        )
        return netio_device

    if int(version) == 4:
        from .esp_400_device import ESP400Device

        netio_device = ESP400Device(
            host,
            username,
            password,
            "",
            "",
            keep_alive,
            netio_manager,  # pyright: ignore[reportUnknownArgumentType]
            use_https,
        )
        return netio_device

    if int(version) == 5:
        if int(minor) >= 4:
            from .esp_540_device import ESP540Device

            netio_device = ESP540Device(
                host,
                username,
                password,
                "",
                "",
                keep_alive,
                netio_manager,  # pyright: ignore[reportUnknownArgumentType]
                use_https,
                ws_connection=ws,
                ws_req_id=ws_req_id,
                is_ws_auth=True if ws is not None else False,
                ws_helo_data=hello_response,
                device_version=(int(version), int(minor), int(patch)),
                ssl_options=ssl_options,
            )
            return netio_device
        elif int(minor) >= 2:
            from .esp_520_device import ESP520Device

            netio_device = ESP520Device(
                host,
                username,
                password,
                "",
                "",
                keep_alive,
                netio_manager,  # pyright: ignore[reportUnknownArgumentType]
                use_https,
                ws_connection=ws,
                ws_req_id=ws_req_id,
                is_ws_auth=True if ws is not None else False,
                ws_helo_data=hello_response,
                device_version=(int(version), int(minor), int(patch)),
                ssl_options=ssl_options,
            )
            return netio_device
        elif int(minor) == 1:
            from .esp_500_device import ESP500Device

            netio_device = ESP500Device(
                host,
                username,
                password,
                "",
                "",
                keep_alive,
                netio_manager,  # pyright: ignore[reportUnknownArgumentType]
                use_https,
                ws_connection=ws,
                ws_req_id=ws_req_id,
                is_ws_auth=True if ws is not None else False,
                ws_helo_data=hello_response,
                device_version=(int(version), int(minor), int(patch)),
                ssl_options=ssl_options,
            )
            return netio_device
        else:
            from .esp_5beta_device import ESP5BetaDevice

            ws = None
            netio_device = ESP5BetaDevice(
                host,
                username,
                password,
                "",
                "",
                keep_alive,
                netio_manager,  # pyright: ignore[reportUnknownArgumentType]
                use_https,
            )
            return netio_device

    raise InvalidParameterValueError(
        f"There is no firmware with major version {version} supported"
    )
