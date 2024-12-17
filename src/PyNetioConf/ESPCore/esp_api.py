"""
This module contains functions for sending requests to the device's API on EPS based devices.
"""
import logging

import requests

from ..exceptions import CommunicationError
from ..netio_device import NETIODevice

logger = logging.getLogger(__name__)


def check_connectivity(fw_object: NETIODevice, timeout: int = 60) -> float:
    try:
        protocol = "https" if fw_object.use_https else "http"
    except AttributeError:
        protocol = "http"

    try:
        logger.debug(f"Checking connection health of {fw_object.host}.")
        response = requests.get(f"{protocol}://{fw_object.host}", timeout=timeout, verify=False)
    except:
        logger.warn(f"Couldn't connect to device {fw_object.host}.")
        return -1

    logger.debug(f"Response time of device {fw_object.host} is {response.elapsed.total_seconds() * 1000.0}ms.")
    return response.elapsed.total_seconds()


def send_request(fw_object: NETIODevice, command: str, data: dict = None, timeout: int = 60, endpoint: str = 'api',
                 close: bool = False) -> requests.Response:
    """
    Send an HTTP request to the device's API and return a `requests.Response` object.

    Parameters
    ----------
    fw_object: NETIODevice
        The NETIODevice compatible object of the device.
    command: str
        API command to send to the device.
    endpoint: str
        The endpoint to send the request to, defaults to 'api'. This means the final request will be sent to
        http://<device_ip>/<api>
    data: dict
        Dictionary containing data for the request, used to specify actions for the API command.
    timeout: int
        Timeout duration, if the device doesn't respond in this time, abandon the request.
    close: bool
        Close the session after the request is sent.

    Returns
    -------
        A response from the api request in the `requests.Response` format.
    """
    try:
        protocol = "https" if fw_object.use_https else "http"
    except AttributeError:
        protocol = "http"
    netio_host = f"{protocol}://{fw_object.host}/{endpoint}"
    if endpoint == 'api':
        json_payload = {"sessionId": fw_object.session_id, "action": command}  # better session id?
    else:
        json_payload = {}

    if data is not None:
        json_payload["data"] = data

    session = requests.Session()

    try:
        logger.debug(f"Sending request to {netio_host} with payload {json_payload}")
        response = session.post(url=netio_host, json=json_payload, timeout=timeout, verify=False)
    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to device {fw_object.host}")
        raise CommunicationError("Cannot connect to device")

    # handle errors and repeat request
    if 'errors' in response.json():
        if response.json()['errors'][0]['code'] == 1000:
            # session expired
            logger.info("Session expired, logging in again")
            fw_object.login(fw_object.username, fw_object.password)
            logger.debug(f"Sending request to {netio_host} with payload {json_payload}")
            response = session.post(url=netio_host, json=json_payload, timeout=timeout, verify=False)
        else:
            raise CommunicationError("Error in response: " + response.json()['errors'][0]['message'])

    if close:
        logger.debug(f"Closing session with {netio_host}")
        session.close()
    return response


def send_file(fw_object: NETIODevice, url_path: str, file, timeout: int = 600) -> requests.Response:
    """
    Upload a file to the device on the specified URL path, returns the response of the request.

    Parameters
    ----------
    fw_object: NETIODevice
        The NETIODevice compatible object of the device.
    url_path: str
        The location on the device where the file will be uploaded
    file
        The file to be uploaded. Based on the size of the file you might change the timeout.
    timeout: int
        The maximum time for the request

    Returns
    -------
        A response from the api request in the `requests.Response` format.
    """
    try:
        protocol = "https" if fw_object.use_https else "http"
    except AttributeError:
        protocol = "http"
    netio_host = f"{protocol}://{fw_object.host}{url_path}"

    session = requests.Session()
    session.cookies.update({"sessionId": fw_object.session_id})

    try:
        if url_path == '/upload/config':
            logger.debug(f"Uploading config file to {netio_host}.")
            response = session.post(netio_host, files={"sessionId": (None, fw_object.session_id),
                                                       "data":      ("config.json", file, "application/json")},
                                    headers={"DNT": "1"}, verify=False)
        elif url_path == '/upload/firmware':
            logger.debug(f"Uploading firmware to {netio_host}")
            response = session.post(url=netio_host, files={"file": file}, timeout=timeout, verify=False)
        elif "upload/ssl/" in url_path:
            if "mqtt_client_key" in url_path:
                filetype = "application/x-iwork-keynote-sffkey"
            elif "mqtt_client_cert" in url_path or "mqtt_root_ca" in url_path:
                filetype = "application/x-x509-ca-cert"
            logger.debug(f"Uploading SSL certificate to {netio_host}")
            response = session.post(
                url=netio_host,
                files={"file": ("file", file, filetype)},
                headers={"Content-Disposition": f'form-data; name="file"; filename="file"'},
                timeout=timeout, verify=False
            )
        else:
            logger.debug(f"Uploading generic file to {netio_host}")
            response = session.post(url=netio_host, files={"file": file}, timeout=timeout, verify=False)
    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to device {fw_object.host}")
        raise CommunicationError("Cannot connect to device")

    try:
        response_status: str = response.json()["status"]
    except KeyError:
        response_status = 'failed'
    except requests.exceptions.JSONDecodeError:
        response_status = 'unknown'
    logger.debug(f"File upload status: {response_status}")

    if response_status == 'failed':
        logger.error(f"Upload failed, logging out, retrying.")
        if check_connectivity(fw_object) != -1:
            fw_object.login(fw_object.username, fw_object.password, logout=True)
        else:
            raise CommunicationError("Couldn't connect to device after a failed request.")
        try:
            if url_path == '/upload/config':
                logger.debug(f"Uploading config file to {netio_host}.")
                response = session.post(netio_host, files={"sessionId": fw_object.session_id,
                                                           "data":      ("config.json", file, "application/json")},
                                        headers={"DNT": "1"}, verify=False)
            elif url_path == "/cfgimport":
                logger.debug(f"Uploading config file to {netio_host}.")
                response = session.post(netio_host, files={"file": ("config.json", file, "application/json")},
                                        verify=False)
            elif url_path == '/upload/firmware':
                logger.debug(f"Uploading firmware to {netio_host}")
                response = session.post(url=netio_host, files={"file": file}, timeout=timeout, verify=False)
            elif "upload/ssl/" in url_path:
                if "mqtt_client_key" in url_path:
                    filetype = "application/x-iwork-keynote-sffkey"
                elif "mqtt_client_cert" in url_path or "mqtt_root_ca" in url_path:
                    filetype = "application/x-x509-ca-cert"
                logger.debug(f"Uploading SSL certificate to {netio_host}")
                response = session.post(
                    url=netio_host,
                    files={"file": ("file", file, filetype)},
                    headers={"Content-Disposition": f'form-data; name="file"; filename="file"'},
                    timeout=timeout, verify=False
                )
            else:
                logger.debug(f"Uploading generic file to {netio_host}")
                response = session.post(url=netio_host, files={"file": file}, timeout=timeout, verify=False)
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to device {fw_object.host}.")
            raise CommunicationError("Cannot connect to device.")
        if response == 'failed':
            logger.error("Could not send file to device.")
            raise CommunicationError("Cannot send file to device.")

    return response


def get_file(fw_object: NETIODevice, url_path: str, timeout: int = 600, ) -> requests.Response:
    """
    Download a file from the device on the specified URL path, returns the response of the request.

    Parameters
    ----------
    fw_object: NETIODevice
        The NETIODevice compatible object of the device.
    url_path: str
        The location on the device where the file will be downloaded from
    timeout: int
        The maximum time for the request

    Returns
    -------
        A response from the api request in the `requests.Response` format.
    """
    protocol = "https" if fw_object.use_https else "http"
    netio_host = f"{protocol}://{fw_object.host}{url_path}"

    session = requests.Session()

    try:
        logger.debug(f"Downloading file from {netio_host}")
        response = session.get(url=netio_host, cookies={"sessionId": fw_object.session_id},
                               timeout=timeout, verify=False)
    except requests.exceptions.ConnectionError:
        raise CommunicationError("Cannot connect to device")

    if response == 'failed':
        logger.error(f"Request failed, logging out, retrying.")
        fw_object.login(fw_object.username, fw_object.password, logout=True)
        try:
            logger.debug(f"Downloading file from {netio_host}")
            response = session.get(url=netio_host, cookies={"sessionId": fw_object.session_id},
                                   timeout=timeout, verify=False)
        except requests.exceptions.ConnectionError:
            raise CommunicationError("Cannot connect to device")
        if response == 'failed':
            raise CommunicationError("Cannot send file to device")

    return response
