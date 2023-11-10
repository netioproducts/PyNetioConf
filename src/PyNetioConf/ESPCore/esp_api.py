"""
This module contains functions for sending requests to the device's API on EPS based devices.
"""
import logging

import requests

from PyNetioConf.exceptions import CommunicationError
from . import ESPDevice

logger = logging.getLogger(__name__)


def send_request(fw_object: ESPDevice, command: str, data: dict = None, timeout: int = 60, endpoint: str = 'api',
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
    netio_host = f"http://{fw_object.host}/{endpoint}"
    if endpoint == 'api':
        json_payload = {"sessionId": fw_object.session_id, "action": command}  # better session id?
    else:
        json_payload = {}

    if data is not None:
        json_payload["data"] = data

    session = requests.Session()

    try:
        logger.debug(f"Sending request to {netio_host} with payload {json_payload}")
        response = session.post(url=netio_host, json=json_payload, timeout=timeout)
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
            response = session.post(url=netio_host, json=json_payload, timeout=timeout)
        else:
            raise CommunicationError("Error in response: " + response.json()['errors'][0]['message'])

    if close:
        logger.debug(f"Closing session with {netio_host}")
        session.close()
    return response


def send_file(fw_object: ESPDevice, url_path: str, file, timeout: int = 600) -> requests.Response:
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
    netio_host = f"http://{fw_object.host}{url_path}"

    session = requests.Session()
    session.cookies.update({"sessionId": fw_object.session_id})

    try:
        if url_path == '/upload/config':
            logger.debug(f"Uploading config file to {netio_host}.")
            response = session.post(netio_host, files={"sessionId": (None, fw_object.session_id),
                                                       "data":      ("config.json", file, "application/json")},
                                    headers={"DNT": "1"})
        else:
            logger.debug(f"Uploading firmware to {netio_host}")
            response = session.post(url=netio_host, files={"file": file}, timeout=timeout)
    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to device {fw_object.host}")
        raise CommunicationError("Cannot connect to device")

    if response == 'failed':
        logger.error(f"Upload failed, logging out, retrying.")
        fw_object.login(fw_object.username, fw_object.password, logout=True)
        try:
            if url_path == '/upload/config':
                logger.debug(f"Uploading config file to {netio_host}.")
                response = session.post(netio_host, files={"sessionId": fw_object.session_id,
                                                           "data":      ("config.json", file, "application/json")},
                                        headers={"DNT": "1"})
            else:
                logger.debug(f"Uploading firmware to {netio_host}")
                response = session.post(url=netio_host, files={"file": file}, timeout=timeout)
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to device {fw_object.host}.")
            raise CommunicationError("Cannot connect to device.")
        if response == 'failed':
            logger.error("Could not send file to device.")
            raise CommunicationError("Cannot send file to device.")

    return response


def get_file(fw_object: ESPDevice, url_path: str, timeout: int = 600, ) -> requests.Response:
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
    netio_host = f"http://{fw_object.host}{url_path}"

    session = requests.Session()

    try:
        logger.debug(f"Downloading file from {netio_host}")
        response = session.get(url=netio_host, cookies={"sessionId": fw_object.session_id},
                               timeout=timeout)
    except requests.exceptions.ConnectionError:
        raise CommunicationError("Cannot connect to device")

    if response == 'failed':
        logger.error(f"Request failed, logging out, retrying.")
        fw_object.login(fw_object.username, fw_object.password, logout=True)
        try:
            logger.debug(f"Downloading file from {netio_host}")
            response = session.get(url=netio_host, cookies={"sessionId": fw_object.session_id},
                                   timeout=timeout)
        except requests.exceptions.ConnectionError:
            raise CommunicationError("Cannot connect to device")
        if response == 'failed':
            raise CommunicationError("Cannot send file to device")

    return response
