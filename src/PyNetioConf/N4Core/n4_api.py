from xml.etree import ElementTree as ET
from . import N4Device
from ..exceptions import *

import requests
import logging

logger = logging.getLogger(__name__)


def get_info(host: str) -> str:
    xml_str = """<request sessionID=""><system action="getVersion"></system></request>"""

    response = requests.post(f"http://{host}/xml", data=xml_str)  # noqa

    return response.content.decode("utf-8")


def send_request(fw_object: N4Device, xml_str: str, timeout: int = 10) -> ET:
    """
    Send an HTTP request to the device's API and return an ElementTree with the response.

    Parameters
    ----------
    fw_object: N4Device
        The N4Device compatible object of the device.
    xml_str: str
        XML string to send to the device.
    timeout: int
        Timeout duration, if the device doesn't respond in this time, abandon the request.

    Returns
    -------
        An ElementTree with the response from the device.
    """
    session = requests.Session()
    xml_endpoint = f"http://{fw_object.host}/xml"
    try:
        logger.debug(f"Sending request to {xml_endpoint} with payload {xml_str}")
        response = session.post(url=xml_endpoint, data=xml_str, timeout=timeout)
    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to device {fw_object.host}")
        raise CommunicationError("Cannot connect to device")

    response_text = response.content.decode("utf-8")
    logger.debug(f"Response from {xml_endpoint}: {response_text}")
    response_xml = ET.fromstring(response_text)
    errors = response_xml.findall(".//error")
    error_status = errors[-1] if errors else None
    if error_status is not None:
        if error_status.get("code") == "0":
            return response_xml
        else:
            raise CommunicationError(f"Error in response: {error_status.text}")
