import base64
import hashlib
import json
import logging
import math
import random
from typing import Dict, Tuple

from ..netio_device import NETIODevice

logger = logging.getLogger(__name__)


def send_request(device: NETIODevice, type: str, topic: str = None, data: Dict = None) -> Dict:
    """
    Send a request to the device's websocket API and return the response.
    Parameters
    ----------
    device : ESPDevice
        The ESPDevice object of the device.
    type : str
        The type of the request. Can be one of the following: "HELO", "AUTH", "SET", "SUBSCRIBE", "UNSUBSCRIBE".
    topic : str
        The target of the request if applicable.
    data : Dict
        The data to send with the request if applicable.

    Returns
    -------
        Upon successful communication returns the direct API response from the device to be further parsed.
    """
    request = {"type": type, "reqId": device.ws_req_id}
    if topic:
        request["topic"] = topic
    if data:
        request["data"] = data
    logger.debug(f"Sending request to {device.host} with payload {request}")
    device.ws.send(json.dumps(request))
    device.ws_req_id += 1
    message = device.ws.recv()
    logger.debug(f"Received response from {device.host} with payload {message}")
    return json.loads(message)


def generate_salt() -> str:
    base = random.randint(0, 2 ** 32)
    # create a sha256 hash of the base
    return hashlib.sha256(str(base).encode()).hexdigest()


def generate_password_hash(username: str, password: str, public_key: str) -> str:
    salted_hash = hashlib.sha256(f"{username}{public_key}{password}".encode()).digest()
    # convert the salted hash to base64
    return base64.b64encode(salted_hash).decode()


def generate_password_token(salt: str, password_hash: str) -> Tuple[str, str]:
    # create a sha256 hash of the salt and password hash
    pwd_hash = hashlib.sha256(f"{salt}{password_hash}".encode()).hexdigest()
    return salt, pwd_hash


def generate_auth_token(password_token: Tuple[str, str], local_timestamp) -> str:
    time_mark = str(math.floor(local_timestamp / 10))
    token_hash = hashlib.sha256(f"{time_mark}{password_token[1]}".encode()).hexdigest()
    return f"{password_token[0]}.{token_hash}"


def login(device: NETIODevice, timestamp: int, public_key: str, username: str, password: str) -> Dict:
    salt = generate_salt()
    password_hash = generate_password_hash(username, password, public_key)
    password_token = generate_password_token(salt, password_hash)
    auth_token = generate_auth_token(password_token, timestamp)
    request = {"type":  "AUTH", "reqId": device.ws_req_id, "username": username,
               "token": auth_token}
    device.ws.send(json.dumps(request))
    logger.debug(f"Sending authentication request to {device.host}, payload: {request}")
    device.ws_req_id += 1
    message = device.ws.recv()
    logger.debug(f"Received authentication response from {device.host}, payload: {message}")
    return json.loads(message)
