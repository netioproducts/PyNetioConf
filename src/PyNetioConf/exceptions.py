class NetioException(Exception):
    """Base class for all exceptions raised by this module"""

    pass


class ElementAlreadyExists(NetioException):
    """Raised when trying to create an element that already exists"""

    pass


class ProtocolNotEnabled(NetioException):
    """Raised when the protocol is not enabled on the device"""

    pass


class CommunicationError(NetioException):
    """Raised when the connection to the Netio device fails"""

    def __init__(self, message: str, error: str = ""):
        super().__init__(message)
        self.error = error


class DeviceError(NetioException):
    """
    Raised when the device answers a request with an error (`"status": "ERROR"`). `code` is the device's error code,
    such as `TopicNotFonud` or `MissingParameter`, `message` the text it sent with it, and `topic` the request's topic.
    """

    def __init__(self, host: str, ws_type: str, topic: str | None, code: str, message: str = ""):
        description = f"Device {host} answered {ws_type} {topic or '(no topic)'} with {code}"
        super().__init__(f"{description}: {message}" if message else description)
        self.host = host
        self.ws_type = ws_type
        self.topic = topic
        self.code = code
        self.message = message


class UnauthorizedError(DeviceError, PermissionError):
    """Raised when the device refuses a request as `Unauthorized`: the user lacks the privilege for it."""

    pass


class AuthError(NetioException):
    """Raised when the authentication with the Netio device fails"""

    pass


class FeatureNotSupported(NetioException):
    """Raised when the device type is not supported"""

    pass


class FirmwareVersionNotSupported(NetioException):
    """Raised when the firmware version is not supported"""

    pass


class DeviceNotYetSupported(NetioException):
    """Raised when the device is not yet supported"""

    pass


class InvalidSocketIndex(NetioException):
    """Raised when the socket index is invalid"""

    pass


class ElementNotFound(NetioException):
    """Raised when looking for an element that doesn't exist on the device."""

    pass


class InvalidParameterValueError(NetioException):
    """Raised when trying to set an invalid paremeter in protocol or configuration methods"""

    pass
