class NetioException(Exception):
    """Base class for all exceptions raised by this module"""
    pass


class ProtocolNotEnabled(NetioException):
    """Raised when the protocol is not enabled on the device"""
    pass


class CommunicationError(NetioException):
    """Raised when the connection to the Netio device fails"""
    def __init__(self, message: str, error: str = ""):
        super().__init__(message)
        self.error = error


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
