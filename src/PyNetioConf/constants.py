from enum import StrEnum

# Timings and timeouts
WS_EXECUTION_DELAY = 0.035  # Serves to give breathing room to the internal device timers and reduce unwanted restarts
WS_DEFAULT_TIMEOUT = 60
WS_RECONNECT_TIMEOUT = 60  # How long a request keeps reconnecting after the connection dropped, e.g. during a reboot
WS_RECONNECT_INTERVAL = 10  # Minimum time between the starts of two reconnects

CLOUD_DEFAULT_CONNECTION_WAIT = 10  # Cloud backend communication before connecting TODO: check the lock
CLOUD_ACTION_COMMUNICATION_DELAY = 3  # TODO: Check the lock

DEVICE_RESET_GRACE_PERIOD = 5

# load_defaults: the device writes the default configuration for about 10 s and restarts. About 10 s after that boot it
# has a network address, marks itself installed and restarts once more, about 30 s after the request
LOAD_DEFAULTS_GRACE_PERIOD = 15  # Wait before the first login, so it doesn't reach the device before it restarts
LOAD_DEFAULTS_RETRY_INTERVAL = 2  # Time between two login attempts while the device restarts
LOAD_DEFAULTS_SETTLE_UPTIME = 40  # An installed device up this long has had its restart after installing
LOAD_DEFAULTS_TIMEOUT = 180  # How long load_defaults waits for the device to come back

# Credentials of the only user a device has after loading the default configuration
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin"

# The device confirms a created or deleted user before users/list shows the change
USER_LIST_SYNC_TIMEOUT = 3  # How long create_user and remove_user wait for users/list to show the change
USER_LIST_SYNC_INTERVAL = 0.5  # Time between two checks of users/list while waiting

# get_firmware_updates_list: the device asks the update server, which takes a few seconds, and locks system/lock
# meanwhile. It unlocks when the request ends and rebuilds fwupdate/list about 0.4 s later
FIRMWARE_LIST_TIMEOUT = 60  # How long get_firmware_updates_list waits for the update server's answer
FIRMWARE_LIST_INTERVAL = 0.2  # Time between two reads of system/lock or fwupdate/list while waiting
FIRMWARE_LIST_SETTLE = 2  # How long the list has to stay unchanged after the unlock to count as the same answer
FIRMWARE_LIST_CACHE_TIME = 120  # How long get_firmware_updates_list reuses its last answer instead of checking again

# update_firmware_online: the device downloads the firmware, restarts and boots it. A failed download restarts it as
# well. The firmware is written to try again after the restart, 3 attempts in all, but 5.4.0 with NETIO Cloud disabled
# didn't
ONLINE_UPDATE_START_TIMEOUT = 10  # How long the device may take to lock system/lock for the update
ONLINE_UPDATE_TIMEOUT = 900  # How long update_firmware_online waits for the device to run the new firmware
ONLINE_UPDATE_INTERVAL = 5  # Time between two reads of the uptime while waiting
ONLINE_UPDATE_ATTEMPTS = 3  # How often the device tries the download before it gives up
ONLINE_UPDATE_RETRY_WAIT = 60  # How long a device back from a failed attempt may take to start the next one
ONLINE_UPDATE_RETRY_INTERVAL = 1  # Time between two reads of system/lock while waiting for the next attempt

# set_server_settings: a change of the web server settings restarts the device about 3 s after the request, and it is
# reachable again about 10 s after that
WEB_SERVER_RESTART_TIMEOUT = 60  # How long set_server_settings waits for the device to come back
WEB_SERVER_RESTART_INTERVAL = 2  # Time between two login attempts while the device restarts

# Uploads. After a firmware update or a configuration import the device restarts, sometimes before it replies
UPLOAD_CHUNK_TIMEOUT = 30  # How long a chunk waits for its reply
UPLOAD_CHUNK_PAUSE = 0.1  # Time between two chunks
UPLOAD_RESTART_REPLY_TIMEOUT = 30  # How long the upload before a restart waits for its reply, then takes the restart
CONFIG_IMPORT_RESTART_TIMEOUT = 90  # How long import_config waits for the device to come back

# Output delays in milliseconds, as the web interface takes them. It allows 4294967296 too, which doesn't fit the
# device's 32-bit value
OUTPUT_RESET_DELAY_MIN = 100
OUTPUT_POWER_UP_INTERVAL_MIN = 0
OUTPUT_DELAY_MAX = 4294967295

# WebSocket 5.0.0+ communication constants
DEFAULT_REQUEST_QUEUE_LEN = 256  # Amount of normal request to keep for lookback
DEFAULT_KEEP_ALIVE_QUEUE_LEN = 64  # Same for keep-alive


class OutputAction(StrEnum):
    """
    What set_output_action() does to an output. The values are the requests firmware 5.x takes. The short actions last
    the output's reset delay (resetDelay in get_output_data(), set with set_output_reset_delay()).
    """

    ON = "on"
    OFF = "off"
    SHORT_ON = "son"  # On for the reset delay, then off
    SHORT_OFF = "soff"  # Off for the reset delay, then on
    TOGGLE = "toggle"


class OutputPowerUpState(StrEnum):
    """
    The state an output takes when the device powers up after a power loss, set_output_power_up_state(). A restart of
    the device keeps the outputs as they are.
    """

    ON = "on"
    OFF = "off"
    LAST = "last"  # The state before the power loss


# The choices of the protocol and network setters. The setters take the plain strings as well, the members are strings.
class NetworkMode(StrEnum):
    """How set_ethernet_settings() gets the device's address."""

    DHCP = "dhcp"
    STATIC = "static"


class PushProtocol(StrEnum):
    """The format of the Netio Push messages, set_netio_push_api_state() takes the lower case names as well."""

    JSON = "JSON"
    XML = "XML"


class SnmpSecurityLevel(StrEnum):
    """The SNMP v3 security level, set_snmp_v3_api_state()."""

    AUTH_PRIV = "authPriv"  # Authentication and encryption
    AUTH_NO_PRIV = "authNoPriv"  # Authentication only
    NO_AUTH_NO_PRIV = "noAuthNoPriv"  # Neither


class SnmpAuthProtocol(StrEnum):
    """The SNMP v3 authentication algorithm, set_snmp_v3_api_state()."""

    MD5 = "MD5"
    SHA = "SHA"


class SnmpPrivProtocol(StrEnum):
    """The SNMP v3 encryption algorithm, set_snmp_v3_api_state()."""

    AES = "AES"
    DES = "DES"


# Privileges a user can have on 5.0.0+ firmware, the device expects every one of them in a user's config
USER_PRIVILEGES = (
    "can_alter_rules",
    "can_alter_settings",
    "can_alter_users",
    "can_login",
    "can_control_outputs",
    "can_alter_outputs",
    "can_view_settings",
    "can_alter_devices",
    "can_view_history",
    "can_control_user_buttons",
    "can_browse_logs",
    "can_use_tunnels",
)
