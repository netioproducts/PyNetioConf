from enum import Enum

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

# WebSocket 5.0.0+ communication constants
DEFAULT_REQUEST_QUEUE_LEN = 256  # Amount of normal request to keep for lookback
DEFAULT_KEEP_ALIVE_QUEUE_LEN = 64  # Same for keep-alive


# Not StrEnum, which needs Python 3.11, PyNetioConf supports 3.10
class OutputAction(str, Enum):  # noqa: UP042
    """
    What set_output_action() does to an output. The values are the requests firmware 5.x takes. The short actions last
    the output's reset delay (resetDelay in get_output_data(), set with set_output_reset_delay()).
    """

    ON = "on"
    OFF = "off"
    SHORT_ON = "son"  # On for the reset delay, then off
    SHORT_OFF = "soff"  # Off for the reset delay, then on
    TOGGLE = "toggle"


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
