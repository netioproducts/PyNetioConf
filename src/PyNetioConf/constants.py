from enum import StrEnum

# Timings and timeouts
WS_EXECUTION_DELAY = 0.03  # Serves to give breathing room to the internal device timers and reduce unwanted restarts
# Factors on WS_EXECUTION_DELAY and UPLOAD_CHUNK_PAUSE: on Wi-Fi, over HTTPS, and per smoothed latency above a threshold
WIFI_DELAY_FACTOR = 1.5
HTTPS_DELAY_FACTOR = 1.75
LATENCY_DELAY_STEPS = ((0.075, 1.15), (0.250, 1.15))  # (seconds, factor), each step on top of the ones below it
WS_DEFAULT_TIMEOUT = 60
WS_RECONNECT_TIMEOUT = 60  # How long a request keeps reconnecting after the connection dropped, e.g. during a reboot
WS_RECONNECT_INTERVAL = 10  # Minimum time between the starts of two reconnects

CLOUD_DEFAULT_CONNECTION_WAIT = 10  # Cloud backend communication before connecting TODO: check the lock
CLOUD_ACTION_COMMUNICATION_DELAY = 3  # TODO: Check the lock

DEVICE_RESET_GRACE_PERIOD = 5

# load_defaults: the device writes the default configuration for about 10 s and restarts. About 10 s after that boot it
# has a network address, marks itself installed and restarts once more, about 30 s after the request
# Wait before the first login: 5.1.3 writes its default files for 20 s before it restarts
LOAD_DEFAULTS_GRACE_PERIOD = 25
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
FIRMWARE_LIST_LOCK_TIMEOUT = 5  # How long the device may take to lock system/lock for the check; 0.1 to 0.5 s seen
# system/lock is followed by its events. Without one for this long it is read, for an event that didn't come
SYSTEM_LOCK_EVENT_WAIT = 5
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
OUTPUT_GROUP_COUNT = 4  # Firmware 5.4.0+ has the output groups 1 to 4; nothing creates or deletes one

# Rules, PABs, watchdogs and schedules (5.x): the limits of their topic table, and the config keys without which the
# firmware drops a watchdog or PAB or a rule never acts
BLOCK_NAME_MAX = 15  # Bytes as UTF-8
BLOCK_CONFIG_MAX = 1024  # Bytes of the config as JSON
RULE_CONFIG_REQUIRED = ("conditions", "actions")
WATCHDOG_CONFIG_REQUIRED = ("target", "pingInterval", "maxTimeouts", "timeToReboot", "maxRestarts")
PAB_CONFIG_REQUIRED: dict[str, tuple[str, ...]] = {
    "RANGE": ("source", "lowerBound", "upperBound", "timeHysteresis"),
    "ZONES": ("source", "thresholds", "timeHysteresis"),
    "DAYLIGHT": (),  # The firmware's own location stands in for a missing latitude or longitude
}
SCHEDULE_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
SCHEDULE_FROM_MAX = 86399  # Seconds since midnight
SCHEDULE_TO_MAX = 86400
# A create waits this long before it reads the new element, for the device to settle after it
BLOCK_CREATE_SETTLE = 1.0
BLOCK_LISTED_TIMEOUT = 5  # How long a create waits for the device to list the new element
BLOCK_LISTED_INTERVAL = 0.2  # Time between two reads of the list while waiting

# MQTT config, what the firmware takes (5.x)
MQTT_BROKER_REQUIRED = ("url", "port", "type", "username", "password", "protocol")
MQTT_PROTOCOLS = ("mqtt", "mqtts")
MQTT_CLIENT_ID_MAX = 31  # Characters, before the variables in it are expanded
MQTT_CONFIG_MAX = 8192  # Bytes of the config as JSON, the limit of protocols/mqtt/config
MQTT_EVENT_TYPES = ("timer", "change", "delta")
MQTT_TIMER_PERIOD_MIN = 5  # Seconds
MQTT_APPLY_TIMEOUT = 5  # How long set_mqttflex_state waits for the device to apply an enabled config
MQTT_APPLY_INTERVAL = 0.5  # Time between two reads of protocols/info while waiting
MQTT_LOG_TYPES = ("MQTT", "Variable parser")  # The log entries that say why a config wasn't applied

# Key and certificate uploads for HTTPS and MQTT (5.x): PEM files
PEM_FILE_MAX = 8192  # Bytes, the web interface's limit; the firmware has none
PEM_CERTIFICATE = ("CERTIFICATE",)  # The PEM blocks a certificate file holds
PEM_PRIVATE_KEY = ("PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY")  # The unencrypted keys the firmware reads
PEM_KEY_EXTRAS = ("EC PARAMETERS",)  # Blocks a key file may hold besides its key

# NBUS discover, firmware 5.4.0+
NBUS_DISCOVER_TIMEOUT = 35  # How long discover_nbus_devices waits for the devices found to report, the device 30 s
NBUS_DISCOVER_SEARCH = 2  # The search itself, before any device found can report; under a second on the line
NBUS_DISCOVER_INTERVAL = 1  # Time between two reads of nbus/devices while waiting
NBUS_DISCOVER_SAVE = 1  # Time for the device to save the line once the devices have reported

# WebSocket 5.0.0+ communication constants
DEFAULT_REQUEST_QUEUE_LEN = 256  # Amount of normal request to keep for lookback
DEFAULT_KEEP_ALIVE_QUEUE_LEN = 64  # Same for keep-alive
EVENT_QUEUE_LEN = 1024  # Events kept per device, the oldest dropped first


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


class TemperatureUnit(StrEnum):
    """The unit an input reports its temperature in (temperatureUnit in get_input_data()), set with
    set_input_temperature_unit()."""

    CELSIUS = "C"
    FAHRENHEIT = "F"


class NbusRole(StrEnum):
    """A device's role on its NBUS line, set_nbus_settings(). The master has its clients' outputs and inputs."""

    MASTER = "master"
    SLAVE = "slave"


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
