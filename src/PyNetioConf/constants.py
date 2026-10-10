# Timings and timeouts
WS_EXECUTION_DELAY = 0.035  # Serves to give breathing room to the internal device timers and reduce unwanted restarts
WS_DEFAULT_TIMEOUT = 60
WS_RECONNECT_TIMEOUT = 60  # How long a request keeps reconnecting after the connection dropped, e.g. during a reboot
WS_RECONNECT_INTERVAL = 10  # Minimum time between the starts of two reconnects

CLOUD_DEFAULT_CONNECTION_WAIT = 10
CLOUD_ACTION_COMMUNICATION_DELAY = 3

DEVICE_RESET_GRACE_PERIOD = 5

# The device confirms a created or deleted user before users/list shows the change
USER_LIST_SYNC_TIMEOUT = 3  # How long create_user and remove_user wait for users/list to show the change
USER_LIST_SYNC_INTERVAL = 0.5  # Time between two checks of users/list while waiting

# WebSocket 5.0.0+ communication constants
DEFAULT_REQUEST_QUEUE_LEN = 256
DEFAULT_KEEP_ALIVE_QUEUE_LEN = 64

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
