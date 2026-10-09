# Timings and timeouts
WS_EXECUTION_DELAY = 0.035  # Serves to give breathing room to the internal device timers and reduce unwanted restarts
WS_DEFAULT_TIMEOUT = 60
WS_RECONNECT_TIMEOUT = 60  # How long a request keeps reconnecting after the connection dropped, e.g. during a reboot
WS_RECONNECT_INTERVAL = 10  # Minimum time between the starts of two reconnects

CLOUD_DEFAULT_CONNECTION_WAIT = 10
CLOUD_ACTION_COMMUNICATION_DELAY = 3

DEVICE_RESET_GRACE_PERIOD = 5

# WebSocket 5.0.0+ communication constants
DEFAULT_REQUEST_QUEUE_LEN = 256
DEFAULT_KEEP_ALIVE_QUEUE_LEN = 64
