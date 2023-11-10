# Import NetioManager, this is all you need to do to start controlling devices
from PyNetioConf import NetioManager

# To see the debug messages, uncomment the following lines
# import logging
# logging.basicConfig(level=logging.DEBUG)

# Create a NetioManager instance
demo_devices = NetioManager()
# You can have multiple instances of NetioManager, each with its own list of connected devices
# which get logged out if you drop the manager instance.

# local_devices = NetioManager()
# local_device = local_devices.init_device("0.0.0.0", "admin", "admin")

# Initialization of ESP devices and NETIO4 is the same, as is the api for controlling them
demo_8qs = demo_devices.init_device("powerpdu-8qs.netio-products.com", "demo", "demo")

# Features can be found in NETIODevice.py doc comments, before public realease I'll make an automated
# documentation generator for the whole project.

# See the socket states
print(f"{demo_8qs.hostname} socket states {demo_8qs.get_socket_states()}")
demo_8qs.set_output(1, False)
print(f"{demo_8qs.hostname} socket states {demo_8qs.get_socket_states()}")
demo_8qs.set_output(1, True)
print(f"{demo_8qs.hostname} socket states {demo_8qs.get_socket_states()}")
# demo_8qs.set_output(0, True) # Using PyNetioConf out of bounds would throw an Exception

demo_4ps = demo_devices.init_device("powerpdu-4ps.netio-products.com:22888", "demo", "demo")
demo_4ps.set_output(1, True)

demo_4c = demo_devices.init_device("netio-4c.netio-products.com", "demo", "demo")
demo_4c.set_output(1, True)
demo_4c.set_outputs_unified(False)
print(f"{demo_4c.hostname} socket states {demo_4c.get_socket_states()}")

# Devices throw exceptions when you try to set features that aren't supported
# demo_8qs.get_wifi_settings() # Throws a FeatureNotSupported exception

# Safe way of getting json api data, if protocol is disabled an exception would be raised
if demo_8qs.get_json_api_state()["enable"]:
    print(demo_8qs.get_json(("", ""))["Agent"]["Time"])

# print(demo_8qs.get_xml(("", ""))) # Would throw an Exception as the xml is disabled on the demo unit

# Function documentation can be found in NETIODevice.py docstrings.
