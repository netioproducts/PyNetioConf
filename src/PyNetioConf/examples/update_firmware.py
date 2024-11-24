from PyNetioConf import NetioManager

# To connect to devices we create an instance of NetioManager, which will manage
# sessions and devices, and ensure a singular connection to a device from the script
nm = NetioManager()

# To get a device object from NetioManager we use the init_device method
DEVICE_IP = "192.168.1.17"
USERNAME = "admin"
PASSWORD = "admin"
FIRMWARE_PATH = "/path/to/firmware/file.package"

netio_device = nm.init_device(DEVICE_IP, USERNAME, PASSWORD)

# Now that we have the device connected we ensure that we get responses from the device
print(netio_device.get_output_states())
# And just to be sure, let's print out the device version
print(netio_device.get_version_detailed())

# Now that we know the device is connected and alive, we can upgrade the firmware
# Note this operation can take considerable time, even over 5 minutes in some cases
with open(FIRMWARE_PATH, "rb") as fw_file:
    netio_device = netio_device.update_firmware(fw_file)

# Now we should be running on updated firmware, let's check it
print(netio_device.get_version_detailed())
