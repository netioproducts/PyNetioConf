from PyNetioConf import NetioManager

# We start by creating a NetioManager class that will manage all the devices and their sessions as they update.
netio_manager = NetioManager()

# Now let's create a list of all the devices we want to update, to update a device we need 4 things: IP, username,
# password, and the firmware file

# For this example let's update all devices to the same firmware, but you can pick and choose by changing the FW_FILE
# in each device definition.
FW_FILE = "/path/to/firmware.package"

DEVICE_LIST = [
    ("192.168.1.10", "admin", "admin", FW_FILE),
    ("192.168.1.11", "admin", "admin", FW_FILE),
    ("192.168.1.12", "admin", "admin", FW_FILE),
    ("192.168.1.13", "admin", "admin", FW_FILE),
]

# Now all we need to do is update the devices
for device_info in DEVICE_LIST:
    device = netio_manager.init_device(device_info[0], device_info[1], device_info[2])
    # We check the device version before upgrading the firmware
    old_version = device.get_version()
    # print(old_version) # We can print it to check it before the update
    # Then we run the device update, note that this might take quite a while depending on the device
    with open(FW_FILE, "rb") as fw:
        device = device.update_firmware(fw)
    # And after all that is done we compare the device version again.
    new_version = device.get_version()
    print(f"Updated device with host: {device_info[0]} from {old_version} to {new_version}.")
