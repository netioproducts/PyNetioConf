# PyNetioConf

A Python module for configuring, controlling and monitoring NETIO devices with a unified API no matter which device
or firmware version you're using.

## Warning

This module is currently under development and is not ready for production use. There might be breaking changes
happening with relative frequency until the official release. The module is tested internally and should work
correctly, but should still be considered alpha release.

Currently, the module supports control and many configuration options on ESP devices running the 2.x.x through 5.x.x
firmware versions and basic socket control operations on legacy NETIO 4 devices.  
NOTE: Even though this library uses an API that supports older firmware versions such as 3.2.6, they are no longer
supported as firmware versions and any bugs on deprecated firmware versions won't be fixed.

## Installation

### Git

- Clone this repository and from the cloned folder install the module using pip:

```bash
git clone https://github.com/netioproducts/PyNetioConf.git
cd PyNetioConf

# If you can't or don't want to install site-wide packages create a virtual environment first:
python3 -m venv pnc_venv
source pnc_venv/bin/activate

pip3 install -e .
```

- To update you can simply run `git pull` in the `PyNetioConf` directory, since the package was installed with the
  `-e` flag, the changes will be reflected, but just to be sure you can rerun `pip3 install -e .`.

### Manual

- Alternatively if you don't have git installed, you can download the code as a ZIP file from GitHub by clicking the
  green "Code" button.
- After downloading the code, extract it to a directory and open that location in the terminal.
- Once in the target directory run the `pip3 install -e .` command to install the package.
    - If this produces an error or you wish to keep site-wide packages separate, create a virtual environment first
      before installing with pip: `python3 -m venv pnc_venv && source pnc_venv/bin/activate` then run
      `pip3 install -e .`

### PyPi

_PyPI planned in future release_.

## Usage

### Development

- After installing the pip package, you can easily use the library in your projects. To start off, you need to
  connect to the device, for that you need to create a `NetioManager` class instance which will handle any devices
  you connect to and their user sessions.

```python
from PyNetioConf import NetioManager

nm = NetioManager()
# The NetioManager instance handles all the devices and their sessions, preventing any session crowding and 
# collisions in case of multiple device instances

device = nm.init_device("powerpdu-8qs.netio-products.com", "demo", "demo")

# You can now control and configure the device using its class methods
# To check all the available methods check the NETIODevice class documentation.
device.set_output(1, False)

# While some cases should be universally available on all device versions, some featuers require
# certain firmware versions or user permissions, to be sure consult the NETIODevice class documentation.*

# To avoid any problems, encapsulate your logic in a try/except block
from PyNetioConf.exceptions import FeatureNotSupported

try:
    # MQTT certificate auth is only available on version 5.0.x or later
    device.upload_mqtt_ca_certificate("certificate_string")
except FeatureNotSupported as e:
    print("Device doesn't support MQTT cert authentication.")

# or

try:
    device.set_output(1, True)
except PermissionError as e:
    print("Logged in account doesn't have permissions to alter output states.")
```

_Note: Currently the firmware version and permission requirements might be missing and will be added over time. In
the meantime please check method implementations for your specific version in `esp_xxx_device.py` files_.

- To see sample usage of the package functions see: `src/PyNetioConf/examples/*`

### Using pre-made scripts

- This repository contains some common usage scenarios as pre-made example scripts, if you are only looking for
  specific use-case and don't intend to develop using this library this section goes over the usage of those scripts.
- All the pre-made scripts are located in `./src/PyNetioConf/examples/` and to use them you will need to have
  installed the library as described in the Installation section of the readme.
- Once you have the library installed you can choose whichever script you want to use and open the file in any text
  editor.
- In the editor you change any necessary constants (variables in UPPER_CASE) such as: `USERNAME` and `PASSWORD`
- For this example let's say I want to update the firmware using the `update_firmware.py` script:
    - First I follow the comments in the file and set all my constants to the ones of my device.
    - ```python
      DEVICE_IP = "192.168.1.17"
      USERNAME = "admin"
      PASSWORD = "admin"
      FIRMWARE_PATH = "/home/user/Downloads/release503.package"
    - Then I run the file with python from the `PyNetioConf` directory: `python3 
      src/PyNetioConf/examples/update_firmware.py`
    - If I did all the steps correctly I should see an output simillar to the following:
    - ```
      TODO
    - To use any of the other scripts, follow the comments in the file for instructions and then run it the same way
      as this script.

## Documentation

Documentation is currently provided for functions as docstrings in the source code. Different forms of documentation
are being worked on and will be provided as the library matures.

## Issues and Suggestions

If you find a bug or an issue, or have a suggestion, please use the GitHub issue tracker and create a new issue, before
doing so, check if your issue isn't listed already. If reporting a bug please turn on logging DEBUG level and include
the output in the report.
