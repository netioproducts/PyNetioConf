# PyNetioConf

A Python module for configuring, controlling and monitoring NETIO devices with a unified API no matter which device
or firmware version you're using.

## Warning

This module is currently under development and is not ready for production use. There might be breaking changes
happening with relative frequency until the official release. The module is tested internally and should work
correctly, but should still be considered alpha release.

Currently, the module supports ESP devices running the 4.0.x firmware and basic socket on/off operations on NETIO 4
devices.

## Installation

_PyPI planned in future release_.

- Clone this repository and from the cloned folder install the module using pip:

```bash
git clone https://github.com/netioproducts/PyNetioConf.git
cd PyNetioConf
pip3 install -e .
```

- You can now use the package in your project:

```python
from PyNetioConf import NetioManager

nm = NetioManager()
device = nm.init_device("powerpdu-8qs.netio-products.com", "demo", "demo")
device.set_output(1, False)
```

- To see sample usage of the package functions see: `src/PyNetioConf/examples/usage_example.py`

## Documentation

Documentation is currently provided for functions as docstrings in the source code. PDF and online versions of the
documentation will be provided when the API stabilizes in future releases.

## Issues and Suggestions

If you find a bug or an issue, or have a suggestion, please use the GitHub issue tracker and create a new issue, before doing so, check if your issue isn't listed already. If reporting a bug please turn on logging DEBUG level and include the output in the report.
