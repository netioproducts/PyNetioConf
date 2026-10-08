# Changelog

All notable changes to PyNetioConf are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [PEP 440](https://peps.python.org/pep-0440/) version numbers.

## [Unreleased]

### Added

- Support for firmware 5.4.x: devices running 5.4.0 and newer are created as the new `ESP540Device` class. On 5.4.x
  the library sends `GET` requests where older 5.x firmware uses `SUBSCRIBE`.
- 5.x devices record their firmware version in `version` as `(major, minor, patch)`.
- Python 3.15 support, including the 3.15 classifier and the release workflow's import test.

### Changed

- The parameters of `ws_api.send_request` are renamed from `type`, `topic` and `data` to `ws_type`, `ws_topic` and
  `ws_data`. Code that calls it with keyword arguments has to be updated.
- Creating a 5.x device no longer sends an extra HELO request when `NetioManager` already passed the HELO reply in.
- Documented every `__init__` parameter and keyword argument of the 5.x device classes, corrected the firmware
  versions in their class docstrings, and corrected the keep-alive interval in `NetioManager.init_device` to 120
  seconds.

### Fixed

- Firmware updates on 2.x.x-4.x.x devices and the 5.0.x beta no longer fail with `AttributeError` after the upload,
  the device now keeps the `NetioManager` it was created by.
- `NetioManager.update_device` now updates the device it was given; it used to match devices by serial number, which
  is empty for all devices, so with several devices it reconnected to the first one in the list.
- Firmware updates on 5.1.x and newer now also work when the device was created by a subclass of `NetioManager`.
- `system_reset` could end in a reboot loop: the reset request was sent again after the device dropped the
  connection to reboot. A `ConnectionResetError` now also triggers a reconnect.
- On 5.x firmware, `change_password` and `change_user_password` hashed the new password with an empty public key,
  which could lock the account out. On 5.2.x–5.3.x they failed with `AttributeError` instead. Both now use the
  device's current public key.
- Over HTTPS, reconnects, for example after a device restart, used no SSL options, so they could be rejected by the
  device's self-signed certificate. They now use the same options as the first connection. Creating a device with
  `use_https=True` without an already-authenticated connection no longer fails with `AttributeError`.

## [0.3.0b1] - 2026-10-05

First public release, published to PyPI as a beta.

[Unreleased]: https://github.com/netioproducts/PyNetioConf/compare/v0.3.0b1...HEAD
[0.3.0b1]: https://github.com/netioproducts/PyNetioConf/releases/tag/v0.3.0b1
