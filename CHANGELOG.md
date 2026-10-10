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

- `ws_api.login` raises `CommunicationError` when the connection fails during authentication, instead of passing on
  the WebSocket or socket exception.
- 5.x devices log to the logger of their module, such as `PyNetioConf.ESPCore.esp_540_device`, instead of a logger
  named after the class, such as `ESP540Device`. Configuring the `PyNetioConf` logger now also covers them; code that
  configured the class-named loggers has to switch to the module names.
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
- On 5.x firmware, `update_firmware` no longer fails with `AttributeError` when the device was created with
  `keep_alive=False`.
- On 5.x firmware, `user_permissions` is now filled with the privileges of the logged-in user; it used to be always
  empty, so `update_firmware` on 5.1.x always failed with `PermissionError`. Creating a 5.x device sends one more
  request to read the privileges.
- `update_firmware` and `import_config` on 2.x.x-4.x.x, the 5.0.x beta and 5.1.x accept in-memory files such as
  `io.BytesIO`; they used to fail with `AttributeError` when logging the file name.
- On 5.1.x firmware, `import_config` failed with `AttributeError` when logging back in after the device restarted. It
  now reconnects with `login`.
- On 5.2.x and newer, `update_firmware` and `import_config` accept a file path (`str` or `os.PathLike`).
  `update_firmware` used to skip the upload for a path and continue as if the update had happened, and
  `import_config` ignored `Path` objects and missing files. `import_config` also accepts files opened in text mode,
  like on older firmware. Unsupported file types now raise `TypeError` and missing files `FileNotFoundError`, before
  anything is sent to the device.
- On 5.x firmware, logging in to a device that can't be reached kept calling itself until it failed with
  `RecursionError`, which took minutes. `login` now makes up to 3 attempts, each connecting if needed and sending
  HELO and AUTH, so a connection that drops during login is also retried, and then raises `CommunicationError`.
- `ws_api.send_request` reconnected without a limit when the connection kept dropping. It now keeps reconnecting for
  up to 60 seconds (`WS_RECONNECT_TIMEOUT`), starting a reconnect at most every 10 seconds (`WS_RECONNECT_INTERVAL`),
  and then raises `CommunicationError`.
- On 5.x firmware, a wrong username or password went unnoticed: creating the device failed later with a `KeyError`,
  and `login` reported success. A refused login now raises `AuthError` with the error code the device sent, such as
  `InvalidCredentials`, or `TooManyFailLogin` while the device refuses logins after repeated failures. `login` doesn't
  retry it, since every attempt counts towards that lockout. Code that caught `KeyError` for wrong credentials has to
  catch `AuthError`.

## [0.3.0b1] - 2026-10-05

First public release, published to PyPI as a beta.

[Unreleased]: https://github.com/netioproducts/PyNetioConf/compare/v0.3.0b1...HEAD
[0.3.0b1]: https://github.com/netioproducts/PyNetioConf/releases/tag/v0.3.0b1
