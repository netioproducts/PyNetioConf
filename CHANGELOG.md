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
- `set_user_privileges(username, privileges)` replaces the privileges of an existing user on 5.x firmware. On
  2.x.x-4.x.x devices and the 5.0.x beta it raises `NotImplementedError`.
- `set_user_privilege(username, privilege, state)` grants or takes away one privilege of an existing user on 5.x
  firmware and leaves the others as they are. On 2.x.x-4.x.x devices and the 5.0.x beta it raises
  `NotImplementedError`.
- `constants.USER_PRIVILEGES` lists the privileges a user can have on 5.x firmware.
- `load_defaults()` resets a 5.x device to its factory default configuration, waits until it has restarted and logs in
  again as admin with the default password admin, which the device object uses from then on. The device restarts twice,
  the second time when it marks itself installed; `load_defaults()` returns after both, about a minute after the
  request. The network settings are reset too, so a device with a static IP address can come back at another address.
  Checked on 5.4.0. On 2.x.x-4.x.x devices and the 5.0.x beta it raises `NotImplementedError`. The timing is set by
  `LOAD_DEFAULTS_GRACE_PERIOD`, `LOAD_DEFAULTS_RETRY_INTERVAL`, `LOAD_DEFAULTS_SETTLE_UPTIME` and
  `LOAD_DEFAULTS_TIMEOUT`, and the default credentials are `DEFAULT_USERNAME` and `DEFAULT_PASSWORD` in `constants`.
- `set_output_action(output_id, action)` controls an output with an `OutputAction` from `constants`: `ON`, `OFF`,
  `SHORT_ON`, `SHORT_OFF` or `TOGGLE`. The short actions switch the output for its reset delay and then back.
  `short_on_output(output_id)` and `toggle_output(output_id)` do one action each, like `set_output` and
  `reset_output`, which now go through `set_output_action` as well. On 2.x.x-4.x.x devices and the 5.0.x beta,
  `set_output_action` does `ON`, `OFF` and `SHORT_OFF` with the requests `set_output` and `reset_output` already used,
  and raises `NotImplementedError` for the others, like `short_on_output` and `toggle_output` do there.
- `set_output_reset_delay(output_id, reset_delay)` sets an output's reset delay in milliseconds on 5.x firmware. On
  2.x.x-4.x.x devices and the 5.0.x beta it raises `NotImplementedError`.
- Enums in `constants` for the settings that take one of a few strings: `NetworkMode` for `set_ethernet_settings`,
  `PushProtocol` for `set_netio_push_api_state`, and `SnmpSecurityLevel`, `SnmpAuthProtocol` and `SnmpPrivProtocol`
  for `set_snmp_v3_api_state`. They are `StrEnum`s, so the plain strings keep working.
- `get_xml_api_state`, `get_urlapi_state`, `create_rule`, `delete_rule_by_name`, `create_pab` and `create_watchdog`,
  which 5.x devices already had, are part of `NETIODevice` now, so they show up for any device `init_device` returns.
  On 2.x.x-4.x.x devices and the 5.0.x beta they raise `NotImplementedError`.

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
- On 5.x firmware, `create_user` raises `InvalidParameterValueError` for privileges the device doesn't know, which it
  used to drop without a word, and `ElementAlreadyExists` for a username that is taken, where the device used to
  keep the existing user unchanged and report success. `remove_user` raises `ElementNotFound` for a user that doesn't
  exist. Code that relied on these calls passing has to handle the exceptions.
- On 5.x firmware, `create_user` and `remove_user` return once `get_users()` shows the change, which the device can
  take a moment to do. They check every 0.5 seconds for up to 3 seconds (`USER_LIST_SYNC_INTERVAL`,
  `USER_LIST_SYNC_TIMEOUT`) and then raise `CommunicationError`. The user management methods also send one more
  `users/list` request to check that the user exists.
- On 2.x.x-4.x.x devices and the 5.0.x beta, `get_users` returns a dictionary keyed by username, as documented and as
  on 5.x firmware, instead of the device's list of users. Code that iterated the list has to iterate `.values()`.
- On 5.x firmware, `set_ethernet_settings` and `set_snmp_v3_api_state` raise `InvalidParameterValueError` for a
  `network_mode`, `security_level`, `auth_protocol` or `priv_protocol` the device doesn't know, before sending
  anything, instead of sending it to the device. `set_netio_push_api_state` already did that for `push_protocol`.
- Modules no longer import names they don't use, so those names can't be imported from them any more. For example
  `from PyNetioConf.NetioManager import FirmwareVersionNotSupported` now fails; import exceptions from
  `PyNetioConf.exceptions`, constants from `PyNetioConf.constants`, and the device classes from their own modules.
  `PyNetioConf` declares `__all__ = ["NetioManager"]`, so `from PyNetioConf import *` imports only `NetioManager`.
- When a 5.x connection attempt fails, the debug log says why.
- On 5.x firmware, `netio_push_api_push_now` raises `FeatureNotSupported` instead of `NotImplementedError`. 5.x
  firmware has no supported way to push on demand; it pushes on its period and when the current changes. Code that
  catches `NotImplementedError` around the call has to catch `FeatureNotSupported`.

### Deprecated

- `get_measurement()` on 5.x devices. It warns with `DeprecationWarning`, returns what `get_outputs_data()` returns
  and will be removed in 1.0. It used to return the device's whole reply to `outputs/measure`, so code that read
  `type`, `status` or `data` from it breaks; use `get_outputs_data()`.

### Removed

- Support for Python 3.10, which reached its end of life in October 2026. PyNetioConf now needs Python 3.11 or newer.
  On Python 3.10, pip and uv keep installing 0.3.0b1.

### Fixed

- `update_firmware` takes the path of the firmware file on every firmware version, as it already did on 5.2.x and
  newer. On 2.x.x-4.x.x devices, the 5.0.x beta and 5.1.x only a file opened in binary mode worked, although 5.1.x
  declared a path. `NETIODevice.update_firmware` documents the parameter and that it returns the device object for
  the new firmware.
- `import_config` takes the path of the configuration file on every firmware version, as it already did on 5.2.x and
  newer. On 2.x.x-4.x.x devices, the 5.0.x beta and 5.1.x only an open file worked. `NETIODevice.import_config`
  documents the paths and files it takes.
- `update_firmware` on 2.x.x-4.x.x devices raises `CommunicationError` when the device has no `NetioManager` to create
  the updated device object, instead of `AttributeError`, as on 5.x.
- Certificate and key uploads (`esp_api.send_file`, used for the MQTT and HTTPS certificates) no longer fail with
  `UnboundLocalError` when they retry an HTTPS server key or certificate after a failed attempt. An upload path of a
  kind the library doesn't know raises `CommunicationError` instead of `UnboundLocalError`.
- `create_rule`, `create_pab`, `create_watchdog` and `create_schedule` raise `ElementAlreadyExists` when the name is
  taken, instead of `RuntimeError: No active exception to reraise`.
- `examples/usage_example.py` calls `get_output_states()`, the `get_socket_states()` it called no longer exists.
- Ctrl-C stops the program while `init_device` detects the firmware version and during `esp_api.check_connectivity`.
  Both caught every exception, `KeyboardInterrupt` included; now `check_connectivity` catches only request errors and
  the version detection only `Exception`.
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
- On 5.x firmware, `get_user_privileges` and `change_user_password` for a user that doesn't exist raise
  `ElementNotFound`. They used to request that user's config, which made firmware 5.4.0 restart, and failed after a
  minute with `CommunicationError`.
- On 5.x firmware, `change_password`, and `change_user_password` for the logged-in user, also change the password the
  device object logs in with, so logging in again after a dropped connection no longer fails with `AuthError`.
- Corrected the docstrings of the user management methods: the privileges `create_user` accepts, what `get_users`
  returns, which privilege changing a password needs, and that 5.x firmware doesn't use `old_password`.
- On 2.x.x-4.x.x devices and the 5.0.x beta, `change_password` passed its arguments to `change_user_password` in the
  wrong order, so it sent the new password as the username and the current password as the new one.
- On 2.x.x-4.x.x devices and the 5.0.x beta, `change_user_password` no longer writes the new password into its debug
  log message.
- `login` with other credentials than the device object had kept the old `username`, `password` and
  `user_permissions`. `change_password` then changed the previous user's password, and the logins after a dropped
  connection went back to the previous user. `login` now keeps the credentials of a successful login and, when the
  user changes, reads the new user's privileges into `user_permissions`.
- On 5.x firmware, `reset_output` resets the output: it switches it off for its reset delay and then on again. It used to
  raise `NotImplementedError`.
- On 5.x firmware, `logout` now closes the WebSocket connection and stops the keep-alive. It used to only drop the
  connection, so the device kept the session open until Python's garbage collector closed the socket, and on 5.2.x and
  newer the keep-alive logged in again on a new connection within 120 seconds. The device has room for only a few
  sessions, and firmware 5.4.0 restarts when a new connection finds them all taken. The connections left behind by
  failed login attempts, reconnects, device objects that failed to initialize and the exit of the program are closed as
  well.

## [0.3.0b1] - 2026-10-05

First public release, published to PyPI as a beta.

[Unreleased]: https://github.com/netioproducts/PyNetioConf/compare/v0.3.0b1...HEAD
[0.3.0b1]: https://github.com/netioproducts/PyNetioConf/releases/tag/v0.3.0b1
