"""
The groups of a device's methods: `device.outputs`, `device.rules`, `device.protocols.mqtt` and the others. Every method
here calls the method of `NETIODevice` that its docstring names, which also holds the full documentation.
"""

import io
import os
from functools import cached_property
from typing import TYPE_CHECKING, Any
from xml.etree.ElementTree import Element

from .constants import (
    NBUS_DISCOVER_TIMEOUT,
    NbusRole,
    NetworkMode,
    OutputAction,
    OutputPowerUpState,
    PushProtocol,
    SnmpAuthProtocol,
    SnmpPrivProtocol,
    SnmpSecurityLevel,
    TemperatureUnit,
)

if TYPE_CHECKING:
    from .netio_device import NETIODevice


# The methods of NETIODevice that have no group
TOP_LEVEL = frozenset({"login", "logout", "ping"})


# Every other public method of NETIODevice and where its group has it
GROUPED: dict[str, str] = {
    "get_output_state": "outputs.get_state",
    "set_output": "outputs.set",
    "set_outputs_unified": "outputs.set_unified",
    "set_output_action": "outputs.set_action",
    "reset_output": "outputs.reset",
    "short_on_output": "outputs.short_on",
    "toggle_output": "outputs.toggle",
    "set_output_reset_delay": "outputs.set_reset_delay",
    "set_output_power_up_state": "outputs.set_power_up_state",
    "set_output_power_up_interval": "outputs.set_power_up_interval",
    "rename_output": "outputs.rename",
    "set_output_schedule": "outputs.set_schedule",
    "get_output_schedule": "outputs.get_schedule",
    "get_output_schedule_id": "outputs.get_schedule_id",
    "set_output_schedule_state": "outputs.set_schedule_state",
    "set_output_schedule_by_name": "outputs.set_schedule_by_name",
    "get_output_data": "outputs.get_data",
    "get_outputs_data": "outputs.get_all_data",
    "get_output_states": "outputs.get_states",
    "get_outputs_list": "outputs.get_all",
    "set_output_group_id": "outputs.set_group_id",
    "get_output_groups": "outputs.groups.get_all",
    "get_output_group": "outputs.groups.get",
    "set_output_group": "outputs.groups.set",
    "set_output_group_action": "outputs.groups.set_action",
    "switch_output_group": "outputs.groups.switch",
    "get_input_list": "inputs.get_all",
    "get_input_data": "inputs.get_data",
    "rename_input": "inputs.rename",
    "set_input_temperature_unit": "inputs.set_temperature_unit",
    "get_global_measurement": "measurement.get_global",
    "reset_power_consumption_counters": "measurement.reset_counters",
    "reset_output_consumption_counter": "measurement.reset_output_counter",
    "reset_global_consumption_counter": "measurement.reset_global_counter",
    "has_nbus": "nbus.supported",
    "get_nbus_settings": "nbus.get_settings",
    "set_nbus_settings": "nbus.set_settings",
    "discover_nbus_devices": "nbus.discover",
    "get_nbus_devices": "nbus.get_devices",
    "delete_nbus_device": "nbus.delete_device",
    "locate_nbus_device": "nbus.locate_device",
    "set_nbus_device_order": "nbus.set_device_order",
    "get_nbus_mapping": "nbus.get_mapping",
    "get_rules": "rules.get_all",
    "get_enabled_rules": "rules.get_enabled",
    "get_disabled_rules": "rules.get_disabled",
    "get_rule_by_name": "rules.get",
    "create_rule": "rules.create",
    "set_rule": "rules.set",
    "delete_rule_by_name": "rules.delete",
    "get_watchdogs": "watchdogs.get_all",
    "get_enabled_watchdogs": "watchdogs.get_enabled",
    "get_disabled_watchdogs": "watchdogs.get_disabled",
    "get_watchdog_by_name": "watchdogs.get",
    "create_watchdog": "watchdogs.create",
    "set_watchdog": "watchdogs.set",
    "delete_watchdog_by_name": "watchdogs.delete",
    "get_pabs": "pabs.get_all",
    "get_enabled_pabs": "pabs.get_enabled",
    "get_disabled_pabs": "pabs.get_disabled",
    "get_pab_by_name": "pabs.get",
    "create_pab": "pabs.create",
    "set_pab": "pabs.set",
    "delete_pab_by_name": "pabs.delete",
    "get_schedules": "schedules.get_all",
    "get_active_schedules": "schedules.get_active",
    "get_schedule_names": "schedules.get_names",
    "get_schedule_by_name": "schedules.get",
    "get_schedule_id": "schedules.get_id",
    "create_schedule": "schedules.create",
    "set_schedule": "schedules.set",
    "delete_schedule_by_name": "schedules.delete",
    "delete_schedule": "schedules.delete_by_id",
    "get_users": "users.get_all",
    "get_current_user": "users.get_current",
    "get_user_privileges": "users.get_privileges",
    "set_user_privileges": "users.set_privileges",
    "set_user_privilege": "users.set_privilege",
    "create_user": "users.create",
    "remove_user": "users.remove",
    "change_user_password": "users.change_password",
    "change_password": "users.change_own_password",
    "get_ethernet_settings": "network.get_ethernet_settings",
    "get_ethernet_status": "network.get_ethernet_status",
    "set_ethernet_settings": "network.set_ethernet_settings",
    "get_wifi_settings": "network.get_wifi_settings",
    "get_wifi_status": "network.get_wifi_status",
    "set_wifi_settings": "network.set_wifi_settings",
    "set_wifi_static_address": "network.set_wifi_static_address",
    "get_server_settings": "network.get_server_settings",
    "set_server_settings": "network.set_server_settings",
    "upload_https_private_key": "network.upload_https_private_key",
    "upload_https_certificate": "network.upload_https_certificate",
    "get_version": "system.get_version",
    "get_version_detailed": "system.get_version_detailed",
    "get_version_revision": "system.get_version_revision",
    "get_features": "system.get_features",
    "get_system_info": "system.get_info",
    "get_system_settings": "system.get_settings",
    "set_system_settings": "system.set_settings",
    "rename_device": "system.rename",
    "get_uptime": "system.get_uptime",
    "get_system_datetime": "system.get_datetime",
    "set_system_datetime": "system.set_datetime",
    "set_periodic_restart": "system.set_periodic_restart",
    "locate": "system.locate",
    "system_reset": "system.reset",
    "load_defaults": "system.load_defaults",
    "import_config": "system.import_config",
    "export_config": "system.export_config",
    "get_system_lock": "system.get_lock",
    "get_system_notifications": "system.get_notifications",
    "get_system_log": "system.get_log",
    "clear_system_log": "system.clear_log",
    "update_firmware": "firmware.update",
    "get_firmware_updates_list": "firmware.get_updates",
    "is_update_available": "firmware.is_update_available",
    "update_firmware_online": "firmware.update_online",
    "update_firmware_incl_low_level_online": "firmware.update_online_incl_low_level",
    "get_active_protocols": "protocols.get_active",
    "get_supported_protocols": "protocols.get_supported",
    "get_cloud_state": "protocols.cloud.get_state",
    "set_cloud_state": "protocols.cloud.set_state",
    "set_on_premise": "protocols.cloud.set_on_premise",
    "register_to_cloud": "protocols.cloud.register",
    "get_urlapi_state": "protocols.urlapi.get_state",
    "set_urlapi_state": "protocols.urlapi.set_state",
    "get_modbus_state": "protocols.modbus.get_state",
    "set_modbus_state": "protocols.modbus.set_state",
    "get_mqttflex_state": "protocols.mqtt.get_state",
    "set_mqttflex_state": "protocols.mqtt.set_state",
    "upload_mqtt_client_key": "protocols.mqtt.upload_client_key",
    "upload_mqtt_client_certificate": "protocols.mqtt.upload_client_certificate",
    "upload_mqtt_ca_certificate": "protocols.mqtt.upload_ca_certificate",
    "get_json_api_state": "protocols.json.get_state",
    "set_json_api_state": "protocols.json.set_state",
    "get_json": "protocols.json.read",
    "get_xml_api_state": "protocols.xml.get_state",
    "set_xml_api_state": "protocols.xml.set_state",
    "get_xml": "protocols.xml.read",
    "get_netio_push_api_state": "protocols.push.get_state",
    "set_netio_push_api_state": "protocols.push.set_state",
    "netio_push_api_push_now": "protocols.push.push_now",
    "get_snmp_api_state": "protocols.snmp.get_state",
    "set_snmp_v1_2_api_state": "protocols.snmp.set_v1_2_state",
    "set_snmp_v3_api_state": "protocols.snmp.set_v3_state",
    "get_telnet_api_state": "protocols.telnet.get_state",
    "set_telnet_api_state": "protocols.telnet.set_state",
}


class _Group:
    def __init__(self, device: "NETIODevice") -> None:
        self._device = device


class OutputGroups(_Group):
    """The output groups."""

    def get_all(self) -> list[dict[str, Any]]:
        """
        Lists the output groups. The device has OUTPUT_GROUP_COUNT groups, 1 to OUTPUT_GROUP_COUNT; nothing creates or
        deletes one. Experimental: output groups came with firmware 5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.get_output_groups`.
        """
        return self._device.get_output_groups()

    def get(self, group_id: int) -> dict[str, Any]:
        """
        Gets an output group's settings. Experimental: output groups came with firmware 5.4.0, which isn't released
        yet.

        Full documentation: `NETIODevice.get_output_group`.
        """
        return self._device.get_output_group(group_id)

    def set(
        self,
        group_id: int,
        name: str | None = None,
        power_up_state: OutputPowerUpState | None = None,
        reset_delay: int | None = None,
        outputs: dict[int, int] | None = None,
    ) -> None:
        """
        Changes an output group's settings. None keeps the value the device has. Experimental: output groups came
        with firmware 5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.set_output_group`.
        """
        self._device.set_output_group(group_id, name, power_up_state, reset_delay, outputs)

    def set_action(self, group_id: int, action: OutputAction) -> None:
        """
        Switches an output group's outputs. OFF and SHORT_OFF switch them at once; ON and SHORT_ON switch them one
        after another, each at its power-up interval after the request. The short actions last the group's reset
        delay from the request, then SHORT_ON switches the outputs off at once and SHORT_OFF on at their intervals
        again. TOGGLE isn't taken for a group. Experimental: output groups came with firmware 5.4.0, which isn't
        released yet.

        Full documentation: `NETIODevice.set_output_group_action`.
        """
        self._device.set_output_group_action(group_id, action)

    def switch(self, group_id: int, state: bool) -> None:
        """
        Switches an output group on or off: set_output_group_action() with ON or OFF. Experimental: output groups
        came with firmware 5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.switch_output_group`.
        """
        self._device.switch_output_group(group_id, state)


class Cloud(_Group):
    """NETIO Cloud."""

    def get_state(self) -> dict[str, Any]:
        """
        Get the cloud state of the device.

        Full documentation: `NETIODevice.get_cloud_state`.
        """
        return self._device.get_cloud_state()

    def set_state(self, state: bool) -> None:
        """
        Set the cloud state of the device.

        Full documentation: `NETIODevice.set_cloud_state`.
        """
        self._device.set_cloud_state(state)

    def set_on_premise(self, url: str) -> None:
        """
        Set the on-premise server of the device.

        Full documentation: `NETIODevice.set_on_premise`.
        """
        self._device.set_on_premise(url)

    def register(self, token: str) -> None:
        """
        Register the device to the cloud using the provided token.

        Full documentation: `NETIODevice.register_to_cloud`.
        """
        self._device.register_to_cloud(token)


class UrlApi(_Group):
    """The URL API."""

    def get_state(self) -> dict[str, Any]:
        """
        Get the URL API state of the device.

        Full documentation: `NETIODevice.get_urlapi_state`.
        """
        return self._device.get_urlapi_state()

    def set_state(
        self, protocol_enabled: bool | None = None, write_enable: bool | None = None, write_password: str | None = None
    ) -> None:
        """
        Configures the URL API protocol with the provided parameters. Any argument left as None keeps the value
        currently configured on the device.

        Full documentation: `NETIODevice.set_urlapi_state`.
        """
        self._device.set_urlapi_state(protocol_enabled, write_enable, write_password)


class Modbus(_Group):
    """Modbus/TCP."""

    def get_state(self) -> dict[str, Any]:
        """
        Get the Modbus M2M API state of the device.

        Full documentation: `NETIODevice.get_modbus_state`.
        """
        return self._device.get_modbus_state()

    def set_state(
        self,
        protocol_enabled: bool | None = None,
        port: int | None = None,
        ip_filter_enabled: bool | None = None,
        ip_from: str | None = None,
        ip_to: str | None = None,
    ) -> None:
        """
        Configures the modbus M2M protocol with the provided parameters. Any argument left as None keeps the value
        currently configured on the device.

        Full documentation: `NETIODevice.set_modbus_state`.
        """
        self._device.set_modbus_state(protocol_enabled, port, ip_filter_enabled, ip_from, ip_to)


class Mqtt(_Group):
    """MQTT-flex."""

    def get_state(self) -> dict[str, Any]:
        """
        Gets the state of the MQTT Flex protocol currently set on the device.

        Full documentation: `NETIODevice.get_mqttflex_state`.
        """
        return self._device.get_mqttflex_state()

    def set_state(self, state: bool | None = None, config: dict[str, Any] | None = None) -> None:
        """
        Sets the state and if provided configuration of the MQTT Flex protocol.

        Full documentation: `NETIODevice.set_mqttflex_state`.
        """
        self._device.set_mqttflex_state(state, config)

    def upload_client_key(self, key: str) -> None:
        """
        Upload a MQTT client private key to the device. On 5.x firmware raises InvalidParameterValueError, before
        anything is sent, unless it is one unencrypted private key as PEM of at most 8192 bytes.

        Full documentation: `NETIODevice.upload_mqtt_client_key`.
        """
        self._device.upload_mqtt_client_key(key)

    def upload_client_certificate(self, cert: str) -> None:
        """
        Uploads the MQTT client certificate to the device. On 5.x firmware raises InvalidParameterValueError,
        before anything is sent, unless it is a certificate as PEM of at most 8192 bytes.

        Full documentation: `NETIODevice.upload_mqtt_client_certificate`.
        """
        self._device.upload_mqtt_client_certificate(cert)

    def upload_ca_certificate(self, ca: str) -> None:
        """
        Uploads the root CA certificate to the device. On 5.x firmware raises InvalidParameterValueError, before
        anything is sent, unless it is PEM text with one or more certificates of at most 8192 bytes together.

        Full documentation: `NETIODevice.upload_mqtt_ca_certificate`.
        """
        self._device.upload_mqtt_ca_certificate(ca)


class JsonApi(_Group):
    """The JSON API."""

    def get_state(self) -> dict[str, Any]:
        """
        Get the JSON M2M API state of the device.

        Full documentation: `NETIODevice.get_json_api_state`.
        """
        return self._device.get_json_api_state()

    def set_state(
        self,
        protocol_enabled: bool | None = None,
        read_enable: bool | None = None,
        write_enable: bool | None = None,
        read_auth: tuple[str, str] | None = None,
        write_auth: tuple[str, str] | None = None,
    ) -> None:
        """
        Function for configuring the JSON M2M on the device. Any argument left as None keeps the value currently
        configured on the device.

        Full documentation: `NETIODevice.set_json_api_state`.
        """
        self._device.set_json_api_state(protocol_enabled, read_enable, write_enable, read_auth, write_auth)

    def read(self, json_auth: tuple[str, str]) -> dict[str, Any]:
        """
        Gets the JSON information from the device. This contains full information about the device.

        Full documentation: `NETIODevice.get_json`.
        """
        return self._device.get_json(json_auth)


class XmlApi(_Group):
    """The XML API."""

    def get_state(self) -> dict[str, Any]:
        """
        Get the XML M2M API state of the device.

        Full documentation: `NETIODevice.get_xml_api_state`.
        """
        return self._device.get_xml_api_state()

    def set_state(
        self,
        protocol_enabled: bool | None = None,
        read_enable: bool | None = None,
        write_enable: bool | None = None,
        read_auth: tuple[str, str] | None = None,
        write_auth: tuple[str, str] | None = None,
    ) -> None:
        """
        Function for configuring the XML M2M on the device. Any argument left as None keeps the value currently
        configured on the device.

        Full documentation: `NETIODevice.set_xml_api_state`.
        """
        self._device.set_xml_api_state(protocol_enabled, read_enable, write_enable, read_auth, write_auth)

    def read(self, xml_auth: tuple[str, str]) -> Element:
        """
        Gets the XML information from the device. This contains full information about the device.

        Full documentation: `NETIODevice.get_xml`.
        """
        return self._device.get_xml(xml_auth)


class NetioPush(_Group):
    """Netio Push."""

    def get_state(self) -> dict[str, Any]:
        """
        Gets the state and settings of the M2M Netio Push protocol currently set on the device.

        Full documentation: `NETIODevice.get_netio_push_api_state`.
        """
        return self._device.get_netio_push_api_state()

    def set_state(
        self,
        protocol_enabled: bool | None = None,
        url: str | None = None,
        push_protocol: PushProtocol | str | None = None,
        delta: int | None = None,
        period: int | None = None,
    ) -> None:
        """
        Sets the state and settings of the M2M Netio Push protocol currently set on the device.

        Full documentation: `NETIODevice.set_netio_push_api_state`.
        """
        self._device.set_netio_push_api_state(protocol_enabled, url, push_protocol, delta, period)

    def push_now(self) -> None:
        """
        Manually use the push protocol if enabled.

        Full documentation: `NETIODevice.netio_push_api_push_now`.
        """
        self._device.netio_push_api_push_now()


class Snmp(_Group):
    """SNMP."""

    def get_state(self) -> dict[str, Any]:
        """
        Gets the state and settings of the M2M SNMP protocol currently set on the device.

        Full documentation: `NETIODevice.get_snmp_api_state`.
        """
        return self._device.get_snmp_api_state()

    def set_v1_2_state(
        self,
        protocol_enabled: bool | None = None,
        location: str | None = None,
        community_read: str | None = None,
        community_write: str | None = None,
    ) -> None:
        """
        Sets the state and settings of the M2M SNMP v1,2c protocol currently set on the device. Enabling this,
        disables the v3 version of SNMP if it's active. Disabling SNMP requires a device restart.

        Full documentation: `NETIODevice.set_snmp_v1_2_api_state`.
        """
        self._device.set_snmp_v1_2_api_state(protocol_enabled, location, community_read, community_write)

    def set_v3_state(
        self,
        protocol_enabled: bool | None = None,
        location: str | None = None,
        security_name: str | None = None,
        security_level: SnmpSecurityLevel | str | None = None,
        auth_protocol: SnmpAuthProtocol | str | None = None,
        auth_key: str | None = None,
        priv_protocol: SnmpPrivProtocol | str | None = None,
        priv_key: str | None = None,
    ) -> None:
        """
        Sets the state and settings of the M2M SNMP v3 protocol currently set on the device. Enabling this will
        disable the v1,2c version of the protocol if it's active. Disabling SNMP requires a device restart.

        Full documentation: `NETIODevice.set_snmp_v3_api_state`.
        """
        self._device.set_snmp_v3_api_state(
            protocol_enabled, location, security_name, security_level, auth_protocol, auth_key, priv_protocol, priv_key
        )


class Telnet(_Group):
    """The Telnet API."""

    def get_state(self) -> dict[str, Any]:
        """
        Gets the state and settings of the telnet M2M protocol currently set on the device.

        Full documentation: `NETIODevice.get_telnet_api_state`.
        """
        return self._device.get_telnet_api_state()

    def set_state(
        self,
        protocol_enabled: bool | None = None,
        port: int | None = None,
        read_enabled: bool | None = None,
        read_auth: tuple[str, str] | None = None,
        write_enabled: bool | None = None,
        write_auth: tuple[str, str] | None = None,
    ) -> None:
        """
        Sets the state and settings of the telnet M2M protocol currently set on the device.

        Full documentation: `NETIODevice.set_telnet_api_state`.
        """
        self._device.set_telnet_api_state(protocol_enabled, port, read_enabled, read_auth, write_enabled, write_auth)


class Outputs(_Group):
    """Output control, output configuration and, under `groups`, the output groups."""

    @cached_property
    def groups(self) -> OutputGroups:
        """The output groups."""
        return OutputGroups(self._device)

    def get_state(self, output_id: int) -> bool:
        """
        Get the output state of the device.

        Full documentation: `NETIODevice.get_output_state`.
        """
        return self._device.get_output_state(output_id)

    def set(self, output_id: int, state: bool) -> None:
        """
        Set a state of an output given its ID and the desired state.

        Full documentation: `NETIODevice.set_output`.
        """
        self._device.set_output(output_id, state)

    def set_unified(self, state: bool) -> None:
        """
        Set all outputs to the same state, on an NBUS master its clients' outputs too.

        Full documentation: `NETIODevice.set_outputs_unified`.
        """
        self._device.set_outputs_unified(state)

    def set_action(self, output_id: int, action: OutputAction) -> None:
        """
        Controls an output: switches it on or off, toggles it, or switches it for its reset delay (short on, short off).
        set_output, reset_output, short_on_output and toggle_output do the same for one action each.

        Full documentation: `NETIODevice.set_output_action`.
        """
        self._device.set_output_action(output_id, action)

    def reset(self, output_id: int) -> None:
        """
        Resets the output: switches it off for its reset delay, then on again (short off).

        Full documentation: `NETIODevice.reset_output`.
        """
        self._device.reset_output(output_id)

    def short_on(self, output_id: int) -> None:
        """
        Switches the output on for its reset delay, then off again (short on).

        Full documentation: `NETIODevice.short_on_output`.
        """
        self._device.short_on_output(output_id)

    def toggle(self, output_id: int) -> None:
        """
        Switches the output to the opposite state.

        Full documentation: `NETIODevice.toggle_output`.
        """
        self._device.toggle_output(output_id)

    def set_reset_delay(self, output_id: int, reset_delay: int) -> None:
        """
        Sets how long reset_output and short_on_output keep the output switched (resetDelay in get_output_data()).

        Full documentation: `NETIODevice.set_output_reset_delay`.
        """
        self._device.set_output_reset_delay(output_id, reset_delay)

    def set_power_up_state(self, output_id: int, state: OutputPowerUpState) -> None:
        """
        Sets the state the output takes when the device powers up after a power loss (default in get_output_data()). A
        restart of the device keeps the outputs as they are.

        Full documentation: `NETIODevice.set_output_power_up_state`.
        """
        self._device.set_output_power_up_state(output_id, state)

    def set_power_up_interval(self, output_id: int, power_up_interval: int) -> None:
        """
        Sets the output's power-up interval (powerUpInterval in get_output_data(), "Output PowerUp interval" on the web
        interface).

        Full documentation: `NETIODevice.set_output_power_up_interval`.
        """
        self._device.set_output_power_up_interval(output_id, power_up_interval)

    def rename(self, output_id: int, output_name: str) -> None:
        """
        Rename the output given its ID.

        Full documentation: `NETIODevice.rename_output`.
        """
        self._device.rename_output(output_id, output_name)

    def set_schedule(self, output_id: int, schedule_id: int, enabled: bool | None = None) -> None:
        """
        Activate or deactivate a specific schedule on a given output provided the schedule's ID.

        Full documentation: `NETIODevice.set_output_schedule`.
        """
        self._device.set_output_schedule(output_id, schedule_id, enabled)

    def get_schedule(self, output_id: int) -> dict[str, Any]:
        """
        Gets the schedule id and its state based on the output ID.

        Full documentation: `NETIODevice.get_output_schedule`.
        """
        return self._device.get_output_schedule(output_id)

    def get_schedule_id(self, output_id: int) -> int:
        """
        Gets the ID of the schedule currently set on the output given its ID.

        Full documentation: `NETIODevice.get_output_schedule_id`.
        """
        return self._device.get_output_schedule_id(output_id)

    def set_schedule_state(self, output_id: int, schedule_enabled: bool) -> None:
        """
        Enables or disables the currently set schedule on an output.

        Full documentation: `NETIODevice.set_output_schedule_state`.
        """
        self._device.set_output_schedule_state(output_id, schedule_enabled)

    def set_schedule_by_name(self, output_id: int, schedule_name: str, enabled: bool | None = None) -> None:
        """
        Activate or deactivate a specific schedule on a given output provided the schedule's name. If the schedule
        with such name isn't available raises ElementNotFound.

        Full documentation: `NETIODevice.set_output_schedule_by_name`.
        """
        self._device.set_output_schedule_by_name(output_id, schedule_name, enabled)

    def get_data(self, output_id: int) -> dict[str, Any]:
        """
        Produces all relevant information about the output given its ID.

        Full documentation: `NETIODevice.get_output_data`.
        """
        return self._device.get_output_data(output_id)

    def get_all_data(self) -> list[dict[str, Any]]:
        """
        Produces a list of all the outputs on the device and relevant information about it. The information might
        differ between device types.

        Full documentation: `NETIODevice.get_outputs_data`.
        """
        return self._device.get_outputs_data()

    def get_states(self) -> list[tuple[int, bool]]:
        """
        Generates a list of the socket states currently on the device.

        Full documentation: `NETIODevice.get_output_states`.
        """
        return self._device.get_output_states()

    def get_all(self) -> list[dict[str, Any]]:
        """
        Gets summary list of outputs with socket types, schedule associations, and status.

        Full documentation: `NETIODevice.get_outputs_list`.
        """
        return self._device.get_outputs_list()

    def set_group_id(self, output_id: int, group_id: int) -> None:
        """
        Puts an output into a group, or takes it out of every group with 0 (groupId in get_output_data()). Its
        power-up interval stays. Experimental: output groups came with firmware 5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.set_output_group_id`.
        """
        self._device.set_output_group_id(output_id, group_id)


class Inputs(_Group):
    """The inputs."""

    def get_all(self) -> dict[str, Any]:
        """
        Returns the device's inputs as the device sends them: {"items": [...]}, each with id, name, state, s0Counter,
        temperature, temperatureUnit and, from firmware 5.2.0 on, humidity. Without a sensor the temperature is 999.0
        and the humidity 999.

        Full documentation: `NETIODevice.get_input_list`.
        """
        return self._device.get_input_list()

    def get_data(self, input_id: int) -> dict[str, Any]:
        """
        Returns one input's item of get_input_list().

        Full documentation: `NETIODevice.get_input_data`.
        """
        return self._device.get_input_data(input_id)

    def rename(self, input_id: int, name: str) -> None:
        """
        Renames the input (name in get_input_data()).

        Full documentation: `NETIODevice.rename_input`.
        """
        self._device.rename_input(input_id, name)

    def set_temperature_unit(self, input_id: int, unit: TemperatureUnit) -> None:
        """
        Sets the unit the input's temperature is reported in (temperatureUnit in get_input_data()).

        Full documentation: `NETIODevice.set_input_temperature_unit`.
        """
        self._device.set_input_temperature_unit(input_id, unit)


class Measurement(_Group):
    """The device's measurement and the consumption counters."""

    def get_global(self) -> dict[str, Any]:
        """
        Gets device-wide global power measurements (voltage, frequency, total energy, power factor, etc.).

        Full documentation: `NETIODevice.get_global_measurement`.
        """
        return self._device.get_global_measurement()

    def reset_counters(self) -> None:
        """
        Resets the power consumption counters on the device for all metered outputs. An NBUS master's clients' outputs
        are left out: the firmware can't reset their counters from the master.

        Full documentation: `NETIODevice.reset_power_consumption_counters`.
        """
        self._device.reset_power_consumption_counters()

    def reset_output_counter(self, output_id: int) -> None:
        """
        Resets power consumption counters for a specific output by its ID.

        Full documentation: `NETIODevice.reset_output_consumption_counter`.
        """
        self._device.reset_output_consumption_counter(output_id)

    def reset_global_counter(self) -> None:
        """
        Resets the consumption counter of all outputs together (energy and reverseEnergy in get_global_measurement()).
        The outputs' own counters stay, reset_power_consumption_counters() resets those.

        Full documentation: `NETIODevice.reset_global_consumption_counter`.
        """
        self._device.reset_global_consumption_counter()


class Nbus(_Group):
    """The NBUS line."""

    def supported(self) -> bool:
        """
        Whether the device has NBUS: firmware 5.4.0 or newer, and a device made with it. Experimental: NBUS came with
        firmware 5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.has_nbus`.
        """
        return self._device.has_nbus()

    def get_settings(self) -> dict[str, Any]:
        """
        Gets the NBUS settings. Experimental: NBUS came with firmware 5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.get_nbus_settings`.
        """
        return self._device.get_nbus_settings()

    def set_settings(self, enabled: bool | None = None, role: NbusRole | None = None) -> None:
        """
        Enables or disables NBUS and sets the device's role on the line. None keeps the value the device has. Every
        call restarts the device's NBUS, which applies the role, and saves the settings, without restarting the device.
        Enabled, the line runs at full speed; disabled, the device only listens for an installation, and a master
        drops the requests to its clients' outputs until it restarts. Experimental: NBUS came with firmware 5.4.0,
        which isn't released yet.

        Full documentation: `NETIODevice.set_nbus_settings`.
        """
        self._device.set_nbus_settings(enabled, role)

    def discover(self, timeout: float = NBUS_DISCOVER_TIMEOUT) -> list[dict[str, Any]]:
        """
        Searches the line for devices, adds the new ones to the device list with their outputs and inputs, and waits
        until they have reported them. Every device found saves itself as an enabled slave of this master, so don't
        discover on a line with devices that aren't to be its clients. A master searches at full speed and finds only
        devices with NBUS enabled: set a line up by enabling each client as a slave, then this device as a master, and
        discover a few seconds later; one sent right after enabling found nothing. A listed device that doesn't answer
        stays listed as Offline without its outputs and inputs; the
        first new device takes its place and its output ids. Requests to the clients' outputs are dropped while the
        search runs. Experimental: NBUS came with firmware 5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.discover_nbus_devices`.
        """
        return self._device.discover_nbus_devices(timeout)

    def get_devices(self) -> list[dict[str, Any]]:
        """
        Lists the master's clients in line order, without the master. Experimental: NBUS came with firmware 5.4.0,
        which isn't released yet.

        Full documentation: `NETIODevice.get_nbus_devices`.
        """
        return self._device.get_nbus_devices()

    def delete_device(self, device_sn: str) -> None:
        """
        Removes a client from the master's list, with its outputs and inputs, and moves the outputs of the clients
        behind it up. The client isn't told and stays a slave, so a later discover adds it back. Experimental: NBUS
        came with firmware 5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.delete_nbus_device`.
        """
        self._device.delete_nbus_device(device_sn)

    def locate_device(self, device_sn: str) -> None:
        """
        Makes a client's LED blink for 60 seconds. Experimental: NBUS came with firmware 5.4.0, which isn't released
        yet.

        Full documentation: `NETIODevice.locate_nbus_device`.
        """
        self._device.locate_nbus_device(device_sn)

    def set_device_order(self, device_sns: list[str]) -> None:
        """
        Puts the clients in a new order. Their outputs move with them and get new ids, keeping their names, groups,
        schedules and delays; rules, PABs, watchdogs and the inputs don't follow. Experimental: NBUS came with firmware
        5.4.0, which isn't released yet.

        Full documentation: `NETIODevice.set_nbus_device_order`.
        """
        self._device.set_nbus_device_order(device_sns)

    def get_mapping(self) -> list[dict[str, Any]]:
        """
        Maps the master's outputs to its clients'. Experimental: NBUS came with firmware 5.4.0, which isn't released
        yet.

        Full documentation: `NETIODevice.get_nbus_mapping`.
        """
        return self._device.get_nbus_mapping()


class Rules(_Group):
    """The rules."""

    def get_all(self) -> list[dict[str, Any]]:
        """
        Gets the list of all rules on the device and their configuration.

        Full documentation: `NETIODevice.get_rules`.
        """
        return self._device.get_rules()

    def get_enabled(self) -> list[dict[str, Any]]:
        """
        Gets the list of all enabled rules on the device and their configuration.

        Full documentation: `NETIODevice.get_enabled_rules`.
        """
        return self._device.get_enabled_rules()

    def get_disabled(self) -> list[dict[str, Any]]:
        """
        Gets the list of all disabled rules on the device and their configuration.

        Full documentation: `NETIODevice.get_disabled_rules`.
        """
        return self._device.get_disabled_rules()

    def get(self, rule_name: str) -> dict[str, Any]:
        """
        Gets a rule based on its name.

        Full documentation: `NETIODevice.get_rule_by_name`.
        """
        return self._device.get_rule_by_name(rule_name)

    def create(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        """
        Creates a rule on the device. Raises ElementAlreadyExists if a rule of the given name is already present.

        Full documentation: `NETIODevice.create_rule`.
        """
        self._device.create_rule(enable, name, config)

    def set(self, name: str, enabled: bool | None = None, config: dict[str, Any] | None = None) -> None:
        """
        Changes an existing rule: enables or disables it, or replaces its configuration. None keeps the value the
        device has. A rule can't be renamed.

        Full documentation: `NETIODevice.set_rule`.
        """
        self._device.set_rule(name, enabled, config)

    def delete(self, name: str) -> None:
        """
        Deletes a rule from the device given its name. Raises ElementNotFound if the rule isn't found.

        Full documentation: `NETIODevice.delete_rule_by_name`.
        """
        self._device.delete_rule_by_name(name)


class Watchdogs(_Group):
    """The watchdogs."""

    def get_all(self) -> list[dict[str, Any]]:
        """
        Gets the list of all watchdogs, enabled or disabled on the device.

        Full documentation: `NETIODevice.get_watchdogs`.
        """
        return self._device.get_watchdogs()

    def get_enabled(self) -> list[dict[str, Any]]:
        """
        Gets all enabled watchdogs  on the device.

        Full documentation: `NETIODevice.get_enabled_watchdogs`.
        """
        return self._device.get_enabled_watchdogs()

    def get_disabled(self) -> list[dict[str, Any]]:
        """
        Gets all disabled watchdogs on the device.

        Full documentation: `NETIODevice.get_disabled_watchdogs`.
        """
        return self._device.get_disabled_watchdogs()

    def get(self, watchdog_name: str) -> dict[str, Any]:
        """
        Gets a watchdog based on its name.

        Full documentation: `NETIODevice.get_watchdog_by_name`.
        """
        return self._device.get_watchdog_by_name(watchdog_name)

    def create(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        """
        Creates a watchdog on the device. Raises ElementAlreadyExists if a watchdog of the given name is already
        present.

        Full documentation: `NETIODevice.create_watchdog`.
        """
        self._device.create_watchdog(enable, name, config)

    def set(self, name: str, enabled: bool | None = None, config: dict[str, Any] | None = None) -> None:
        """
        Changes an existing watchdog: enables or disables it, or replaces its configuration. None keeps the value the
        device has. A watchdog can't be renamed.

        Full documentation: `NETIODevice.set_watchdog`.
        """
        self._device.set_watchdog(name, enabled, config)

    def delete(self, name: str) -> None:
        """
        Deletes a watchdog from the device given its name. Raises ElementNotFound if the watchdog isn't found.

        Full documentation: `NETIODevice.delete_watchdog_by_name`.
        """
        self._device.delete_watchdog_by_name(name)


class Pabs(_Group):
    """The PABs."""

    def get_all(self) -> list[dict[str, Any]]:
        """
        Gets the list of PABs, enabled or disabled on the device.

        Full documentation: `NETIODevice.get_pabs`.
        """
        return self._device.get_pabs()

    def get_enabled(self) -> list[dict[str, Any]]:
        """
        Gets the list of enabled PABs on the device.

        Full documentation: `NETIODevice.get_enabled_pabs`.
        """
        return self._device.get_enabled_pabs()

    def get_disabled(self) -> list[dict[str, Any]]:
        """
        Gets the list of disabled PABs on the device.

        Full documentation: `NETIODevice.get_disabled_pabs`.
        """
        return self._device.get_disabled_pabs()

    def get(self, pab_name: str) -> dict[str, Any]:
        """
        Gets a PAB and its configuration based on its name. Raises ElementNotFound if the PAB isn't found.

        Full documentation: `NETIODevice.get_pab_by_name`.
        """
        return self._device.get_pab_by_name(pab_name)

    def create(self, enable: bool, name: str, config: dict[str, Any]) -> None:
        """
        Creates a PAB on the device. Raises ElementAlreadyExists if a PAB of the given name is already present.

        Full documentation: `NETIODevice.create_pab`.
        """
        self._device.create_pab(enable, name, config)

    def set(self, name: str, enabled: bool | None = None, config: dict[str, Any] | None = None) -> None:
        """
        Changes an existing PAB: enables or disables it, or replaces its configuration. None keeps the value the
        device has. A PAB can't be renamed.

        Full documentation: `NETIODevice.set_pab`.
        """
        self._device.set_pab(name, enabled, config)

    def delete(self, pab_name: str) -> None:
        """
        Deletes a PAB from the device given its name. Raises ElementNotFound if the PAB isn't found.

        Full documentation: `NETIODevice.delete_pab_by_name`.
        """
        self._device.delete_pab_by_name(pab_name)


class Schedules(_Group):
    """The schedules."""

    def get_all(self) -> list[dict[str, Any]]:
        """
        Gets the list of all the schedules available on the device.

        Full documentation: `NETIODevice.get_schedules`.
        """
        return self._device.get_schedules()

    def get_active(self) -> list[dict[str, Any]]:
        """
        Gets all the schedules that are currently active on the device.

        Full documentation: `NETIODevice.get_active_schedules`.
        """
        return self._device.get_active_schedules()

    def get_names(self) -> list[str]:
        """
        Gets all the schedules available on the device.

        Full documentation: `NETIODevice.get_schedule_names`.
        """
        return self._device.get_schedule_names()

    def get(self, schedule_name: str) -> dict[str, Any]:
        """
        Gets a schedule based on its name. Raises ElementNotFound if the schedule isn't found.

        Full documentation: `NETIODevice.get_schedule_by_name`.
        """
        return self._device.get_schedule_by_name(schedule_name)

    def get_id(self, schedule_name: str) -> int:
        """
        Gets the schedule ID for a schedule based on its name. Raises ElementNotFound if schedule isn't found.

        Full documentation: `NETIODevice.get_schedule_id`.
        """
        return self._device.get_schedule_id(schedule_name)

    def create(self, name: str, intervals: list[dict[str, Any]]) -> None:
        """
        Creates a scedulule on the device given its configuration JSON.

        Full documentation: `NETIODevice.create_schedule`.
        """
        self._device.create_schedule(name, intervals)

    def set(self, name: str, intervals: list[dict[str, Any]]) -> None:
        """
        Replaces the intervals of an existing schedule. A schedule can't be renamed. The device stores one interval per
        day, so an interval for several days reads back as one per day.

        Full documentation: `NETIODevice.set_schedule`.
        """
        self._device.set_schedule(name, intervals)

    def delete(self, schedule_name: str) -> None:
        """
        Deletes a schedule from the device given its name.

        Full documentation: `NETIODevice.delete_schedule_by_name`.
        """
        self._device.delete_schedule_by_name(schedule_name)

    def delete_by_id(self, schedule_id: int) -> None:
        """
        Deletes a schedule from the device.

        Full documentation: `NETIODevice.delete_schedule`.
        """
        self._device.delete_schedule(schedule_id)


class Users(_Group):
    """The users and their privileges."""

    def get_all(self) -> dict[str, Any]:
        """
        Gets the users on the device.

        Full documentation: `NETIODevice.get_users`.
        """
        return self._device.get_users()

    def get_current(self) -> dict[str, Any]:
        """
        Gets the logged-in user that corresponds to the session id used in this request.

        Full documentation: `NETIODevice.get_current_user`.
        """
        return self._device.get_current_user()

    def get_privileges(self, username: str) -> list[str]:
        """
        Gets a list of privileges for the specified user.

        Full documentation: `NETIODevice.get_user_privileges`.
        """
        return self._device.get_user_privileges(username)

    def set_privileges(self, username: str, privileges: list[str]) -> None:
        """
        Replaces the privileges of an existing user. Requires the can_alter_users privilege.

        Full documentation: `NETIODevice.set_user_privileges`.
        """
        self._device.set_user_privileges(username, privileges)

    def set_privilege(self, username: str, privilege: str, state: bool) -> None:
        """
        Grants or takes away one privilege of an existing user and leaves the others as they are. Requires the
        can_alter_users privilege.

        Full documentation: `NETIODevice.set_user_privilege`.
        """
        self._device.set_user_privilege(username, privilege, state)

    def create(self, username: str, password: str, privileges: list[str] | None = None) -> None:
        """
        Creates a new user on the device with the given parameters.

        Full documentation: `NETIODevice.create_user`.
        """
        self._device.create_user(username, password, privileges)

    def remove(self, username: str) -> None:
        """
        Removes the specified user, requires your account to have a privilege to edit users.

        Full documentation: `NETIODevice.remove_user`.
        """
        self._device.remove_user(username)

    def change_password(self, username: str, old_password: str, new_password: str) -> None:
        """
        Changes the password of a user. Requires the can_alter_users privilege. When the user is the logged-in one,
        the password the device object uses to log in again is changed as well.

        Full documentation: `NETIODevice.change_user_password`.
        """
        self._device.change_user_password(username, old_password, new_password)

    def change_own_password(self, new_password: str) -> None:
        """
        Changes the password of the logged-in user, and the password the device object uses to log in again
        after a dropped connection. On 5.x firmware the user needs the can_alter_users privilege.

        Full documentation: `NETIODevice.change_password`.
        """
        self._device.change_password(new_password)


class Network(_Group):
    """Ethernet, Wi-Fi, the device's servers and the HTTPS certificate."""

    def get_ethernet_settings(self) -> dict[str, Any]:
        """
        Gets Ethernet network interface configuration (MAC, networkMode, IP, netmask, gateway, DNS).

        Full documentation: `NETIODevice.get_ethernet_settings`.
        """
        return self._device.get_ethernet_settings()

    def get_ethernet_status(self) -> dict[str, Any]:
        """
        Gets Ethernet interface connection status.

        Full documentation: `NETIODevice.get_ethernet_status`.
        """
        return self._device.get_ethernet_status()

    def set_ethernet_settings(
        self,
        network_mode: NetworkMode | str | None = None,
        ip: str | None = None,
        netmask: str | None = None,
        gateway: str | None = None,
        dns: str | None = None,
    ) -> None:
        """
        Sets Ethernet network interface configuration (DHCP or static IP parameters).
        Any argument left as None keeps the value currently configured on the device. When switching from DHCP to
        "static", ip, netmask and gateway are required.

        Full documentation: `NETIODevice.set_ethernet_settings`.
        """
        self._device.set_ethernet_settings(network_mode, ip, netmask, gateway, dns)

    def get_wifi_settings(self) -> dict[str, Any]:
        """
        Produces all relevant information about the Wi-Fi settings on the device.

        Full documentation: `NETIODevice.get_wifi_settings`.
        """
        return self._device.get_wifi_settings()

    def get_wifi_status(self) -> dict[str, Any]:
        """
        Gets Wi-Fi interface link and connection status.

        Full documentation: `NETIODevice.get_wifi_status`.
        """
        return self._device.get_wifi_status()

    def set_wifi_settings(self, ssid: str, password: str) -> None:
        """
        Connects the device to a specified Wi-Fi network provided the SSID and password.

        Full documentation: `NETIODevice.set_wifi_settings`.
        """
        self._device.set_wifi_settings(ssid, password)

    def set_wifi_static_address(
        self,
        address: str | None = None,
        net_mask: str | None = None,
        gateway: str | None = None,
        dns_server: str | None = None,
        hostname: str | None = None,
    ) -> None:
        """
        Sets the device static address on the currently connected Wi-Fi network. Any argument left as None keeps
        the value currently configured on the device. When the device is currently using DHCP, address, net_mask
        and gateway are required.

        Full documentation: `NETIODevice.set_wifi_static_address`.
        """
        self._device.set_wifi_static_address(address, net_mask, gateway, dns_server, hostname)

    def get_server_settings(self) -> dict[str, Any]:
        """
        Gets web server HTTP / HTTPS ports and enablement configuration.

        Full documentation: `NETIODevice.get_server_settings`.
        """
        return self._device.get_server_settings()

    def set_server_settings(
        self,
        http_enable: bool | None = None,
        http_port: int | None = None,
        https_enable: bool | None = None,
        https_port: int | None = None,
    ) -> None:
        """
        Sets which web server the device runs, HTTP or HTTPS, and their ports. The device runs one of them, not both:
        enabling one disables the other. Arguments left at None keep the device's current values.

        Full documentation: `NETIODevice.set_server_settings`.
        """
        self._device.set_server_settings(http_enable, http_port, https_enable, https_port)

    def upload_https_private_key(self, keyfile: str) -> None:
        """
        Uploads the private key of the device's HTTPS server, a PEM file. Upload the matching certificate with
        upload_https_certificate as well.

        Full documentation: `NETIODevice.upload_https_private_key`.
        """
        self._device.upload_https_private_key(keyfile)

    def upload_https_certificate(self, certfile: str) -> None:
        """
        Uploads the certificate of the device's HTTPS server, a PEM file. It has to match the private key uploaded with
        upload_https_private_key.

        Full documentation: `NETIODevice.upload_https_certificate`.
        """
        self._device.upload_https_certificate(certfile)


class System(_Group):
    """The device itself: versions, settings, time, restart, configuration files and the log."""

    def get_version(self) -> str:
        """
        Get the version information of the device.

        Full documentation: `NETIODevice.get_version`.
        """
        return self._device.get_version()

    def get_version_detailed(self) -> str:
        """
        Get the detailed version information of the device.

        Full documentation: `NETIODevice.get_version_detailed`.
        """
        return self._device.get_version_detailed()

    def get_version_revision(self) -> str:
        """
        Fetches the revision of the current firmware version.

        Full documentation: `NETIODevice.get_version_revision`.
        """
        return self._device.get_version_revision()

    def get_features(self) -> dict[str, Any]:
        """
        Get the features of the device.

        Full documentation: `NETIODevice.get_features`.
        """
        return self._device.get_features()

    def get_info(self) -> dict[str, Any]:
        """
        Gets the system info on the device.

        Full documentation: `NETIODevice.get_system_info`.
        """
        return self._device.get_system_info()

    def get_settings(self) -> dict[str, Any]:
        """
        Gets the system settings on the device: the device name, the periodic restart and the syslog settings, the
        ones set_system_settings() changes.

        Full documentation: `NETIODevice.get_system_settings`.
        """
        return self._device.get_system_settings()

    def set_settings(
        self,
        device_name: str | None = None,
        port: int | None = None,
        periodic_restart: bool | None = None,
        restart_period: int | None = None,
        syslog_enable: bool | None = None,
        syslog_server: str | None = None,
        syslog_port: int | None = None,
    ) -> None:
        """
        Sets the system settings on device given the provided parameters. Any argument left as None keeps the
        value currently configured on the device.

        Full documentation: `NETIODevice.set_system_settings`.
        """
        self._device.set_system_settings(
            device_name, port, periodic_restart, restart_period, syslog_enable, syslog_server, syslog_port
        )

    def rename(self, device_name: str) -> None:
        """
        Rename the device to the provided name, requried to be administrator to change settings.

        Full documentation: `NETIODevice.rename_device`.
        """
        self._device.rename_device(device_name)

    def get_uptime(self) -> int:
        """
        Gets the device's current uptime in seconds.

        Full documentation: `NETIODevice.get_uptime`.
        """
        return self._device.get_uptime()

    def get_datetime(self) -> dict[str, Any]:
        """
        Gets current system date, time, timezone, and NTP configuration.

        Full documentation: `NETIODevice.get_system_datetime`.
        """
        return self._device.get_system_datetime()

    def set_datetime(
        self,
        ntp_enabled: bool | None = None,
        ntp_server: str | None = None,
        timezone: str | None = None,
        time: int | None = None,
    ) -> None:
        """
        Sets system date, time, timezone, and NTP configuration. Any argument left as None keeps the value
        currently configured on the device.

        Full documentation: `NETIODevice.set_system_datetime`.
        """
        self._device.set_system_datetime(ntp_enabled, ntp_server, timezone, time)

    def set_periodic_restart(self, enable: bool | None = None, restart_period: int | None = None) -> None:
        """
        Sets the periodic restart feature toggle and optionally changes the restart period.

        Full documentation: `NETIODevice.set_periodic_restart`.
        """
        self._device.set_periodic_restart(enable, restart_period)

    def locate(self) -> None:
        """
        Blinks the LED on the device for a period of time.

        Full documentation: `NETIODevice.locate`.
        """
        self._device.locate()

    def reset(self) -> None:
        """
        Restarts the device and returns once it is reachable again, about 10 s later. A reset sent on a connection the
        device had already dropped is sent again, and the restart is checked through the uptime.

        Full documentation: `NETIODevice.system_reset`.
        """
        self._device.system_reset()

    def load_defaults(self) -> None:
        """
        Resets the device to its factory default configuration, which restarts it. Afterwards the device has only the
        user admin, with the password admin. Waits until the device is back and logs in as admin with that password;
        the device object uses these credentials from then on. The device restarts twice: once to load the defaults,
        and once more when it marks itself installed after getting a network address. This method returns after both.

        Full documentation: `NETIODevice.load_defaults`.
        """
        self._device.load_defaults()

    def import_config(self, file: str | os.PathLike[str] | io.BufferedIOBase | io.TextIOBase, **kwargs: Any) -> None:
        """
        Import configuration to the device from a JSON file. On 5.x the device restarts with it, and the method logs in
        again once it is back.

        Full documentation: `NETIODevice.import_config`.
        """
        self._device.import_config(file, **kwargs)

    def export_config(self, save_file: str | None = None) -> dict[str, Any]:
        """
        Export the device's configuration to a JSON file.

        Full documentation: `NETIODevice.export_config`.
        """
        return self._device.export_config(save_file)

    def get_lock(self) -> dict[str, Any]:
        """
        Gets current system lock status (e.g. while performing cloud synchronization).

        Full documentation: `NETIODevice.get_system_lock`.
        """
        return self._device.get_system_lock()

    def get_notifications(self) -> list[dict[str, Any]]:
        """
        Gets active system notification/error messages.

        Full documentation: `NETIODevice.get_system_notifications`.
        """
        return self._device.get_system_notifications()

    def get_log(self) -> list[dict[str, Any]]:
        """
        Gets the system log of the device.

        Full documentation: `NETIODevice.get_system_log`.
        """
        return self._device.get_system_log()

    def clear_log(self) -> None:
        """
        Clears the system log of the device.

        Full documentation: `NETIODevice.clear_system_log`.
        """
        self._device.clear_system_log()


class Firmware(_Group):
    """Firmware updates."""

    def update(self, file: str | os.PathLike[str] | io.BufferedIOBase) -> "NETIODevice":
        """
        Upload a firmware file to the device and begin the upgrade. Note this locks the device out for a time.

        Full documentation: `NETIODevice.update_firmware`.
        """
        return self._device.update_firmware(file)

    def get_updates(self) -> list[dict[str, Any]]:
        """
        Has the device check the NETIO update server for newer firmware, like "Check for update" in the web interface,
        and waits for the answer, which takes a few seconds. NETIO Cloud doesn't have to be enabled for it.

        Full documentation: `NETIODevice.get_firmware_updates_list`.
        """
        return self._device.get_firmware_updates_list()

    def is_update_available(self) -> bool:
        """
        Has the device check the NETIO update server for newer firmware through get_firmware_updates_list(), which takes
        a few seconds. The answer is reused for FIRMWARE_LIST_CACHE_TIME seconds, so update_firmware_online() right
        after this doesn't check again.

        Full documentation: `NETIODevice.is_update_available`.
        """
        return self._device.is_update_available()

    def update_online(self, include_low_level_system: bool = False, version: str | None = None) -> "NETIODevice":
        """
        Updates the device to firmware the NETIO update server offers, like "Update device firmware" in the web
        interface, and waits until the device runs it. The device downloads the firmware itself and restarts. This
        takes a few minutes, and the device can't be reached in between. A failed download restarts the device as well.
        The device may try again after that restart, ONLINE_UPDATE_ATTEMPTS attempts in all; when it doesn't start
        another attempt within ONLINE_UPDATE_RETRY_WAIT seconds, the update counts as failed.

        Full documentation: `NETIODevice.update_firmware_online`.
        """
        return self._device.update_firmware_online(include_low_level_system, version)

    def update_online_incl_low_level(self, version: str | None = None) -> "NETIODevice":
        """
        Updates the device and its low-level system (the MCU firmware) to firmware the NETIO update server offers, like
        "Update incl. low-level system" in the web interface. A shortcut for
        update_firmware_online(include_low_level_system=True), see there.

        Full documentation: `NETIODevice.update_firmware_incl_low_level_online`.
        """
        return self._device.update_firmware_incl_low_level_online(version)


class Protocols(_Group):
    """The M2M protocols, each under its own name."""

    @cached_property
    def cloud(self) -> Cloud:
        """NETIO Cloud."""
        return Cloud(self._device)

    @cached_property
    def urlapi(self) -> UrlApi:
        """The URL API."""
        return UrlApi(self._device)

    @cached_property
    def modbus(self) -> Modbus:
        """Modbus/TCP."""
        return Modbus(self._device)

    @cached_property
    def mqtt(self) -> Mqtt:
        """MQTT-flex."""
        return Mqtt(self._device)

    @cached_property
    def json(self) -> JsonApi:
        """The JSON API."""
        return JsonApi(self._device)

    @cached_property
    def xml(self) -> XmlApi:
        """The XML API."""
        return XmlApi(self._device)

    @cached_property
    def push(self) -> NetioPush:
        """Netio Push."""
        return NetioPush(self._device)

    @cached_property
    def snmp(self) -> Snmp:
        """SNMP."""
        return Snmp(self._device)

    @cached_property
    def telnet(self) -> Telnet:
        """The Telnet API."""
        return Telnet(self._device)

    def get_active(self) -> list[int]:
        """
        Produces a list of the currently active protocols.

        Full documentation: `NETIODevice.get_active_protocols`.
        """
        return self._device.get_active_protocols()

    def get_supported(self) -> list[int]:
        """
        Produces a list of all the protocols supported by the current device, also contains relevant information about
        those protocols.

        Full documentation: `NETIODevice.get_supported_protocols`.
        """
        return self._device.get_supported_protocols()
