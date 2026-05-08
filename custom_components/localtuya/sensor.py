"""Platform to present any Tuya DP as a sensor."""

import base64
import logging
from functools import partial

import voluptuous as vol
from homeassistant.components.sensor import (
    DEVICE_CLASSES_SCHEMA,
    DOMAIN,
    STATE_CLASSES_SCHEMA,
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import (
    ATTR_CONNECTIONS,
    ATTR_VIA_DEVICE,
    CONF_DEVICES,
    CONF_DEVICE_CLASS,
    CONF_HOST,
    CONF_UNIT_OF_MEASUREMENT,
    EntityCategory,
    Platform,
    STATE_UNKNOWN,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfPower,
)
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers import entity_registry as er

from .config_flow import col_to_select
from .entity import LocalTuyaEntity, async_setup_entry
from .const import (
    CONF_NODE_ID,
    CONF_SCALING,
    CONF_STATE_CLASS,
    DOMAIN,
    DeviceConfig,
)

_LOGGER = logging.getLogger(__name__)

DEFAULT_PRECISION = 2

ATTR_POWER = "power"
ATTR_VOLTAGE = "voltage"
ATTR_CURRENT = "current"
MAP_UOM = {
    ATTR_CURRENT: UnitOfElectricCurrent.AMPERE,
    ATTR_VOLTAGE: UnitOfElectricPotential.VOLT,
    ATTR_POWER: UnitOfPower.KILO_WATT,
}


def flow_schema(dps):
    """Return schema used in config flow."""
    return {
        vol.Optional(CONF_UNIT_OF_MEASUREMENT): str,
        vol.Optional(CONF_DEVICE_CLASS): DEVICE_CLASSES_SCHEMA,
        vol.Optional(CONF_STATE_CLASS): col_to_select(
            [sc.value for sc in SensorStateClass]
        ),
        vol.Optional(CONF_SCALING): vol.All(
            vol.Coerce(float), vol.Range(min=-1000000.0, max=1000000.0)
        ),
    }


class LocalTuyaSensor(LocalTuyaEntity, SensorEntity):
    """Representation of a Tuya sensor."""

    def __init__(
        self,
        device,
        config_entry,
        sensorid,
        **kwargs,
    ):
        """Initialize the Tuya sensor."""
        super().__init__(device, config_entry, sensorid, _LOGGER, **kwargs)
        self._state = None

        self._has_sub_entities = False
        self._attr_device_class = self._config.get(CONF_DEVICE_CLASS)

    @property
    def native_value(self):
        """Return sensor state."""
        return self._state

    @property
    def state_class(self) -> str | None:
        """Return state class."""
        return getattr(self, "_attr_state_class", self._config.get(CONF_STATE_CLASS))

    @property
    def native_unit_of_measurement(self):
        """Return the unit of measurement of this entity, if any."""
        return getattr(
            self,
            "_attr_native_unit_of_measurement",
            self._config.get(CONF_UNIT_OF_MEASUREMENT),
        )

    def status_updated(self):
        """Device status was updated."""

        state = self.dp_value(self._dp_id)

        if self.is_base64(state):
            if not self._has_sub_entities:
                self.hass.add_job(self.__create_sub_sensors())

            if None not in (
                sub_sensor := getattr(self, "_attr_sub_sensor", None),
                sub_sensor_state := self.decode_base64(state).get(sub_sensor),
            ):
                self._state = sub_sensor_state
            else:
                self._state = state
        else:
            self._state = self.scale(state)

    def status_restored(self, stored_state) -> None:
        super().status_restored(stored_state)

        if (last_state := self._last_state) and self.is_base64(last_state):
            self._status.update({self._dp_id: last_state})

    # No need to restore state for a sensor
    async def restore_state_when_connected(self):
        """Do nothing for a sensor."""
        return

    def is_base64(self, data):
        """Return if the data is valid Tuya raw Base64 encoded data."""
        return (
            (data and isinstance(data, str))
            and len(data) >= 12
            and len(data) % 2 == 0
            and data.endswith("=")
        )

    def decode_base64(self, data):
        """Decode data base64 such as DPS phase_a."""
        buf = base64.b64decode(data)
        voltage = (buf[1] | buf[0] << 8) / 10
        current = (buf[4] | buf[3] << 8) / 1000
        power = (buf[7] | buf[6] << 8) / 1000
        return {ATTR_VOLTAGE: voltage, ATTR_CURRENT: current, ATTR_POWER: power}

    async def __create_sub_sensors(self):
        """Create sub entities for voltage, current and power and hide this parent sensor."""
        sub_entities = []

        for sensor in (ATTR_CURRENT, ATTR_POWER, ATTR_VOLTAGE):
            sub_entity = LocalTuyaSensor(
                self._device, self._device_config.as_dict(), self._dp_id
            )
            setattr(sub_entity, "_attr_sub_sensor", sensor)
            setattr(sub_entity, "_attr_unique_id", f"{self.unique_id}_{sensor}")
            setattr(sub_entity, "_attr_name", f"{self.name} {sensor.capitalize()}")
            setattr(sub_entity, "_attr_device_class", SensorDeviceClass(sensor))
            setattr(sub_entity, "_attr_state_class", SensorStateClass.MEASUREMENT)
            setattr(sub_entity, "_attr_native_unit_of_measurement", MAP_UOM[sensor])
            sub_entities.append(sub_entity)

        # Sub entities shouldn't have add entities attr.
        if sub_entities and self.componet_add_entities:
            self._has_sub_entities = True
            self.componet_add_entities(sub_entities)
            er.async_get(self.hass).async_update_entity(
                self.entity_id, hidden_by=er.RegistryEntryHider.INTEGRATION
            )


class LocalTuyaTransportSensor(SensorEntity):
    """Diagnostic sensor that exposes the active connection transport."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_has_entity_name = True
    _attr_name = "Active Transport"
    _attr_should_poll = False

    def __init__(self, device, device_config: dict):
        """Initialize the transport sensor."""
        self._device = device
        self._device_config = DeviceConfig(device_config)
        self._attr_unique_id = f"local_{self._device_config.id}_active_transport"

    @property
    def native_value(self):
        """Return the current transport state."""
        return self._device.active_transport or "disconnected"

    @property
    def available(self):
        """The transport sensor is always available."""
        return True

    @property
    def device_info(self):
        """Return device registry information for this entity."""
        device_info = DeviceInfo(
            identifiers={(DOMAIN, f"local_{self._device_config.id}")},
            name=self._device_config.name,
            manufacturer="Tuya",
            model=f"{self._device_config.model} ({self._device_config.id})",
            sw_version=self._device_config.protocol_version,
        )
        if self._device_config.ble_host and not self._device.is_subdevice:
            device_info[ATTR_CONNECTIONS] = {
                (CONNECTION_BLUETOOTH, self._device_config.ble_host.upper())
            }
        if self._device.is_subdevice and self._device.id != self._device.gateway.id:
            device_info[ATTR_VIA_DEVICE] = (DOMAIN, f"local_{self._device.gateway.id}")
        return device_info

    async def restore_state_when_connected(self) -> None:
        """No-op: transport sensor has no state to restore on connect."""

    async def async_added_to_hass(self) -> None:
        """Subscribe to dispatcher updates and hide the entity by default."""
        signal = f"localtuya_{self._device_config.id}"
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, signal, lambda _status: self.schedule_update_ha_state()
            )
        )
        await super().async_added_to_hass()
        er.async_get(self.hass).async_update_entity(
            self.entity_id, hidden_by=er.RegistryEntryHider.INTEGRATION
        )


_BASE_ASYNC_SETUP_ENTRY = partial(async_setup_entry, DOMAIN, LocalTuyaSensor, flow_schema)


async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up LocalTuya sensors and the hidden active transport sensor."""
    await _BASE_ASYNC_SETUP_ENTRY(hass, config_entry, async_add_entities)

    transport_entities = []
    hass_entry_data = hass.data[DOMAIN][config_entry.entry_id]
    for dev_id, dev_entry in config_entry.data[CONF_DEVICES].items():
        host = dev_entry.get(CONF_HOST)
        node_id = dev_entry.get(CONF_NODE_ID)
        device_key = f"{host}_{node_id}" if node_id else host
        if device_key not in hass_entry_data.devices:
            continue
        transport_entities.append(
            LocalTuyaTransportSensor(hass_entry_data.devices[device_key], dev_entry)
        )

    if transport_entities:
        for entity in transport_entities:
            entity._device.add_entities([entity])
        async_add_entities(transport_entities)
