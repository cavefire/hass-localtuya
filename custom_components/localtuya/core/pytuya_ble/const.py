"""Constants for Tuya BLE protocol."""

from enum import IntEnum

# Default GATT UUIDs used by most Tuya BLE devices (e.g. FingerBot, some switches)
DEFAULT_NOTIF_UUID = "00002b10-0000-1000-8000-00805f9b34fb"
DEFAULT_CHAR_UUID = "00002b11-0000-1000-8000-00805f9b34fb"

# Maximum BLE MTU for GATT writes (bytes)
GATT_MTU = 20


class Coder(IntEnum):
    """Tuya BLE command/response codes."""

    FUN_SENDER_DEVICE_INFO = 0
    FUN_SENDER_PAIR = 1
    FUN_SENDER_DPS = 2
    FUN_SENDER_DEVICE_STATUS = 3
    FUN_RECEIVE_TIME1_REQ = 32785
    FUN_RECEIVE_DP = 32769


class DpType(IntEnum):
    """Tuya DP value type identifiers."""

    RAW = 0
    BOOLEAN = 1
    INT = 2
    STRING = 3
    ENUM = 4
