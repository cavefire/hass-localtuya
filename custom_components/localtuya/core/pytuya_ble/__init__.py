"""Tuya BLE Protocol — async interface for Tuya Bluetooth Low Energy devices.

This module mirrors the public interface of TuyaProtocol (core/pytuya/__init__.py)
so that TuyaDevice in coordinator.py can use BLE devices transparently.

Protocol overview
-----------------
1. Connect to the GATT characteristic and subscribe to notifications.
2. Send FUN_SENDER_DEVICE_INFO → receive srand from device.
3. Derive session key:  MD5(login_key + srand)
4. Send FUN_SENDER_PAIR (uuid + login_key + dev_id) with session key.
5. Receive FUN_SENDER_PAIR ACK → device is paired and ready.
6. Send FUN_SENDER_DPS to set data points.
7. Receive FUN_RECEIVE_DP notifications for status updates.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from struct import pack
from typing import TYPE_CHECKING

from .cipher import AesUtils, SecretKeyManager
from .const import Coder, DEFAULT_CHAR_UUID, DEFAULT_NOTIF_UUID, DpType
from .packet import BleReceiver, TuyaDataPacket, XRequest

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

# Timeout for the initial pairing handshake (seconds)
PAIR_TIMEOUT = 15


class TuyaBLEProtocol:
    """Async BLE interface for a Tuya device.

    Public methods match TuyaProtocol so coordinator.py can use this
    as a drop-in replacement for WiFi devices.
    """

    def __init__(
        self,
        dev_id: str,
        local_key: str,
        ble_uuid: str,
        listener,
        notif_uuid: str = DEFAULT_NOTIF_UUID,
        char_uuid: str = DEFAULT_CHAR_UUID,
    ) -> None:
        """Initialise without connecting."""
        self._dev_id = dev_id
        self._local_key = local_key
        self._ble_uuid: bytes = (
            ble_uuid.encode("utf-8") if isinstance(ble_uuid, str) else ble_uuid
        )
        self._dev_id_bytes: bytes = dev_id.encode("utf-8")
        self._listener = listener
        self._notif_uuid = notif_uuid
        self._char_uuid = char_uuid

        # login_key = first 6 chars of local_key
        login_key: bytes = local_key[:6].encode("utf-8")
        self._secret_key_manager = SecretKeyManager(login_key)
        self._ble_receiver = BleReceiver()

        self._client = None
        self._sn_ack: int = 0
        self._paired_event: asyncio.Event = asyncio.Event()
        self.is_connected: bool = False
        # Mirrors TuyaProtocol.dispatched_dps used by coordinator event logic
        self.dispatched_dps: dict = {}

    # ------------------------------------------------------------------
    # Public interface matching TuyaProtocol
    # ------------------------------------------------------------------

    async def connect(self, hass: HomeAssistant, mac: str) -> None:
        """Connect to the BLE device and complete the pairing handshake."""
        from bleak import BleakClient, BleakError
        from homeassistant.components import bluetooth

        device = bluetooth.async_ble_device_from_address(hass, mac, connectable=True)
        if device is None:
            raise OSError(
                f"BLE device {mac} not yet discoverable — waiting for advertisement"
            )
        self._client = BleakClient(device)

        try:
            await self._client.connect()
        except BleakError as exc:
            raise OSError(f"BLE connect failed for {mac}: {exc}") from exc

        # Register a disconnection callback so the coordinator can reconnect
        self._client.set_disconnected_callback(self._on_ble_disconnected)
        await self._client.start_notify(self._notif_uuid, self._handle_notification)

        # Start handshake
        self._paired_event.clear()
        req = self._device_info_request()
        await self._write_request(req)

        try:
            async with asyncio.timeout(PAIR_TIMEOUT):
                await self._paired_event.wait()
        except TimeoutError as exc:
            await self._client.disconnect()
            raise OSError(f"BLE pairing timed out for {mac}") from exc

        self.is_connected = True

    async def status(self, cid=None) -> dict:
        """Return empty status — BLE devices push updates via notifications."""
        return {}

    async def set_dp(self, value, dp_index, cid=None) -> None:
        """Set a single DP value."""
        await self.set_dps({str(dp_index): value}, cid=cid)

    async def set_dps(self, dps: dict, cid=None) -> None:
        """Send a DPS dict to the device."""
        req = self._dps_request(dps)
        await self._write_request(req)
        # Optimistically track so coordinator event logic works
        self.dispatched_dps = dps

    async def update_dps(self, dps=None, cid=None) -> None:
        """No-op: BLE devices push state via notifications."""

    def add_dps_to_request(self, dp_indices) -> None:
        """No-op: BLE devices don't need DP request lists."""

    def set_updatedps_list(self, dpids) -> None:
        """No-op."""

    def keep_alive(self, _has_subdevices: bool = False) -> None:
        """No-op: BLE connection is maintained by bleak."""

    def enable_debug(self, enable: bool, name: str = "") -> None:
        """No-op."""

    async def reset(self, dpids, cid=None) -> None:
        """No-op."""

    async def close(self) -> None:
        """Disconnect from the BLE device."""
        self.is_connected = False
        if self._client and self._client.is_connected:
            try:
                await self._client.disconnect()
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("Error disconnecting BLE device: %s", exc)
        self._client = None

    # ------------------------------------------------------------------
    # Internal BLE notification handler
    # ------------------------------------------------------------------

    def _on_ble_disconnected(self, client) -> None:
        """Called by bleak when the BLE connection drops unexpectedly."""
        if self.is_connected:
            _LOGGER.debug("BLE device disconnected")
            self.is_connected = False
            self._listener.disconnected(Exception("BLE device disconnected"))

    def _handle_notification(self, handle: int, value: bytes) -> None:
        """Handle incoming BLE notification data."""
        ret = self._ble_receiver.parse_data_received(value, self._secret_key_manager)
        if ret is None:
            return

        if ret.code == Coder.FUN_SENDER_DEVICE_INFO:
            if ret.resp and ret.resp.success:
                self._secret_key_manager.set_srand(ret.resp.srand)
                req = self._pair_request()
                asyncio.ensure_future(self._write_request(req))

        elif ret.code == Coder.FUN_SENDER_PAIR:
            self._paired_event.set()
            self._listener.status_updated({})

        elif ret.code == Coder.FUN_RECEIVE_DP:
            dps = self._decode_dp_payload(ret.resp)
            if dps:
                self.dispatched_dps = dps
                self._listener.status_updated(dps)

    # ------------------------------------------------------------------
    # Request builders
    # ------------------------------------------------------------------

    def _next_sn_ack(self) -> int:
        self._sn_ack += 1
        return self._sn_ack

    def _device_info_request(self) -> XRequest:
        security_flag = 4
        return XRequest(
            sn_ack=self._next_sn_ack(),
            ack_sn=0,
            code=Coder.FUN_SENDER_DEVICE_INFO,
            security_flag=security_flag,
            secret_key=self._secret_key_manager.get(security_flag),
            iv=AesUtils.random_iv(),
            inp=b"",
        )

    def _pair_request(self) -> XRequest:
        security_flag = 5
        inp = bytearray()
        inp += self._ble_uuid
        inp += self._secret_key_manager.login_key
        inp += self._dev_id_bytes
        # Pad dev_id section to 22 bytes total
        for _ in range(22 - len(self._dev_id_bytes)):
            inp += b"\x00"
        return XRequest(
            sn_ack=self._next_sn_ack(),
            ack_sn=0,
            code=Coder.FUN_SENDER_PAIR,
            security_flag=security_flag,
            secret_key=self._secret_key_manager.get(security_flag),
            iv=AesUtils.random_iv(),
            inp=bytes(inp),
        )

    def _dps_request(self, dps: dict) -> XRequest:
        security_flag = 5
        raw = self._encode_dps(dps)
        return XRequest(
            sn_ack=self._next_sn_ack(),
            ack_sn=0,
            code=Coder.FUN_SENDER_DPS,
            security_flag=security_flag,
            secret_key=self._secret_key_manager.get(security_flag),
            iv=AesUtils.random_iv(),
            inp=raw,
        )

    # ------------------------------------------------------------------
    # DPS encoding / decoding
    # ------------------------------------------------------------------

    @staticmethod
    def _encode_dps(dps: dict) -> bytes:
        """Encode a DP dict to the Tuya BLE binary DPS format."""
        raw = b""
        for dp_id_str, dp_value in dps.items():
            dp_id = int(dp_id_str)
            if isinstance(dp_value, bool):
                raw += pack(">BB", dp_id, DpType.BOOLEAN)
                raw += pack(">BB", 1, 1 if dp_value else 0)
            elif isinstance(dp_value, int):
                raw += pack(">BB", dp_id, DpType.INT)
                raw += pack(">BI", 4, dp_value)
            elif isinstance(dp_value, str):
                encoded = dp_value.encode("utf-8")
                raw += pack(">BB", dp_id, DpType.STRING)
                raw += pack(">B", len(encoded)) + encoded
            else:
                # Treat as enum (single byte integer)
                raw += pack(">BB", dp_id, DpType.ENUM)
                raw += pack(">BB", 1, int(dp_value))
        return raw

    @staticmethod
    def _decode_dp_payload(raw: bytes) -> dict:
        """Decode a Tuya BLE binary DPS payload to a Python dict."""
        if not raw:
            return {}
        dps = {}
        i = 0
        try:
            while i < len(raw):
                dp_id = raw[i]
                dp_type = raw[i + 1]
                length = raw[i + 2]
                value_bytes = raw[i + 3 : i + 3 + length]
                i += 3 + length

                if dp_type == DpType.BOOLEAN:
                    dps[str(dp_id)] = value_bytes[0] != 0
                elif dp_type == DpType.INT:
                    dps[str(dp_id)] = int.from_bytes(value_bytes, "big")
                elif dp_type == DpType.STRING:
                    dps[str(dp_id)] = value_bytes.decode("utf-8", errors="replace")
                elif dp_type == DpType.ENUM:
                    dps[str(dp_id)] = value_bytes[0]
                elif dp_type == DpType.RAW:
                    dps[str(dp_id)] = value_bytes.hex()
        except (IndexError, struct.error):
            _LOGGER.debug("Failed to decode DP payload at offset %d", i)
        return dps

    # ------------------------------------------------------------------
    # GATT write helper
    # ------------------------------------------------------------------

    async def _write_request(self, req: XRequest) -> None:
        """Write all MTU-sized packets of a request to the GATT characteristic."""
        if self._client is None or not self._client.is_connected:
            raise OSError("BLE device not connected")
        for packet in req.pack():
            await self._client.write_gatt_char(
                self._char_uuid, bytes(packet), response=False
            )
