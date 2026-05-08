"""Packet framing and reassembly for the Tuya BLE protocol."""

from __future__ import annotations

import logging
from struct import pack, unpack
from typing import TYPE_CHECKING

from .cipher import AesUtils, CrcUtils

if TYPE_CHECKING:
    from .cipher import SecretKeyManager

_LOGGER = logging.getLogger(__name__)

# Default GATT MTU in bytes
GATT_MTU = 20


class TuyaDataPacket:
    """Build encrypted BLE data packets ready for GATT writes."""

    @staticmethod
    def prepare_crc(sn_ack: int, ack_sn: int, code: int, inp: bytes) -> bytes:
        """Assemble header + payload + CRC-16."""
        raw = pack(">IIHH", sn_ack, ack_sn, code, len(inp)) + inp
        crc = CrcUtils.crc16(raw)
        return raw + pack(">H", crc)

    @staticmethod
    def encrypt_packet(
        secret_key: bytes, security_flag: int, iv: bytes, data: bytes
    ) -> bytes:
        """Pad to 16-byte boundary, encrypt with AES-CBC, prepend flag + IV."""
        while len(data) % 16 != 0:
            data += b"\x00"
        encrypted = AesUtils.encrypt(data, iv, secret_key)
        return security_flag.to_bytes(1, "big") + iv + encrypted


class XRequest:
    """Represents a single BLE command that can be split into GATT packets."""

    def __init__(
        self,
        sn_ack: int,
        ack_sn: int,
        code: int,
        security_flag: int,
        secret_key: bytes,
        iv: bytes,
        inp: bytes,
        gatt_mtu: int = GATT_MTU,
    ) -> None:
        """Initialise the request."""
        self.sn_ack = sn_ack
        self.ack_sn = ack_sn
        self.code = code
        self.security_flag = security_flag
        self.secret_key = secret_key
        self.iv = iv
        self.inp = inp
        self.gatt_mtu = gatt_mtu

    def _split_packet(self, protocol_version: int, data: bytes) -> list[bytearray]:
        """Split encrypted data into MTU-sized GATT frames."""
        output: list[bytearray] = []
        packet_number = 0
        pos = 0
        length = len(data)

        while pos < length:
            b = bytearray()
            b += packet_number.to_bytes(1, "big")

            if packet_number == 0:
                b += pack(">B", length)
                b += pack("<B", protocol_version << 4)

            sub_data = data[pos : pos + self.gatt_mtu - len(b)]
            b += sub_data
            output.append(b)

            pos += len(sub_data)
            packet_number += 1

        return output

    def pack(self) -> list[bytearray]:
        """Return the list of GATT write packets for this request."""
        code_value = self.code.value if hasattr(self.code, "value") else self.code
        data = TuyaDataPacket.prepare_crc(
            self.sn_ack, self.ack_sn, code_value, self.inp
        )
        encrypted = TuyaDataPacket.encrypt_packet(
            self.secret_key, self.security_flag, self.iv, data
        )
        return self._split_packet(2, encrypted)


class DeviceInfoResp:
    """Parsed Tuya BLE device info response."""

    def __init__(self) -> None:
        """Initialise with failure state."""
        self.success: bool = False
        self.srand: bytes = b""
        self.flag: int = 0
        self.is_bind: int = 0

    def parse(self, raw: bytes) -> None:
        """Parse the raw device info payload."""
        if len(raw) < 46:
            return
        (
            _dev_ver_major,
            _dev_ver_minor,
            proto_ver_major,
            proto_ver_minor,
            flag,
            is_bind,
            srand,
            _hw_major,
            _hw_minor,
            _auth_key,
        ) = unpack(">BBBBBB6sBB32s", raw[:46])

        proto = proto_ver_major * 10 + proto_ver_minor
        if proto < 20:
            return

        self.flag = flag
        self.is_bind = is_bind
        self.srand = srand
        self.success = True


class Ret:
    """A fully reassembled and decrypted BLE response."""

    def __init__(self, raw: bytes, version: int) -> None:
        """Initialise."""
        self.raw = raw
        self.version = version
        self.code = None
        self.resp = None

    def parse(self, secret_key: bytes) -> None:
        """Decrypt and parse the response payload."""
        from .const import Coder

        security_flag = self.raw[0]  # noqa: F841  (kept for clarity)
        iv = self.raw[1:17]
        encrypted_data = self.raw[17:]
        decrypted_data = AesUtils.decrypt(encrypted_data, iv, secret_key)

        _sn, _sn_ack, code, length = unpack(">IIHH", decrypted_data[:12])
        raw_data = decrypted_data[12 : 12 + length]

        try:
            self.code = Coder(code)
        except ValueError:
            self.code = code
            return

        if self.code == Coder.FUN_SENDER_DEVICE_INFO:
            resp = DeviceInfoResp()
            resp.parse(raw_data)
            self.resp = resp
        elif self.code == Coder.FUN_RECEIVE_DP:
            self.resp = raw_data
        elif self.code == Coder.FUN_SENDER_PAIR:
            # ACK for pair — no payload needed
            self.resp = raw_data


class BleReceiver:
    """Reassemble fragmented BLE notification frames into complete messages."""

    def __init__(self) -> None:
        """Initialise receiver state."""
        self.last_index: int = 0
        self.data_length: int = 0
        self.current_length: int = 0
        self.raw: bytearray = bytearray()
        self.version: int = 0

    def _unpack(self, arr: bytes) -> int:
        """Parse a GATT frame fragment.

        Returns:
            0 = complete message ready
            1 = incomplete, more frames needed
            2 = framing error (first-packet header issue)
            3 = length mismatch
        """
        i = 0
        packet_number = 0
        while i < 4 and i < len(arr):
            b = arr[i]
            packet_number |= (b & 255) << (i * 7)
            if not ((b >> 7) & 1):
                break
            i += 1

        pos = i + 1

        if packet_number == 0:
            self.data_length = 0
            while pos <= i + 4 and pos < len(arr):
                b2 = arr[pos]
                self.data_length |= (b2 & 255) << (((pos - 1) - i) * 7)
                if not ((b2 >> 7) & 1):
                    break
                pos += 1

            self.current_length = 0
            self.last_index = 0

            if pos == i + 5 or len(arr) < pos + 2:
                return 2

            self.raw = bytearray()
            pos += 1
            self.version = (arr[pos] >> 4) & 15
            pos += 1

        if packet_number == 0 or packet_number > self.last_index:
            data = bytearray(arr[pos:])
            self.current_length += len(data)
            self.last_index = packet_number
            self.raw += data

            if self.current_length < self.data_length:
                return 1
            return 0 if self.current_length == self.data_length else 3

        return 3

    def parse_data_received(
        self, arr: bytes, secret_key_manager: SecretKeyManager
    ) -> Ret | None:
        """Parse incoming GATT notification data.

        Returns a Ret instance when a full message has been received and
        decrypted, or None if the message is incomplete.
        """
        status = self._unpack(arr)
        if status != 0:
            return None

        security_flag = self.raw[0]
        secret_key = secret_key_manager.get(security_flag)
        if secret_key is None:
            _LOGGER.warning(
                "No BLE key for security_flag=%d — is pairing complete?", security_flag
            )
            return None

        ret = Ret(bytes(self.raw), self.version)
        ret.parse(secret_key)
        return ret
