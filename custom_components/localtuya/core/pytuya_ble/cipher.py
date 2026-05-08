"""Cryptographic utilities for Tuya BLE protocol."""

from __future__ import annotations

import hashlib
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SecretKeyManager:
    """Manage AES keys derived from the device login key.

    security_flag 4 → MD5(login_key)
    security_flag 5 → MD5(login_key + srand)  (set after device info response)
    """

    def __init__(self, login_key: bytes) -> None:
        """Initialise with the BLE login key (local_key[:6] as bytes)."""
        self.login_key: bytes = login_key
        self._keys: dict[int, bytes] = {
            4: hashlib.md5(login_key).digest(),
        }

    def get(self, security_flag: int) -> bytes | None:
        """Return the AES key for the given security flag, or None if unknown."""
        return self._keys.get(security_flag)

    def set_srand(self, srand: bytes) -> None:
        """Derive and store the session key using the device srand value."""
        self._keys[5] = hashlib.md5(self.login_key + srand).digest()


class AesUtils:
    """AES-CBC encrypt/decrypt helpers."""

    @staticmethod
    def decrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
        """Decrypt AES-CBC ciphertext."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    @staticmethod
    def encrypt(data: bytes, iv: bytes, key: bytes) -> bytes:
        """Encrypt plaintext with AES-CBC."""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    @staticmethod
    def random_iv() -> bytes:
        """Return a cryptographically random 16-byte IV."""
        return secrets.token_bytes(16)


class CrcUtils:
    """CRC-16 (Modbus/IBM variant) utilities."""

    @staticmethod
    def crc16(data: bytes) -> int:
        """Compute CRC-16 checksum."""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte & 0xFF
            for _ in range(8):
                tmp = crc & 1
                crc >>= 1
                if tmp:
                    crc ^= 0xA001
        return crc
