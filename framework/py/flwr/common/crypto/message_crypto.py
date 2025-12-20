# Copyright 2025 Flower Labs GmbH. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
"""Message crypto utilities."""

from __future__ import annotations

import base64
import binascii
from typing import Protocol

from .aes_gcm import AesGcmCrypto


class MessageCrypto(Protocol):
    """Protocol for message encryption/decryption."""

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext bytes."""

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext bytes."""


class NoopCrypto:
    """No-op crypto implementation."""

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return plaintext as-is."""
        return plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Return ciphertext as-is."""
        return ciphertext


def get_message_crypto(config: dict) -> MessageCrypto:
    """Return MessageCrypto based on configuration."""
    crypto_type = str(config.get("type", "none")).lower()
    if crypto_type in {"none", "noop"}:
        return NoopCrypto()
    if crypto_type == "aes":
        key_b64 = config.get("key")
        if not key_b64:
            raise ValueError("AES message crypto requires a base64 key.")
        try:
            key = base64.b64decode(key_b64, validate=True)
        except (ValueError, binascii.Error) as err:
            raise ValueError("Invalid base64 key for AES message crypto.") from err
        return AesGcmCrypto(key)
    raise ValueError(f"Unsupported message crypto type: {crypto_type}")
