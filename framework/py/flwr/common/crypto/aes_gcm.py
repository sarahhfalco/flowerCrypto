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
"""AES-GCM implementation for message crypto."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_AES_GCM_NONCE_SIZE = 12


class AesGcmCrypto:
    """AES-GCM crypto implementation with random IV."""

    def __init__(self, key: bytes) -> None:
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext bytes."""
        nonce = os.urandom(_AES_GCM_NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext bytes."""
        if len(ciphertext) <= _AES_GCM_NONCE_SIZE:
            raise ValueError("Ciphertext is too short for AES-GCM payload.")
        nonce = ciphertext[:_AES_GCM_NONCE_SIZE]
        payload = ciphertext[_AES_GCM_NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, payload, None)
