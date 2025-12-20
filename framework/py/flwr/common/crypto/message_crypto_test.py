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
"""Tests for message crypto."""

import base64
import os

import pytest

from .message_crypto import get_message_crypto


def test_aes_gcm_roundtrip() -> None:
    """Test AES-GCM encryption/decryption roundtrip."""
    key = base64.b64encode(os.urandom(32)).decode("utf-8")
    crypto = get_message_crypto({"type": "aes", "key": key})
    plaintext = b"flower-crypto"
    ciphertext = crypto.encrypt(plaintext)

    assert ciphertext != plaintext
    assert crypto.decrypt(ciphertext) == plaintext


def test_noop_crypto_no_change() -> None:
    """Test noop mode does not modify bytes."""
    crypto = get_message_crypto({"type": "none"})
    plaintext = b"noop"

    assert crypto.encrypt(plaintext) == plaintext
    assert crypto.decrypt(plaintext) == plaintext


def test_aes_gcm_missing_key_raises() -> None:
    """Test missing AES key raises error."""
    with pytest.raises(ValueError, match="base64 key"):
        get_message_crypto({"type": "aes"})
