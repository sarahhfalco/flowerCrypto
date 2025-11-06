# Reimport necessary packages after environment reset
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import  ec
from cryptography.hazmat.primitives import  hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import os
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_aes_key(private_key, peer_public_key) -> bytes:
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)
    return derived_key

def encrypt_ecc_aes_gcm(data: bytes, aes_key: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_ecc_aes_gcm(encrypted_data: bytes, aes_key: bytes) -> bytes:
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
