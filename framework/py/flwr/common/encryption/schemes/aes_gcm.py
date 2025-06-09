from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

KEY_AESGCM = b"0123456789abcdef0123456789abcdef"
NONCE_SIZE = 12

def encrypt(data: bytes) -> bytes:
    aesgcm = AESGCM(KEY_AESGCM)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt(encrypted_data: bytes) -> bytes:
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    aesgcm = AESGCM(KEY_AESGCM)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
