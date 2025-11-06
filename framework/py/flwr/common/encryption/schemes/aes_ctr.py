# Reimport necessary packages after environment reset

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os
KEY = b"0123456789abcdef0123456789abcdef"  # 32 byte per AES-256
NONCE = os.urandom(16)

def encrypt_aes_ctr(data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(KEY), modes.CTR(NONCE), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return NONCE + ciphertext

def decrypt_aes_ctr(encrypted: bytes) -> bytes:
    nonce = encrypted[:16]
    ciphertext = encrypted[16:]
    cipher = Cipher(algorithms.AES(KEY), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
