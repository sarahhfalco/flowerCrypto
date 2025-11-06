
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import os
KEY_CBC = b"0123456789abcdef0123456789abcdef"
KEY_HMAC = b"fedcba9876543210fedcba9876543210"
BLOCK_SIZE = 16
HMAC_LEN = 32

def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_aes_cbc_hmac(data: bytes) -> bytes:
    start = time.perf_counter()
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(KEY_CBC), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pad(data)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(KEY_HMAC, iv + ciphertext, hashlib.sha256).digest()
    duration = time.perf_counter() - start
    print(f"[CBC+HMAC ENCRYPT] {len(data)} byte → {duration:.6f} s")
    return iv + ciphertext + mac

def decrypt_aes_cbc_hmac(enc: bytes) -> bytes:
    start = time.perf_counter()
    iv = enc[:BLOCK_SIZE]
    ciphertext = enc[BLOCK_SIZE:-HMAC_LEN]
    mac = enc[-HMAC_LEN:]
    expected_mac = hmac.new(KEY_HMAC, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed!")
    cipher = Cipher(algorithms.AES(KEY_CBC), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad(padded)
    duration = time.perf_counter() - start
    print(f"[CBC+HMAC DECRYPT] {len(ciphertext)} byte → {duration:.6f} s")
    return plaintext
