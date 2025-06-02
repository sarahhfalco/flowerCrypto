import os
import time
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# === AES-GCM (AEAD) ===

KEY_AESGCM = b"0123456789abcdef0123456789abcdef"
NONCE_SIZE = 12

def encrypt_aes_gcm(data: bytes) -> bytes:
    start = time.perf_counter()
    aesgcm = AESGCM(KEY_AESGCM)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    duration = time.perf_counter() - start
    print(f"[AES-GCM ENCRYPT] {len(data)} byte → {duration:.6f} s")
    return nonce + ciphertext

def decrypt_aes_gcm(encrypted_data: bytes) -> bytes:
    start = time.perf_counter()
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    aesgcm = AESGCM(KEY_AESGCM)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    duration = time.perf_counter() - start
    print(f"[AES-GCM DECRYPT] {len(ciphertext)} byte → {duration:.6f} s")
    return plaintext

# === RSA ===

RSA_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PUBLIC_KEY = RSA_PRIVATE_KEY.public_key()

def encrypt_rsa(data: bytes) -> bytes:
    start = time.perf_counter()
    ciphertext = RSA_PUBLIC_KEY.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    duration = time.perf_counter() - start
    print(f"[RSA ENCRYPT] {len(data)} byte → {duration:.6f} s")
    return ciphertext

def decrypt_rsa(ciphertext: bytes) -> bytes:
    start = time.perf_counter()
    plaintext = RSA_PRIVATE_KEY.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    duration = time.perf_counter() - start
    print(f"[RSA DECRYPT] {len(ciphertext)} byte → {duration:.6f} s")
    return plaintext

# === AES-CBC + HMAC (Encrypt-then-MAC) ===

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
