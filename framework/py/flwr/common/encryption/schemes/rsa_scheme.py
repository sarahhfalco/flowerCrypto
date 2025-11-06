# Reimport necessary packages after environment reset
import os
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# === AES-GCM ===
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
