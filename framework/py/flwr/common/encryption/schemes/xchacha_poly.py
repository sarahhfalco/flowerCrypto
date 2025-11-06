from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
import os

# 256-bit example key (do not use in production)
KEY_XCHACHA = b"abcdef0123456789abcdef0123456789"
NONCE_SIZE = 24  # XChaCha20-Poly1305 uses 24-byte nonces

def encrypt(data: bytes) -> bytes:
    """Encrypt data using XChaCha20-Poly1305."""
    nonce = os.urandom(NONCE_SIZE)
    cipher = XChaCha20Poly1305(KEY_XCHACHA)
    ciphertext = cipher.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt(encrypted_data: bytes) -> bytes:
    """Decrypt data encrypted with XChaCha20-Poly1305."""
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    cipher = XChaCha20Poly1305(KEY_XCHACHA)
    return cipher.decrypt(nonce, ciphertext, None)
