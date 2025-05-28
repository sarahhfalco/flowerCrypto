import os, hmac, hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Chiave e nonce fissi a scopo di test
key = b"0123456789abcdef0123456789abcdef"  # 32 byte = 256 bit
nonce = b"abcdef123456"  # 12 byte per AES-GCM
KEY_ENC = os.urandom(32)
KEY_MAC = os.urandom(32)

def encrypt_tensor(tensor_bytes: bytes) -> bytes:
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, tensor_bytes, None)
    return nonce + ciphertext 

def decrypt_tensor(encrypted: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


KEY_ENC = b"0123456789abcdef0123456789abcdef"  # 32 byte (AES-256)
KEY_MAC = b"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"  # 64 byte

# Lunghezze fisse
NONCE_LEN = 12
HMAC_LEN = 32


def encrypt_and_mac(plaintext: bytes) -> bytes:
    """Cifra i dati con AES-GCM e aggiunge un HMAC-SHA256 su nonce+ciphertext."""
    # Cifratura AES-GCM
    aesgcm = AESGCM(KEY_ENC)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Calcola HMAC su nonce+ciphertext
    msg = nonce + ciphertext
    mac = hmac.new(KEY_MAC, msg, hashlib.sha256).digest()

    return msg + mac  # nonce + ciphertext + mac


def decrypt_and_verify(enc_data: bytes) -> bytes:
    """Verifica HMAC e decifra i dati con AES-GCM."""
    if len(enc_data) < NONCE_LEN + HMAC_LEN:
        raise ValueError("Encrypted data too short")

    nonce = enc_data[:NONCE_LEN]
    ciphertext = enc_data[NONCE_LEN:-HMAC_LEN]
    mac = enc_data[-HMAC_LEN:]

    # Verifica HMAC
    expected_mac = hmac.new(KEY_MAC, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed")

    # Decifra
    aesgcm = AESGCM(KEY_ENC)
    return aesgcm.decrypt(nonce, ciphertext, None)
