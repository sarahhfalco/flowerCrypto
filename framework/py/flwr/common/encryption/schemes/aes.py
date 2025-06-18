
# crypto_aes_puro.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

KEY_AES = b"0123456789abcdef0123456789abcdef"  # 32 byte -> AES-256
IV_SIZE = 16  # per CBC serve un IV di 16 byte (128 bit blocco AES)

def pad(data: bytes) -> bytes:
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(padded_data: bytes) -> bytes:
    pad_len = padded_data[-1]
    return padded_data[:-pad_len]

def encrypt(data: bytes) -> bytes:
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(KEY_AES), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = pad(data)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # prepende IV al risultato

def decrypt(encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:IV_SIZE]
    ciphertext = encrypted_data[IV_SIZE:]
    cipher = Cipher(algorithms.AES(KEY_AES), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded_plaintext)
