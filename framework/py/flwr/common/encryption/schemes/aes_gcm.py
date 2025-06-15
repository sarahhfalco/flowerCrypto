# crypto_aes.py
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

KEY_AESGCM = b"0123456789abcdef0123456789abcdef"
NONCE_SIZE = 12
#Garantisce confidenzialità e integrità aggiunge 28 byte di overhead (12 di nonce + 16 di tag)
def encrypt(data: bytes) -> bytes:
    #print("data origin", len(data), "bytes");
    aesgcm = AESGCM(KEY_AESGCM)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    result = nonce + ciphertext
    #print("data cript", len(result), "bytes");
    return result

def decrypt(encrypted_data: bytes) -> bytes:
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    aesgcm = AESGCM(KEY_AESGCM)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext
