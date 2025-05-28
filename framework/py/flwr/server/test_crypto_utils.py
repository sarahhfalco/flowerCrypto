import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM encryption configuration
AES_KEY = os.urandom(32)  # 256-bit key
ENCRYPTED_PREFIX = b"CYPH"  # Custom prefix to identify encrypted tensors


def encrypt_tensor(tensor: bytes) -> bytes:
    nonce = os.urandom(12)  # 96-bit nonce
    aesgcm = AESGCM(AES_KEY)
    ciphertext = aesgcm.encrypt(nonce, tensor, associated_data=None)
    return ENCRYPTED_PREFIX + nonce + ciphertext


def decrypt_tensor(encrypted_tensor: bytes) -> bytes:
    if not encrypted_tensor.startswith(ENCRYPTED_PREFIX):
        raise ValueError("Tensore non cifrato con AES-GCM (prefisso mancante).")

    nonce = encrypted_tensor[4:16]         # 12 byte dopo il prefisso
    ciphertext = encrypted_tensor[16:]     # il resto è il ciphertext
    aesgcm = AESGCM(AES_KEY)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# Test routine
def test_encryption_decryption():
    original_tensor = b"This is a test tensor. It contains numerical weights like a model."

    print("\n=== TEST ENCRYPTION/DECRYPTION ===")
    print("Original tensor:", original_tensor)

    encrypted = encrypt_tensor(original_tensor)
    print("Encrypted tensor (hex preview):", encrypted[:32].hex(), "...")

    decrypted = decrypt_tensor(encrypted)
    print("Decrypted tensor:", decrypted)

    assert decrypted == original_tensor, "Decryption failed: data does not match"
    print("✅ Decryption successful. Tensor integrity verified.\n")


if __name__ == "__main__":
    test_encryption_decryption()
