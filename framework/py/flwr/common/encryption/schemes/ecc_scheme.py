from ecies import encrypt, decrypt
import os

# Path alla directory `encryption/`
base_dir = os.path.dirname(os.path.dirname(__file__))  # flwr/common/encryption/
key_dir = os.path.join(base_dir, "keys")

# Path completi alle chiavi
private_key_path = os.path.join(key_dir, "private_key.hex")
public_key_path = os.path.join(key_dir, "public_key.hex")

# Carica chiavi da file
def load_key(path: str) -> str:
    with open(path, "r") as f:
        return f.read().strip()

# Chiavi caricate
PRIVATE_KEY_HEX = load_key(private_key_path)
PUBLIC_KEY_HEX = load_key(public_key_path)

# Cifratura/decifratura
def ecc_encrypt(data: bytes) -> bytes:
    return encrypt(PUBLIC_KEY_HEX, data)

def ecc_decrypt(data: bytes) -> bytes:
    return decrypt(PRIVATE_KEY_HEX, data)
