# encryption/crypto_backend.py

from .schemes import aes_gcm, cbc_hmac, rsa_scheme, ecc_scheme, aes_ctr, hmac_only

def encrypt(data: bytes, method: str) -> bytes:
    if method == "aes_gcm":
        return aes_gcm.encrypt(data)
    elif method == "cbc_hmac":
        return cbc_hmac.encrypt(data)
    elif method == "rsa":
        return rsa_scheme.encrypt(data)
    elif method == "aes_ctr":
        return aes_ctr.encrypt(data)
    elif method == "hmac":
        return hmac_only.add_hmac(data)
    else:
        raise ValueError(f"Unknown encryption method: {method}")

def decrypt(data: bytes, method: str) -> bytes:
    if method == "aes_gcm":
        return aes_gcm.decrypt(data)
    elif method == "cbc_hmac":
        return cbc_hmac.decrypt(data)
    elif method == "rsa":
        return rsa_scheme.decrypt(data)
    elif method == "aes_ctr":
        return aes_ctr.decrypt(data)
    elif method == "hmac":
        return hmac_only.check_hmac(data)
    else:
        raise ValueError(f"Unknown decryption method: {method}")
