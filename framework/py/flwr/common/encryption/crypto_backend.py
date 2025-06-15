from .schemes import (
    aes_gcm,
    hmac_only,
    chacha_poly
)


def encrypt(data: bytes, method: str) -> bytes:
    if method == "aes_gcm":
        return aes_gcm.encrypt(data)
    elif method == "hmac":
        return hmac_only.add_hmac(data)
    elif method == "chacha_poly":
        return chacha_poly.encrypt(data)



    else:
        raise ValueError(f"Unknown encryption method: {method}")


def decrypt(data: bytes, method: str) -> bytes:
    if method == "aes_gcm":
        return aes_gcm.decrypt(data)
    elif method == "hmac":
        return hmac_only.check_hmac(data)
    elif method == "chacha_poly":
        return chacha_poly.decrypt(data)
    else:
        raise ValueError(f"Unknown decryption method: {method}")
