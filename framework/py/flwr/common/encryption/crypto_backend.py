from .schemes import (
    aes_gcm,
    hmac_only,
    chacha_poly,ecc_scheme, he_ckks
)


def encrypt(data: bytes, method: str) -> bytes:
    if method == "aes_gcm":
        return aes_gcm.encrypt(data)
    elif method == "hmac":
        return hmac_only.add_hmac(data)
    elif method == "chacha_poly":
        return chacha_poly.encrypt(data)
    elif method == "ecc":
        return ecc_scheme.ecc_encrypt(data)
    elif method == "he_ckks":
         return he_ckks.encrypt(data)
    else:
        raise ValueError(f"Unknown encryption method: {method}")


def decrypt(data: bytes, method: str) -> bytes:
    if method == "aes_gcm":
        return aes_gcm.decrypt(data)
    elif method == "hmac":
        return hmac_only.check_hmac(data)
    elif method == "chacha_poly":
        return chacha_poly.decrypt(data)
    elif method == "ecc":
        return ecc_scheme.ecc_decrypt(data)
    elif method == "he_ckks":
        return he_ckks.decrypt(data)
    else:
        raise ValueError(f"Unknown decryption method: {method}")
