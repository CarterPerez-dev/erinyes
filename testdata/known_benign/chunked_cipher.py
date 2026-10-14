# ©AngelaMos | 2026
# chunked_cipher.py
#
# A legitimate 32-byte-block keystream loop built on hmac from the standard
# library. The block-size indicator fires on the min(32, len(data) - offset)
# idiom, which honest cryptographic code uses constantly.

import hmac
import hashlib


def apply(key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    offset = 0
    counter = 0
    while offset < len(data):
        block = hmac.new(key, nonce + counter.to_bytes(8, "little"), hashlib.sha256).digest()
        take = min(32, len(data) - offset)
        for i in range(take):
            out[offset + i] = data[offset + i] ^ block[i]
        offset += take
        counter += 1
    return bytes(out)
