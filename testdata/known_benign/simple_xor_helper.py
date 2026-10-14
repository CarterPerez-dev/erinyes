# ©AngelaMos | 2026
# simple_xor_helper.py
#
# Legitimate single-byte XOR helper of the kind CTF tooling and firmware
# parsers ship. One indicator fires. One indicator must never be enough.

import os


def xor(data: bytes, key: int) -> bytes:
    return bytes(v ^ key for v in data)


decrypt = lambda a, k: bytes(v ^ k for v in a)


def load(path: str, key: int) -> bytes:
    with open(path, "rb") as fh:
        return xor(fh.read(), key)


def save(path: str, data: bytes, key: int) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(xor(data, key))
    os.replace(tmp, path)
