"""Hash, HMAC, PBKDF2, Base64, and UTF-8 helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Literal


HashName = Literal["sha1", "sha256", "sha3", "ripemd160"]


def digest(data: bytes, algorithm: str) -> bytes:
    name = algorithm.lower().replace("-", "")
    if name == "sha1":
        return hashlib.sha1(data).digest()
    if name == "sha256":
        return hashlib.sha256(data).digest()
    if name in {"sha3", "sha3256"}:
        return hashlib.sha3_256(data).digest()
    if name == "ripemd160":
        h = hashlib.new("ripemd160")
        h.update(data)
        return h.digest()
    raise ValueError(f"unsupported hash algorithm: {algorithm}")


def digest_hex(data: bytes, algorithm: str) -> str:
    return digest(data, algorithm).hex()


def hmac_digest(data: bytes, key: bytes, algorithm: str) -> bytes:
    name = algorithm.lower().replace("-", "")
    if name == "hmacsha1":
        return hmac.new(key, data, hashlib.sha1).digest()
    if name == "hmacsha256":
        return hmac.new(key, data, hashlib.sha256).digest()
    raise ValueError(f"unsupported HMAC algorithm: {algorithm}")


def pbkdf2(password: bytes, salt: bytes, iterations: int = 100_000, dklen: int = 32, algorithm: str = "sha256") -> bytes:
    return hashlib.pbkdf2_hmac(algorithm.lower().replace("-", ""), password, salt, iterations, dklen)


def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64_decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def utf8_encode(text: str) -> bytes:
    return text.encode("utf-8")


def utf8_decode(data: bytes) -> str:
    return data.decode("utf-8")
