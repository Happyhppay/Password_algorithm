"""Shared helpers for byte conversion, padding, and number theory."""

from __future__ import annotations

import secrets
from typing import Any


def to_bytes(value: Any, encoding: str = "utf-8") -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode(encoding)
    if isinstance(value, int):
        if value == 0:
            return b"\x00"
        return value.to_bytes((value.bit_length() + 7) // 8, "big")
    return str(value).encode(encoding)


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_bytes(value: str) -> bytes:
    value = value.strip()
    if value.startswith("0x"):
        value = value[2:]
    if len(value) % 2:
        value = "0" + value
    return bytes.fromhex(value)


def bytes_to_b64(data: bytes) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    out = []
    for i in range(0, len(data), 3):
        block = data[i : i + 3]
        value = int.from_bytes(block.ljust(3, b"\x00"), "big")
        out.append(alphabet[(value >> 18) & 0x3F])
        out.append(alphabet[(value >> 12) & 0x3F])
        out.append(alphabet[(value >> 6) & 0x3F] if len(block) > 1 else "=")
        out.append(alphabet[value & 0x3F] if len(block) > 2 else "=")
    return "".join(out)


def b64_to_bytes(value: str) -> bytes:
    alphabet = {ch: i for i, ch in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}
    clean = "".join(ch for ch in value if not ch.isspace())
    if len(clean) % 4:
        raise ValueError("invalid Base64 length")
    out = bytearray()
    for i in range(0, len(clean), 4):
        quad = clean[i : i + 4]
        pad = quad.count("=")
        n = 0
        for ch in quad:
            n <<= 6
            if ch != "=":
                if ch not in alphabet:
                    raise ValueError("invalid Base64 character")
                n |= alphabet[ch]
        out.extend(n.to_bytes(3, "big")[: 3 - pad])
    return bytes(out)


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in range 1..255")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid PKCS#7 data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data: bytes, block_size: int) -> list[bytes]:
    if len(data) % block_size:
        raise ValueError("data length must be a multiple of block size")
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    if n < 0:
        raise ValueError("negative integers are not supported")
    needed = max(1, (n.bit_length() + 7) // 8)
    size = needed if length is None else length
    if needed > size:
        raise ValueError("integer does not fit in requested length")
    return n.to_bytes(size, "big")


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("prime size is too small")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << bits - 1) | 1
        if is_probable_prime(candidate):
            return candidate


def sha1_digest_info(digest: bytes) -> bytes:
    prefix = bytes.fromhex("3021300906052b0e03021a05000414")
    return prefix + digest


def sha256_digest_info(digest: bytes) -> bytes:
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    return prefix + digest
