"""RC6-32/20/16 block cipher with ECB/CBC helpers."""

from __future__ import annotations

from .utils import pkcs7_pad, pkcs7_unpad, split_blocks, xor_bytes

BLOCK_SIZE = 16
W = 32
R = 20
PW = 0xB7E15163
QW = 0x9E3779B9
MASK = 0xFFFFFFFF


def _rotl(x: int, y: int) -> int:
    y &= 31
    return ((x << y) | (x >> (32 - y))) & MASK


def _rotr(x: int, y: int) -> int:
    y &= 31
    return ((x >> y) | (x << (32 - y))) & MASK


def _u32(data: bytes) -> int:
    return int.from_bytes(data, "little")


def _pack(words: list[int]) -> bytes:
    return b"".join((w & MASK).to_bytes(4, "little") for w in words)


def key_schedule(key: bytes) -> list[int]:
    if not key:
        raise ValueError("RC6 key must not be empty")
    c = max(1, (len(key) + 3) // 4)
    padded = key + bytes(4 * c - len(key))
    l_words = [_u32(padded[i : i + 4]) for i in range(0, len(padded), 4)]
    s = [PW]
    for i in range(1, 2 * R + 4):
        s.append((s[i - 1] + QW) & MASK)

    a = b = i = j = 0
    for _ in range(3 * max(len(s), c)):
        a = s[i] = _rotl((s[i] + a + b) & MASK, 3)
        b = l_words[j] = _rotl((l_words[j] + a + b) & MASK, (a + b) & 31)
        i = (i + 1) % len(s)
        j = (j + 1) % c
    return s


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("RC6 block must be 16 bytes")
    s = key_schedule(key)
    a, b, c, d = [_u32(block[i : i + 4]) for i in range(0, 16, 4)]
    b = (b + s[0]) & MASK
    d = (d + s[1]) & MASK
    for i in range(1, R + 1):
        t = _rotl((b * ((2 * b + 1) & MASK)) & MASK, 5)
        u = _rotl((d * ((2 * d + 1) & MASK)) & MASK, 5)
        a = (_rotl(a ^ t, u) + s[2 * i]) & MASK
        c = (_rotl(c ^ u, t) + s[2 * i + 1]) & MASK
        a, b, c, d = b, c, d, a
    a = (a + s[2 * R + 2]) & MASK
    c = (c + s[2 * R + 3]) & MASK
    return _pack([a, b, c, d])


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("RC6 block must be 16 bytes")
    s = key_schedule(key)
    a, b, c, d = [_u32(block[i : i + 4]) for i in range(0, 16, 4)]
    c = (c - s[2 * R + 3]) & MASK
    a = (a - s[2 * R + 2]) & MASK
    for i in range(R, 0, -1):
        a, b, c, d = d, a, b, c
        u = _rotl((d * ((2 * d + 1) & MASK)) & MASK, 5)
        t = _rotl((b * ((2 * b + 1) & MASK)) & MASK, 5)
        c = _rotr((c - s[2 * i + 1]) & MASK, t) ^ u
        a = _rotr((a - s[2 * i]) & MASK, u) ^ t
    d = (d - s[1]) & MASK
    b = (b - s[0]) & MASK
    return _pack([a, b, c, d])


def encrypt(data: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    mode = mode.upper()
    padded = pkcs7_pad(data, BLOCK_SIZE)
    if mode == "ECB":
        return b"".join(encrypt_block(block, key) for block in split_blocks(padded, BLOCK_SIZE))
    if mode != "CBC":
        raise ValueError("RC6 mode must be ECB or CBC")
    if iv is None:
        iv = bytes(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("RC6-CBC IV must be 16 bytes")
    out, prev = [], iv
    for block in split_blocks(padded, BLOCK_SIZE):
        enc = encrypt_block(xor_bytes(block, prev), key)
        out.append(enc)
        prev = enc
    return b"".join(out)


def decrypt(data: bytes, key: bytes, mode: str = "CBC", iv: bytes | None = None) -> bytes:
    mode = mode.upper()
    if mode == "ECB":
        return pkcs7_unpad(b"".join(decrypt_block(block, key) for block in split_blocks(data, BLOCK_SIZE)), BLOCK_SIZE)
    if mode != "CBC":
        raise ValueError("RC6 mode must be ECB or CBC")
    if iv is None:
        iv = bytes(BLOCK_SIZE)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("RC6-CBC IV must be 16 bytes")
    out, prev = [], iv
    for block in split_blocks(data, BLOCK_SIZE):
        dec = xor_bytes(decrypt_block(block, key), prev)
        out.append(dec)
        prev = block
    return pkcs7_unpad(b"".join(out), BLOCK_SIZE)
