"""Manual hash, HMAC, PBKDF2, Base64, and UTF-8 helpers."""

from __future__ import annotations

MASK32 = 0xFFFFFFFF


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _pad_64_be(data: bytes) -> bytes:
    bit_len = len(data) * 8
    data += b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64)
    return data + bit_len.to_bytes(8, "big")


def _pad_64_le(data: bytes) -> bytes:
    bit_len = len(data) * 8
    data += b"\x80"
    data += b"\x00" * ((56 - len(data) % 64) % 64)
    return data + bit_len.to_bytes(8, "little")


def sha1(data: bytes) -> bytes:
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    for chunk_start in range(0, len(_pad_64_be(data)), 64):
        chunk = _pad_64_be(data)[chunk_start : chunk_start + 64]
        w = [int.from_bytes(chunk[i : i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 80):
            w.append(_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20:
                f, k = (b & c) | ((~b) & d), 0x5A827999
            elif i < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif i < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6
            temp = (_rotl32(a, 5) + f + e + k + w[i]) & MASK32
            e, d, c, b, a = d, c, _rotl32(b, 30), a, temp
        h0 = (h0 + a) & MASK32
        h1 = (h1 + b) & MASK32
        h2 = (h2 + c) & MASK32
        h3 = (h3 + d) & MASK32
        h4 = (h4 + e) & MASK32
    return b"".join(x.to_bytes(4, "big") for x in (h0, h1, h2, h3, h4))


K256 = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def sha256(data: bytes) -> bytes:
    h = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    padded = _pad_64_be(data)
    for chunk_start in range(0, len(padded), 64):
        chunk = padded[chunk_start : chunk_start + 64]
        w = [int.from_bytes(chunk[i : i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (hh + s1 + ch + K256[i] + w[i]) & MASK32
            s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & MASK32
            hh, g, f, e, d, c, b, a = g, f, e, (d + temp1) & MASK32, c, b, a, (temp1 + temp2) & MASK32
        h = [(x + y) & MASK32 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return b"".join(x.to_bytes(4, "big") for x in h)


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


KECCAK_R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def _keccak_f(state: list[int]) -> None:
    for rc in KECCAK_RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], KECCAK_R[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= rc


def sha3_256(data: bytes) -> bytes:
    rate = 136
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x06)
    padded.extend(b"\x00" * ((rate - len(padded) % rate) % rate))
    padded[-1] ^= 0x80
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        _keccak_f(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(rate // 8):
            out.extend(state[i].to_bytes(8, "little"))
            if len(out) >= 32:
                return bytes(out[:32])
        _keccak_f(state)
    return bytes(out[:32])


R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
R2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
S1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
S2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]


def _ripemd_f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160(data: bytes) -> bytes:
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    k1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    k2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    padded = _pad_64_le(data)
    for chunk_start in range(0, len(padded), 64):
        block = padded[chunk_start : chunk_start + 64]
        x = [int.from_bytes(block[i : i + 4], "little") for i in range(0, 64, 4)]
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            t = (_rotl32((al + _ripemd_f(j, bl, cl, dl) + x[R1[j]] + k1[j // 16]) & MASK32, S1[j]) + el) & MASK32
            al, el, dl, cl, bl = el, dl, _rotl32(cl, 10), bl, t
            t = (_rotl32((ar + _ripemd_f(79 - j, br, cr, dr) + x[R2[j]] + k2[j // 16]) & MASK32, S2[j]) + er) & MASK32
            ar, er, dr, cr, br = er, dr, _rotl32(cr, 10), br, t
        t = (h1 + cl + dr) & MASK32
        h1 = (h2 + dl + er) & MASK32
        h2 = (h3 + el + ar) & MASK32
        h3 = (h4 + al + br) & MASK32
        h4 = (h0 + bl + cr) & MASK32
        h0 = t
    return b"".join(x.to_bytes(4, "little") for x in (h0, h1, h2, h3, h4))


def digest(data: bytes, algorithm: str) -> bytes:
    name = algorithm.lower().replace("-", "")
    if name == "sha1":
        return sha1(data)
    if name == "sha256":
        return sha256(data)
    if name in {"sha3", "sha3256"}:
        return sha3_256(data)
    if name == "ripemd160":
        return ripemd160(data)
    raise ValueError(f"unsupported hash algorithm: {algorithm}")


def digest_hex(data: bytes, algorithm: str) -> str:
    return digest(data, algorithm).hex()


def hmac_digest(data: bytes, key: bytes, algorithm: str) -> bytes:
    name = algorithm.lower().replace("-", "")
    hash_name = "sha1" if name == "hmacsha1" else "sha256" if name == "hmacsha256" else None
    if hash_name is None:
        raise ValueError(f"unsupported HMAC algorithm: {algorithm}")
    block_size = 64
    if len(key) > block_size:
        key = digest(key, hash_name)
    key = key.ljust(block_size, b"\x00")
    ipad = bytes(x ^ 0x36 for x in key)
    opad = bytes(x ^ 0x5C for x in key)
    return digest(opad + digest(ipad + data, hash_name), hash_name)


def pbkdf2(password: bytes, salt: bytes, iterations: int = 100_000, dklen: int = 32, algorithm: str = "sha256") -> bytes:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    name = algorithm.lower().replace("-", "")
    hlen = len(digest(b"", name))
    blocks = []
    for block_index in range(1, -(-dklen // hlen) + 1):
        u = hmac_digest(salt + block_index.to_bytes(4, "big"), password, f"hmac{name}")
        acc = bytearray(u)
        for _ in range(iterations - 1):
            u = hmac_digest(u, password, f"hmac{name}")
            acc = bytearray(a ^ b for a, b in zip(acc, u))
        blocks.append(bytes(acc))
    return b"".join(blocks)[:dklen]


def base64_encode(data: bytes) -> str:
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


def base64_decode(text: str) -> bytes:
    alphabet = {ch: i for i, ch in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}
    clean = "".join(ch for ch in text if not ch.isspace())
    if len(clean) % 4:
        raise ValueError("invalid Base64 length")
    out = bytearray()
    for i in range(0, len(clean), 4):
        quad = clean[i : i + 4]
        pad = quad.count("=")
        value = 0
        for ch in quad:
            value <<= 6
            if ch != "=":
                if ch not in alphabet:
                    raise ValueError("invalid Base64 character")
                value |= alphabet[ch]
        out.extend(value.to_bytes(3, "big")[: 3 - pad])
    return bytes(out)


def utf8_encode(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        code = ord(ch)
        if code <= 0x7F:
            out.append(code)
        elif code <= 0x7FF:
            out.extend((0xC0 | (code >> 6), 0x80 | (code & 0x3F)))
        elif code <= 0xFFFF:
            out.extend((0xE0 | (code >> 12), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F)))
        elif code <= 0x10FFFF:
            out.extend((0xF0 | (code >> 18), 0x80 | ((code >> 12) & 0x3F), 0x80 | ((code >> 6) & 0x3F), 0x80 | (code & 0x3F)))
        else:
            raise ValueError("invalid Unicode code point")
    return bytes(out)


def utf8_decode(data: bytes) -> str:
    chars = []
    i = 0
    while i < len(data):
        b0 = data[i]
        if b0 <= 0x7F:
            chars.append(chr(b0))
            i += 1
        elif 0xC2 <= b0 <= 0xDF:
            if i + 1 >= len(data) or data[i + 1] & 0xC0 != 0x80:
                raise ValueError("invalid UTF-8 sequence")
            chars.append(chr(((b0 & 0x1F) << 6) | (data[i + 1] & 0x3F)))
            i += 2
        elif 0xE0 <= b0 <= 0xEF:
            if i + 2 >= len(data) or any(b & 0xC0 != 0x80 for b in data[i + 1 : i + 3]):
                raise ValueError("invalid UTF-8 sequence")
            code = ((b0 & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F)
            chars.append(chr(code))
            i += 3
        elif 0xF0 <= b0 <= 0xF4:
            if i + 3 >= len(data) or any(b & 0xC0 != 0x80 for b in data[i + 1 : i + 4]):
                raise ValueError("invalid UTF-8 sequence")
            code = ((b0 & 0x07) << 18) | ((data[i + 1] & 0x3F) << 12) | ((data[i + 2] & 0x3F) << 6) | (data[i + 3] & 0x3F)
            chars.append(chr(code))
            i += 4
        else:
            raise ValueError("invalid UTF-8 sequence")
    return "".join(chars)
