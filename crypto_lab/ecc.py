"""ECC-160 implementation over secp160r1 with ECDSA."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from .utils import modinv

# SEC 2 secp160r1 parameters.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF
A = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
B = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45
GX = 0x4A96B5688EF573284664698968C38BB913CBFC82
GY = 0x23A628553168947D59DCC912042351377AC5FB32
N = 0x0100000000000000000001F4C8F927AED3CA752257
H = 1


@dataclass(frozen=True)
class Point:
    x: int
    y: int
    infinity: bool = False


G = Point(GX, GY)
O = Point(0, 0, True)


@dataclass(frozen=True)
class ECCPrivateKey:
    d: int

    @property
    def public_key(self) -> "ECCPublicKey":
        return ECCPublicKey(scalar_mult(self.d, G))


@dataclass(frozen=True)
class ECCPublicKey:
    q: Point


def is_on_curve(point: Point) -> bool:
    if point.infinity:
        return True
    return (point.y * point.y - (point.x * point.x * point.x + A * point.x + B)) % P == 0


def point_neg(point: Point) -> Point:
    if point.infinity:
        return point
    return Point(point.x, (-point.y) % P)


def point_add(p1: Point, p2: Point) -> Point:
    if p1.infinity:
        return p2
    if p2.infinity:
        return p1
    if p1.x == p2.x and (p1.y + p2.y) % P == 0:
        return O
    if p1 == p2:
        lam = ((3 * p1.x * p1.x + A) * modinv(2 * p1.y, P)) % P
    else:
        lam = ((p2.y - p1.y) * modinv(p2.x - p1.x, P)) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)


def scalar_mult(k: int, point: Point = G) -> Point:
    if k % N == 0 or point.infinity:
        return O
    if k < 0:
        return scalar_mult(-k, point_neg(point))
    result = O
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def generate_keypair() -> ECCPrivateKey:
    return ECCPrivateKey(secrets.randbelow(N - 1) + 1)


def _bits2int(digest: bytes) -> int:
    z = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - N.bit_length()
    if excess > 0:
        z >>= excess
    return z


def sign(message: bytes, private_key: ECCPrivateKey, hash_name: str = "sha1") -> tuple[int, int]:
    digest = hashlib.new(hash_name, message).digest()
    z = _bits2int(digest)
    while True:
        k = secrets.randbelow(N - 1) + 1
        p = scalar_mult(k, G)
        r = p.x % N
        if r == 0:
            continue
        s = (modinv(k, N) * (z + r * private_key.d)) % N
        if s:
            return r, s


def verify(message: bytes, signature: tuple[int, int], public_key: ECCPublicKey, hash_name: str = "sha1") -> bool:
    r, s = signature
    if not (1 <= r < N and 1 <= s < N) or not is_on_curve(public_key.q):
        return False
    digest = hashlib.new(hash_name, message).digest()
    z = _bits2int(digest)
    w = modinv(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    point = point_add(scalar_mult(u1, G), scalar_mult(u2, public_key.q))
    if point.infinity:
        return False
    return point.x % N == r


def ecdh(private_key: ECCPrivateKey, public_key: ECCPublicKey) -> int:
    if not is_on_curve(public_key.q):
        raise ValueError("public key point is not on curve")
    shared = scalar_mult(private_key.d, public_key.q)
    if shared.infinity:
        raise ValueError("invalid shared point")
    return shared.x


def private_key_to_dict(key: ECCPrivateKey) -> dict[str, str]:
    return {"curve": "secp160r1", "d": hex(key.d)}


def public_key_to_dict(key: ECCPublicKey) -> dict[str, str]:
    return {"curve": "secp160r1", "x": hex(key.q.x), "y": hex(key.q.y)}


def private_key_from_dict(data: dict) -> ECCPrivateKey:
    return ECCPrivateKey(int(str(data["d"]), 0))


def public_key_from_dict(data: dict) -> ECCPublicKey:
    return ECCPublicKey(Point(int(str(data["x"]), 0), int(str(data["y"]), 0)))
