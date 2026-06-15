"""Educational RSA-1024 implementation and RSA-SHA1 signatures."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .hash_codecs import sha1
from .utils import bytes_to_int, generate_prime, int_to_bytes, modinv, sha1_digest_info


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)


def generate_keypair(bits: int = 1024, e: int = 65537) -> RSAPrivateKey:
    if bits < 512:
        raise ValueError("RSA key size must be at least 512 bits")
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        d = modinv(e, phi)
        return RSAPrivateKey(n=n, e=e, d=d, p=p, q=q)


def _key_len(n: int) -> int:
    return (n.bit_length() + 7) // 8


def encrypt(message: bytes, public_key: RSAPublicKey) -> bytes:
    k = _key_len(public_key.n)
    if len(message) > k - 11:
        raise ValueError("message too long for RSA PKCS#1 v1.5 encryption block")
    ps_len = k - len(message) - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.randbelow(255) + 1
        ps.append(b)
    encoded = b"\x00\x02" + bytes(ps) + b"\x00" + message
    c = pow(bytes_to_int(encoded), public_key.e, public_key.n)
    return int_to_bytes(c, k)


def decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    k = _key_len(private_key.n)
    if len(ciphertext) != k:
        raise ValueError("ciphertext length does not match RSA modulus")
    m = pow(bytes_to_int(ciphertext), private_key.d, private_key.n)
    encoded = int_to_bytes(m, k)
    if not encoded.startswith(b"\x00\x02"):
        raise ValueError("invalid RSA PKCS#1 v1.5 encryption padding")
    sep = encoded.find(b"\x00", 2)
    if sep < 10:
        raise ValueError("invalid RSA PKCS#1 v1.5 encryption padding")
    return encoded[sep + 1 :]


def sign_sha1(message: bytes, private_key: RSAPrivateKey) -> bytes:
    k = _key_len(private_key.n)
    digest_info = sha1_digest_info(sha1(message))
    if len(digest_info) > k - 11:
        raise ValueError("digest info too long")
    padding = b"\xff" * (k - len(digest_info) - 3)
    encoded = b"\x00\x01" + padding + b"\x00" + digest_info
    sig = pow(bytes_to_int(encoded), private_key.d, private_key.n)
    return int_to_bytes(sig, k)


def verify_sha1(message: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    k = _key_len(public_key.n)
    if len(signature) != k:
        return False
    recovered = int_to_bytes(pow(bytes_to_int(signature), public_key.e, public_key.n), k)
    digest_info = sha1_digest_info(sha1(message))
    expected = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    return recovered == expected


def private_key_to_dict(key: RSAPrivateKey) -> dict[str, str | int]:
    return {
        "n": hex(key.n),
        "e": key.e,
        "d": hex(key.d),
        "p": hex(key.p),
        "q": hex(key.q),
    }


def public_key_to_dict(key: RSAPublicKey) -> dict[str, str | int]:
    return {"n": hex(key.n), "e": key.e}


def private_key_from_dict(data: dict) -> RSAPrivateKey:
    return RSAPrivateKey(
        n=int(str(data["n"]), 0),
        e=int(data["e"]),
        d=int(str(data["d"]), 0),
        p=int(str(data["p"]), 0),
        q=int(str(data["q"]), 0),
    )


def public_key_from_dict(data: dict) -> RSAPublicKey:
    return RSAPublicKey(n=int(str(data["n"]), 0), e=int(data["e"]))
