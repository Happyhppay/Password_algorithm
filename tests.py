"""Self-checks and visible execution examples for the assignment."""

from __future__ import annotations

from crypto_lab import aes, ecc, rc6, rsa, sm4
from crypto_lab.api import STATUS_OK, call_algorithm


def check(condition: bool, name: str) -> None:
    if not condition:
        raise AssertionError(name)
    print(f"[OK] {name}")


def main() -> None:
    aes_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    aes_plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    aes_cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    check(aes.encrypt_block(aes_plain, aes_key) == aes_cipher, "AES-128 block encrypt vector")
    check(aes.decrypt_block(aes_cipher, aes_key) == aes_plain, "AES-128 block decrypt vector")

    sm4_key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    sm4_plain = bytes.fromhex("0123456789abcdeffedcba9876543210")
    sm4_cipher = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
    check(sm4.encrypt_block(sm4_plain, sm4_key) == sm4_cipher, "SM4 block encrypt vector")
    check(sm4.decrypt_block(sm4_cipher, sm4_key) == sm4_plain, "SM4 block decrypt vector")

    rc6_key = bytes.fromhex("00000000000000000000000000000000")
    rc6_plain = bytes.fromhex("00000000000000000000000000000000")
    rc6_cipher = rc6.encrypt_block(rc6_plain, rc6_key)
    check(rc6.decrypt_block(rc6_cipher, rc6_key) == rc6_plain, "RC6 block round trip")

    text = "北邮信息安全"
    aes_resp = call_algorithm(
        "AES",
        "encrypt",
        {"data": text, "key": "00112233445566778899aabbccddeeff", "key_format": "hex", "output_format": "hex"},
    )
    check(aes_resp["status"] == STATUS_OK, "Unified API AES encrypt")
    dec_resp = call_algorithm(
        "AES",
        "decrypt",
        {
            "data": aes_resp["result"],
            "data_format": "hex",
            "key": "00112233445566778899aabbccddeeff",
            "key_format": "hex",
            "output_format": "text",
        },
    )
    check(dec_resp["result"] == text, "Unified API AES decrypt")

    check(call_algorithm("SHA1", "digest", {"data": "abc"})["result"] == "a9993e364706816aba3e25717850c26c9cd0d89d", "SHA1")
    check(
        call_algorithm("SHA256", "digest", {"data": "abc"})["result"]
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA256",
    )
    check(call_algorithm("Base64", "encode", {"data": "hello"})["result"] == "aGVsbG8=", "Base64 encode")
    check(call_algorithm("UTF-8", "encode", {"data": "密码"})["result"] == "e5af86e7a081", "UTF-8 encode")

    rsa_key = rsa.generate_keypair(1024)
    message = b"assignment message"
    ciphertext = rsa.encrypt(message, rsa_key.public_key)
    check(rsa.decrypt(ciphertext, rsa_key) == message, "RSA-1024 encrypt/decrypt")
    signature = rsa.sign_sha1(message, rsa_key)
    check(rsa.verify_sha1(message, signature, rsa_key.public_key), "RSA-SHA1 sign/verify")

    ecc_key = ecc.generate_keypair()
    sig = ecc.sign(message, ecc_key, "sha1")
    check(ecc.verify(message, sig, ecc_key.public_key, "sha1"), "ECDSA secp160r1 sign/verify")
    alice = ecc.generate_keypair()
    bob = ecc.generate_keypair()
    check(ecc.ecdh(alice, bob.public_key) == ecc.ecdh(bob, alice.public_key), "ECC-160 ECDH shared secret")

    print("All checks passed.")


if __name__ == "__main__":
    main()
