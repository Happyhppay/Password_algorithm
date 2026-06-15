"""Unified callable interface for third-party programs."""

from __future__ import annotations

import json
from typing import Any

from . import aes, ecc, hash_codecs, rc6, rsa, sm4
from .utils import b64_to_bytes, bytes_to_b64, hex_to_bytes, to_bytes

STATUS_OK = 0
STATUS_ERROR = 1


def _read_bytes(params: dict[str, Any], name: str, default: Any = None) -> bytes:
    value = params.get(name, default)
    if value is None:
        return b""
    fmt = str(params.get(f"{name}_format", "text")).lower()
    if fmt == "hex":
        return hex_to_bytes(str(value))
    if fmt in {"base64", "b64"}:
        return b64_to_bytes(str(value))
    return to_bytes(value)


def _encode_bytes(data: bytes, fmt: str = "hex") -> str:
    fmt = fmt.lower()
    if fmt == "hex":
        return data.hex()
    if fmt in {"base64", "b64"}:
        return bytes_to_b64(data)
    if fmt == "text":
        return data.decode("utf-8")
    raise ValueError(f"unsupported output format: {fmt}")


def _symmetric(module: Any, operation: str, params: dict[str, Any]) -> str:
    key = _read_bytes(params, "key")
    data = _read_bytes(params, "data")
    iv = _read_bytes(params, "iv") if "iv" in params else None
    mode = str(params.get("mode", "CBC"))
    out_fmt = str(params.get("output_format", "hex"))
    if operation == "encrypt":
        return _encode_bytes(module.encrypt(data, key, mode, iv), out_fmt)
    if operation == "decrypt":
        return _encode_bytes(module.decrypt(data, key, mode, iv), out_fmt)
    if operation == "encrypt_block":
        return _encode_bytes(module.encrypt_block(data, key), out_fmt)
    if operation == "decrypt_block":
        return _encode_bytes(module.decrypt_block(data, key), out_fmt)
    raise ValueError(f"unsupported symmetric operation: {operation}")


def _rsa(operation: str, params: dict[str, Any]) -> Any:
    if operation == "generate_keypair":
        key = rsa.generate_keypair(int(params.get("bits", 1024)))
        return {"private_key": rsa.private_key_to_dict(key), "public_key": rsa.public_key_to_dict(key.public_key)}
    if operation == "encrypt":
        public = rsa.public_key_from_dict(params["public_key"])
        return _encode_bytes(rsa.encrypt(_read_bytes(params, "data"), public), str(params.get("output_format", "hex")))
    if operation == "decrypt":
        private = rsa.private_key_from_dict(params["private_key"])
        return _encode_bytes(rsa.decrypt(_read_bytes(params, "data"), private), str(params.get("output_format", "text")))
    if operation in {"sign", "sign_sha1", "rsa_sha1"}:
        private = rsa.private_key_from_dict(params["private_key"])
        return _encode_bytes(rsa.sign_sha1(_read_bytes(params, "data"), private), str(params.get("output_format", "hex")))
    if operation in {"verify", "verify_sha1"}:
        public = rsa.public_key_from_dict(params["public_key"])
        signature = _read_bytes(params, "signature")
        return rsa.verify_sha1(_read_bytes(params, "data"), signature, public)
    raise ValueError(f"unsupported RSA operation: {operation}")


def _ecc(operation: str, params: dict[str, Any]) -> Any:
    if operation == "generate_keypair":
        key = ecc.generate_keypair()
        return {"private_key": ecc.private_key_to_dict(key), "public_key": ecc.public_key_to_dict(key.public_key)}
    if operation in {"sign", "ecdsa"}:
        private = ecc.private_key_from_dict(params["private_key"])
        r, s = ecc.sign(_read_bytes(params, "data"), private, str(params.get("hash", "sha1")))
        return {"r": hex(r), "s": hex(s)}
    if operation == "verify":
        public = ecc.public_key_from_dict(params["public_key"])
        sig = params["signature"]
        signature = (int(str(sig["r"]), 0), int(str(sig["s"]), 0))
        return ecc.verify(_read_bytes(params, "data"), signature, public, str(params.get("hash", "sha1")))
    if operation in {"ecdh", "shared_secret"}:
        private = ecc.private_key_from_dict(params["private_key"])
        public = ecc.public_key_from_dict(params["public_key"])
        return hex(ecc.ecdh(private, public))
    raise ValueError(f"unsupported ECC operation: {operation}")


def call_algorithm(algorithm: str, operation: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call an algorithm and return a visible status/result object.

    Status code 0 means success; status code 1 means the algorithm rejected the input
    or an unsupported algorithm/operation was requested.
    """

    params = params or {}
    name = algorithm.lower().replace("-", "").replace("_", "")
    op = operation.lower().replace("-", "_")
    try:
        if name == "aes":
            result = _symmetric(aes, op, params)
        elif name == "sm4":
            result = _symmetric(sm4, op, params)
        elif name == "rc6":
            result = _symmetric(rc6, op, params)
        elif name in {"sha1", "sha256", "sha3", "sha3256", "ripemd160"}:
            result = hash_codecs.digest_hex(_read_bytes(params, "data"), name)
        elif name in {"hmacsha1", "hmacsha256"}:
            result = hash_codecs.hmac_digest(_read_bytes(params, "data"), _read_bytes(params, "key"), name).hex()
        elif name == "pbkdf2":
            result = hash_codecs.pbkdf2(
                _read_bytes(params, "password"),
                _read_bytes(params, "salt"),
                int(params.get("iterations", 100000)),
                int(params.get("dklen", 32)),
                str(params.get("hash", "sha256")),
            ).hex()
        elif name == "base64":
            result = hash_codecs.base64_encode(_read_bytes(params, "data")) if op == "encode" else _encode_bytes(
                hash_codecs.base64_decode(str(params.get("data", ""))), str(params.get("output_format", "text"))
            )
        elif name in {"utf8", "utf8encoding"}:
            if op == "encode":
                result = hash_codecs.utf8_encode(str(params.get("data", ""))).hex()
            elif op == "decode":
                result = hash_codecs.utf8_decode(_read_bytes(params, "data"))
            else:
                raise ValueError("UTF-8 operation must be encode or decode")
        elif name == "rsa":
            result = _rsa(op, params)
        elif name in {"rsasha1", "rsasignsha1"}:
            result = _rsa("sign_sha1" if op == "sign" else op, params)
        elif name in {"ecc", "ecdsa"}:
            result = _ecc(op, params)
        else:
            raise ValueError(f"unsupported algorithm: {algorithm}")
        return {"status": STATUS_OK, "message": "ok", "result": result}
    except Exception as exc:
        return {"status": STATUS_ERROR, "message": str(exc), "result": None}


def call_algorithm_json(request_json: str) -> str:
    request = json.loads(request_json)
    response = call_algorithm(request["algorithm"], request["operation"], request.get("params", {}))
    return json.dumps(response, ensure_ascii=False, indent=2)
