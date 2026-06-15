"""Command-line interface for the password algorithm assignment."""

from __future__ import annotations

import argparse
import json
import sys

from crypto_lab.api import call_algorithm, call_algorithm_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Network information security password algorithm demo CLI")
    parser.add_argument("algorithm", nargs="?", help="Algorithm name, e.g. AES, SM4, SHA256, RSA, ECDSA")
    parser.add_argument("operation", nargs="?", help="Operation name, e.g. encrypt, decrypt, sign, verify")
    parser.add_argument("--data", help="Input data")
    parser.add_argument("--data-format", default="text", choices=["text", "hex", "base64", "b64"])
    parser.add_argument("--key", help="Symmetric/HMAC key")
    parser.add_argument("--key-format", default="text", choices=["text", "hex", "base64", "b64"])
    parser.add_argument("--iv", help="CBC IV")
    parser.add_argument("--iv-format", default="hex", choices=["text", "hex", "base64", "b64"])
    parser.add_argument("--mode", default="CBC", choices=["CBC", "ECB"])
    parser.add_argument("--output-format", default="hex", choices=["text", "hex", "base64", "b64"])
    parser.add_argument("--password", help="PBKDF2 password")
    parser.add_argument("--salt", help="PBKDF2 salt")
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--dklen", type=int, default=32)
    parser.add_argument("--hash", default="sha256")
    parser.add_argument("--bits", type=int, default=1024)
    parser.add_argument("--public-key", help="JSON public key for RSA/ECC")
    parser.add_argument("--private-key", help="JSON private key for RSA/ECC")
    parser.add_argument("--signature", help="Signature bytes or JSON signature object")
    parser.add_argument("--signature-format", default="hex", choices=["text", "hex", "base64", "b64"])
    parser.add_argument("--json", help="Full JSON request: {algorithm, operation, params}")
    return parser


def _maybe_json(value: str | None):
    if value is None:
        return None
    return json.loads(value)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.json:
        print(call_algorithm_json(args.json))
        return 0
    if not args.algorithm or not args.operation:
        parser.error("algorithm and operation are required unless --json is used")

    params = {
        "mode": args.mode,
        "output_format": args.output_format,
        "iterations": args.iterations,
        "dklen": args.dklen,
        "hash": args.hash,
        "bits": args.bits,
    }
    for name in ("data", "key", "iv", "password", "salt", "signature"):
        value = getattr(args, name)
        if value is not None:
            params[name] = value
            fmt = getattr(args, f"{name}_format", None)
            if fmt is not None:
                params[f"{name}_format"] = fmt
    if args.public_key:
        params["public_key"] = _maybe_json(args.public_key)
    if args.private_key:
        params["private_key"] = _maybe_json(args.private_key)
    if args.signature and args.signature.strip().startswith("{"):
        params["signature"] = json.loads(args.signature)

    print(json.dumps(call_algorithm(args.algorithm, args.operation, params), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
