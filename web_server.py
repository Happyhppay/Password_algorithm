"""Small standard-library web server for the crypto demo frontend."""

from __future__ import annotations

import argparse
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from crypto_lab.api import call_algorithm

ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"


class CryptoDemoHandler(BaseHTTPRequestHandler):
    server_version = "CryptoDemoHTTP/1.0"

    def do_GET(self) -> None:
        target = self.path.split("?", 1)[0]
        if target == "/":
            target = "/index.html"
        relative = unquote(target).lstrip("/")
        path = (WEB_ROOT / relative).resolve()
        if not str(path).startswith(str(WEB_ROOT.resolve())) or not path.is_file():
            self._send_json(404, {"status": 1, "message": "not found", "result": None})
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/api/call":
            self._send_json(404, {"status": 1, "message": "not found", "result": None})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            request = json.loads(body)
            response = call_algorithm(request["algorithm"], request["operation"], request.get("params", {}))
            self._send_json(200, response)
        except Exception as exc:
            self._send_json(400, {"status": 1, "message": str(exc), "result": None})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def _send_json(self, code: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run crypto algorithm web demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), CryptoDemoHandler)
    print(f"Crypto demo running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
