#!/usr/bin/env python3
"""
Low-Interaction-Honeypot, der Langflow 1.8.1 imitiert.

- Fuehrt NIEMALS Code aus, startet keine Subprozesse, wertet nichts aus.
- Speichert Requests (JSONL) und Request-Bodies (Dateien, benannt nach SHA-256).
- Nur Python-Standardbibliothek.

Pfade:
  /, /health, /api/v1/version     Fingerprinting (wie Langflow 1.8.1)
  /api/v1/auto_login, /api/v1/login   Fake-Token, Zugangsdaten werden geloggt
  /api/v1/build_public_tmp/{id}/flow  Flow-Koeder mit festen IDs
                                      (/build_public_temp/ wird ebenfalls akzeptiert)
  /api/v1/validate/code           Falle: Body speichern, nichts ausfuehren
  alles andere                    404
"""
import argparse
import base64
import hashlib
import json
import re
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

VERSION = "1.8.1"
MAX_BODY = 1024 * 1024          # 1 MiB, mehr wird nicht gelesen
LOG_BODY_PREVIEW = 8192         # so viel Body landet direkt im JSONL

# Feste Flow-IDs fuer die Koeder (frei aenderbar)
DECOY_FLOWS = {
    "6f1c2a4e-3b7d-4c59-9a1e-0d2f8b5c7e11": "Customer Support Agent",
    "a3d9b0c2-58e4-4f6a-8c37-1e9d4b2a6f50": "Internal RAG Knowledge Base",
    "c82e5f17-9a04-4d3b-b6c1-7f0a3e8d2b94": "OpenAI Prod Chatbot",
}

INDEX_HTML = (
    '<!doctype html><html lang="en"><head><meta charset="utf-8" />'
    '<link rel="icon" href="/favicon.ico" />'
    '<meta name="viewport" content="width=device-width, initial-scale=1" />'
    '<title>Langflow</title></head><body><noscript>You need to enable '
    'JavaScript to run this app.</noscript><div id="root"></div></body></html>'
)

LOG_LOCK = threading.Lock()
CFG = {}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def fake_jwt(kind: str) -> str:
    """Sieht aus wie ein JWT, ist aber unsigniert/wertlos."""
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({
        "sub": "7d2b1c9e-4f3a-4a8e-9c61-5b0e2d7a8f13",
        "type": kind,
        "exp": int(time.time()) + (3600 if kind == "access" else 604800),
    }).encode())
    sig = b64url(hashlib.sha256(uuid.uuid4().bytes).digest())
    return f"{header}.{payload}.{sig}"


def write_log(entry: dict):
    line = json.dumps(entry, ensure_ascii=False)
    with LOG_LOCK:
        with open(CFG["log_file"], "a", encoding="utf-8") as f:
            f.write(line + "\n")
    if CFG["verbose"]:
        print(line, flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 15  # Slowloris-Schutz

    # Server-Header wie uvicorn, kein Python-Banner
    def version_string(self):
        return "uvicorn"

    def log_message(self, *args):  # Standard-Logging abschalten
        pass

    # ---------- HelperHelfer --------------------------------------------------------------------------------------------------------------------------------------------------------------------
    def client_ip(self):
        if CFG["trust_proxy"]:
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return self.client_address[0]

    def read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        length = max(0, min(length, MAX_BODY))
        return self.rfile.read(length) if length else b""

    def send(self, status, body, ctype="application/json", extra=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def store_body(self, body: bytes):
        if not body:
            return None, None
        digest = hashlib.sha256(body).hexdigest()
        path = CFG["payload_dir"] / digest
        if not path.exists():
            path.write_bytes(body)
        return digest, str(path)

    # ---------- Routing --------------------------------------------------------------------------------------------------------------------------------------------------------------------
    def handle_any(self):
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        body = self.read_body()
        digest, stored = self.store_body(body)

        entry = {
            "ts": now_iso(),
            "src_ip": self.client_ip(),
            "src_port": self.client_address[1],
            "method": self.command,
            "path": parts.path,
            "query": parts.query,
            "headers": dict(self.headers.items()),
            "body_len": len(body),
            "body_sha256": digest,
            "body_file": stored,
            "body_preview": body[:LOG_BODY_PREVIEW].decode("utf-8", "replace"),
            "event": "request",
        }

        status = self.route(path, body, entry)
        entry["status"] = status
        write_log(entry)

    def route(self, path, body, entry) -> int:
        m = self.command

        # --- Fingerprinting --------------------------------------------------------------------------------------------------------------------------------------------------------------------
        if path == "/":
            if m in ("GET", "HEAD"):
                return self._ret(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
            return self._ret(405, {"detail": "Method Not Allowed"})

        if path == "/health":
            if m in ("GET", "HEAD"):
                return self._ret(200, {"status": "ok"})
            return self._ret(405, {"detail": "Method Not Allowed"})

        if path == "/api/v1/version":
            if m in ("GET", "HEAD"):
                return self._ret(200, {
                    "version": VERSION,
                    "main_version": VERSION,
                    "package": "Langflow",
                })
            return self._ret(405, {"detail": "Method Not Allowed"})

        # --- Login --------------------------------------------------------------------------------------------------------------------------------------------------------------------
        if path == "/api/v1/auto_login":
            if m in ("GET", "HEAD"):
                entry["event"] = "auto_login"
                return self._ret(200, self._tokens())
            return self._ret(405, {"detail": "Method Not Allowed"})

        if path == "/api/v1/login":
            if m == "POST":
                entry["event"] = "login_attempt"
                entry["credentials"] = self._parse_credentials(body)
                return self._ret(200, self._tokens())
            return self._ret(405, {"detail": "Method Not Allowed"})

        # --- Flow-Koeder --------------------------------------------------------------------------------------------------------------------------------------------------------------------
        mo = re.fullmatch(r"/api/v1/build_public_(?:tmp|temp)/([^/]+)/flow", path)
        if mo:
            flow_id = mo.group(1)
            if m == "POST":
                entry["event"] = "build_public_tmp"
                entry["flow_id"] = flow_id
                entry["flow_known"] = flow_id in DECOY_FLOWS
                if flow_id in DECOY_FLOWS:
                    return self._ret(200, {"job_id": str(uuid.uuid4())})
                return self._ret(404, {"detail": "Flow not found"})
            return self._ret(405, {"detail": "Method Not Allowed"})

        # --- Falle --------------------------------------------------------------------------------------------------------------------------------------------------------------------
        if path == "/api/v1/validate/code":
            if m == "POST":
                entry["event"] = "validate_code"
                # NICHTS ausfuehren/parsen. Nur Standardantwort fuer "gueltigen" Code.
                return self._ret(200, {
                    "imports": {"errors": []},
                    "function": {"errors": []},
                })
            return self._ret(405, {"detail": "Method Not Allowed"})

        # --- Rest --------------------------------------------------------------------------------------------------------------------------------------------------------------------
        return self._ret(404, {"detail": "Not Found"})

    def _ret(self, status, body, ctype="application/json"):
        self.send(status, body, ctype)
        return status

    @staticmethod
    def _tokens():
        return {
            "access_token": fake_jwt("access"),
            "refresh_token": fake_jwt("refresh"),
            "token_type": "bearer",
        }

    def _parse_credentials(self, body: bytes):
        text = body.decode("utf-8", "replace")
        ctype = (self.headers.get("Content-Type") or "").lower()
        try:
            if "json" in ctype:
                data = json.loads(text)
                return {"username": data.get("username"), "password": data.get("password")}
            qs = parse_qs(text, keep_blank_values=True)
            return {
                "username": (qs.get("username") or [None])[0],
                "password": (qs.get("password") or [None])[0],
            }
        except Exception:
            return {"raw": text[:512]}

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = handle_any


def main():
    ap = argparse.ArgumentParser(description="Langflow 1.8.1 Low-Interaction-Honeypot")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=7861)  # Langflow-Standardport
    ap.add_argument("--data-dir", default="./data")
    ap.add_argument("--trust-proxy", action="store_true",
                    help="X-Forwarded-For als Quell-IP verwenden (nur hinter eigenem Proxy)")
    ap.add_argument("--quiet", action="store_true", help="Events nicht auf stdout ausgeben")
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    (data_dir / "payloads").mkdir(parents=True, exist_ok=True)
    CFG.update(
        log_file=data_dir / "events.jsonl",
        payload_dir=data_dir / "payloads",
        trust_proxy=args.trust_proxy,
        verbose=not args.quiet,
    )

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    print(f"[*] Langflow {VERSION} honeypot auf {args.host}:{args.port}, "
          f"Logs in {data_dir}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
