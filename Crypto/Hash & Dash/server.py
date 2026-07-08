#!/usr/bin/env python3
"""
challenge_6 - "Roll your own MAC"

A tiny token service. An admin token is computed as:

        token = SHA256(secret || message)

where `secret` is a server-side value (8..24 bytes) the client never sees,
and `message` describes the granted privileges.

Modes:

    # issue the public user token for local testing
    python server.py issue

    # verify a submitted forgery for local testing
    echo '{"msg":"<hex>","tag":"<hex>"}' | python server.py verify

    # run the TCP service used by Docker/CTFd Whale
    PORT=9999 python server.py listen

The vulnerability: a SHA-256 of `secret || message` is NOT a secure MAC.
Because SHA-256 is a Merkle-Damgard hash, knowing H(secret||message) and
len(message) lets an attacker compute H(secret||message||padding||extra)
for arbitrary `extra` -- a length-extension attack -- without ever knowing
the secret. Use HMAC instead.
"""

import hashlib
import json
import os
import secrets
import socketserver
import sys
from typing import BinaryIO


# --- challenge instance configuration -------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
SECRET_PATH = os.environ.get("SECRET_PATH", os.path.join(HERE, "secret.bin"))
FLAG_PATH = os.environ.get("FLAG_PATH", os.path.join(HERE, "flag.txt"))

# The public message the ordinary user is given a valid token for.
USER_MESSAGE = b"user=guest&role=viewer"
DEFAULT_PORT = 9999
MAX_REQUEST_BYTES = 4096

_SECRET: bytes | None = None


def _validate_secret(secret: bytes) -> bytes:
    if not (8 <= len(secret) <= 24):
        raise SystemExit("secret length out of the advertised 8..24 range")
    return secret


def _load_secret_from_env() -> bytes | None:
    secret_hex = os.environ.get("MAC_SECRET_HEX") or os.environ.get("SECRET_HEX")
    if secret_hex:
        try:
            return _validate_secret(bytes.fromhex(secret_hex.strip()))
        except ValueError as exc:
            raise SystemExit(f"bad hex secret: {exc}") from exc

    secret_text = os.environ.get("MAC_SECRET") or os.environ.get("SECRET")
    if secret_text:
        return _validate_secret(secret_text.encode("utf-8"))

    return None


def get_secret() -> bytes:
    """Return one stable secret for this server process."""
    global _SECRET
    if _SECRET is not None:
        return _SECRET

    env_secret = _load_secret_from_env()
    if env_secret is not None:
        _SECRET = env_secret
        return _SECRET

    try:
        with open(SECRET_PATH, "rb") as f:
            _SECRET = _validate_secret(f.read())
    except FileNotFoundError:
        # In the Whale/Docker image we do not ship secret.bin. Generate one per
        # container process; the TCP server keeps this process alive.
        _SECRET = secrets.token_bytes(16)
    return _SECRET


def load_flag() -> str:
    """Read the Whale dynamic flag from $FLAG, then fall back to flag.txt."""
    flag = os.environ.get("FLAG")
    if flag:
        return flag.strip()

    try:
        with open(FLAG_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "CTF{dont_build_mac_with_plain_hash}"


def mac(secret: bytes, message: bytes) -> str:
    """The intentionally-broken MAC: a raw hash of secret || message."""
    return hashlib.sha256(secret + message).hexdigest()


def issue_payload(secret: bytes) -> dict[str, str]:
    return {
        "message": USER_MESSAGE.decode("latin-1"),
        "message_hex": USER_MESSAGE.hex(),
        "token": mac(secret, USER_MESSAGE),
        "note": "secret length is between 8 and 24 bytes",
    }


def verify_payload(secret: bytes, raw: str) -> dict[str, object]:
    try:
        req = json.loads(raw)
        message = bytes.fromhex(req["msg"])
        tag = req["tag"].strip().lower()
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"bad request: {exc}"}

    expected = mac(secret, message)
    if tag != expected:
        return {"ok": False, "error": "invalid token"}

    if b"admin=true" not in message:
        return {
            "ok": True,
            "admin": False,
            "error": "token valid but no admin grant",
        }

    return {"ok": True, "admin": True, "flag": load_flag()}


def cmd_issue() -> None:
    print(json.dumps(issue_payload(get_secret()), indent=2))


def cmd_verify() -> None:
    raw = sys.stdin.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        print(json.dumps({"ok": False, "error": "request too large"}))
        return
    print(json.dumps(verify_payload(get_secret(), raw)))


def _write(out: BinaryIO, text: str) -> None:
    out.write(text.encode("utf-8"))
    out.flush()


def run_session(inp: BinaryIO, out: BinaryIO) -> None:
    secret = get_secret()
    _write(out, "== Roll your own MAC ==\n")
    _write(out, "Here is your public token:\n")
    _write(out, json.dumps(issue_payload(secret)) + "\n")
    _write(out, "Submit one JSON line with msg and tag.\n> ")

    raw = inp.readline(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        _write(out, json.dumps({"ok": False, "error": "request too large"}) + "\n")
        return
    if not raw:
        _write(out, json.dumps({"ok": False, "error": "no request received"}) + "\n")
        return

    try:
        request = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        response = {"ok": False, "error": f"request is not utf-8: {exc}"}
    else:
        response = verify_payload(secret, request)
    _write(out, json.dumps(response) + "\n")


class ChallengeHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        run_session(self.rfile, self.wfile)


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_forever() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", str(DEFAULT_PORT)))
    with ThreadingTCPServer((host, port), ChallengeHandler) as server:
        print(f"listening on {host}:{port}", file=sys.stderr, flush=True)
        server.serve_forever()


def main() -> None:
    if len(sys.argv) == 1:
        run_session(sys.stdin.buffer, sys.stdout.buffer)
        return

    command = sys.argv[1]
    if command == "issue":
        cmd_issue()
    elif command == "verify":
        cmd_verify()
    elif command == "listen":
        serve_forever()
    else:
        print(__doc__)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
