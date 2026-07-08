#!/usr/bin/env python3
"""
challenge_6 solver - SHA-256 length-extension forgery.

Given a valid token = SHA256(secret || message) and len(message), but NOT
the secret, forge a valid token for (message || glue_padding || extra)
where `extra` carries the admin grant -- all without knowing the secret.

We don't depend on hashpumpy. Instead we implement SHA-256 with a settable
initial state. SHA-256 is Merkle-Damgard: the 256-bit digest *is* the
internal state (h0..h7) after the final block. So:

  1. Split the known digest into eight 32-bit words -> resumed state.
  2. Compute the glue padding SHA-256 would have appended to a message of
     length (len(secret) + len(message)) bytes.
  3. Feed `extra` into the compression function starting from the resumed
     state, with the bit-length counter pre-loaded to account for everything
     that came before. The result is SHA256(secret || message || glue || extra).

We don't know len(secret), only that it's in 8..24, so we try each length
and submit whichever forgery the server accepts.
"""

import json
import socket
import struct
import subprocess
import sys

# --- SHA-256 with a settable initial state --------------------------------

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_MASK = 0xffffffff


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK)

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & _MASK
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & _MASK
        h, g, f, e, d, c, b, a = (
            g, f, e, (d + t1) & _MASK, c, b, a, (t1 + t2) & _MASK)

    return [(x + y) & _MASK for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def _md_padding(msg_len_bytes):
    """The padding SHA-256 appends for a message of msg_len_bytes bytes."""
    bit_len = msg_len_bytes * 8
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len_bytes + 1) % 64) % 64)
    pad += struct.pack(">Q", bit_len)
    return pad


def sha256_extend(orig_digest_hex, extra, prefixed_len):
    """
    Continue hashing from a known digest.

    orig_digest_hex : SHA256(prefix) as hex, where prefix is the unknown
                      `secret || message`.
    extra           : bytes to append after the glue padding.
    prefixed_len    : len(prefix) in bytes (secret + message).

    Returns SHA256(prefix || glue_padding(prefixed_len) || extra) as hex.
    """
    state = list(struct.unpack(">8I", bytes.fromhex(orig_digest_hex)))

    # Bytes already "consumed" before `extra`: the prefix plus its padding,
    # which together are a whole number of 64-byte blocks.
    already = prefixed_len + len(_md_padding(prefixed_len))

    # Build the final message that `extra` represents, then pad it as if the
    # total stream length were (already + len(extra)).
    total_len = already + len(extra)
    stream = extra + _md_padding(total_len)

    for i in range(0, len(stream), 64):
        state = _compress(state, stream[i:i + 64])

    return struct.pack(">8I", *state).hex()


# --- driver ----------------------------------------------------------------

# server.py lives next to this script.
import os
BASE = os.path.dirname(os.path.abspath(__file__))


def run_server(args, stdin_bytes=b""):
    return subprocess.run(
        [sys.executable, os.path.join(BASE, "server.py"), *args],
        input=stdin_bytes, capture_output=True, cwd=BASE,
    )


def local_issue():
    return json.loads(run_server(["issue"]).stdout)


def local_submit(req):
    return json.loads(run_server(["verify"], req).stdout)


def _json_from_text(text):
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object in line")
    return json.loads(text[start:end + 1])


def _read_json(reader, required_key):
    for _ in range(40):
        line = reader.readline()
        if not line:
            break
        text = line.decode("utf-8", errors="replace")
        if "{" not in text:
            continue
        try:
            obj = _json_from_text(text)
        except json.JSONDecodeError:
            continue
        if required_key in obj:
            return obj
    raise RuntimeError(f"did not receive JSON containing {required_key!r}")


def make_forgery(message, token, secret_len, extra):
    prefixed_len = secret_len + len(message)
    forged_tag = sha256_extend(token, extra, prefixed_len)
    forged_msg = message + _md_padding(prefixed_len) + extra
    req = json.dumps({"msg": forged_msg.hex(), "tag": forged_tag}).encode()
    return forged_msg, forged_tag, req


def remote_attempt(host, port, secret_len, extra):
    with socket.create_connection((host, port), timeout=5) as sock:
        reader = sock.makefile("rb")
        writer = sock.makefile("wb")
        issued = _read_json(reader, "token")
        message = bytes.fromhex(issued["message_hex"])
        token = issued["token"]
        forged_msg, forged_tag, req = make_forgery(
            message, token, secret_len, extra)
        writer.write(req + b"\n")
        writer.flush()
        resp = _read_json(reader, "ok")
    return issued, forged_msg, forged_tag, resp


def solve_local(extra):
    issued = local_issue()
    message = bytes.fromhex(issued["message_hex"])
    token = issued["token"]
    print(f"[*] user message : {message!r}")
    print(f"[*] user token   : {token}")

    for secret_len in range(8, 25):
        forged_msg, forged_tag, req = make_forgery(
            message, token, secret_len, extra)
        resp = local_submit(req)

        if resp.get("admin"):
            print(f"\n[+] secret length = {secret_len}")
            print(f"[+] forged message = {forged_msg!r}")
            print(f"[+] forged token   = {forged_tag}")
            print(f"[+] FLAG           = {resp['flag']}")
            return

    print("[-] no length in 8..24 worked -- check assumptions")
    sys.exit(1)


def solve_remote(host, port, extra):
    first = True
    for secret_len in range(8, 25):
        issued, forged_msg, forged_tag, resp = remote_attempt(
            host, port, secret_len, extra)

        if first:
            message = bytes.fromhex(issued["message_hex"])
            print(f"[*] user message : {message!r}")
            print(f"[*] user token   : {issued['token']}")
            first = False

        if resp.get("admin"):
            print(f"\n[+] secret length = {secret_len}")
            print(f"[+] forged message = {forged_msg!r}")
            print(f"[+] forged token   = {forged_tag}")
            print(f"[+] FLAG           = {resp['flag']}")
            return

    print("[-] no length in 8..24 worked -- check assumptions")
    sys.exit(1)


def main():
    extra = b"&admin=true"
    if len(sys.argv) == 1:
        print("[*] target       : local server.py")
        solve_local(extra)
    elif len(sys.argv) == 3:
        host, port = sys.argv[1], int(sys.argv[2])
        print(f"[*] target       : {host}:{port}")
        solve_remote(host, port, extra)
    else:
        print(f"usage: {sys.argv[0]} [HOST PORT]")
        sys.exit(2)


if __name__ == "__main__":
    main()
