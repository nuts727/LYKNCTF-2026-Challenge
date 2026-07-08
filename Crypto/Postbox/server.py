#!/usr/bin/env python3
"""
crypto_challenge_4 - "Padding Postbox" (AES-128-CBC)

A tiny login service. On `GET /login` it hands you a freshly encrypted session
token of the form:

        AES-128-CBC( key, iv, plaintext )

where `plaintext` is a server-side message that ends with the flag and is
PKCS#7-padded to a multiple of 16 bytes. You receive `iv` and `ciphertext`
(both hex) -- but never the key.

On `POST /decrypt` you may submit ANY `{"iv": <hex>, "ciphertext": <hex>}`.
The server decrypts it (AES-128-CBC), strips PKCS#7 padding, and tells you
only ONE bit of information:

    {"ok": true}                 -> the padding was valid
    {"error": "bad padding"}     -> the padding was invalid

That single bit is a *padding oracle*. It is enough to decrypt the entire
token byte-by-byte without ever recovering the key -- the classic
Vaudenay padding-oracle attack.

The fix in the real world: authenticate your ciphertext (encrypt-then-MAC, or
an AEAD mode like AES-GCM) so the server refuses to decrypt -- and therefore
never reveals padding validity for -- any ciphertext it did not produce.

Run it as a plain HTTP service (stdlib only, no Flask needed):

    python server.py                 # binds 127.0.0.1:9999
    python server.py 0.0.0.0 9999    # bind address + port

Endpoints:

    GET  /            -> this help (text)
    GET  /login       -> {"iv": <hex>, "ciphertext": <hex>}  (fresh token)
    POST /decrypt     -> body {"iv": <hex>, "ciphertext": <hex>}
                         -> {"ok": true} | {"error": "bad padding"}
"""

import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# =========================================================================
#  Pure-Python AES-128 (no third-party crypto libraries available).
#  Only block encrypt/decrypt + CBC are needed for this service.
# =========================================================================

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11b
    return a & 0xff


def _mul(a, b):
    """Multiply two bytes in GF(2^8)."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        b >>= 1
        a = _xtime(a)
    return res


def _key_expansion(key):
    """Expand a 16-byte key into 11 round keys (each 16 bytes)."""
    assert len(key) == 16
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]                  # RotWord
            temp = [_SBOX[b] for b in temp]             # SubWord
            temp[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(11):
        rk = []
        for w in words[4 * r:4 * r + 4]:
            rk.extend(w)
        round_keys.append(rk)
    return round_keys


def _add_round_key(state, rk):
    return [state[i] ^ rk[i] for i in range(16)]


def _sub_bytes(state, box):
    return [box[b] for b in state]


def _shift_rows(state):
    # state is column-major: index = col*4 + row
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[c * 4 + r] = state[((c + r) % 4) * 4 + r]
    return out


def _inv_shift_rows(state):
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[c * 4 + r] = state[((c - r) % 4) * 4 + r]
    return out


def _mix_columns(state):
    out = [0] * 16
    for c in range(4):
        col = state[c * 4:c * 4 + 4]
        out[c * 4 + 0] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
        out[c * 4 + 1] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
        out[c * 4 + 2] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
        out[c * 4 + 3] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
    return out


def _inv_mix_columns(state):
    out = [0] * 16
    for c in range(4):
        col = state[c * 4:c * 4 + 4]
        out[c * 4 + 0] = (_mul(col[0], 14) ^ _mul(col[1], 11)
                          ^ _mul(col[2], 13) ^ _mul(col[3], 9))
        out[c * 4 + 1] = (_mul(col[0], 9) ^ _mul(col[1], 14)
                          ^ _mul(col[2], 11) ^ _mul(col[3], 13))
        out[c * 4 + 2] = (_mul(col[0], 13) ^ _mul(col[1], 9)
                          ^ _mul(col[2], 14) ^ _mul(col[3], 11))
        out[c * 4 + 3] = (_mul(col[0], 11) ^ _mul(col[1], 13)
                          ^ _mul(col[2], 9) ^ _mul(col[3], 14))
    return out


class AES128:
    def __init__(self, key):
        self.rk = _key_expansion(key)

    def encrypt_block(self, block):
        state = _add_round_key(list(block), self.rk[0])
        for r in range(1, 10):
            state = _sub_bytes(state, _SBOX)
            state = _shift_rows(state)
            state = _mix_columns(state)
            state = _add_round_key(state, self.rk[r])
        state = _sub_bytes(state, _SBOX)
        state = _shift_rows(state)
        state = _add_round_key(state, self.rk[10])
        return bytes(state)

    def decrypt_block(self, block):
        state = _add_round_key(list(block), self.rk[10])
        for r in range(9, 0, -1):
            state = _inv_shift_rows(state)
            state = _sub_bytes(state, _INV_SBOX)
            state = _add_round_key(state, self.rk[r])
            state = _inv_mix_columns(state)
        state = _inv_shift_rows(state)
        state = _sub_bytes(state, _INV_SBOX)
        state = _add_round_key(state, self.rk[0])
        return bytes(state)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def cbc_encrypt(key, iv, plaintext):
    aes = AES128(key)
    out = b""
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        cipher = aes.encrypt_block(_xor(block, prev))
        out += cipher
        prev = cipher
    return out


def cbc_decrypt(key, iv, ciphertext):
    aes = AES128(key)
    out = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        out += _xor(aes.decrypt_block(block), prev)
        prev = block
    return out


def pkcs7_pad(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def pkcs7_unpad(data, block=16):
    """Return the unpadded bytes, or raise ValueError on invalid padding."""
    if not data or len(data) % block != 0:
        raise ValueError("invalid length")
    n = data[-1]
    if n < 1 or n > block:
        raise ValueError("bad pad value")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("bad pad bytes")
    return data[:-n]


# =========================================================================
#  Challenge instance: one random key + token per server process.
# =========================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HOST = os.environ.get("HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("PORT", "9999"))


def load_flag():
    env = os.environ.get("FLAG")
    if env:
        return env.strip()
    try:
        with open(os.path.join(HERE, "flag.txt"), "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "LYKNCTF{padding_oracle_byte_by_byte}"


# The plaintext the player must recover. It deliberately spans several blocks
# so the attack has to walk multiple ciphertext blocks, and it ends with the
# flag so a full decryption reveals it.
def make_token_plaintext():
    return (b"session: user=guest; role=viewer; flag=" + load_flag().encode()).strip()


# Fresh, unpredictable key + IV for the lifetime of this process. Players get
# the IV and ciphertext but never the key.
KEY = secrets.token_bytes(16)
IV = secrets.token_bytes(16)
TOKEN = cbc_encrypt(KEY, IV, pkcs7_pad(make_token_plaintext()))


class Handler(BaseHTTPRequestHandler):
    # Silence the default per-request stderr logging.
    def log_message(self, *args):
        pass

    def _send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = self.path.split("?", 1)[0].rstrip("/")
        if route == "/login":
            self._send_json(200, {
                "iv": IV.hex(),
                "ciphertext": TOKEN.hex(),
                "note": "AES-128-CBC token. POST manipulated (iv, ciphertext) "
                        "to /decrypt to learn if the padding is valid.",
            })
            return
        if route == "":
            body = __doc__.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/decrypt":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            req = json.loads(raw)
            iv = bytes.fromhex(req["iv"])
            ct = bytes.fromhex(req["ciphertext"])
        except (ValueError, KeyError, TypeError) as exc:
            self._send_json(400, {"error": f"bad request: {exc}"})
            return

        if len(iv) != 16 or len(ct) == 0 or len(ct) % 16 != 0:
            self._send_json(400, {"error": "iv must be 16 bytes; "
                                            "ciphertext a non-empty multiple of 16"})
            return

        plaintext = cbc_decrypt(KEY, iv, ct)
        try:
            pkcs7_unpad(plaintext)
        except ValueError:
            # The ONLY signal the oracle leaks: padding validity.
            self._send_json(200, {"error": "bad padding"})
            return
        self._send_json(200, {"ok": True})


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[*] padding-oracle service on http://{host}:{port}")
    print(f"[*] GET /login then POST /decrypt")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
