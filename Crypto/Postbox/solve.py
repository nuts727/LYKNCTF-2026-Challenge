#!/usr/bin/env python3
"""
crypto_challenge_4 solver -- AES-128-CBC padding-oracle attack.

The whole point of this attack: we recover the plaintext WITHOUT the key and
WITHOUT ever implementing AES. The only thing we use is the server's one-bit
"is the PKCS#7 padding valid?" oracle exposed at POST /decrypt.

Recap of CBC decryption for a single ciphertext block C with "previous" block
P (P is the IV for the first block, or C_{i-1} otherwise):

        plaintext = AES_dec(C)  XOR  P
                  =     I        XOR  P          (call I the "intermediate")

The server lets us choose P freely (we send it in the `iv` field) while keeping
C fixed. So if we send a forged P' and the block, the decrypted plaintext is

        P'  XOR  I

We brute-force P'[15] over all 256 values until the padding is valid. Valid
padding (almost always) means the last byte decrypted to 0x01, i.e.

        P'[15] XOR I[15] == 0x01   ->   I[15] = P'[15] XOR 0x01

Knowing I[15] and the REAL previous byte P[15], the true plaintext byte is
I[15] XOR P[15]. We then forge P' so the tail decrypts to 0x02 0x02, brute the
next byte for I[14], and walk left to the start of the block. Repeat for every
ciphertext block.

Usage:
    python solve.py                     # talks to 127.0.0.1:9999
    python solve.py <host> <port>
"""

import json
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from urllib.error import HTTPError, URLError


class Oracle:
    """Thin client over the HTTP padding-oracle service."""

    def __init__(self, host, port):
        self.base = f"http://{host}:{port}"
        self.queries = 0
        self._query_lock = Lock()

    def login(self):
        with urllib.request.urlopen(self.base + "/login", timeout=10) as r:
            data = json.loads(r.read())
        return bytes.fromhex(data["iv"]), bytes.fromhex(data["ciphertext"])

    def valid_padding(self, prev_block, target_block):
        """True iff CBC-decrypting target_block under prev_block pads validly."""
        with self._query_lock:
            self.queries += 1
        payload = json.dumps({
            "iv": prev_block.hex(),
            "ciphertext": target_block.hex(),
        }).encode()
        req = urllib.request.Request(
            self.base + "/decrypt", data=payload,
            headers={"Content-Type": "application/json"},
        )
        for attempt in range(6):
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    resp = json.loads(r.read())
                return bool(resp.get("ok"))
            except (HTTPError, URLError, TimeoutError):
                if attempt == 5:
                    raise
                time.sleep(0.1 * (attempt + 1))


def recover_block(oracle, prev_block, target_block, executor, workers):
    """Recover the 16 intermediate bytes I = AES_dec(target_block)."""
    inter = bytearray(16)            # the intermediate state we are solving for
    for pos in range(15, -1, -1):
        pad = 16 - pos               # 1, 2, 3, ... as we move left
        forged = bytearray(16)
        # Fix every already-known byte to the right so it decrypts to `pad`.
        for j in range(pos + 1, 16):
            forged[j] = inter[j] ^ pad

        def try_guess(guess):
            candidate = bytearray(forged)
            candidate[pos] = guess
            if not oracle.valid_padding(bytes(candidate), target_block):
                return None
            # Guard against the false positive at the rightmost byte: a "valid"
            # padding might be 0x02 0x02 (or longer) instead of 0x01.
            if pos == 15:
                candidate[14] ^= 0xff
                if not oracle.valid_padding(bytes(candidate), target_block):
                    return None
            return guess

        found = False
        # Submit bounded batches instead of all 256 guesses. This preserves the
        # low query count while hiding reverse-proxy latency behind concurrency.
        for start in range(0, 256, workers):
            guesses = range(start, min(start + workers, 256))
            results = executor.map(try_guess, guesses)
            match = next((guess for guess in results if guess is not None), None)
            if match is not None:
                inter[pos] = match ^ pad
                found = True
                break

        if not found:
            raise RuntimeError(f"no padding byte found at position {pos}")
    return bytes(inter)


def pkcs7_unpad(data):
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data            # tolerate odd output rather than crashing the print


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 32
    oracle = Oracle(host, port)

    iv, ct = oracle.login()
    print(f"[*] token: iv={iv.hex()}  ct={ct.hex()}", flush=True)
    blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
    prevs = [iv] + blocks[:-1]      # the "previous" block for each ct block

    recovered = bytearray()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for idx, (prev, blk) in enumerate(zip(prevs, blocks)):
            inter = recover_block(oracle, prev, blk, executor, workers)
            plain = bytes(a ^ b for a, b in zip(inter, prev))
            recovered += plain
            print(f"[+] block {idx}: {plain!r}", flush=True)

    plaintext = pkcs7_unpad(bytes(recovered))
    print(f"\n[*] oracle queries: {oracle.queries}")
    print(f"[*] recovered plaintext:\n    {plaintext!r}")

    text = plaintext.decode("latin-1")
    match = re.search(r"[A-Z0-9_]*CTF\{[^}]+\}", text)
    if match:
        print(f"\n[+] FLAG = {match.group(0)}")
    else:
        print("\n[-] no flag-like token found in recovered plaintext")
        sys.exit(1)


if __name__ == "__main__":
    main()
