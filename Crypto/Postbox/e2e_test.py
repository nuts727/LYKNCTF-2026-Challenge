#!/usr/bin/env python3
"""End-to-end check: boot server.py on an ephemeral port, run the padding
oracle attack, assert the flag comes back.

No network setup or third-party libs needed -- it binds 127.0.0.1 on a free
port and drives the real HTTP service exactly like a remote player would.
"""
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import solve  # noqa: E402

SERVER = os.path.join(HERE, "server.py")
SENTINEL = "LYKNCTF{padding_oracle_byte_by_byte}"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_up(port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/login", timeout=1).read()
            return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.1)
    return False


def main():
    port = free_port()
    env = dict(os.environ, FLAG=SENTINEL)
    proc = subprocess.Popen(
        [sys.executable, SERVER, "127.0.0.1", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_up(port):
            print("server did not come up")
            return 1

        oracle = solve.Oracle("127.0.0.1", port)
        iv, ct = oracle.login()
        blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
        prevs = [iv] + blocks[:-1]

        recovered = bytearray()
        workers = 32
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for prev, blk in zip(prevs, blocks):
                inter = solve.recover_block(oracle, prev, blk, executor, workers)
                recovered += bytes(a ^ b for a, b in zip(inter, prev))

        plaintext = solve.pkcs7_unpad(bytes(recovered)).decode("latin-1")
        ok = SENTINEL in plaintext
        print(f"queries={oracle.queries}  recovered={plaintext!r}")
        print("RESULT:", "OK" if ok else "MISS")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
