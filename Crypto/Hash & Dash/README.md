# Writeup - Hash & Dash

## Challenge Info

- Category: Crypto
- Topic: Roll-your-own MAC, SHA-256 length-extension
- Flag: `CTF{dont_build_mac_with_plain_hash}`

A token service uses a home-made MAC:

```text
token = SHA256(secret || message)
```

The player is issued a valid token for a regular user. The task is to
forge a token for a message containing `admin=true` to get the flag.

## The Bug

`server.py` authenticates an admin grant with:

```
token = SHA256(secret || message)
```

This is a classic broken MAC. Because SHA-256 is a Merkle–Damgård
construction, the 256-bit digest *is* the full internal state after the
last compressed block. An attacker who knows `H(secret || message)` and
the byte length of `secret || message` can resume hashing and append
arbitrary bytes — producing a valid tag for
`secret || message || padding || extra` without ever learning `secret`.

The service grants the flag for any validly-tagged message containing
`admin=true`, so the attacker appends `&admin=true`.

## Solve Path

1. `python server.py issue` → public `(message, token)` for
   `user=guest&role=viewer`.
2. The secret length is unknown but advertised as 8..24 bytes. For each
   candidate length `L`:
   - `prefixed_len = L + len(message)`
   - compute the glue padding SHA-256 would append for a
     `prefixed_len`-byte input
   - resume SHA-256 from the known digest, feeding `&admin=true`
   - submit `message || glue || &admin=true` with the forged tag
3. The server accepts the forgery at the true length (13 in this
   instance) and returns the flag.

`solve.py` implements SHA-256 with a settable initial state (no
`hashpumpy` dependency needed). Verified end-to-end: the forged tag
equals `hashlib.sha256(secret + forged_msg).hexdigest()` and the service
returns the flag.

```bash
$ python solve.py
[*] target       : local server.py
[*] user message : b'user=guest&role=viewer'
[*] user token   : aba8ee51df74de0e627fa9fc662b100e90de3d00b30011a8ada9f5ab3a0cac24

[+] secret length = 13
[+] forged message = b'user=guest&role=viewer\x80\x00...\x01\x18&admin=true'
[+] forged token   = 33f6e1810aa55dad7a595ebe80b58089cecbf1dad81677aef93d390d1e03b9d8
[+] FLAG           = CTF{dont_build_mac_with_plain_hash}
```

## Fix

Use HMAC: `hmac.new(secret, message, hashlib.sha256).hexdigest()`. HMAC's
nested construction is not vulnerable to length extension.

## Running It

```text
$ python server.py
== Roll your own MAC ==
Here is your public token:
{"message": "user=guest&role=viewer", "message_hex": "...", "token": "...", "note": "secret length is between 8 and 24 bytes"}
Submit one JSON line with msg and tag.
> {"msg":"<message_hex>","tag":"<token_hex>"}
```

Solver:

```bash
python solve.py                 # against a local server.py subprocess
python solve.py <host> <port>   # against a deployed instance
```

Since the Dockerfile uses `socat EXEC`, every connection spawns a fresh
Python process. The remote solver therefore fetches the token and submits
its forgery within the same connection.

## Deployment (CTFd Whale / dynamic_docker)

The Dockerfile follows the Whale `socat` pattern:

```dockerfile
FROM python:3.12-alpine
RUN apk add --no-cache socat
CMD sh -c 'socat TCP-LISTEN:9999,reuseaddr,fork EXEC:"python3 /app/server.py"'
```

Build the image from this directory:

```bash
docker build -t hash-and-dash:latest .
```

Suggested CTFd fields:

| Field | Value |
| --- | --- |
| Challenge type | `dynamic_docker` |
| Docker image | `hash-and-dash:latest` (or a pushed registry image) |
| Redirect type | `direct` |
| Redirect port | `9999` |
| Protocol | `tcp` |

Whale generates a random flag and passes it into the container via the
`FLAG` environment variable — no static flag needed in the Flags tab. The
image doesn't copy `flag.txt` or `secret.bin`.

## Local Test

```bash
docker build -t hash-and-dash:latest .
docker run --rm -p 9999:9999 -e FLAG='CTF{local_dynamic_flag}' hash-and-dash:latest
nc 127.0.0.1 9999
```

The service prints a public token as JSON, then reads one JSON line back:

```json
{"msg":"<message_hex>","tag":"<token_hex>"}
```

- Ship to players: `server.py` (+ `README.md` if desired).
- Keep private: `flag.txt`, `secret.bin`, `solve.py`.
- `secret.bin` is regenerated per deploy via:
  `python -c "import os; open('secret.bin','wb').write(os.urandom(13))"`
  (any length in 8..24 works; the solver brute-forces the range).

## Files

| File | Role |
| --- | --- |
| `server.py` | Crypto service; supports local CLI and stdin/stdout for socat |
| `Dockerfile` | Image for CTFd Whale/dynamic_docker, listens on port `9999` |
| `.dockerignore` | Excludes `flag.txt`, `secret.bin`, `solve.py`, `README.md` from the image |
| `flag.txt` | Fallback flag for local testing, not copied into the image |
| `secret.bin` | Fallback secret for local testing, not copied into the image |
| `solve.py` | Length-extension solver, runs local or remote |

## Flag

```text
CTF{dont_build_mac_with_plain_hash}
```
