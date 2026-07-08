# Writeup - Postbox

## Challenge Info

- Category: Crypto
- Topic: AES-128-CBC padding oracle (Vaudenay)
- Flag: `LYKNCTF{padding_oracle_byte_by_byte}`

A small login service issues encrypted session tokens. Players can
request a token, and ask the service to check whether a submitted token
is structurally acceptable. The secret is hidden inside the encrypted
session data.

Endpoints:

- `GET /login`
- `POST /decrypt`

## The Bug

The service decrypts *any* ciphertext a client submits and leaks one bit:
whether the resulting plaintext has valid PKCS#7 padding. That single bit
is a **padding oracle**, and it is enough to decrypt arbitrary ciphertext
without the key (Vaudenay, 2002).

### CBC Recap

For ciphertext block `C_i` with preceding block `P` (the IV for `i = 0`,
else `C_{i-1}`):

```
plaintext_i = AES_dec(C_i)  XOR  P
            =      I_i       XOR  P
```

`I_i = AES_dec(C_i)` is the **intermediate state**. It depends only on the
key and `C_i` — *not* on `P`. The server lets us pick `P` freely (we put
it in the `iv` field) while keeping `C_i` fixed in the `ciphertext` field.
So whatever we send as `P'`, the server decrypts the block to
`P' XOR I_i` and checks *that* for valid padding.

### Recovering One Byte

Work on the last byte first. Choose `P'` with `P'[0..14]` arbitrary and
sweep `P'[15]` through all 256 values. For exactly the value(s) where

```
(P'[15] XOR I_i[15]) == 0x01
```

the decrypted block ends in a single `0x01` byte — valid PKCS#7. From a
hit:

```
I_i[15] = P'[15] XOR 0x01
```

The **real** plaintext byte is then `I_i[15] XOR P_real[15]`, where
`P_real` is the genuine previous block (`C_{i-1}` or the real IV).

#### The False-Positive Guard

A "valid padding" hit at the last byte might actually be `0x02 0x02` (or
longer) rather than `0x01`, if the second-to-last decrypted byte happened
to already be `0x02`. To disambiguate, after a hit we flip a byte further
left in `P'` and re-query: a genuine `0x01` terminator is unaffected
(still valid), but a `0x02 0x02` pattern breaks (now invalid). `solve.py`
does exactly this in `recover_block` for `pos == 15`.

### Walking the Rest of the Block

Once `I_i[15]` is known, force the tail to decrypt to `0x02 0x02`: set
`P'[15] = I_i[15] XOR 0x02` and sweep `P'[14]` until padding is valid →
`I_i[14] = P'[14] XOR 0x02`. Continue with pad value `0x03`, `0x04`, …
moving left, until all 16 intermediate bytes are recovered. Then

```
plaintext_i = I_i XOR P_real
```

Repeat for every ciphertext block (`prev` = IV for block 0, else the
previous ciphertext block). Concatenate, strip PKCS#7, and the flag is in
the tail.

### Cost

16 bytes/block × ~128 expected guesses/byte ≈ ~2k queries per block (plus
the guard probes). For the ~5-block token that is ~10k oracle queries — a
few seconds over localhost with concurrent requests. No AES
implementation is required on the attacker side at all.

## Running It

```bash
python server.py                 # binds 127.0.0.1:9999
```

```bash
# against a deployed instance
python solve.py <host> <port>

# fully self-contained: boots server.py on a temp port and attacks it
python e2e_test.py
```

Verified output:

```text
[*] token: iv=...  ct=...
[+] block 0: b'session: user=g'
...
[*] oracle queries: <~10000>
[*] recovered plaintext:
    b'session: user=guest; role=viewer; flag=LYKNCTF{padding_oracle_byte_by_byte}'

[+] FLAG = LYKNCTF{padding_oracle_byte_by_byte}
```

## Fix

Authenticate ciphertext so the server never decrypts (and never reveals
padding validity for) anything it did not produce:

- **Encrypt-then-MAC:** verify an HMAC over `iv || ciphertext` *before*
  decrypting; reject on MAC failure with a uniform error.
- **AEAD:** use AES-GCM (or ChaCha20-Poly1305); a tag failure aborts
  before any padding is examined.

Either way the oracle disappears. Also: return an identical,
constant-time error for *all* decryption failures so padding validity
can't leak via error text or timing.

## Deployment (CTFd Whale / dynamic_docker)

CTFd challenge description:

```md
A small login service issues encrypted session tokens.

You can request a token, and you can ask the service to check whether a
submitted token is structurally acceptable. The secret is hidden inside
the encrypted session data.

Start an instance and open the provided URL.

Endpoints:

- GET /login
- POST /decrypt

Recover the flag from the session.
```

Build the image from this directory:

```bash
docker build -t postbox:latest .
```

Suggested CTFd fields:

| Field | Value |
| --- | --- |
| Challenge type | `dynamic_docker` |
| Name | `Padding Postbox` |
| Category | `crypto` |
| Docker image | `postbox:latest` (or a pushed registry image) |
| Redirect type | `direct` |
| Redirect port | `9999` |
| Protocol | `http` |

Do not add a static flag manually — Whale provides the random dynamic flag
via the `FLAG` environment variable, and the service reads it from there.
If your CTFd workers can't see local images, tag and push:

```bash
docker tag postbox:latest registry.example.com/postbox:latest
docker push registry.example.com/postbox:latest
```

## Local Test

```bash
docker build -t postbox:latest .
docker run --rm -p 9999:9999 -e FLAG='LYKNCTF{local_dynamic_flag}' postbox:latest
```

Then visit `http://127.0.0.1:9999/login`, or run the solver:

```bash
python solve.py 127.0.0.1 9999
```

## Files

| File | Purpose |
| --- | --- |
| `server.py` | HTTP challenge service (pure-Python AES-128-CBC, no dependencies) |
| `Dockerfile` | CTFd Whale image, binds `0.0.0.0:9999` |
| `.dockerignore` | Keeps `flag.txt`, `solve.py`, `e2e_test.py`, and docs out of the image |
| `flag.txt` | Local fallback only, not copied into the image |
| `solve.py` | Padding-oracle solver, runs against a local or remote instance |
| `e2e_test.py` | Self-contained check: boots `server.py` on a temp port and attacks it |

## Flag

```text
LYKNCTF{padding_oracle_byte_by_byte}
```
