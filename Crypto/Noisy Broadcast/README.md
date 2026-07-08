# Noisy Broadcast — Crypto Challenge

**Category:** Cryptography  
**Difficulty:** Medium  
**Flag format:** `LYKNCTF{...}`

## Description

The same secret message was broadcast to three different recipients using
textbook RSA with a small public exponent `e = 3`. Unfortunately, the
communication channel was noisy — each recipient received a ciphertext
with exactly **one random bit flipped**.

You are given the three corrupted ciphertexts and their corresponding
moduli. Recover the original plaintext.

**Skills tested:** Håstad’s broadcast attack, noisy CRT reconstruction,
lattice-based error correction (Kannan embedding), integer cube root.

## Files provided to players

- `output.txt` — three RSA moduli and their corrupted ciphertexts

## Setup (netcat, optional)

If you want to serve the challenge over the network instead of providing
the file, use the following wrapper:

```python
# server.py
import socketserver
import time

DATA = open("output.txt", "rb").read()

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"Welcome to Noisy Broadcast!\n")
        time.sleep(0.5)
        self.wfile.write(DATA)
        self.wfile.write(b"\nRecover the flag!\n")

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", 9999), Handler) as server:
        print("[*] Listening on port 9999")
        server.serve_forever()
```

```bash
docker run -d -p 9999:9999 -v "$PWD":/chal python:3-slim \
    bash -c "pip install pycryptodome && python /chal/server.py"
```

## How to create (re-generate) the challenge

```bash
pip install pycryptodome
python source.py
```

This writes a fresh `output.txt`. The flag and bit-flip range are
hard-coded in `source.py` — change them before re-generating.

## Solution

### 1. Understanding the problem

Three RSA moduli `n₁, n₂, n₃` and three corrupted ciphertexts
`c₁', c₂', c₃'` are given.  They were produced as follows:

```
cᵢ = m³  mod nᵢ
cᵢ' = cᵢ  ⊕  2^pos      (pos ∈ [0, 128], random)
```

Because the flag is short (~319 bits), `m³ < min(nᵢ)` holds for the
1024‑bit moduli.  Therefore **no modular reduction happens** — each
`cᵢ` is actually equal to `m³` as an integer.  The corrupted ciphertext
is simply `m³` with one bit flipped:

```
cᵢ' = m³  ±  2^posᵢ
```

### 2. Standard Håstad’s attack

If the ciphertexts were **not** corrupted, CRT would reconstruct `m³`
exactly over the integers:

```
C = CRT(c₁, n₁ ; c₂, n₂ ; c₃, n₃) = m³
```

Taking the integer cube root would then recover `m`.

### 3. Noisy CRT — correcting the errors

Because each `cᵢ'` differs from `m³` by a power of two, we can
brute‑force the error on **one** ciphertext and verify consistency
against the other two:

1. For every admissible error `e` (≈258 candidates):
   - Compute candidate `x = c₁' − e`
   - Check whether `c₂' − x` and `c₃' − x` are both powers of two
     (with sign).
2. When both checks pass, `x` is `m³`.
3. Compute the integer cube root of `x` to obtain `m`.

#### Why does this work?

| Step | Equation | Note |
|------|----------|------|
| c₁' | `m³ + e*₁` | true error e₁\* = ±2⁵² |
| c₂' | `m³ + e*₂` | true error e₂\* = ±2⁴² |
| c₃' | `m³ + e*₃` | true error e₃\* = ±2⁶⁸ |
| Guess e₁ | `x = c₁' − e₁` | |
| If e₁ = e₁\* | `x = m³` | |
| Then | `c₂' − x = e*₂` | power of two ✓ |
|  | `c₃' − x = e*₃` | power of two ✓ |
| If e₁ ≠ e₁\* | `c₂' − x = e*₂ − e₁\* + e₁` | ≠ power of two ✗ |

### 4. Kannan embedding (lattice method)

A more general lattice-based approach for noisy CRT with larger errors
works as follows:

Let `N = n₁·n₂·n₃` and `Tᵢ = (N/nᵢ) · (N/nᵢ)⁻¹ mod nᵢ` (the CRT
coefficient, taken modulo `N`).

The noisy CRT combination is:

```
C = Σ cᵢ'·Tᵢ   (mod N)   ⇒   C ≡ m³ + Σ eᵢ·Tᵢ   (mod N)
```

Rearranged:

```
m³ ≡ C − e₁·T₁ − e₂·T₂ − e₃·T₃   (mod N)
```

We want small errors `|eᵢ| < 2¹²⁸`.  The **Kannan embedding** builds a
lattice whose short vectors encode `(e₁, e₂, e₃, k)` satisfying:

```
e₁·T₁ + e₂·T₂ + e₃·T₃ + k·N = C − m³
```

In SageMath:

```python
N = n1 * n2 * n3
N1, N2, N3 = N//n1, N//n2, N//n3
T1 = (N1 * inverse_mod(N1, n1)) % N
T2 = (N2 * inverse_mod(N2, n2)) % N
T3 = (N3 * inverse_mod(N3, n3)) % N
C = (c1*T1 + c2*T2 + c3*T3) % N

M = Matrix(ZZ, [
    [1, 0, 0, T1],
    [0, 1, 0, T2],
    [0, 0, 1, T3],
    [0, 0, 0, N ],
])
L = M.LLL()
for row in L:
    e1, e2, e3, val = row
    if e1 == 0 and e2 == 0 and e3 == 0:
        continue
    if val == 0:
        continue
    # val = C - m^3 (mod N)
    # Check if m^3 is a perfect cube...
```

### 5. Complete solve script (`solve.py`)

```python
#!/usr/bin/env python3
"""
Noisy CRT Reconstruction – Challenge Solver
Brute‑force error on c₁, verify against c₂ and c₃.
"""
from Crypto.Util.number import long_to_bytes

def is_power_of_two(n):
    n = abs(n)
    return n > 0 and (n & (n - 1)) == 0

def integer_nth_root(n, k):
    if n < 0:
        return 0, False
    if n == 0:
        return 0, True
    lo, hi = 0, 1 << ((n.bit_length() + k - 1) // k)
    while lo <= hi:
        mid = (lo + hi) // 2
        p = pow(mid, k)
        if p == n:
            return mid, True
        elif p < n:
            lo = mid + 1
        else:
            hi = mid - 1
    return lo - 1, False

with open("output.txt") as f:
    data = {}
    for line in f:
        if "=" in line:
            k, v = line.strip().split("=", 1)
            data[k.strip()] = int(v.strip())

c1, c2, c3 = data["c1"], data["c2"], data["c3"]
BIT_FLIP_RANGE = 128

errors = []
for pos in range(BIT_FLIP_RANGE + 1):
    v = 1 << pos
    errors.extend([v, -v])

for e1 in errors:
    x = c1 - e1
    if x <= 0:
        continue
    d2, d3 = c2 - x, c3 - x
    if is_power_of_two(d2) and is_power_of_two(d3):
        m, exact = integer_nth_root(x, 3)
        if exact:
            flag = long_to_bytes(m)
            if flag.startswith(b"LYKNCTF"):
                print(flag.decode())
                break
```

### 6. Expected output

```
$ python solve.py
LYKNCTF{n01sy_CRT_w1th_K4nn4n_3mb3dd1ng}
```

## Directory structure

```
Challenge3/
├── README.md      # This file
├── source.py      # Challenge generator
├── output.txt     # Provided to players
└── solve.py       # Solution script
```
