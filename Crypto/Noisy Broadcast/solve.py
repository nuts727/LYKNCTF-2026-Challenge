#!/usr/bin/env python3
"""
Noisy CRT Reconstruction - Challenge Solver

Approach: Since m^3 < min(n_i) for each modulus, the residues are m^3 directly 
(no modular reduction). Each ciphertext is m^3 with one bit flipped.
We brute-force the error on c1 and verify against c2, c3.
"""
from Crypto.Util.number import long_to_bytes


def is_power_of_two(n):
    """True if |n| is a power of 2."""
    n = abs(n)
    return n > 0 and (n & (n - 1)) == 0


def integer_nth_root(n, k):
    """Return (root, exact) using binary search. Works for arbitrarily large ints."""
    if n < 0:
        return 0, False
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    # Binary search
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


def solve():
    # ---- 1. read output ----
    ns = {}
    cs = {}
    e_val = 3
    with open("output.txt") as f:
        for line in f:
            line = line.strip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = int(val.strip())
            if key.startswith("n"):
                ns[key] = val
            elif key.startswith("c"):
                cs[key] = val
            elif key == "e":
                e_val = val

    n1, n2, n3 = ns["n1"], ns["n2"], ns["n3"]
    c1, c2, c3 = cs["c1"], cs["c2"], cs["c3"]

    # ---- 2. build error list ----
    # From source: BIT_FLIP_RANGE = 128, pos in [0,128]
    BIT_FLIP_RANGE = 128
    errors = []
    for pos in range(0, BIT_FLIP_RANGE + 1):
        val = 1 << pos
        errors.append(+val)
        errors.append(-val)

    print(f"[*] Trying {len(errors)} error candidates for c1...")

    # ---- 3. brute-force: try each e1, verify against c2,c3 ----
    for e1 in errors:
        x = c1 - e1  # candidate: m^3
        if x <= 0:
            continue

        d2 = c2 - x
        d3 = c3 - x

        if is_power_of_two(d2) and is_power_of_two(d3):
            m, exact = integer_nth_root(x, 3)
            if exact:
                flag = long_to_bytes(m)
                if flag.startswith(b"LYKNCTF"):
                    print(f"[+] Found!  e1={e1:+d}  d2={d2:+d}  d3={d3:+d}")
                    print(f"[+] m^3 = {x}")
                    print(f"[+] m   = {m}")
                    print(f"\n[+] FLAG: {flag.decode()}")
                    return flag.decode()

    print("[-] No valid flag recovered.")
    return None


if __name__ == "__main__":
    solve()
