#!/usr/bin/env python3
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

FLAG = b"LYKNCTF{n01sy_CRT_w1th_K4nn4n_3mb3dd1ng}"
e = 3

m = bytes_to_long(FLAG)
m3 = pow(m, e)
print(f"[*] m      = {m.bit_length()} bits")
print(f"[*] m^3    = {m3.bit_length()} bits")

assert m3.bit_length() < 3072, "m^3 must be smaller than product of three 1024-bit moduli"

n1 = getPrime(512) * getPrime(512)
n2 = getPrime(512) * getPrime(512)
n3 = getPrime(512) * getPrime(512)
n = [n1, n2, n3]
N = n1 * n2 * n3
print(f"[*] n_i    = {n[0].bit_length()} bits")
print(f"[*] N      = {N.bit_length()} bits")

assert m3 < N, "Hastad condition: m^3 < n1*n2*n3"
assert m3 < min(n), "Additionally: m^3 < min(n_i) so residues are just m^3 directly"

c = [pow(m, e, ni) for ni in n]
for i, ci in enumerate(c):
    assert ci == m3, f"Expected ci == m^3 since m^3 < n_i"

BIT_FLIP_RANGE = 128  # error positions 0..127, so |error| <= 2^128

c_corrupted = []
for i, ci in enumerate(c):
    pos = random.randint(0, BIT_FLIP_RANGE)
    corrupted = ci ^ (1 << pos)
    c_corrupted.append(corrupted)
    delta = corrupted - ci
    print(f"[*] c{i+1} bit flip at pos {pos}, delta = {delta:+d}")

with open("output.txt", "w") as f:
    f.write(f"e = {e}\n")
    for i in range(3):
        f.write(f"n{i+1} = {n[i]}\n")
        f.write(f"c{i+1} = {c_corrupted[i]}\n")

print("\n[+] output.txt written.")
print(f"[+] Flag: {FLAG.decode()}")
