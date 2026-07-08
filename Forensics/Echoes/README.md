
# Echoes — Solution

## Concept

**Cross Fork Object Reference (CFOR):** Git objects pushed to any fork remain accessible by SHA-1 hash even after the fork is deleted.

---

## Solve Path

**1. Recon** — Repo has 1 commit, empty README. Description hints "nothing disappears on GitHub" → CFOR.

**2. Brute-force hidden commit** — Enumerate all 65,536 four-char SHA-1 prefixes via GitHub GraphQL API:

```bash
python solve.py ghp_YOUR_TOKEN datxmilanista-png/echoes
# or: python3 cfor_exp.py -t https://github.com/datxmilanista-png/echoes
```

Hit: commit `783f2e04...` — *"experimenting with encoding stuff (wip, do not share)"*

**3. Read `experiment.py`** from the hidden commit:

```python
_raw = ("d727336733...", "36f54633...", "")

def _recover(s):
    return bytes.fromhex(s[::-1]).decode()

# print(_recover(_raw))  # uncomment when ready
```

**4. Decode:**

```python
print(_recover(_raw))
# LYKNCTF{0rph4n3d_c0mm1t5_l1v3_f0r3v3r}
```

---

## Flag

`LYKNCTF{0rph4n3d_c0mm1t5_l1v3_f0r3v3r}`

---

## Unintended Path (Blocked)

If a player comments on the hidden commit → GitHub Events API leaks the URL.
**Mitigated:** Interaction limit set to `collaborators_only` until 2026-12-24.

---

## References

- https://trufflesecurity.com/blog/anyone-can-access-deleted-and-private-repo-data-github
- https://github.com/SorceryIE/cfor_exploit
