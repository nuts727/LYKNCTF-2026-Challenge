# Follow The Layer — Solution

## Concept

**USDT TRC-20 Layering:** A common money laundering technique on the Tron blockchain
where scammers consolidate funds from multiple victims, then forward through pass-through
wallets to break the attribution trail before reaching a high-volume aggregation point.

Key difference from Bitcoin peel chains: there is no "change output". Every USDT transfer
is a direct, full-amount move. The trail is followed by tracking where **all** of the
received amount goes next.

---

## Solve Path

### Step 1 — Look up the starting transaction

Search TronScan or TronGrid for the given TX hash:

```
d4500023a8114caaa640ab92bb8f73830a5303ccdfc4e9b0cf862bdae7ae336b
```

Findings:
- **From:** `TXk7Dor9GeRRpR5hbCGd4rBieM21v4BcwX`
- **To:** `TNmRfnSUXZoWWzxcDDbf95eGQYXt1mJDt8`
- **Amount:** 2,700 USDT
- **Date:** 2025-02-27

### Step 2 — Investigate the receiving address

Check `TNmRfnSUXZoWWzxcDDbf95eGQYXt1mJDt8` on TronScan.

Observations:
- Receives USDT from **many different addresses** in small amounts (~500–3,000 USDT each)
- Periodically forwards larger **consolidated** amounts to a single address
- No name tag on TronScan initially

This is a **collection address** — typical of a scam operation aggregating victim payments.

### Step 3 — Cross-reference with OFAC

Search the address at https://sanctionssearch.ofac.treas.gov

Result: `TNmRfnSUXZoWWzxcDDbf95eGQYXt1mJDt8` belongs to **FUNNULL TECHNOLOGY INC**,
sanctioned under **CYBER3** — a company that provided CDN and hosting infrastructure
for pig-butchering scam websites across Southeast Asia.

### Step 4 — Find the consolidation batch

Look at FUNNULL's outgoing transactions. Notice that:
- `TXk7Dor9` sent **2,700 USDT** on 2025-02-27
- `TPfTT8bT` sent **2,522 USDT** on 2025-03-07
- 2,700 + 2,522 = **5,222 USDT** ← FUNNULL later sends exactly this amount

This proves both victims' funds were **consolidated** before forwarding.

Outgoing TX from FUNNULL:
```
2ef09557180070d4bfd274f771619b062fa9a1dec5087869b45e65003256b9d9
5,222 USDT → TQMq9s5eqxzHW9CG4hgrWxVZaz4oZDo3tb
Date: 2025-03-21 03:03 UTC
```

### Step 5 — Follow the pass-through

Check `TQMq9s5eqxzHW9CG4hgrWxVZaz4oZDo3tb`. This wallet:
- Receives the exact same amount from FUNNULL
- Forwards the **exact same amount** 4 minutes later
- Has never held a balance — pure pass-through

Final traceable TX:
```
7e401f8004084d4bf9f792535fdf5b89138a935d027b6b75ceb2dd3ac8838fab
5,222 USDT → TJ7hhYhVhaxNx6BPyq7yFpqZrQULL3JSdb
Date: 2025-03-21 03:07 UTC
```

### Step 6 — Confirm the chain ends here

Check `TJ7hhYhVhaxNx6BPyq7yFpqZrQULL3JSdb`:
- **75+ unique senders**
- **100+ unique receivers**
- Millions of USDT flowing through daily
- No attributable entity — this is a high-volume aggregation/mixer

The funds have lost their identity. The chain is no longer traceable. This is the end.

---

## Flag

```
LYKNCTF{7e401f8004084d4bf9f792535fdf5b89138a935d027b6b75ceb2dd3ac8838fab:03/21/2025:FUNNULL}
```

---

## Summary Table

| Hop | TX Hash (truncated) | From | To | Amount | Date |
|---|---|---|---|---|---|
| 1 *(start)* | `d4500023...` | TXk7Dor9... | **FUNNULL** | 2,700 USDT | 2025-02-27 |
| — | `5d1c353f...` | TPfTT8bT... | **FUNNULL** | 2,522 USDT | 2025-03-07 |
| 2 | `2ef09557...` | **FUNNULL** | TQMq9s5e... | 5,222 USDT | 2025-03-21 |
| 3 *(end)* | `7e401f80...` | TQMq9s5e... | TJ7hhYhV... | 5,222 USDT | 2025-03-21 |

---

## References

- OFAC SDN Sanctions List: https://sanctionssearch.ofac.treas.gov
- FUNNULL TECHNOLOGY INC sanction notice: search "FUNNULL" on OFAC
- TronScan explorer: https://tronscan.org
- TronGrid API docs: https://developers.tron.network/reference/trc20-transaction-information-by-account-address
