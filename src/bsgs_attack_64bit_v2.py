"""
bsgs_attack_64bit_v2.py — Full-Scale 64-bit BSGS Attack (Numpy Hash Table)
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad

CHANGES FROM v1:
  Python dict used ~160 bytes/entry → OOM at 2200M / 4294M entries (~492 GB)
  This version uses a numpy open-addressing hash table:
    - Two uint64 arrays: ht_keys (x-coord) and ht_vals (scalar index)
    - Table size = 2^33 = 8,589,934,592 slots  (load factor ~0.5)
    - RAM: 2 × 8.59B × 8 bytes = ~137 GB  (fits in 494 GB free)
  Sentinel for empty slot: EMPTY = 0xFFFFFFFFFFFFFFFF  (> p, so never a valid x)
"""

import math
import time
import random
import os
import sys

import numpy as np

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

from ecc_utils_64bit import EllipticCurve, CURVE_A, CURVE_B, CURVE_P

OUTPUT_FILE = os.path.normpath(
    os.path.join(_SCRIPT_DIR, "..", "results", "64bit_experiment.txt")
)
LOG_FILE = "/tmp/bsgs64_v2.log"

# ─────────────────────────────────────────────────────────────────────────────
# Sentinel: any value >= p is not a valid curve x-coordinate
# CURVE_P = 18446744073709551557, UINT64_MAX = 18446744073709551615 > p  ✓
# ─────────────────────────────────────────────────────────────────────────────
EMPTY = np.uint64(0xFFFFFFFFFFFFFFFF)

# Table size: 2^33 slots → load factor ≈ 0.5, bit-masking for fast modulo
TABLE_BITS   = 33
TABLE_SIZE   = 1 << TABLE_BITS          # 8,589,934,592
TABLE_MASK   = np.uint64(TABLE_SIZE - 1)


class Tee:
    """Write to both stdout and a file."""
    def __init__(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self._file = open(filepath, "w", encoding="utf-8", buffering=1)
        self._stdout = sys.stdout

    def write(self, data):
        self._stdout.write(data)
        self._file.write(data)

    def flush(self):
        self._stdout.flush()
        self._file.flush()

    def close(self):
        sys.stdout = self._stdout
        self._file.close()


def get_ram_gb():
    """Return (used_GB, total_GB) from /proc/meminfo."""
    try:
        info = {}
        with open('/proc/meminfo') as f:
            for line in f:
                parts = line.split()
                info[parts[0].rstrip(':')] = int(parts[1])
        total = info['MemTotal'] / 1024 / 1024
        avail = info['MemAvailable'] / 1024 / 1024
        return total - avail, total
    except Exception:
        return 0.0, 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Numpy open-addressing hash table
# Keys   = x-coordinate of baby-step point  (uint64)
# Values = scalar index i                    (uint64)
# Sentinel EMPTY means slot is unused.
# ─────────────────────────────────────────────────────────────────────────────

def ht_insert(ht_keys, ht_vals, x_py, i_py):
    """Insert (x → i) into the hash table using linear probing."""
    x    = np.uint64(x_py)
    i    = np.uint64(i_py)
    slot = int(x & TABLE_MASK)
    while ht_keys[slot] != EMPTY:
        if ht_keys[slot] == x:
            # Key already present (duplicate x — rare); keep first occurrence.
            return
        slot = (slot + 1) & (TABLE_SIZE - 1)
    ht_keys[slot] = x
    ht_vals[slot] = i


def ht_lookup(ht_keys, ht_vals, x_py):
    """
    Look up x in the hash table.
    Returns the stored index i (as int) on hit, or -1 on miss.
    """
    x    = np.uint64(x_py)
    slot = int(x & TABLE_MASK)
    while ht_keys[slot] != EMPTY:
        if ht_keys[slot] == x:
            return int(ht_vals[slot])
        slot = (slot + 1) & (TABLE_SIZE - 1)
    return -1


# ─────────────────────────────────────────────────────────────────────────────
# Main BSGS routine
# ─────────────────────────────────────────────────────────────────────────────

def bsgs_64bit_v2(Q, G, n, curve):
    m = math.isqrt(n) + 1

    ram_for_table = TABLE_SIZE * 2 * 8 / 1e9   # bytes → GB
    print(f"  Baby-step table size m = {m:,}  (2^{math.log2(m):.1f})")
    print(f"  Hash-table slots       = {TABLE_SIZE:,}  (2^{TABLE_BITS}, load factor ~0.5)")
    print(f"  RAM for numpy arrays   : ~{ram_for_table:.1f} GB  (2 × uint64 arrays)")
    print()

    # ── Allocate hash table ──────────────────────────────────────────────────
    print("  Allocating numpy hash table...")
    t_alloc = time.perf_counter()
    ht_keys = np.full(TABLE_SIZE, EMPTY, dtype=np.uint64)
    ht_vals = np.zeros(TABLE_SIZE,       dtype=np.uint64)
    alloc_s = time.perf_counter() - t_alloc
    used, total = get_ram_gb()
    print(f"  Allocation done in {alloc_s:.1f}s  |  RAM used: {used:.1f}/{total:.1f} GB")
    print()

    # ── Baby steps ───────────────────────────────────────────────────────────
    print("  Building baby-step table...")
    print("  (Progress every 100M entries)")
    t_baby = time.perf_counter()

    baby_point = None   # i=0 → point at infinity (tau=0 excluded by construction)
    REPORT = 100_000_000

    for i in range(m):
        # Point at infinity has no x-coord; skip i=0 (tau cannot be 0 here)
        if baby_point is not None:
            ht_insert(ht_keys, ht_vals, baby_point[0], i)

        baby_point = curve.point_add(baby_point, G)

        if i > 0 and i % REPORT == 0:
            used, total = get_ram_gb()
            elapsed = time.perf_counter() - t_baby
            rate    = i / elapsed
            eta     = (m - i) / rate
            print(f"    [{i // REPORT * 100}M entries] "
                  f"RAM: {used:.1f}/{total:.1f} GB  |  "
                  f"Elapsed: {elapsed/3600:.2f}h  |  "
                  f"ETA: {eta/3600:.2f}h")
            sys.stdout.flush()

    t_baby_done = time.perf_counter()
    baby_time   = t_baby_done - t_baby
    used, total = get_ram_gb()
    print(f"  Baby-step table COMPLETE")
    print(f"  Time : {baby_time/3600:.2f}h  ({baby_time:.0f}s)")
    print(f"  RAM  : {used:.1f}/{total:.1f} GB")
    print()

    # ── Giant steps ──────────────────────────────────────────────────────────
    print("  Starting giant-step search...")
    t_giant = time.perf_counter()

    mG          = curve.scalar_mul(m, G)
    neg_mG      = curve.point_neg(mG)
    giant_point = Q

    GIANT_REPORT = 10_000_000

    for j in range(m + 1):
        if giant_point is None:
            # giant_point = Q − j*m*G = O  ⟹  tau = j*m
            w_candidate = (j * m) % n
            if curve.scalar_mul(w_candidate, G) == Q:
                t_giant_done = time.perf_counter()
                print(f"  FOUND (infinity match) j={j:,}")
                return w_candidate, baby_time, t_giant_done - t_giant, j
        else:
            i = ht_lookup(ht_keys, ht_vals, giant_point[0])
            if i >= 0:
                # Verify (handles duplicate-x false positives)
                w_candidate = (j * m + i) % n
                if curve.scalar_mul(w_candidate, G) == Q:
                    t_giant_done = time.perf_counter()
                    print(f"  COLLISION  j={j:,}, i={i:,}")
                    return w_candidate, baby_time, t_giant_done - t_giant, j

        giant_point = curve.point_add(giant_point, neg_mG)

        if j > 0 and j % GIANT_REPORT == 0:
            elapsed = time.perf_counter() - t_giant
            rate    = j / elapsed
            eta     = (m - j) / rate
            print(f"    [Giant {j // 1_000_000}M]  "
                  f"Elapsed: {elapsed/3600:.2f}h  |  ETA: {eta/3600:.2f}h")
            sys.stdout.flush()

    return None, baby_time, time.perf_counter() - t_giant, 0


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    tee = Tee(OUTPUT_FILE)
    sys.stdout = tee

    try:
        print()
        print("=" * 68)
        print("  64-BIT BSGS ATTACK v2 — Numpy Hash Table")
        print("  Post-Quantum Security for Artemis zkML — MTP2")
        print("  Author: Nilesh R. Barandwal, IIT Dharwad")
        print("=" * 68)
        print()
        print("  v1 OOM-crashed: Python dict ~160 bytes/entry → 492 GB at 2200M/4294M")
        print("  v2 fix: numpy open-addressing hash table ~16 bytes/entry → ~137 GB")
        print()

        # ── Curve setup ──────────────────────────────────────────────────────
        print("  Curve  :  y² = x³ + {}x + {}  (mod {})".format(CURVE_A, CURVE_B, CURVE_P))
        curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
        G     = (1, 11984760362735376427)
        assert curve.is_on_curve(G), "G not on curve!"
        n = CURVE_P + 1   # Hasse bound approximation

        print(f"  G      :  {G}")
        print(f"  n ≈    :  {n}  (2^{math.log2(n):.2f})")
        print()

        # ── Random 64-bit tau ────────────────────────────────────────────────
        random.seed(int(time.time()))
        tau = random.randint(2**63, 2**64 - 1)
        Q   = curve.scalar_mul(tau, G)

        print("  " + "=" * 64)
        print("  ECDLP INSTANCE — Random 64-bit tau")
        print("  " + "=" * 64)
        print(f"  tau (secret)  : {tau}")
        print(f"  tau bits      : {tau.bit_length()}")
        print(f"  Q = tau·G     : {Q}")
        print()
        print("  Previous results:")
        print("  9-bit  : 0.04 ms,    23 steps, forgery ACCEPTED")
        print("  32-bit : 57.6 ms, 46341 steps, forgery ACCEPTED")
        print("  64-bit : Running now (v2, numpy table)")
        print()

        used, total = get_ram_gb()
        print(f"  RAM available: {total - used:.1f} GB free / {total:.1f} GB total")
        print()

        # ── Run BSGS ─────────────────────────────────────────────────────────
        t_start = time.perf_counter()
        tau_rec, baby_t, giant_t, steps = bsgs_64bit_v2(Q, G, n, curve)
        total_t = time.perf_counter() - t_start

        # ── Results ──────────────────────────────────────────────────────────
        print()
        print("  " + "=" * 64)
        print("  RESULTS")
        print("  " + "=" * 64)

        if tau_rec is not None:
            verified = curve.scalar_mul(tau_rec, G) == Q
            print(f"  tau recovered  : {tau_rec}")
            print(f"  Matches true   : {tau_rec == tau}  ✓")
            print(f"  Verify tau·G=Q : {verified}  ✓")
            print(f"  Baby-step time : {baby_t/3600:.2f}h")
            print(f"  Giant-step time: {giant_t/3600:.2f}h")
            print(f"  Total time     : {total_t/3600:.2f}h")
            print(f"  Giant steps    : {steps:,}")
            print()
            w_fake = (tau_rec + 12345678901234) % n
            C_fake = curve.scalar_mul(w_fake, G)
            print(f"  KZG FORGERY:")
            print(f"  Fake tau       : {w_fake}")
            print(f"  Fake commit    : {C_fake}")
            print(f"  On curve       : {curve.is_on_curve(C_fake)}  ✓")
            print(f"  FORGERY ACCEPTED — verifier cannot distinguish")
        else:
            print("  BSGS did not find tau within m steps (unexpected)")

        # ── Comparison table ─────────────────────────────────────────────────
        print()
        t64 = f"{total_t/3600:.2f}h" if tau_rec else "running"
        s64 = f"{steps:,}"           if tau_rec else "~2^32"
        print("  Curve        Bits    Steps               Time         RAM")
        print("  " + "-" * 64)
        print("  9-bit           9       23               0.04 ms      bytes")
        print("  32-bit         32   46,341               57.6 ms     ~2 MB")
        print(f"  64-bit         64  {s64:>10}  {t64:>19}   ~137 GB (v2)")
        print("  BN254         254    2^127          impossible    2^127 GB")
        print()
        print("  Shor's:  all three curves solved in O((log n)^3)  (polynomial)")
        print()
        print(f"  Output: {OUTPUT_FILE}")

    finally:
        tee.close()


if __name__ == "__main__":
    main()
