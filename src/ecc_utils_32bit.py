"""
ecc_utils_32bit.py — 32-bit Elliptic Curve (drop-in for ecc_utils.py)
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad
Date  : March 2026

PURPOSE:
  32-bit curve replacement for the 9-bit demo curve in ecc_utils.py.
  BSGS breaks it in ~100-200 ms — visible but not instant.
  Stronger demonstration than the 9-bit curve without being impractical.

CURVE PARAMETERS:
  y² = x³ + 3x + 7  (mod p)
  p  = 4294967291   (largest 32-bit prime)
  a  = 3
  b  = 7
  G  = (1, 1789981121)  (verified on curve)
  n  ≈ p ≈ 2^32

COMPLEXITY:
  Curve     | Bits | BSGS steps    | Time on laptop
  ──────────|──────|───────────────|────────────────
  9-bit     |  9   | √502 ≈ 23     | 0.03 ms
  This file | 32   | √2^32 = 65536 | ~100-200 ms
  64-bit    |  64  | √2^64 = 2^32  | ~4 hours
  BN254     | 254  | √2^254 = 2^127| age of universe

SAME INTERFACE as ecc_utils.py — drop-in replacement.
Change one line in part1_demo.py:
  from ecc_utils_32bit import EllipticCurve, CURVE_A, CURVE_B, CURVE_P, print_curve_info
"""

import time
import random
import math


# ─────────────────────────────────────────────────────────────────────────────
# Curve constants
# ─────────────────────────────────────────────────────────────────────────────

CURVE_P = 4294967291    # largest 32-bit prime
CURVE_A = 3
CURVE_B = 7

# Generator: G = (1, 1789981121)
# Verify: 1789981121² mod p = 11 = 1³ + 3·1 + 7 mod p  ✓
_GX = 1
_GY = 1789981121


# ─────────────────────────────────────────────────────────────────────────────
# Modular square root — Tonelli-Shanks
# ─────────────────────────────────────────────────────────────────────────────

def _sqrt_mod(n, p):
    """Compute sqrt(n) mod p. Returns None if no square root exists."""
    n = n % p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    # p = 4294967291 ≡ 3 (mod 4) — fast formula applies
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    # Tonelli-Shanks (general case)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while True:
        if t == 0: return 0
        if t == 1: return r
        i, temp = 1, (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, b*b%p, t*b*b%p, r*b%p


# ─────────────────────────────────────────────────────────────────────────────
# EllipticCurve class — same interface as ecc_utils.py
# ─────────────────────────────────────────────────────────────────────────────

class EllipticCurve:
    """
    Weierstrass elliptic curve: y² = x³ + ax + b  (mod p)
    Drop-in replacement for ecc_utils.EllipticCurve.
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        disc = (4 * a**3 + 27 * b**2) % p
        assert disc != 0, f"Curve is singular! discriminant = {disc}"

    def is_on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def point_neg(self, P):
        if P is None:
            return None
        return (P[0], (-P[1]) % self.p)

    def point_add(self, P, Q):
        p = self.p
        if P is None: return Q
        if Q is None: return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if y1 != y2: return None
            if y1 == 0:  return None
            s = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            s = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (s * s - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        return (x3, y3)

    def scalar_mul(self, k, P):
        if k == 0 or P is None: return None
        if k < 0: return self.scalar_mul(-k, self.point_neg(P))
        result = None
        addend = P
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result

    def find_generator(self):
        """Return precomputed generator G = (1, 1789981121)."""
        G = (_GX, _GY)
        assert self.is_on_curve(G), f"Generator G={G} not on curve!"
        return G

    def compute_group_order(self, G):
        """
        Return approximate group order n ≈ p (Hasse bound).
        For 32-bit curve: exact order computation via Schoof is out of scope.
        n ≈ p = 4294967291 ≈ 2^32. BSGS uses math.isqrt(n)+1 steps.
        """
        return self.p


# ─────────────────────────────────────────────────────────────────────────────
# print_curve_info — matches ecc_utils.py interface
# ─────────────────────────────────────────────────────────────────────────────

def print_curve_info(curve, G, n):
    m = math.isqrt(n) + 1
    print()
    print("=" * 66)
    print("  32-BIT ELLIPTIC CURVE SETUP")
    print("=" * 66)
    print(f"  Equation       :  y² = x³ + {curve.a}x + {curve.b}  (mod p)")
    print(f"  Field prime    :  p = {curve.p}")
    print(f"  Bit length     :  {curve.p.bit_length()} bits")
    print(f"  Discriminant   :  4a³+27b² = "
          f"{(4*curve.a**3+27*curve.b**2)%curve.p} (mod p) ≠ 0 ✓")
    print(f"  Generator G    :  {G}")
    print(f"  On curve       :  {curve.is_on_curve(G)} ✓")
    print(f"  Order n ≈      :  {n}  (≈ 2^{n.bit_length()-1})")
    print()
    print(f"  [Classical BSGS complexity]")
    print(f"  m = ⌈√n⌉       :  {m:,} steps  (≈ 2^16)")
    print(f"  [9-bit demo]   :  23 steps      → 0.03 ms")
    print(f"  [32-bit]       :  65,536 steps  → ~100-200 ms  ← THIS CURVE")
    print(f"  [64-bit]       :  2^32 steps    → ~4 hours")
    print(f"  [BN254]        :  2^127 steps   → age of universe")
    print()
    print(f"  [Quantum Shor's complexity]")
    print(f"  All curves     :  O((log n)³) — polynomial time")
    print(f"  [32-bit]       :  O(32³) = 32,768 quantum ops")
    print(f"  [BN254]        :  O(254³) ≈ 16M quantum ops")
    print(f"  Conclusion     :  Shor's breaks ALL ECC in polynomial time")
    print("=" * 66)


# ─────────────────────────────────────────────────────────────────────────────
# Main — run when executed directly
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print()
    print("  " + "═" * 62)
    print("  ═   ecc_utils_32bit.py — 32-bit Curve Verification        ═")
    print("  ═   MTP2: Post-Quantum Security for Artemis zkML          ═")
    print("  ═   Author: Nilesh R. Barandwal, IIT Dharwad              ═")
    print("  " + "═" * 62)

    curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
    G = curve.find_generator()
    n = curve.compute_group_order(G)

    print_curve_info(curve, G, n)

    # ── Timing ────────────────────────────────────────────────────────────
    print("  TIMING: Measuring ECC point addition speed...")
    SAMPLES = 1_000
    P = G
    t0 = time.perf_counter()
    for _ in range(SAMPLES):
        P = curve.point_add(P, G)
    t1 = time.perf_counter()

    ops_per_sec = SAMPLES / (t1 - t0)
    bsgs_steps  = math.isqrt(n) + 1
    est_ms      = (bsgs_steps / ops_per_sec) * 1000

    print(f"  Speed           :  {ops_per_sec:,.0f} point additions / second")
    print(f"  BSGS steps      :  {bsgs_steps:,}  (⌈√{n}⌉)")
    print(f"  Estimated time  :  {est_ms:.1f} ms  (~{est_ms/1000:.2f} seconds)")
    print()

    # ── Sanity check ─────────────────────────────────────────────────────
    print("  SANITY CHECK — scalar multiplication:")
    k = random.randint(2, 1000)
    Pk  = curve.scalar_mul(k,   G)
    Pk1 = curve.scalar_mul(k+1, G)
    R   = curve.point_add(Pk, G)
    print(f"  {k}·G   = {Pk}")
    print(f"  {k+1}·G = {Pk1}")
    print(f"  {k}·G+G = {R}")
    print(f"  Match  : {Pk1 == R} ✓")
    print()
    print(f"  32-bit curve ready.")
    print(f"  To use in part1_demo.py — change one import line:")
    print(f"  from ecc_utils_32bit import EllipticCurve, CURVE_A, CURVE_B, CURVE_P, print_curve_info")
    print()
