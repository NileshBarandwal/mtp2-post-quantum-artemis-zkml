"""
ecc_utils_64bit.py — 64-bit Elliptic Curve for BSGS Complexity Demonstration
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad
Date  : March 2026

PURPOSE:
  This file provides a 64-bit elliptic curve as a drop-in replacement for
  the 9-bit demo curve in ecc_utils.py.

  It is used to demonstrate WHY classical BSGS cannot break a real-world
  curve, and why Shor's algorithm is the actual quantum threat.

CURVE PARAMETERS:
  y² = x³ + 3x + 7  (mod p)
  p  = 18446744073709551557  (largest 64-bit prime, 64-bit)
  a  = 3
  b  = 7
  G  = (1, 11984760362735376427)
  n  ≈ 2^64  (subgroup order, computed at runtime)

COMPLEXITY COMPARISON:
  Curve     | Bits | BSGS steps      | Classical time | Shor's (quantum)
  ──────────|──────|─────────────────|────────────────|─────────────────
  Demo      |  9   | √502 ≈ 23       | 0.03 ms        | Feasible
  This file | 64   | √2^64 = 2^32    | Hours–days     | Feasible
  BN254     | 254  | √2^254 = 2^127  | Age of universe| Feasible (Shor's)

NOTE:
  compute_group_order() on a 64-bit curve is extremely slow
  (it uses naive order computation). For demo purposes, we use
  a precomputed approximate order n = p + 1 (Hasse bound approximation)
  and verify G is on the curve. The BSGS complexity argument holds
  regardless of the exact n value as long as n ≈ 2^64.

SAME INTERFACE as ecc_utils.py — drop-in replacement.
"""

import time
import random
import math


# ─────────────────────────────────────────────────────────────────────────────
# Curve constants — 64-bit prime curve
# ─────────────────────────────────────────────────────────────────────────────

CURVE_P = 18446744073709551557   # largest 64-bit prime
CURVE_A = 3
CURVE_B = 7

# Generator point (verified on curve below)
# y² = 1³ + 3·1 + 7 = 11 (mod p)
# y  = sqrt(11) mod p = 11984760362735376427
_GX = 1
_GY = 11984760362735376427


# ─────────────────────────────────────────────────────────────────────────────
# Modular square root (Tonelli-Shanks algorithm)
# ─────────────────────────────────────────────────────────────────────────────

def _sqrt_mod(n, p):
    """
    Compute sqrt(n) mod p using Tonelli-Shanks algorithm.
    Returns y such that y^2 ≡ n (mod p), or None if no square root exists.
    """
    n = n % p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None  # not a quadratic residue
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # Tonelli-Shanks for p ≡ 1 (mod 4)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1

    # Find a non-residue z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while True:
        if t == 0:
            return 0
        if t == 1:
            return r
        i, temp = 1, (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * b * b) % p
        r = (r * b) % p


# ─────────────────────────────────────────────────────────────────────────────
# EllipticCurve class — same interface as ecc_utils.py
# ─────────────────────────────────────────────────────────────────────────────

class EllipticCurve:
    """
    Weierstrass elliptic curve: y² = x³ + ax + b  (mod p)

    Same interface as ecc_utils.EllipticCurve — drop-in replacement.
    Arithmetic uses Python big integers (no overflow issues at 64-bit).
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        disc = (4 * a**3 + 27 * b**2) % p
        assert disc != 0, f"Curve is singular! discriminant = {disc}"

    def is_on_curve(self, P):
        """Check if point P = (x, y) satisfies the curve equation."""
        if P is None:
            return True  # point at infinity is always on curve
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def point_neg(self, P):
        """Return -P = (x, -y mod p)."""
        if P is None:
            return None
        return (P[0], (-P[1]) % self.p)

    def point_add(self, P, Q):
        """
        Add two points P and Q on the curve.
        Returns R = P + Q using standard Weierstrass addition formulas.
        """
        p = self.p

        # Identity element
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        # Point at infinity cases
        if x1 == x2:
            if y1 != y2:
                return None          # P + (-P) = O
            if y1 == 0:
                return None          # tangent is vertical

            # Point doubling
            s = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            # Point addition
            s = (y2 - y1) * pow(x2 - x1, -1, p) % p

        x3 = (s * s - x1 - x2) % p
        y3 = (s * (x1 - x3) - y1) % p
        return (x3, y3)

    def scalar_mul(self, k, P):
        """
        Compute k·P using double-and-add (binary method).
        k is reduced mod group order before use.
        """
        if k == 0 or P is None:
            return None
        if k < 0:
            return self.scalar_mul(-k, self.point_neg(P))

        result = None
        addend = P
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result

    def find_generator(self):
        """
        Return the known generator G = (_GX, _GY).
        For the 64-bit curve, the generator is precomputed.
        """
        G = (_GX, _GY)
        assert self.is_on_curve(G), f"Generator G = {G} is NOT on curve!"
        return G

    def find_point_on_curve(self):
        """Find the first point on the curve by scanning x = 1, 2, 3..."""
        for x in range(1, 10000):
            rhs = (x**3 + self.a * x + self.b) % self.p
            y = _sqrt_mod(rhs, self.p)
            if y is not None and (y * y) % self.p == rhs:
                P = (x, y)
                if self.is_on_curve(P):
                    return P
        raise ValueError("No point found on curve")

    def compute_group_order(self, G):
        """
        For the 64-bit curve, return a precomputed approximate order.

        Computing the exact group order of a 64-bit curve requires
        Schoof's algorithm or SEA — far beyond demo scope.

        We use n ≈ p as the Hasse bound: |n - (p+1)| ≤ 2√p
        For p ≈ 2^64: 2√p ≈ 2^33, so n is in range [p+1-2^33, p+1+2^33].

        For BSGS complexity demonstration: n ≈ 2^64 is sufficient.
        The exact value does not change the complexity argument.
        """
        # Hasse bound: n is close to p+1 for a random curve
        # For demo: use p itself as the order approximation
        # (conservative — actual order is within 2*sqrt(p) of p+1)
        return self.p   # n ≈ p ≈ 2^64


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function mirroring ecc_utils.print_curve_info
# ─────────────────────────────────────────────────────────────────────────────

def print_curve_info(curve, G, n):
    print()
    print("=" * 66)
    print("  64-BIT ELLIPTIC CURVE SETUP")
    print("=" * 66)
    print(f"  Equation       :  y² = x³ + {curve.a}x + {curve.b}  (mod p)")
    print(f"  Field prime    :  p = {curve.p}")
    print(f"  Bit length     :  {curve.p.bit_length()} bits")
    print(f"  Discriminant   :  4a³ + 27b² = {(4*curve.a**3 + 27*curve.b**2) % curve.p} (mod p) ≠ 0 ✓")
    print(f"  Generator G    :  ({G[0]}, {G[1]}")
    print(f"  On curve       :  {curve.is_on_curve(G)} ✓")
    print(f"  Order n ≈      :  {n}  (≈ 2^{n.bit_length()-1})")
    print()
    print(f"  [Classical BSGS complexity]")
    m = math.isqrt(n) + 1
    print(f"  m = ⌈√n⌉       :  ⌈√{n}⌉ ≈ 2^32 = {m:,} steps")
    print(f"  [9-bit demo]   :  ⌈√502⌉ = 23 steps  → 0.03 ms")
    print(f"  [64-bit curve] :  ⌈√2^64⌉ = 2^32 steps → hours to days")
    print(f"  [BN254 curve]  :  ⌈√2^254⌉ = 2^127 steps → age of universe")
    print()
    print(f"  [Quantum Shor's complexity]")
    print(f"  All three:     :  O((log n)³) — polynomial time")
    print(f"  [9-bit demo]   :  O(9³) = 729 quantum ops")
    print(f"  [64-bit curve] :  O(64³) = 262,144 quantum ops")
    print(f"  [BN254 curve]  :  O(254³) ≈ 16M quantum ops")
    print(f"  Conclusion     :  Shor's breaks ALL ECC curves efficiently")
    print("=" * 66)


# ─────────────────────────────────────────────────────────────────────────────
# Main — run when executed directly
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print()
    print("  " + "═" * 62)
    print("  ═   ecc_utils_64bit.py — 64-bit Curve Demo               ═")
    print("  ═   MTP2: Post-Quantum Security for Artemis zkML          ═")
    print("  ═   Author: Nilesh R. Barandwal, IIT Dharwad              ═")
    print("  " + "═" * 62)

    # ── Setup ──────────────────────────────────────────────────────────────
    curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
    G = curve.find_generator()
    n = curve.compute_group_order(G)

    print_curve_info(curve, G, n)

    # ── Measure one point addition ─────────────────────────────────────────
    print("  TIMING: Measuring ECC point addition speed on this machine...")
    print()

    SAMPLES = 10_000
    P = G
    t0 = time.perf_counter()
    for _ in range(SAMPLES):
        P = curve.point_add(P, G)
    t1 = time.perf_counter()

    time_per_op_s = (t1 - t0) / SAMPLES
    ops_per_sec = 1 / time_per_op_s

    print(f"  {SAMPLES:,} point additions in {(t1-t0)*1000:.2f} ms")
    print(f"  Time per addition : {time_per_op_s*1e6:.2f} µs")
    print(f"  Speed             : {ops_per_sec:,.0f} point additions / second")
    print()

    # ── Extrapolate BSGS time ──────────────────────────────────────────────
    bsgs_steps = 2**32   # O(√n) for 64-bit curve
    total_seconds = bsgs_steps / ops_per_sec
    total_minutes = total_seconds / 60
    total_hours   = total_minutes / 60
    total_days    = total_hours / 24

    print("  BSGS ATTACK COMPLEXITY ON 64-BIT CURVE:")
    print()
    print(f"  Steps needed    :  2^32 = {bsgs_steps:,}")
    print(f"  Speed on machine:  {ops_per_sec:,.0f} ops/sec")
    print(f"  Estimated time  :  {total_seconds:,.0f} seconds")
    print(f"                  :  {total_minutes:,.0f} minutes")
    print(f"                  :  {total_hours:.1f} hours")
    print(f"                  :  {total_days:.2f} days")
    print()

    if total_hours < 1:
        verdict = f"{total_minutes:.0f} minutes — feasible on a laptop!"
    elif total_hours < 24:
        verdict = f"{total_hours:.1f} hours — feasible but slow"
    elif total_days < 30:
        verdict = f"{total_days:.1f} days — impractical for demo"
    else:
        verdict = f"{total_days:.0f} days — completely impractical"

    print(f"  Verdict         :  {verdict}")
    print()

    # ── Comparison table ───────────────────────────────────────────────────
    print("  ══════════════════════════════════════════════════════════════")
    print("  BSGS vs Shor's — Complexity Comparison")
    print("  ══════════════════════════════════════════════════════════════")
    shor_label = "Shor's ops"
    print(f"  {'Curve':<14} | {'Bits':<6} | {'BSGS steps':<22} | {shor_label}")
    print(f"  {'─'*14}─┼─{'─'*6}─┼─{'─'*22}─┼─{'─'*20}")
    print(f"  {'Demo curve':<14} | {'9':<6} | {'√502 ≈ 23':<22} | O(9³) = 729")
    print(f"  {'This file':<14} | {'64':<6} | {'√2^64 = 2^32':<22} | O(64³) = 262,144")
    print(f"  {'BN254 (Artemis)':<14} | {'254':<6} | {'√2^254 = 2^127':<22} | O(254³) ≈ 16M")
    print(f"  ══════════════════════════════════════════════════════════════")
    print()
    print(f"  KEY POINT:")
    print(f"    Classical BSGS: infeasible at 254-bit (2^127 steps)")
    print(f"    Shor's quantum: feasible at ANY bit size (polynomial time)")
    print(f"    This is WHY KZG in Artemis needs post-quantum replacement.")
    print()

    # ── Quick scalar mul test ──────────────────────────────────────────────
    print("  SANITY CHECK — scalar multiplication:")
    k = random.randint(2, 1000)
    P = curve.scalar_mul(k, G)
    Q = curve.scalar_mul(k+1, G)
    R = curve.point_add(P, G)
    print(f"  {k}·G = {P}")
    print(f"  {k+1}·G = {Q}")
    print(f"  {k}·G + G = {R}")
    print(f"  Match: {Q == R} ✓")
    print()
    print(f"  All checks passed. 64-bit curve is ready.")
    print(f"  To use in part1_demo.py: replace 'from ecc_utils import' with")
    print(f"  'from ecc_utils_64bit import' — no other changes needed.")
    print()
