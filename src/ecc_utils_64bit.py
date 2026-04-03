"""
ecc_utils_64bit.py — 64-bit Prime-Order Elliptic Curve
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad

CURVE PARAMETERS (prime order, verified):
  y² = x³ + 7800851958821274545x + 3032140762713616321  (mod 12543974025918169487)
  p  = 12543974025918169487   (64-bit prime)
  a  = 7800851958821274545
  b  = 3032140762713616321
  n  = 12543974020049812861   (TRUE prime group order, cofactor h=1)
  G  = (9288838633539720391, 2052742288688552359)

Verified: n*G = O, isprime(n) = True
"""

import time
import random
import math

CURVE_P = 12543974025918169487
CURVE_A = 7800851958821274545
CURVE_B = 3032140762713616321
CURVE_N = 12543974020049812861  # TRUE prime group order

_GX = 9288838633539720391
_GY = 2052742288688552359


def _sqrt_mod(n, p):
    n = n % p
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)
    while True:
        if t == 0: return 0
        if t == 1: return r
        i, temp = 1, (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * b * b) % p
        r = (r * b) % p


class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        disc = (4 * a**3 + 27 * b**2) % p
        assert disc != 0, f"Curve is singular!"

    def is_on_curve(self, P):
        if P is None: return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def point_neg(self, P):
        if P is None: return None
        return (P[0], (-P[1]) % self.p)

    def point_add(self, P, Q):
        p = self.p
        if P is None: return Q
        if Q is None: return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2:
            if y1 != y2: return None
            if y1 == 0: return None
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
        G = (_GX, _GY)
        assert self.is_on_curve(G), f"G not on curve!"
        return G

    def compute_group_order(self, G):
        return CURVE_N  # exact prime order


def print_curve_info(curve, G, n):
    print()
    print("=" * 66)
    print("  64-BIT PRIME-ORDER ELLIPTIC CURVE SETUP")
    print("=" * 66)
    print(f"  Equation : y² = x³ + {curve.a}x + {curve.b}  (mod {curve.p})")
    print(f"  p        : {curve.p}  ({curve.p.bit_length()} bits)")
    print(f"  G        : {G}")
    print(f"  n        : {n}  (prime, exact)")
    print(f"  n*G = O  : {curve.scalar_mul(n, G) is None} ✓")
    print("=" * 66)
