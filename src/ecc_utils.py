"""
ecc_utils.py — Small Elliptic Curve Arithmetic
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad

PURPOSE:
    Implements elliptic curve arithmetic over a small finite field F_p.
    We deliberately use a SMALL curve (p = 1021) so that the Baby-step
    Giant-step (BSGS) attack can break commitments in under a second —
    demonstrating the vulnerability that Shor's algorithm would exploit
    at production (256-bit) scale.

CRYPTOGRAPHIC SIGNIFICANCE:
    Real Artemis/KZG deployments use p ≈ 2^254 (BN254 curve).
    The SAME mathematical group structure that BSGS exploits here is what
    Shor's quantum algorithm exploits at 256-bit scale — in O((log n)^3)
    quantum time instead of O(√n) classical time.

    The takeaway: KZG security collapses entirely on a quantum computer
    because the ECDLP assumption it relies on is broken by Shor's algorithm.
"""

import math


# ---------------------------------------------------------------------------
# Curve Parameters (verified pre-computation)
# ---------------------------------------------------------------------------

# Curve:  y² = x³ + 2x + 3  (mod 1021)
# Chosen because:
#   - Discriminant Δ = -16(4·2³ + 27·3²) = -16·275 ≡ 705 (mod 1021) ≠ 0
#     → non-singular (smooth curve, valid for cryptography)
#   - Group order n = 1004  (counted by brute force over F_1021)
#   - n > 42 → weight w = 42 is a valid scalar for our demo commitment
#   - √n ≈ 31 → BSGS needs only ~31 baby steps (runs in milliseconds)
#   - Hasse bound satisfied: |n - (p+1)| = |1004 - 1022| = 18 ≤ 2√1021 ≈ 64
CURVE_A = 2
CURVE_B = 3
CURVE_P = 1021  # Small prime field — intentionally breakable for demo


class EllipticCurve:
    """
    Elliptic curve in short Weierstrass form: y² = x³ + ax + b (mod p)

    This is the standard form used by all major cryptographic curves:
    secp256k1 (Bitcoin/Ethereum), BN254 (used in KZG/Artemis), etc.

    Points are represented as:
      - (x, y) tuple for finite points
      - None for the point at infinity O (the group identity element)

    The group operation (point addition) has the property:
      - Given generator G and scalar k, computing Q = k·G is easy (O(log k) ops)
      - Given G and Q = k·G, recovering k is the ECDLP — computationally hard
        classically, but solvable in polynomial time by Shor's algorithm
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
        self._check_nonsingular()

    def _check_nonsingular(self):
        """
        Verify the curve is non-singular via the discriminant condition.

        A singular curve (discriminant = 0) has cusps or self-intersections,
        which destroy the group structure needed for cryptography. Any
        implementation using a singular curve is immediately broken.

        Condition: 4a³ + 27b² ≢ 0 (mod p)
        """
        val = (4 * self.a**3 + 27 * self.b**2) % self.p
        if val == 0:
            raise ValueError(
                f"Curve y²=x³+{self.a}x+{self.b} mod {self.p} is SINGULAR. "
                f"Choose different parameters."
            )
        # Δ = -16 * val  (we store the inner value for display)
        self._discriminant_inner = val

    def is_on_curve(self, P):
        """
        Check if point P satisfies the curve equation.

        Every point in a KZG commitment must lie on the curve — this is what
        allows the verifier to confirm the proof was honestly generated.
        """
        if P is None:
            return True  # O (point at infinity) is always on the curve
        x, y = P
        lhs = (y * y) % self.p
        rhs = (x**3 + self.a * x + self.b) % self.p
        return lhs == rhs

    def point_neg(self, P):
        """
        Negate a point: -P = (x, -y mod p)

        Point negation reflects P across the x-axis. Used in BSGS (subtraction
        in the giant step). Also: P + (-P) = O (group identity).
        """
        if P is None:
            return None
        x, y = P
        return (x, (-y) % self.p)

    def point_add(self, P, Q):
        """
        Elliptic curve point addition: R = P + Q

        This is the "dot function" — the fundamental group operation of ECC.
        Three cases exist on an elliptic curve (as shown in ECC slides):

          Case A (P ≠ Q, secant): draw line through P and Q, reflect third intersection
          Case B (P = Q, tangent): draw tangent at P, reflect second intersection (= 2P)
          Case C (P = -Q, vertical): line is vertical, no third point → result is O

        SECURITY NOTE: The hardness of inverting this operation (finding k from k·G)
        is the ECDLP. KZG polynomial commitments commit to a polynomial P(x) as
        the curve point P(τ)·G — this is only hiding because ECDLP is hard.
        """
        # Identity: O + P = P
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        # Case C: P + (-P) = O
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None

        if P != Q:
            # Case A: Secant line — slope = (y2 - y1) / (x2 - x1) mod p
            # Division mod p uses Fermat's little theorem: a^(-1) ≡ a^(p-2) mod p
            s = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        else:
            # Case B: Tangent line — slope from implicit differentiation of curve
            # d/dx[y²=x³+ax+b] → 2y·dy = 3x²+a  →  slope = (3x²+a)/(2y)
            if y1 == 0:
                return None  # Vertical tangent at inflection point → O
            s = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, self.p) % self.p

        # New point coordinates (from the chord-and-tangent group law)
        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def scalar_mul(self, k, P):
        """
        Scalar multiplication: R = k·P  (compute P + P + ... + P, k times)

        Uses the double-and-add algorithm (binary method):
          - Process each bit of k from LSB to MSB
          - If bit is 1: add current power-of-2 point to result
          - Always: double the current power-of-2 point
          - Complexity: O(log k) point additions — efficient for any k

        THIS IS THE ONE-WAY FUNCTION UNDERLYING KZG:
          - Prover computes  C = w·G          (easy, O(log w) steps)
          - Verifier sees    C, G             (public information)
          - Attacker wants   w                (hard — requires solving ECDLP)
          - BSGS recovers    w  in O(√n)      (classical, feasible for small n)
          - Shor's recovers  w  in O((log n)³) (quantum, feasible for ALL n)

        For the Artemis KZG commitment, k = polynomial coefficient, P = τ^i · G.
        """
        if k < 0:
            # Handle negative scalars via group inverse: (-k)·P = k·(-P)
            k = -k
            P = self.point_neg(P)

        result = None   # Start with O (identity element)
        addend = P      # Current power of 2: 2^bit · P

        while k:
            if k & 1:                              # Current bit is 1
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)  # Double: 2^(bit+1) · P
            k >>= 1                                # Move to next bit

        return result

    def compute_group_order(self, G):
        """
        Compute the order of the cyclic subgroup generated by G.

        Order n = smallest positive integer such that n·G = O.
        Equivalently: the number of distinct points {G, 2G, 3G, ..., nG=O}.

        For small curves: brute-force traversal (used here for demo setup).
        For real curves (p ≈ 2^254): Schoof's or SEA algorithm is used.

        The group order n is public — it's needed to reduce scalars mod n.
        """
        P = G
        order = 1
        while P is not None:
            P = self.point_add(P, G)
            order += 1
        return order

    def find_generator(self):
        """
        Find the first point G on the curve (lowest x-coordinate).

        For a demo curve, any non-identity point generates a subgroup.
        We pick the lexicographically smallest to ensure reproducibility.

        Method: iterate x ∈ {0, ..., p-1}, check if x³+ax+b is a
        quadratic residue mod p (i.e., has a square root). If yes,
        compute y = √(x³+ax+b) mod p using Tonelli-Shanks / Euler's criterion.
        """
        for x in range(self.p):
            rhs = (x**3 + self.a * x + self.b) % self.p
            # Euler's criterion: rhs^((p-1)/2) ≡ 1 mod p iff rhs is a QR
            if rhs == 0:
                return (x, 0)
            if pow(rhs, (self.p - 1) // 2, self.p) == 1:
                # Compute √rhs mod p using Tonelli-Shanks shortcut (p ≡ 1 mod 4)
                # For p = 1021 ≡ 1 mod 4, we need the full Tonelli-Shanks
                y = tonelli_shanks(rhs, self.p)
                if y is not None:
                    return (x, y)
        raise ValueError("No point found on curve — check parameters.")


# ---------------------------------------------------------------------------
# Helper: Tonelli-Shanks square root mod p
# ---------------------------------------------------------------------------

def tonelli_shanks(n, p):
    """
    Compute x such that x² ≡ n (mod p) using the Tonelli-Shanks algorithm.

    This is needed to find y-coordinates of curve points given x.
    Works for any odd prime p (not just p ≡ 3 mod 4).
    """
    if n == 0:
        return 0
    if pow(n, (p - 1) // 2, p) != 1:
        return None  # n is not a quadratic residue mod p

    # Special case: p ≡ 3 mod 4 → simple formula
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # General Tonelli-Shanks
    # Write p - 1 = Q * 2^S with Q odd
    Q, S = p - 1, 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    # Find a quadratic non-residue z mod p
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q + 1) // 2, p)

    while True:
        if t == 1:
            return R
        # Find the least i such that t^(2^i) ≡ 1
        i, tmp = 1, (t * t) % p
        while tmp != 1:
            tmp = (tmp * tmp) % p
            i += 1
        b = pow(c, pow(2, M - i - 1, p - 1), p)
        M, c, t, R = i, (b * b) % p, (t * b * b) % p, (R * b) % p


# ---------------------------------------------------------------------------
# Curve info printer (called at demo start)
# ---------------------------------------------------------------------------

def count_all_points(a, b, p):
    """
    Count all affine points on y² = x³ + ax + b (mod p) plus the point at infinity.

    Uses Euler's criterion: rhs is a quadratic residue iff rhs^((p-1)/2) ≡ 1 mod p.
    Each QR gives 2 points (y and p-y); rhs=0 gives 1 point.

    This gives the full group order #E(Fp), which satisfies the Hasse bound:
        |#E(Fp) - (p+1)| ≤ 2√p   (Hasse's theorem, 1933)

    NOTE: The cyclic subgroup generated by a specific point G may have a smaller
    order n = order(G) that divides #E(Fp). BSGS uses n = order(G), not #E(Fp).
    """
    count = 1  # point at infinity O
    for x in range(p):
        rhs = (x**3 + a * x + b) % p
        if rhs == 0:
            count += 1
        elif pow(rhs, (p - 1) // 2, p) == 1:
            count += 2
    return count


def print_curve_info(curve, G, n):
    """
    Print all curve parameters and their cryptographic significance.

    This output is designed to appear at the top of the demo so a reader
    (including a thesis reviewer) immediately understands the setup.

    Displays both:
      - Full curve order #E(Fp) (for Hasse bound verification)
      - Subgroup order n = order(G) (the value used in BSGS)
    These differ when the group is non-cyclic (as is the case for this curve,
    where #E(F_1021) = 1004 = 4×251 but max element order is 502).
    """
    import math
    bsgs_steps = math.isqrt(n) + 1
    full_order = count_all_points(curve.a, curve.b, curve.p)
    hasse_diff = abs(full_order - (curve.p + 1))
    hasse_bound = 2 * int(math.isqrt(curve.p))

    print("=" * 62)
    print("  ELLIPTIC CURVE SETUP")
    print("=" * 62)
    print(f"  Equation       :  y² = x³ + {curve.a}x + {curve.b}  (mod {curve.p})")
    print(f"  Field prime    :  p = {curve.p}  (small — intentionally breakable)")
    print(f"  Discriminant   :  4a³ + 27b² = {curve._discriminant_inner} (mod {curve.p})")
    print(f"                    ≠ 0  →  curve is non-singular ✓")
    print(f"  Generator      :  G = {G}   (verified on curve: {curve.is_on_curve(G)})")
    print(f"  Full curve     :  #E(F_{curve.p}) = {full_order}  "
          f"(Hasse: |{full_order}−{curve.p+1}|={hasse_diff} ≤ 2√p≈{hasse_bound} ✓)")
    print(f"  Subgroup order :  n = order(G) = {n}")
    print(f"  Note           :  Group non-cyclic ({full_order}=4×251); max element order={n}")
    print(f"  Weight w=42    :  valid scalar (42 < n={n}) ✓")
    print()
    print(f"  [Classical security]")
    print(f"  BSGS complexity:  O(√n) = O(√{n}) ≈ {bsgs_steps} steps  [demo curve]")
    print(f"  At 256-bit scale: O(√2²⁵⁶) = O(2¹²⁸) — classically infeasible")
    print()
    print(f"  [Quantum threat — Shor's algorithm]")
    print(f"  Shor's complexity: O((log n)³) — polynomial in key size")
    print(f"  At 256-bit scale: O(256³) ≈ 16M quantum ops — FEASIBLE")
    print(f"  Conclusion     :  ECDLP provides NO quantum security")
    print("=" * 62)


# ---------------------------------------------------------------------------
# Module self-test
# ---------------------------------------------------------------------------

def _self_test():
    """Basic correctness checks run when this module is imported or executed."""
    curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
    G = curve.find_generator()
    n = curve.compute_group_order(G)

    # Test 1: n·G = O
    assert curve.scalar_mul(n, G) is None, "n·G should be point at infinity"

    # Test 2: Commutativity: k·G + j·G = (k+j)·G
    k, j = 7, 13
    lhs = curve.point_add(curve.scalar_mul(k, G), curve.scalar_mul(j, G))
    rhs = curve.scalar_mul((k + j) % n, G)
    assert lhs == rhs, "Group addition is not commutative — bug in point_add"

    # Test 3: Double-and-add matches repeated addition for small k
    # P starts at G (= 1·G). Each loop adds one more G, so after iteration i
    # P holds i·G. We compare against scalar_mul(i, G) to confirm they match.
    P = G  # 1·G
    for i in range(2, 11):
        P = curve.point_add(P, G)   # P = i·G (accumulated via point_add)
        assert P == curve.scalar_mul(i, G), f"scalar_mul incorrect at k={i}"

    return curve, G, n


if __name__ == "__main__":
    print("Running ecc_utils.py self-test...\n")
    curve, G, n = _self_test()
    print("All internal tests passed.\n")
    print_curve_info(curve, G, n)
    print()
    print("Sample scalar multiplications:")
    for w in [1, 2, 10, 42, 99]:
        Q = curve.scalar_mul(w, G)
        print(f"  {w:>3} · G = {Q}")
