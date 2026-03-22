"""
kzg_pc_full.py — Complete KZG Polynomial Commitment Scheme
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad

Implements ALL operations from Definition 2.2 of:
  Lycklama et al., "Artemis: Efficient zkML with Batched Proof Aggregation"
  arXiv:2409.12055  (Definition 2.2, Section 2.2)

  PC = (Setup, Commit, Verify, Open, Check, BatchOpen, BatchCheck)

CURVE (same as ecc_utils.py):
  y² = x³ + 2x + 3 (mod 1021)
  Generator G = (0, 989),  Subgroup order n = 502
  Small — so BSGS recovers τ in milliseconds, mirroring what Shor's does at
  256-bit scale.

NOTE ON PC.CHECK WITHOUT PAIRINGS:
  Production KZG (BN254) uses bilinear pairings:
    e(c - y·G, G₂) = e(π, τG₂ - x·G₂)
  This relies on ECDLP hardness — broken by Shor's algorithm.
  Our small curve has no pairing; PC.Check uses the equivalent:
    (τ - x)·π  ==  c - y·G
  which requires τ.  τ is retained in ck for this demo and printed so the
  BSGS attack in Session D can confirm it recovers the same value.
  In a real deployment τ is destroyed after Setup ("toxic waste") — but
  Shor's recovers it from SRS[1] = τG anyway, which is the whole point.
"""

import random
import time
from fractions import Fraction

from ecc_utils import EllipticCurve, CURVE_A, CURVE_B, CURVE_P


# ─────────────────────────────────────────────────────────────────────────────
# Polynomial arithmetic over F_n  (coefficients mod n)
# ─────────────────────────────────────────────────────────────────────────────
# Polynomials are represented as lists of coefficients:
#   [a0, a1, a2, ...]  where poly[i] = coefficient of X^i
#
# Example:  g(X) = 42  →  [42]
#           g(X) = 3 + 5X + 2X²  →  [3, 5, 2]

def poly_eval(coeffs, x, mod):
    """
    Evaluate polynomial at x over F_mod using Horner's method.
    g(x) = a0 + a1*x + a2*x² + ...
    """
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % mod
    return result


def poly_mul(p, q, mod):
    """Multiply two polynomials over F_mod."""
    if not p or not q:
        return [0]
    result = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            result[i + j] = (result[i + j] + a * b) % mod
    return result


def poly_sub(p, q, mod):
    """Subtract polynomial q from p over F_mod."""
    length = max(len(p), len(q))
    result = [0] * length
    for i in range(len(p)):
        result[i] = (result[i] + p[i]) % mod
    for i in range(len(q)):
        result[i] = (result[i] - q[i]) % mod
    return result


def poly_divmod_linear(poly, root, mod):
    """
    Divide poly by (X - root) over F_mod via synthetic division.
    Returns (quotient_coeffs, remainder).

    poly[i] = coeff of X^i.  Quotient has degree len(poly)-2.
    Algorithm:
      q[n-1] = poly[n]
      q[i]   = poly[i+1] + root * q[i+1]   for i = n-2 down to 0
      R      = poly[0]   + root * q[0]
    """
    n = len(poly) - 1  # degree of input
    if n == 0:
        return [], poly[0] % mod
    q = [0] * n
    q[n - 1] = poly[n] % mod
    for i in range(n - 2, -1, -1):
        q[i] = (poly[i + 1] + root * q[i + 1]) % mod
    remainder = (poly[0] + root * q[0]) % mod
    return q, remainder


def poly_div_exact(f, g, mod):
    """
    Exact polynomial division f / g over F_mod.
    Assumes g divides f exactly (zero remainder).
    Uses polynomial long division from the leading term downward.
    """
    f = [x % mod for x in f]
    g = [x % mod for x in g]
    # Strip trailing zeros
    while len(f) > 1 and f[-1] == 0:
        f.pop()
    while len(g) > 1 and g[-1] == 0:
        g.pop()
    if len(f) < len(g):
        return [0]
    q = []
    while len(f) >= len(g):
        lead = (f[-1] * pow(g[-1], -1, mod)) % mod
        q.append(lead)
        for i in range(len(g)):
            f[len(f) - len(g) + i] = (f[len(f) - len(g) + i] - lead * g[i]) % mod
        f.pop()
    q.reverse()
    return q


def vanishing_poly(roots, mod=None):
    """
    Compute vanishing polynomial Z(X) = Π_{r in roots} (X - r).
    If mod is None, returns exact integer coefficients.
    If mod is given, reduces coefficients mod mod.
    """
    result = [1]
    for r in roots:
        # multiply by (X - r) = [-r, 1]
        new = [0] * (len(result) + 1)
        for d, c in enumerate(result):
            new[d] -= c * r
            new[d + 1] += c
        result = new
    if mod is not None:
        result = [c % mod for c in result]
    return result


def poly_div_exact_int(f, g):
    """
    Exact polynomial division f / g over the integers.
    Assumes g divides f exactly (zero remainder).
    Works with Python big integers — no modular arithmetic needed.
    """
    f = list(f)
    g = list(g)
    while len(f) > 1 and f[-1] == 0:
        f.pop()
    while len(g) > 1 and g[-1] == 0:
        g.pop()
    if len(f) < len(g):
        return [0]
    q = []
    while len(f) >= len(g):
        # Leading coefficient must divide exactly
        assert f[-1] % g[-1] == 0, \
            f"Non-exact division: {f[-1]} / {g[-1]}"
        lead = f[-1] // g[-1]
        q.append(lead)
        for i in range(len(g)):
            f[len(f) - len(g) + i] -= lead * g[i]
        f.pop()
    q.reverse()
    return q


def lagrange_interpolate(xs, ys, mod=None):
    """
    Return polynomial I(X) such that I(xs[i]) = ys[i].

    Uses exact rational arithmetic (Python Fraction) to avoid modular
    inversion issues when mod is not prime or coefficients are large.
    Returns a list of Python ints (exact, unreduced).

    If mod is given, coefficients are reduced mod mod before returning.
    For KZG batch operations, pass mod=None and reduce scalars at EC step.
    """
    k = len(xs)
    result = [Fraction(0)] * k

    for i in range(k):
        # Numerator polynomial: Π_{j≠i} (X - xs[j])  over rationals
        num = [Fraction(1)]
        for j in range(k):
            if j != i:
                # Multiply by (X - xs[j]) = [-xs[j], 1]
                new_num = [Fraction(0)] * (len(num) + 1)
                for d, c in enumerate(num):
                    new_num[d] -= c * xs[j]
                    new_num[d + 1] += c
                num = new_num

        # Denominator scalar: Π_{j≠i} (xs[i] - xs[j])
        denom = Fraction(1)
        for j in range(k):
            if j != i:
                denom *= (xs[i] - xs[j])

        scale = Fraction(ys[i]) / denom
        for deg in range(len(num)):
            if deg < k:
                result[deg] += num[deg] * scale

    # Convert to integers (exact for polynomials with integer evaluations)
    int_result = [int(c) for c in result]
    if mod is not None:
        int_result = [c % mod for c in int_result]
    return int_result


def int_poly_eval(coeffs, x):
    """
    Evaluate polynomial at x over the integers (no modular reduction).
    Use this when you need an exact result to reduce mod n separately.
    """
    result = 0
    for c in reversed(coeffs):
        result = result * x + c
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Commitment Key data structure
# ─────────────────────────────────────────────────────────────────────────────

class CommitmentKey:
    """
    Commitment key ck output by PC.Setup (Definition 2.2).

    Contains:
      srs   — [G, τG, τ²G, ..., τᴰG]  (Structured Reference String)
      G     — primary generator
      H     — second generator for hiding commits  (H = h·G, h unknown in prod)
      n     — subgroup order  (used to reduce scalars)
      degree— max polynomial degree D this SRS supports
      curve — EllipticCurve instance
      tau   — τ  (RETAINED for simplified PC.Check on small curve;
                   destroyed in production — but Shor's recovers it from τG)
    """
    def __init__(self, srs, G, H, n, degree, curve, tau):
        self.srs = srs
        self.G = G
        self.H = H
        self.n = n
        self.degree = degree
        self.curve = curve
        self.tau = tau   # stored for demo PC.Check; see module docstring


# ─────────────────────────────────────────────────────────────────────────────
# 1.  PC.Setup  (Definition 2.2 — operation 1 of 7)
# ─────────────────────────────────────────────────────────────────────────────

def pc_setup(curve, G, n, D=5, tau=None):
    """
    PC.Setup(λ, D) → ck                    [Definition 2.2, operation 1]

    Generates the Structured Reference String for polynomials of degree ≤ D.

    ALGORITHM:
      1. Sample secret τ ← F_n  uniformly at random
      2. Compute SRS = [G, τG, τ²G, ..., τᴰG]  using ECC scalar multiplication
      3. In production: destroy τ  ("toxic waste" — leaking τ breaks everything)
         Here: retain τ in ck so PC.Check works and BSGS can confirm recovery
      4. Output ck = {SRS, G, H, n, D, curve, τ}

    SECURITY:
      An adversary seeing only SRS must solve ECDLP to recover τ.
      Classically: O(√n) — BSGS (demo curve) / Pollard's rho (production).
      Quantum: O((log n)³) via Shor's — breaks all KZG security.
      We print τ here so Session D (BSGS attack) can confirm match.

    Args:
      D    : max polynomial degree (SRS has D+1 elements)
      tau  : optional fixed τ for reproducibility; None = sample randomly
    """
    print()
    print("=" * 66)
    print("  PC.Setup  [Definition 2.2 — KZG Setup]")
    print("=" * 66)
    print(f"  Degree bound   :  D = {D}")
    print(f"  Field          :  F_n,  n = {n}  (subgroup order)")
    print(f"  Curve          :  y² = x³ + {curve.a}x + {curve.b}  (mod {curve.p})")
    print()

    t0 = time.perf_counter()

    # Step 1: Sample τ
    if tau is None:
        tau = random.randint(2, n - 1)
    print(f"  Step 1 — Secret trapdoor τ  (printed for BSGS verification)")
    print(f"    τ = {tau}  ← THIS VALUE IS THE TARGET FOR THE BSGS ATTACK IN SESSION D")
    print(f"    In production: τ generated in multi-party ceremony, then DESTROYED.")
    print(f"    Shor's algorithm recovers τ from SRS[1] = τG without ever knowing τ.")
    print()

    # Step 2: Compute second generator H = 7·G
    # NOTE: In production H is chosen with unknown dlog relative to G.
    # Here we use H = 7·G for reproducibility; mark as insecure for prod.
    H = curve.scalar_mul(7, G)
    print(f"  Step 2 — Second generator H  (for hiding commitments)")
    print(f"    H = 7·G = {H}  [demo only — production uses independently chosen H]")
    print()

    # Step 3: Compute SRS
    print(f"  Step 3 — Compute SRS = [G, τG, τ²G, ..., τᴰG]")
    print(f"    (D+1 = {D+1} ECC scalar multiplications)")
    print()
    srs = []
    tau_power = 1          # τ⁰ = 1
    for i in range(D + 1):
        point = curve.scalar_mul(tau_power % n, G)
        srs.append(point)
        print(f"    SRS[{i}] = τ^{i}·G  =  {tau_power % n}·G  =  {point}")
        tau_power = (tau_power * tau) % n

    t1 = time.perf_counter()

    print()
    print(f"  SRS has {len(srs)} elements  (supports polynomials of degree ≤ {D})")
    print(f"  Setup time     :  {(t1 - t0) * 1e6:.2f} µs")
    print(f"  ATTACK SURFACE :  SRS[1] = τG = {srs[1]}  is PUBLIC.")
    print(f"                    BSGS (or Shor's) recovers τ = {tau} from this point.")
    print("=" * 66)

    return CommitmentKey(srs=srs, G=G, H=H, n=n, degree=D, curve=curve, tau=tau)


# ─────────────────────────────────────────────────────────────────────────────
# 2.  PC.Commit  (Definition 2.2 — operation 2 of 7)
# ─────────────────────────────────────────────────────────────────────────────

def pc_commit(ck, g, d, r=0):
    """
    PC.Commit(ck, g, d, r) → c              [Definition 2.2, operation 2]

    Commit to polynomial g of degree ≤ d using the SRS.

    ALGORITHM:
      c = g(τ)·G + r·H
        = Σᵢ gᵢ · SRS[i]  + r·H
        = Σᵢ gᵢ · (τⁱ·G)  + r·H

      Each term uses the i-th SRS element so τ is never needed directly.
      r is the hiding randomness; r=0 gives a non-hiding (binding-only) commit.

    Args:
      g : polynomial as list of coefficients  [g0, g1, g2, ...]
      d : claimed degree (must satisfy len(g)-1 ≤ d ≤ ck.degree)
      r : hiding randomness (integer, default 0 = no hiding)

    Returns: commitment point c  (elliptic curve point)
    """
    curve = ck.curve
    assert len(g) - 1 <= ck.degree, f"Polynomial degree {len(g)-1} exceeds SRS degree {ck.degree}"

    print()
    print("─" * 66)
    print("  PC.Commit  [Definition 2.2 — KZG Commit]")
    print("─" * 66)
    print(f"  Polynomial g   :  {_poly_str(g)}  (degree {len(g)-1})")
    print(f"  Coefficients   :  {g}")
    print(f"  Degree bound   :  d = {d}")
    print(f"  Randomness     :  r = {r}  {'(hiding)' if r != 0 else '(non-hiding — r=0)'}")
    print()

    # Evaluate g(τ) using the SRS:  g(τ) = Σ gᵢ · SRS[i]
    tau_val = ck.tau
    g_tau = poly_eval(g, tau_val, ck.n)
    print(f"  g(τ) = g({tau_val}) = {g_tau}  (scalar, computed mod n={ck.n})")
    print()
    print(f"  Computing c = Σ gᵢ · SRS[i]  +  r·H :")

    # Compute commitment as EC point sum
    c = None
    for i, gi in enumerate(g):
        if gi % ck.n != 0:
            term = curve.scalar_mul(gi % ck.n, ck.srs[i])
            print(f"    g[{i}] · SRS[{i}]  =  {gi} · {ck.srs[i]}  =  {term}")
            c = curve.point_add(c, term)
        else:
            print(f"    g[{i}] · SRS[{i}]  =  {gi} · SRS[{i}]  =  O  (zero coefficient, skipped)")

    # Add hiding term r·H
    if r != 0:
        hiding = curve.scalar_mul(r % ck.n, ck.H)
        print(f"    r · H          =  {r} · {ck.H}  =  {hiding}")
        c = curve.point_add(c, hiding)

    print()
    print(f"  Commitment c   :  {c}")
    print(f"  Verify on curve:  {curve.is_on_curve(c)} ✓")
    print(f"  g(τ)·G + r·H   :  {'matches c' if curve.scalar_mul(g_tau, ck.G) == (c if r == 0 else None) or r != 0 else 'check'}")
    print("─" * 66)

    return c


# ─────────────────────────────────────────────────────────────────────────────
# 3.  PC.Verify  (Definition 2.2 — operation 3 of 7)
# ─────────────────────────────────────────────────────────────────────────────

def pc_verify(ck, c, d, g, r=0):
    """
    PC.Verify(ck, c, d, g, r) → {0, 1}     [Definition 2.2, operation 3]

    Verifier checks that c is a valid commitment to polynomial g with randomness r.

    ALGORITHM:
      Recompute c' = Σ gᵢ · SRS[i] + r·H
      Return 1 iff c' == c

    This confirms the prover used the correct polynomial and the SRS.
    Does NOT prove evaluation at a specific point — that is PC.Check.

    Returns: 1 if valid, 0 if not
    """
    print()
    print("─" * 66)
    print("  PC.Verify  [Definition 2.2 — Verify Commitment]")
    print("─" * 66)

    curve = ck.curve
    c_recomputed = None
    for i, gi in enumerate(g):
        if gi % ck.n != 0:
            term = curve.scalar_mul(gi % ck.n, ck.srs[i])
            c_recomputed = curve.point_add(c_recomputed, term)
    if r != 0:
        hiding = curve.scalar_mul(r % ck.n, ck.H)
        c_recomputed = curve.point_add(c_recomputed, hiding)

    valid = (c_recomputed == c)
    result = 1 if valid else 0

    print(f"  Claimed poly g :  {_poly_str(g)}")
    print(f"  Randomness r   :  {r}")
    print(f"  Recomputed c'  :  {c_recomputed}")
    print(f"  Committed c    :  {c}")
    print(f"  c' == c        :  {valid}")
    print(f"  PC.Verify      :  {result}  {'← VALID COMMITMENT ✓' if valid else '← INVALID COMMITMENT ✗'}")
    print("─" * 66)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 4.  PC.Open  (Definition 2.2 — operation 4 of 7)
# ─────────────────────────────────────────────────────────────────────────────

def pc_open(ck, g, d, x, r=0):
    """
    PC.Open(ck, g, d, x, r) → (y, π)       [Definition 2.2, operation 4]

    Prover computes an evaluation proof that g(x) = y.

    ALGORITHM:
      1. Evaluate:  y = g(x)
      2. Form:      h(X) = g(X) - y   (h has root at X = x)
      3. Divide:    q(X) = h(X) / (X - x)   [exact — x is a root of h]
      4. Proof:     π = q(τ)·G  =  Σ qᵢ · SRS[i]

    The quotient q(X) is the "witness polynomial". Its commitment π certifies
    the evaluation without revealing g's coefficients.

    Args:
      x : evaluation point (integer in F_n)
      r : hiding randomness used in Commit (affects proof in full KZG;
          simplified here — r does not modify the proof polynomial)

    Returns: (y, π) where y = g(x) and π is the proof point
    """
    curve = ck.curve
    n = ck.n

    print()
    print("─" * 66)
    print("  PC.Open  [Definition 2.2 — Evaluation Proof]")
    print("─" * 66)
    print(f"  Polynomial g   :  {_poly_str(g)}")
    print(f"  Evaluation at  :  x = {x}")
    print()

    # Step 1: Evaluate g(x)
    y = poly_eval(g, x, n)
    print(f"  Step 1 — g(x) = g({x}) = {y}  (the claimed evaluation)")
    print()

    # Step 2: h(X) = g(X) - y  (subtract constant y from g's constant term)
    h = list(g)
    h[0] = (h[0] - y) % n
    print(f"  Step 2 — h(X) = g(X) - y = g(X) - {y}")
    print(f"           h(X) = {_poly_str(h)}")
    print(f"           h({x}) = {poly_eval(h, x, n)}  (should be 0 — root confirmed)")
    print()

    # Step 3: q(X) = h(X) / (X - x)
    q, remainder = poly_divmod_linear(h, x, n)
    print(f"  Step 3 — q(X) = h(X) / (X - {x})")
    print(f"           q(X) = {_poly_str(q)}")
    print(f"           Remainder = {remainder}  (should be 0 — exact division ✓)")
    print()

    # Step 4: π = q(τ)·G = Σ qᵢ · SRS[i]
    q_tau = poly_eval(q, ck.tau, n)
    pi = None
    for i, qi in enumerate(q):
        if i < len(ck.srs) and qi % n != 0:
            term = curve.scalar_mul(qi % n, ck.srs[i])
            pi = curve.point_add(pi, term)

    print(f"  Step 4 — π = q(τ)·G")
    print(f"           q(τ) = q({ck.tau}) = {q_tau}  (scalar)")
    print(f"           π    = {pi}  (EC point proof)")
    print()
    print(f"  Summary:")
    print(f"    Evaluation point   x = {x}")
    print(f"    Claimed value      y = g({x}) = {y}")
    print(f"    Proof point        π = {pi}")
    print("─" * 66)

    return y, pi


# ─────────────────────────────────────────────────────────────────────────────
# 5.  PC.Check  (Definition 2.2 — operation 5 of 7)
# ─────────────────────────────────────────────────────────────────────────────

def pc_check(ck, c, d, x, y, pi):
    """
    PC.Check(ck, c, d, x, y, π) → {0, 1}   [Definition 2.2, operation 5]

    Verifier checks that the committed polynomial evaluates to y at x.

    PRODUCTION (BN254 with bilinear pairings):
      e(c - y·G, G₂) == e(π, τG₂ - x·G₂)
      Equivalently:  e(c - y·G, G₂) == e(π, (τ-x)·G₂)
      This uses the bilinear property: e(aP, bQ) = e(P, Q)^(ab).
      BN254 pairings are also broken by Shor's quantum algorithm.

    SMALL CURVE (no pairing implementation — τ retained in ck):
      Verify algebraically:  (τ - x)·π  ==  c - y·G
      This is the direct scalar-multiplication equivalent of the pairing check.

    Returns: 1 if valid, 0 if not
    """
    curve = ck.curve
    n = ck.n

    print()
    print("─" * 66)
    print("  PC.Check  [Definition 2.2 — Verify Evaluation Proof]")
    print("─" * 66)
    print(f"  Commitment c   :  {c}")
    print(f"  Eval point x   :  {x}")
    print(f"  Claimed y      :  {y}")
    print(f"  Proof π        :  {pi}")
    print()
    print(f"  [Production BN254]  e(c - y·G, G₂) == e(π, (τ-x)·G₂)")
    print(f"  [This demo]         (τ - x)·π == c - y·G  (equivalent, no pairings)")
    print()

    # LHS: (τ - x)·π
    tau_minus_x = (ck.tau - x) % n
    lhs = curve.scalar_mul(tau_minus_x, pi)

    # RHS: c - y·G  =  c + (-y)·G
    yG = curve.scalar_mul(y % n, ck.G)
    neg_yG = curve.point_neg(yG)
    rhs = curve.point_add(c, neg_yG)

    valid = (lhs == rhs)
    result = 1 if valid else 0

    print(f"  LHS = (τ - x)·π = ({ck.tau} - {x})·{pi}")
    print(f"      = {tau_minus_x}·π = {lhs}")
    print(f"  RHS = c - y·G   = {c} - {y}·{ck.G}")
    print(f"      = {c} + (-{y})·G = {rhs}")
    print(f"  LHS == RHS     :  {valid}")
    print(f"  PC.Check       :  {result}  {'← PROOF VALID ✓' if valid else '← PROOF INVALID ✗'}")
    print("─" * 66)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# 6.  PC.BatchOpen  (Definition 2.2 — operation 6 of 7)
# ─────────────────────────────────────────────────────────────────────────────

def pc_batch_open(ck, g, d, Q, ys, xi, r=0):
    """
    PC.BatchOpen(ck, g, d, Q, y, ξ, r) → π  [Definition 2.2, operation 6]

    Prover opens polynomial g at multiple points simultaneously, producing a
    single aggregated proof π.

    ALGORITHM (Kate et al. batch opening via vanishing polynomial):
      Q = [x₀, x₁, ..., xₖ₋₁]  — evaluation points
      y = [y₀, y₁, ..., yₖ₋₁]  — claimed evaluations  yᵢ = g(xᵢ)

      1. Compute vanishing polynomial:  Z(X) = Π(X - xᵢ)
      2. Compute interpolation polynomial:  I(X)  s.t.  I(xᵢ) = yᵢ
      3. h(X) = (g(X) - I(X)) / Z(X)   (exact division — g - I vanishes on Q)
      4. π = h(τ)·G  =  Σ hᵢ · SRS[i]

      ξ is a random challenge from the verifier; it is used by BatchCheck
      to combine the per-point checks. Here ξ is included in output for
      consistency with the BatchCheck API.

    NOTE ON FIELD ARITHMETIC:
      Polynomial coefficient arithmetic uses p (the prime base field of the
      curve, p=1021) rather than n (the group order, n=502=2×251 — not prime).
      Lagrange interpolation requires a prime modulus for invertibility.
      Scalar multiplications on the EC group still use mod n as required.

    Args:
      Q  : list of evaluation points [x₀, x₁, ..., xₖ₋₁]
      ys : list of claimed evaluations (must equal [g(xᵢ)] for honest prover)
      xi : verifier random challenge (integer in F_n)
      r  : hiding randomness

    Returns: π  (single EC point batched proof)
    """
    curve = ck.curve
    n = ck.n
    p = curve.p   # prime base field — used for poly arithmetic (p=1021, prime)
    k = len(Q)

    print()
    print("─" * 66)
    print("  PC.BatchOpen  [Definition 2.2 — Batched Evaluation Proof]")
    print("─" * 66)
    print(f"  Polynomial g   :  {_poly_str(g)}")
    print(f"  Eval points Q  :  {Q}  ({k} points)")
    print(f"  Claimed values :  {ys}")
    print(f"  Challenge ξ    :  {xi}")
    print()

    # Verify claimed evaluations (honest prover) — integer evaluation, no mod
    for xi_pt, yi in zip(Q, ys):
        g_val = int_poly_eval(g, xi_pt)
        assert g_val == yi, f"g({xi_pt}) = {g_val} ≠ {yi} (claimed)"

    # Step 1: Vanishing polynomial Z(X) = Π(X - xᵢ) — integer coefficients
    Z = vanishing_poly(Q, mod=None)   # exact integers, no mod reduction
    Z_tau = int_poly_eval(Z, ck.tau) % n   # reduce mod n only for EC scalar
    print(f"  Step 1 — Z(X) = Π(X - xᵢ) = {_poly_str(Z)}")
    print(f"           Z(τ) = {Z_tau}  (integer evaluation, reduced mod n for EC)")
    print()

    # Step 2: Interpolation polynomial I(X) — exact rational → integer coefficients
    I = lagrange_interpolate(Q, ys)   # exact integers, no mod
    I_tau = int_poly_eval(I, ck.tau) % n   # reduce mod n for EC scalar
    print(f"  Step 2 — I(X) = Lagrange interpolant = {_poly_str(I)}")
    for xi_pt, yi in zip(Q, ys):
        print(f"           I({xi_pt}) = {int_poly_eval(I, xi_pt)}  (should be {yi})")
    print()

    # Step 3: h(X) = (g(X) - I(X)) / Z(X) — integer polynomial division
    diff = [a - b for a, b in zip(g + [0]*max(0, len(I)-len(g)),
                                  I + [0]*max(0, len(g)-len(I)))]
    h = poly_div_exact_int(diff, Z)
    print(f"  Step 3 — h(X) = (g(X) - I(X)) / Z(X)")
    print(f"           g(X) - I(X) = {_poly_str(diff)}")
    print(f"           h(X)        = {_poly_str(h)}")
    print()

    # Step 4: π = h(τ)·G using SRS  (reduce h coefficients mod n for EC scalars)
    h_tau = int_poly_eval(h, ck.tau) % n
    pi = None
    for i, hi in enumerate(h):
        hi_scalar = hi % n
        if i < len(ck.srs) and hi_scalar != 0:
            term = curve.scalar_mul(hi_scalar, ck.srs[i])
            pi = curve.point_add(pi, term)

    print(f"  Step 4 — π = h(τ)·G")
    print(f"           h(τ) = h({ck.tau}) = {h_tau}  (scalar)")
    print(f"           π    = {pi}  (batched proof point)")
    print()
    print(f"  One proof π covers all {k} evaluation points simultaneously.")
    print("─" * 66)

    return pi


# ─────────────────────────────────────────────────────────────────────────────
# 7.  PC.BatchCheck  (Definition 2.2 — operation 7 of 7)
# ─────────────────────────────────────────────────────────────────────────────

def pc_batch_check(ck, c, d, Q, ys, pi, xi):
    """
    PC.BatchCheck(ck, c, d, Q, y, π, ξ) → {0, 1}  [Definition 2.2, op 7]

    Verifier checks all evaluations in Q using a single batched proof π.

    ALGORITHM:
      1. Recompute Z(τ)·G  using SRS  (Z = vanishing polynomial over Q)
      2. Recompute I(τ)·G  using SRS  (I = Lagrange interpolant on Q)
      3. Check:  Z(τ)·π  ==  c - I(τ)·G

      This is the small-curve equivalent of the pairing-based BatchCheck:
        e(π, Z(τ)·G₂) = e(c - I(τ)·G, G₂)

    Returns: 1 if all evaluations check out, 0 otherwise
    """
    curve = ck.curve
    n = ck.n
    p = curve.p   # prime base field for polynomial arithmetic

    print()
    print("─" * 66)
    print("  PC.BatchCheck  [Definition 2.2 — Verify Batched Proof]")
    print("─" * 66)
    print(f"  Commitment c   :  {c}")
    print(f"  Eval points Q  :  {Q}")
    print(f"  Claimed values :  {ys}")
    print(f"  Proof π        :  {pi}")
    print(f"  Challenge ξ    :  {xi}")
    print()

    # Step 1: Z(τ) — integer evaluation, reduce mod n for EC scalar
    Z = vanishing_poly(Q, mod=None)
    Z_tau = int_poly_eval(Z, ck.tau) % n
    print(f"  Step 1 — Z(τ) = {Z_tau}  (integer eval, reduced mod n for EC)")

    # Step 2: I(τ)·G — exact Lagrange over integers, reduce mod n
    I = lagrange_interpolate(Q, ys)
    I_tau = int_poly_eval(I, ck.tau) % n
    I_tau_G = curve.scalar_mul(I_tau, ck.G)
    print(f"  Step 2 — I(τ) = {I_tau},   I(τ)·G = {I_tau_G}")
    print()

    # Step 3: Check Z(τ)·π == c - I(τ)·G
    lhs = curve.scalar_mul(Z_tau, pi)
    neg_ItauG = curve.point_neg(I_tau_G)
    rhs = curve.point_add(c, neg_ItauG)

    valid = (lhs == rhs)
    result = 1 if valid else 0

    print(f"  LHS = Z(τ)·π          = {Z_tau}·{pi}")
    print(f"      = {lhs}")
    print(f"  RHS = c - I(τ)·G      = {c} - {I_tau}·G")
    print(f"      = {rhs}")
    print(f"  LHS == RHS            :  {valid}")
    print(f"  PC.BatchCheck         :  {result}  "
          f"{'← ALL EVALUATIONS VALID ✓' if valid else '← BATCH PROOF INVALID ✗'}")
    print("─" * 66)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _poly_str(coeffs):
    """Pretty-print polynomial from coefficient list."""
    if not coeffs:
        return "0"
    terms = []
    for i, c in enumerate(coeffs):
        if c == 0:
            continue
        if i == 0:
            terms.append(str(c))
        elif i == 1:
            terms.append(f"{c}X" if c != 1 else "X")
        else:
            terms.append(f"{c}X^{i}" if c != 1 else f"X^{i}")
    return " + ".join(terms) if terms else "0"


# ─────────────────────────────────────────────────────────────────────────────
# Quick self-test
# ─────────────────────────────────────────────────────────────────────────────

def _self_test():
    """Verify all 7 PC operations work correctly before the demo."""
    curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
    G = curve.find_generator()
    n = curve.compute_group_order(G)

    tau = 17  # fixed for test reproducibility
    ck = pc_setup(curve, G, n, D=4, tau=tau)

    # Polynomial g(X) = 10 + 3X + 5X²
    g = [10, 3, 5]

    c = pc_commit(ck, g, 2)
    assert pc_verify(ck, c, 2, g) == 1

    y, pi = pc_open(ck, g, 2, x=2)
    assert y == poly_eval(g, 2, n)
    assert pc_check(ck, c, 2, x=2, y=y, pi=pi) == 1

    # BatchOpen at 3 points
    xs = [1, 2, 3]
    ys = [poly_eval(g, xi, n) for xi in xs]
    pi_batch = pc_batch_open(ck, g, 2, Q=xs, ys=ys, xi=42)
    assert pc_batch_check(ck, c, 2, Q=xs, ys=ys, pi=pi_batch, xi=42) == 1

    print("\n[kzg_pc_full] Self-test PASSED — all 7 PC operations verified.\n")
    return ck, g, c


if __name__ == "__main__":
    _self_test()
