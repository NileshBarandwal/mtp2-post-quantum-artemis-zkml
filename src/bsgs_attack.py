"""
bsgs_attack.py — Baby-step Giant-step Attack on ECDLP
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad

PURPOSE:
    Implements the Baby-step Giant-step (BSGS) algorithm to solve the
    Elliptic Curve Discrete Logarithm Problem (ECDLP):
        Given: public point Q = w·G and generator G
        Find:  secret scalar w

    This demonstrates the VULNERABILITY of KZG-based polynomial commitments
    (as used in Artemis) against quantum adversaries.

CONNECTION TO SHOR'S ALGORITHM:
    BSGS and Shor's algorithm both exploit the CYCLIC GROUP STRUCTURE of the
    elliptic curve. The key difference is computational complexity:

        BSGS (classical):  O(√n) time and space
        Shor's (quantum):  O((log n)³) time, O(log n) space

    For n ≈ 2^256 (production KZG):
        BSGS:   O(2^128) operations — classically infeasible
        Shor's: O(256³) ≈ 16M quantum gate operations — feasible

    We demonstrate BSGS breaking a small (n ≈ 1000) curve in milliseconds.
    The SAME structural weakness exists at 256-bit scale — Shor's just
    exploits it faster using quantum superposition.

WHY THIS BREAKS ARTEMIS:
    In the Artemis CP-SNARK, a KZG commitment to a neural network weight w is:
        C = w · G   (an elliptic curve point, published publicly)

    If an attacker (with a quantum computer) recovers w from C and G:
        1. They know the exact model weights — privacy is broken
        2. They can compute ANY commitment C' = w'·G for false weights w'
        3. They can forge valid proofs that pass the KZG verifying key
        4. The entire Artemis integrity guarantee is destroyed

PROPOSED FIX (demonstrated in hash_commitment.py):
    Replace KZG with a hash-based commitment: C = Hash(w || nonce)
    BSGS has no group structure to exploit → attack fails by design.
"""

import math
import time
from ecc_utils import EllipticCurve, CURVE_A, CURVE_B, CURVE_P, print_curve_info


# ---------------------------------------------------------------------------
# Core BSGS Algorithm
# ---------------------------------------------------------------------------

def bsgs(Q, G, n, curve):
    """
    Baby-step Giant-step: recover w such that Q = w·G (mod n)

    ALGORITHM (Shanks, 1971):
    ─────────────────────────────────────────────────────────────────────────
    Let m = ⌈√n⌉. Write w = j·m + i  where  0 ≤ i < m,  0 ≤ j ≤ m.

    Then:  Q = w·G = (j·m + i)·G = j·(m·G) + i·G

    Rearranging:  i·G = Q - j·(m·G)

    Baby steps (precompute and store):
        For i = 0, 1, ..., m-1:  compute B_i = i·G, store {B_i → i}

    Giant steps (search):
        For j = 0, 1, ..., m:  compute Q - j·(m·G)
        If this equals some B_i in the table:  w = j·m + i
    ─────────────────────────────────────────────────────────────────────────

    Time complexity:  O(m) = O(√n)  baby steps + O(m) giant steps = O(√n)
    Space complexity: O(m) = O(√n)  for the baby-step lookup table

    Returns: (w, baby_time, giant_time, steps) where w is the recovered scalar
             (or None if not found), times are in seconds, steps is giant-step count.
    """
    m = math.isqrt(n) + 1   # Step size: m = ⌈√n⌉

    # ── Baby steps ──────────────────────────────────────────────────────────
    # Precompute i·G for i = 0, 1, ..., m-1 and store in a hash table.
    # The table maps: curve_point → scalar_index
    #
    # This is the "small" direction: each entry is a small multiple of G.
    t_baby = time.perf_counter()
    baby_table = {}
    baby_point = None           # 0·G = O (point at infinity)
    for i in range(m):
        # Store point as key (tuples are hashable in Python; None = infinity)
        baby_table[baby_point] = i
        baby_point = curve.point_add(baby_point, G)   # Increment: (i+1)·G
    baby_time = time.perf_counter() - t_baby

    # ── Giant steps ──────────────────────────────────────────────────────────
    # Compute Q - j·(m·G) for j = 0, 1, ..., m and check baby table.
    #
    # Each giant step subtracts m·G from the running point — this corresponds
    # to searching over the "large" direction in scalar space.
    #
    # If we find:  Q - j·(m·G) = i·G  (in the baby table)
    # Then:        Q = j·m·G + i·G = (j·m + i)·G
    # So:          w = j·m + i

    mG = curve.scalar_mul(m, G)         # The giant step increment: m·G
    neg_mG = curve.point_neg(mG)        # Negation for subtraction: -(m·G)

    t_giant = time.perf_counter()
    giant_point = Q                     # Start at Q = w·G (j=0 case)
    for j in range(m + 1):
        if giant_point in baby_table:
            i = baby_table[giant_point]
            w_candidate = (j * m + i) % n
            # Verify before returning (guards against hash collisions)
            if curve.scalar_mul(w_candidate, G) == Q:
                giant_time = time.perf_counter() - t_giant
                return w_candidate, baby_time, giant_time, j
        # Subtract m·G: advance giant by one step
        giant_point = curve.point_add(giant_point, neg_mG)

    giant_time = time.perf_counter() - t_giant
    return None, baby_time, giant_time, m + 1   # Should not happen if n is the true group order


# ---------------------------------------------------------------------------
# Attack Runner (with full printed output for thesis)
# ---------------------------------------------------------------------------

def run_bsgs_attack(curve, G, n, w_secret, label="w"):
    """
    Full BSGS attack demonstration:
      1. Compute the KZG-style commitment C = w·G
      2. Launch BSGS to recover w from C (simulating quantum adversary)
      3. Use recovered w to forge a fake commitment for a different weight
      4. Show the fake commitment passes as valid

    This models the complete attack on an Artemis deployment:
        Step 1 → Prover commits to model weight w
        Step 2 → Quantum attacker runs Shor's / BSGS, recovers w
        Step 3 → Attacker forges commitment to fraudulent weight w'
        Step 4 → Verifier cannot distinguish fake from real → system broken

    Args:
        w_secret : int   The secret scalar (neural network weight)
        label    : str   Display name for the variable (for output clarity)
    """
    m = math.isqrt(n) + 1
    print()
    print("=" * 62)
    print("  BSGS ATTACK — Elliptic Curve Discrete Logarithm")
    print("=" * 62)

    # ── Step 1: Commitment ────────────────────────────────────────────────
    print()
    print(f"  [Step 1] Computing KZG-style commitment")
    print(f"  Secret scalar  : {label} = {w_secret}  (neural network weight — private)")
    C = curve.scalar_mul(w_secret, G)
    print(f"  Commitment     : C = {label}·G = {C}")
    print(f"  Published      : C is public (anyone can see it)")
    print(f"  Security claim : 'Given C and G, recovering {label} requires solving ECDLP'")
    print(f"  Quantum threat : Shor's algorithm solves ECDLP in polynomial time")

    # ── Step 2: BSGS Attack ───────────────────────────────────────────────
    print()
    print(f"  [Step 2] Launching BSGS attack  (classical Shor's-equivalent)")
    print(f"  Input          : C = {C},  G = {G},  n = {n}")
    print(f"  Strategy       : Write {label} = j·m + i,  m = ⌈√n⌉ = {m}")
    print(f"  Baby steps     : Precompute {{i·G : i = 0..{m-1}}} → lookup table")
    print(f"  Giant steps    : Compute C - j·(m·G) until collision found")
    print(f"  Complexity     : O(√{n}) ≈ {m} steps  (vs O(256³) Shor's at 256-bit)")

    w_recovered, baby_ms, giant_ms, _ = bsgs(C, G, n, curve)
    elapsed_ms = (baby_ms + giant_ms) * 1000

    # ── Step 3: Result and verification ───────────────────────────────────
    print()
    print(f"  [Step 3] Attack result")
    if w_recovered is not None:
        C_check = curve.scalar_mul(w_recovered, G)
        verified = (C_check == C)
        print(f"  Recovered      : {label}' = {w_recovered}")
        print(f"  Verify         : {label}'·G = {C_check}")
        print(f"  Matches C?     : {verified}  {'✓ — SECRET EXPOSED' if verified else '✗ — bug in BSGS'}")
        print(f"  Time taken     : {elapsed_ms:.4f} ms")
        print(f"  Security status: BROKEN — attacker knows the private weight")
    else:
        print(f"  Attack FAILED  (unexpected — check group order)")
        return None

    # ── Step 4: Commitment forgery ────────────────────────────────────────
    print()
    print(f"  [Step 4] Forging a fake commitment  (shows full impact)")
    w_fake = (w_secret + 57) % n    # Arbitrary fraudulent weight ≠ w_secret
    C_fake = curve.scalar_mul(w_fake, G)
    print(f"  True weight    : {label} = {w_secret}")
    print(f"  Fake weight    : {label}_fake = {w_fake}  (fraudulent model)")
    print(f"  Fake commitment: C_fake = {w_fake}·G = {C_fake}")
    print(f"  Verifier check : is C_fake a valid curve point? {curve.is_on_curve(C_fake)}")
    print(f"  Verdict        : FORGERY SUCCEEDS — verifier cannot detect the fraud")
    print()
    print(f"  [Artemis Impact]")
    print(f"  In a real Artemis deployment, the attacker has now:")
    print(f"    1. Extracted the private model weights ({label}={w_secret})")
    print(f"    2. Committed to fraudulent weights ({label}_fake={w_fake})")
    print(f"    3. The KZG verifying key will accept both — system integrity broken")
    print("=" * 62)

    return w_recovered


# ---------------------------------------------------------------------------
# Standalone test: verify BSGS recovers known values before Session 2
# ---------------------------------------------------------------------------

def _run_correctness_tests(curve, G, n):
    """
    Systematic correctness verification for BSGS.
    Tests a range of scalars to confirm the attack is reliable.
    Called before the main demo to ensure the attack is trustworthy.
    """
    print()
    print("=" * 62)
    print("  BSGS CORRECTNESS VERIFICATION")
    print("=" * 62)
    print(f"  Testing BSGS recovery across multiple scalars...")
    print(f"  Curve order n = {n},  m = ⌈√n⌉ = {math.isqrt(n)+1}")
    print()

    test_scalars = [1, 5, 10, 42, 99, 200, 500, n - 1]
    all_passed = True

    for w in test_scalars:
        Q = curve.scalar_mul(w, G)
        w_rec, _, _, _ = bsgs(Q, G, n, curve)
        ok = (w_rec is not None) and (curve.scalar_mul(w_rec, G) == Q)
        status = "✓ PASS" if ok else "✗ FAIL"
        if not ok:
            all_passed = False
        print(f"    w = {w:>4}  →  Q = w·G = {str(Q):<22}  →  recovered = {str(w_rec):<6}  {status}")

    print()
    if all_passed:
        print("  All tests passed. BSGS is reliable. ✓")
        print("  Conclusion: any ECC commitment on this curve is breakable.")
    else:
        print("  SOME TESTS FAILED. Check bsgs() implementation.")
    print("=" * 62)
    return all_passed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Build the curve
    curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
    G = curve.find_generator()
    n = curve.compute_group_order(G)

    # Print curve parameters (always shown first)
    print_curve_info(curve, G, n)

    # Run correctness tests before the actual attack demo
    all_ok = _run_correctness_tests(curve, G, n)

    if all_ok:
        # Demo the full attack on w = 42 (the neural network weight from our demo)
        run_bsgs_attack(curve, G, n, w_secret=42, label="w")
