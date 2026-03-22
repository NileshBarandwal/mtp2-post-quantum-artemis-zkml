"""
kzg_commitment.py — KZG-style Polynomial Commitment and Full Attack Chain
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad

PURPOSE:
    Demonstrates the complete Artemis KZG commitment pipeline on a neural
    network weight, then shows how a quantum attacker breaks it.

    Maps directly to:
        Slide 13 — How the SRS is built using ECC (PC.Setup + PC.Commit)
        Slide 14 — The full ZK pipeline (weights → constraints → proof)

KZG COMMITMENT SCHEME (simplified for demo):
    A KZG commitment to polynomial P(x) = w  (constant polynomial) is:
        C = w · G   (an elliptic curve point)

    This is equivalent to: C = P(τ) · G = w · τ⁰ · G = w · G
    because for a degree-0 polynomial, the only SRS element used is G = τ⁰·G.

    In Artemis, each layer's weight vector is encoded as a polynomial
    and committed this way. Our demo simplifies to a single neuron: P(x) = w.

ATTACK CHAIN (end of this file):
    1. Model owner commits: C = 42 · G  (published)
    2. Quantum attacker sees C and G → runs Shor's/BSGS → recovers w = 42
    3. Attacker forges:  C_fake = 99 · G  (commitment to fraudulent model)
    4. Verifier checks C_fake — it passes all KZG validity checks
    5. Artemis integrity guarantee is broken

THESIS CONTRIBUTION:
    Replacing KZG with a hash-based commitment eliminates step 2 entirely —
    there is no group structure for BSGS/Shor's to exploit.
"""

import time
import random

from ecc_utils import (
    EllipticCurve, CURVE_A, CURVE_B, CURVE_P,
    print_curve_info, count_all_points
)
from bsgs_attack import bsgs


# ─────────────────────────────────────────────────────────────────────────────
# KZG Setup Data Structure
# ─────────────────────────────────────────────────────────────────────────────

class KZGSetup:
    """
    Structured Reference String (SRS) for KZG polynomial commitments.

    In a real KZG deployment (e.g., the Groth16 or Plonk trusted setup):
        - τ (tau) is generated in a multi-party ceremony
        - SRS = [G, τG, τ²G, ..., τᵈG] is published for polynomial degree ≤ d
        - τ is destroyed ("toxic waste") — if it survives, any proof can be forged

    In our demo: τ is chosen randomly from [2, n-1], used to build a degree-2 SRS,
    then "destroyed" (deleted). The attack recovers w (the committed value), not τ
    itself — but the mechanism is identical: BSGS exploits group structure.

    Fields:
        srs     — list of curve points [τ⁰G, τ¹G, τ²G]
        G       — generator point (= srs[0])
        n       — group order (used to reduce scalars mod n)
        degree  — maximum polynomial degree this SRS supports
        curve   — the EllipticCurve object
    """
    def __init__(self, srs, G, n, degree, curve, tau_destroyed=True):
        self.srs = srs
        self.G = G
        self.n = n
        self.degree = degree
        self.curve = curve
        self.tau_destroyed = tau_destroyed   # Should always be True after setup


# ─────────────────────────────────────────────────────────────────────────────
# PC.Setup  (Slide 13, Steps 1–4)
# ─────────────────────────────────────────────────────────────────────────────

def pc_setup(curve, G, n, degree=2, verbose=True):
    """
    PC.Setup — Generate the Structured Reference String (SRS).

    Maps directly to Slide 13 of the ECC presentation:
        Step 1: Generate secret τ  (random scalar)
        Step 2: Compute [G, τG, τ²G, ..., τᵈG]  (powers of τ on the curve)
        Step 3: Destroy τ forever  (critical — leaking τ breaks everything)
        Step 4: Publish SRS  (the list of curve points is public)

    Security: After τ is destroyed, the only way to find τ from [G, τG]
    is to solve the ECDLP — computationally hard classically (O(√n)),
    but solvable in polynomial time by Shor's algorithm.

    Returns: KZGSetup object (τ is NOT stored — it has been destroyed)
    """
    if verbose:
        _sep()
        print("  [SLIDE 13 — STEP 1]  Generate secret τ  (the KZG trapdoor)")
        print()

    t0 = time.perf_counter()

    # Step 1: Generate τ — a random secret scalar from the group
    # In a real ceremony, τ comes from a multi-party computation.
    # Here we generate it locally to show the structure, then destroy it.
    tau = random.randint(2, n - 1)

    t1 = time.perf_counter()

    if verbose:
        print(f"    τ generated    (value kept secret — not printed)")
        print(f"    τ is a random scalar in {{2, ..., n-1}} = {{2, ..., {n-1}}}")
        print(f"    Time           : {(t1-t0)*1e6:.2f} µs")
        print()
        print("  [SLIDE 13 — STEP 2]  Compute powers of τ on the curve")
        print()
        print(f"    Computing SRS = [τ⁰G, τ¹G, τ²G]  (degree-{degree} SRS)")
        print(f"    Each τⁱG is a scalar multiplication on y²=x³+{curve.a}x+{curve.b} mod {curve.p}")
        print()

    # Step 2: Compute SRS = [τ⁰G, τ¹G, ..., τᵈG]
    # These are ECC points — τ is hidden inside them by the ECDLP
    t2 = time.perf_counter()
    srs = []
    tau_power = 1       # τ⁰ = 1
    for i in range(degree + 1):
        point = curve.scalar_mul(tau_power % n, G)
        srs.append(point)
        if verbose:
            print(f"    SRS[{i}] = τ^{i}·G = {tau_power % n}·G = {point}")
        tau_power = (tau_power * tau) % n

    t3 = time.perf_counter()

    if verbose:
        print()
        print(f"    SRS computed in {(t3-t2)*1e6:.2f} µs")
        print()
        print("  [SLIDE 13 — STEP 3]  Destroy τ forever  (toxic waste)")
        print()

    # Step 3: Destroy τ — overwrite and delete
    # In a real ceremony, τ is never written to disk. Here we simulate
    # deletion by overwriting with zero and unbinding the name.
    tau = 0
    del tau
    tau_power = 0
    del tau_power

    if verbose:
        print(f"    τ overwritten with 0 and deleted from memory.")
        print(f"    If τ survived: any KZG proof can be forged.")
        print(f"    QUANTUM THREAT: Shor's algorithm recovers τ from τG = SRS[1]")
        print(f"    even WITHOUT the τ destruction step — from public SRS alone.")
        print()
        print("  [SLIDE 13 — STEP 4]  Publish the SRS  (public Structured Reference String)")
        print()
        for i, pt in enumerate(srs):
            print(f"    SRS[{i}] = τ^{i}·G = {pt}  [PUBLIC]")
        print()
        print(f"    The SRS is now public. Anyone can commit polynomials using it.")
        print(f"    Time (total setup): {(t3-t0)*1e6:.2f} µs")

    return KZGSetup(srs=srs, G=G, n=n, degree=degree, curve=curve)


# ─────────────────────────────────────────────────────────────────────────────
# PC.Commit  (Slide 13, Step 5 / Slide 14, Steps 1–4)
# ─────────────────────────────────────────────────────────────────────────────

def pc_commit(w, setup, verbose=True):
    """
    PC.Commit — Commit to neural network weight w as a polynomial.

    Maps directly to Slide 13 Step 5 and Slide 14 Steps 1–4:

        Slide 14, Step 1: Neural network weight w  (private input)
        Slide 14, Step 2: Constraint:  output = w · x + b
        Slide 14, Step 3: Polynomial:  P(x) = w  (constant poly, coeff c₀ = w)
        Slide 14, Step 4: Evaluate at τ using SRS:
                          C = c₀ · SRS[0] = w · G = w · τ⁰ · G

    Why a constant polynomial?
        In Artemis, each weight is a single field element committed independently.
        P(x) = w means: "I commit to the scalar w."
        The commitment C = w·G hides w behind the ECDLP.

    Returns: (C, elapsed_ms)  where C is the commitment point
    """
    curve = setup.curve

    # Model context: P(x) = w (constant polynomial, degree 0)
    # Commitment = c₀ · (τ⁰G) = w · G
    #            = sum over i of  cᵢ · SRS[i]   with c₀=w, c₁=c₂=...=0

    if verbose:
        _sep()
        print("  [SLIDE 13 — STEP 5]  Commit to polynomial  P(x) = w")
        print()
        print(f"  [SLIDE 14 — STEP 1]  Neural network weight (private input)")
        print()
        print(f"    Model          :  y = w·x + b  (single neuron)")
        print(f"    Weight         :  w = {w}  (THIS IS WHAT WE COMMIT TO — keep private)")
        print(f"    Bias           :  b = 7   (not committed in this demo)")
        print(f"    Representation :  y = {w}·x + 7")
        print()
        print(f"  [SLIDE 14 — STEP 2]  Constraint encoding")
        print()
        print(f"    Constraint     :  output = w · input + b")
        print(f"    For ZK         :  we prove 'I know w such that C = w·G'")
        print(f"                     without revealing w to the verifier")
        print()
        print(f"  [SLIDE 14 — STEP 3]  Polynomial encoding")
        print()
        print(f"    Polynomial     :  P(x) = w = {w}  (degree-0, constant)")
        print(f"    Coefficients   :  c₀ = {w},  c₁ = 0,  c₂ = 0")
        print(f"    Evaluation     :  P(τ) = {w}  (τ is unknown — in the SRS)")
        print()
        print(f"  [SLIDE 14 — STEP 4]  Evaluate at τ using SRS")
        print()
        print(f"    Formula        :  C = c₀·SRS[0] + c₁·SRS[1] + c₂·SRS[2]")
        print(f"                         = {w}·{setup.srs[0]} + 0·... + 0·...")
        print(f"                         = {w}·G")

    t0 = time.perf_counter()
    C = curve.scalar_mul(w % setup.n, setup.G)
    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000

    if verbose:
        print()
        print(f"  [SLIDE 14 — STEP 5]  Commitment  (elliptic curve point = proof)")
        print()
        print(f"    Commitment     :  C = w·G = {w}·{setup.G} = {C}")
        print(f"    C is on curve  :  {curve.is_on_curve(C)} ✓")
        print(f"    Published      :  C = {C}  [PUBLIC — anyone can see this]")
        print(f"    Time (commit)  :  {elapsed_ms*1000:.2f} µs")
        print()
        print(f"    Security claim :  'Given C = {C} and G = {setup.G},")
        print(f"                       recovering w = {w} requires solving ECDLP.'")
        print(f"    Quantum threat :  Shor's algorithm recovers w from C in O((log n)³)")

    return C, elapsed_ms


# ─────────────────────────────────────────────────────────────────────────────
# PC.Verify  (simplified — no pairings, checks w·G = C)
# ─────────────────────────────────────────────────────────────────────────────

def pc_verify(C, w_claimed, setup, label="", verbose=True):
    """
    PC.Verify — Verify that commitment C opens to claimed value w_claimed.

    Full KZG verification uses bilinear pairings:
        e(C - w·G, G) == e(π, τG - z·G)

    For our simplified constant-polynomial demo, the opening proof π is
    trivial (there is no evaluation point z), so verification reduces to:
        w_claimed · G == C

    This is the check a verifier performs. It confirms:
        1. The prover knew w when they created C
        2. The claimed w is consistent with the published C

    THE VULNERABILITY: Because verification is just w·G == C, ANY curve point
    C' = w'·G will pass for the corresponding w'. An attacker who can choose
    arbitrary w' can always produce a passing verification — the only protection
    is that the attacker shouldn't know w. But BSGS/Shor's recovers w, so:
        - Attacker forges w' = anything  →  C_fake = w'·G  →  verification passes
    """
    curve = setup.curve
    t0 = time.perf_counter()
    C_recomputed = curve.scalar_mul(w_claimed % setup.n, setup.G)
    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000

    passes = (C_recomputed == C)

    if verbose:
        prefix = f"[{label}] " if label else ""
        status = "PASS ✓" if passes else "FAIL ✗"
        print(f"    {prefix}Claimed w      :  {w_claimed}")
        print(f"    {prefix}Recomputed C   :  {w_claimed}·G = {C_recomputed}")
        print(f"    {prefix}Published C    :  {C}")
        print(f"    {prefix}Match          :  {C_recomputed == C}")
        print(f"    {prefix}Verdict        :  {status}")
        print(f"    {prefix}Time (verify)  :  {elapsed_ms*1000:.2f} µs")

    return passes, elapsed_ms


# ─────────────────────────────────────────────────────────────────────────────
# Full Attack Chain
# ─────────────────────────────────────────────────────────────────────────────

def run_full_attack_chain(curve, G, n, w_true=42, w_fake=99, b_bias=7):
    """
    The complete attack pipeline from honest commitment to forged verification.

    Shows:
      Phase A — Honest model owner commits to w=42 using KZG
      Phase B — Quantum attacker breaks the commitment via BSGS
      Phase C — Attacker forges a commitment to w'=99
      Phase D — Verifier checks both commitments (cannot tell them apart)

    This is the core thesis demonstration. The output is structured to be
    screenshottable for the MTP2 thesis document.
    """
    _big_sep("KZG COMMITMENT — FULL ATTACK CHAIN")
    print()
    print("  CONTEXT: Artemis CP-SNARK for zkML")
    print("  An ML model owner wants to prove inference is correct")
    print("  WITHOUT revealing the model weights to the verifier.")
    print()
    print("  CLAIM: KZG commitments provide this guarantee.")
    print("  ATTACK: A quantum adversary using Shor's algorithm breaks it.")
    print("  FIX:    Replace KZG with a hash-based commitment (Session 3).")

    # ── Phase A: Setup and Commit ─────────────────────────────────────────
    _big_sep("PHASE A — Honest Commitment  (PC.Setup + PC.Commit)")
    print()
    print("  The model owner generates the SRS and commits to their weight.")
    print()

    setup = pc_setup(curve, G, n, degree=2, verbose=True)

    print()
    C_real, t_commit = pc_commit(w_true, setup, verbose=True)

    _sep()
    print(f"  [SLIDE 14 — STEP 6]  Verifying Key  (published so anyone can verify)")
    print()
    print(f"    Verifying key  :  (G, SRS[1]) = ({G}, {setup.srs[1]})")
    print(f"    Anyone holding :  C = {C_real}  and  VK = ({G}, ...)")
    print(f"    Can verify     :  that C is a valid KZG commitment on this curve.")
    print(f"    Cannot see     :  the secret weight w  (protected by ECDLP)")
    print()
    print(f"  ─── COMMIT PHASE COMPLETE ───────────────────────────────────────")
    print(f"  Published commitment : C = {C_real}")
    print(f"  Commit time          : {t_commit*1000:.2f} µs")
    print(f"  Status               : Model identity committed. Ready to prove inference.")

    # ── Phase B: BSGS Attack ──────────────────────────────────────────────
    _big_sep("PHASE B — Quantum Attack  (BSGS = classical Shor's equivalent)")
    print()
    print("  An adversary with a quantum computer sees the published commitment C")
    print("  and the public SRS. They run Shor's algorithm (simulated here via BSGS)")
    print("  to recover the secret weight w.")
    print()
    print(f"  Adversary has   :  C = {C_real},  G = {G},  n = {n}")
    print(f"  Adversary wants :  w  such that  C = w·G")
    print()

    m = __import__('math').isqrt(n) + 1
    print(f"  [BSGS] Setting m = ⌈√{n}⌉ = {m}")
    print(f"  [BSGS] Baby steps  : {{i·G → i}}  for i = 0..{m-1}")
    print(f"  [BSGS] Giant steps : C - j·(m·G)  for j = 0..{m}")

    t0 = time.perf_counter()
    w_recovered = bsgs(C_real, G, n, curve)
    t1 = time.perf_counter()
    t_attack = (t1 - t0) * 1000

    print()
    if w_recovered is not None and curve.scalar_mul(w_recovered, G) == C_real:
        print(f"  ┌─ ATTACK RESULT ──────────────────────────────────────────────")
        print(f"  │  Recovered w   : {w_recovered}  ← SECRET WEIGHT EXPOSED")
        print(f"  │  Verified      : {w_recovered}·G = {curve.scalar_mul(w_recovered, G)} = C ✓")
        print(f"  │  Attack time   : {t_attack:.4f} ms")
        print(f"  │")
        print(f"  │  CONSEQUENCE: The model owner's private weight is now known.")
        print(f"  │  Artemis privacy guarantee — BROKEN.")
        print(f"  └──────────────────────────────────────────────────────────────")
        print()
        print(f"  Attacker now knows: the neural network y = {w_recovered}·x + {b_bias}")
        print(f"  This is the exact model that was committed. Privacy is GONE.")
    else:
        print("  Attack failed — unexpected. Check BSGS implementation.")
        return

    # ── Phase C: Commitment Forgery ───────────────────────────────────────
    _big_sep("PHASE C — Commitment Forgery  (fraudulent model w'=99)")
    print()
    print(f"  The attacker now creates a FAKE commitment to a DIFFERENT weight.")
    print(f"  Goal: convince the verifier that the committed model uses w'={w_fake},")
    print(f"  not the true weight w={w_true}.")
    print()
    print(f"  This would let the attacker:")
    print(f"    • Sell a high-quality model (w={w_true}) but prove ownership of garbage (w'={w_fake})")
    print(f"    • Submit proofs of correct inference for a model they don't own")
    print(f"    • Undermine any zkML marketplace built on Artemis")
    print()

    t0 = time.perf_counter()
    C_fake = curve.scalar_mul(w_fake % n, G)
    t1 = time.perf_counter()
    t_forge = (t1 - t0) * 1000

    print(f"  True commitment  :  C_real = {w_true}·G = {C_real}   [w = {w_true}]")
    print(f"  Forged commitment:  C_fake = {w_fake}·G = {C_fake}  [w'= {w_fake}]")
    print()
    print(f"  C_fake is on curve :  {curve.is_on_curve(C_fake)} ✓")
    print(f"  C_fake ≠ C_real    :  {C_fake != C_real} ✓  (genuinely different weight)")
    print(f"  Forge time         :  {t_forge*1000:.2f} µs  (trivial once w is known)")

    # ── Phase D: Verifier is Fooled ───────────────────────────────────────
    _big_sep("PHASE D — Verifier Check  (BEFORE and AFTER forgery)")
    print()
    print("  The verifier runs PC.Verify on both the real and forged commitments.")
    print("  KZG verification only checks: 'does w_claimed·G equal C?'")
    print("  It CANNOT detect forgery — any valid (w', C') pair will pass.")
    print()

    # BEFORE
    print("  ┌─ BEFORE ATTACK — Honest verification ────────────────────────")
    print(f"  │  Verifier checks: does the prover know w such that w·G = C_real?")
    print(f"  │  C_real = {C_real}")
    print(f"  │")
    passes_real, t_vreal = pc_verify(C_real, w_true, setup, verbose=False)
    print(f"  │  Claimed w = {w_true}   →   {w_true}·G = {curve.scalar_mul(w_true, G)}")
    print(f"  │  C_real    = {C_real}")
    print(f"  │  Match     : {passes_real}   Verdict: {'PASS ✓  (honest)' if passes_real else 'FAIL ✗'}")
    print(f"  └──────────────────────────────────────────────────────────────")
    print()

    # AFTER — verifier sees the forged commitment
    print("  ┌─ AFTER ATTACK — Forged commitment verification ──────────────")
    print(f"  │  Attacker submits: C_fake = {C_fake}")
    print(f"  │  Attacker claims : 'I committed to w' = {w_fake}'")
    print(f"  │")
    passes_fake, t_vfake = pc_verify(C_fake, w_fake, setup, verbose=False)
    print(f"  │  Claimed w'= {w_fake}   →   {w_fake}·G = {curve.scalar_mul(w_fake, G)}")
    print(f"  │  C_fake    = {C_fake}")
    print(f"  │  Match     : {passes_fake}   Verdict: {'PASS ✓  ← FORGERY ACCEPTED' if passes_fake else 'FAIL ✗'}")
    print(f"  └──────────────────────────────────────────────────────────────")
    print()
    print(f"  BEFORE: Verifier correctly accepts real commitment (w={w_true})  → PASS")
    print(f"  AFTER : Verifier incorrectly accepts forged commitment (w'={w_fake}) → PASS")
    print()
    print(f"  The verifier CANNOT DISTINGUISH real from forged.")
    print(f"  Any curve point C' = w'·G passes verification for the corresponding w'.")

    # ── Final Summary ─────────────────────────────────────────────────────
    _big_sep("ATTACK CHAIN SUMMARY")
    print()
    print(f"  Step 1  [COMMIT]    Model owner publishes C = {w_true}·G = {C_real}")
    print(f"  Step 2  [ATTACK]    Adversary runs BSGS on C → recovers w = {w_recovered}")
    print(f"                      (Shor's does this in O((log n)³) on a quantum computer)")
    print(f"  Step 3  [FORGE]     Adversary computes C_fake = {w_fake}·G = {C_fake}")
    print(f"  Step 4  [DECEIVE]   Verifier checks C_fake → PASS  (fooled ✓)")
    print()
    print(f"  ┌───────────────────────────────────────────────────────────────")
    print(f"  │  TIMING SUMMARY")
    print(f"  │  Commit time   :  {t_commit*1000:.2f} µs")
    print(f"  │  Attack time   :  {t_attack:.4f} ms  ←  O(√{n}) = {m} steps")
    print(f"  │  Forge time    :  {t_forge*1000:.2f} µs")
    print(f"  │  Verify (real) :  {t_vreal*1000:.2f} µs")
    print(f"  │  Verify (fake) :  {t_vfake*1000:.2f} µs")
    print(f"  └───────────────────────────────────────────────────────────────")
    print()
    print(f"  ROOT CAUSE: KZG commitment C = w·G leaks group structure.")
    print(f"  ECDLP protects w classically but NOT against Shor's algorithm.")
    print(f"  All three ECC dependencies in Artemis trace to this single weakness:")
    print(f"    1. SRS generation   → τ can be recovered from τG via Shor's")
    print(f"    2. Commitment       → w can be recovered from w·G via Shor's")
    print(f"    3. Verifying key    → pairing-based, collapses with ECC")
    print()
    print(f"  PROPOSED FIX (Session 3):")
    print(f"    Replace C = w·G  with  C = SHA256(w || nonce)")
    print(f"    BSGS has no group structure to exploit → attack fails by design.")
    _big_sep("END SESSION 2")

    return {
        "C_real": C_real,
        "C_fake": C_fake,
        "w_recovered": w_recovered,
        "t_commit_us": t_commit * 1000,
        "t_attack_ms": t_attack,
        "t_forge_us": t_forge * 1000,
        "passes_real": passes_real,
        "passes_fake": passes_fake,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sep():
    print("  " + "─" * 60)


def _big_sep(title=""):
    print()
    if title:
        pad = max(0, 60 - len(title) - 4)
        left = pad // 2
        right = pad - left
        print("  ═" + "═" * left + "  " + title + "  " + "═" * right + "═")
    else:
        print("  " + "═" * 62)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Build the curve (same parameters as Session 1)
    curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
    G = curve.find_generator()
    n = curve.compute_group_order(G)

    # Print curve parameters (always first)
    print_curve_info(curve, G, n)

    # Run the full attack chain
    results = run_full_attack_chain(
        curve, G, n,
        w_true=42,   # The real neural network weight
        w_fake=99,   # The forged weight the attacker claims
        b_bias=7,    # Bias term (contextual, not committed in this demo)
    )
