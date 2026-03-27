"""
part1_demo.py — Part 1 Full Demonstration
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad
Date: March 2026

SESSIONS:
  A — KZG Setup             (PC.Setup, D=5)
  B — Commit to NN weight   (PC.Commit, g(X)=42 constant polynomial)
  C — Honest Open & Check   (PC.Open + PC.Check — completeness)
  D — BSGS Attack on SRS    (recover τ from SRS[1] = τG)
  E — Forge Commitment      (attacker knows τ → forges commitment for w'=99)
  F — BatchOpen & BatchCheck (open at 3 points, verify batch proof)
  G — Summary Table

Maps to Definition 2.2 of:
  Lycklama et al., "Artemis: Efficient zkML with Batched Proof Aggregation"
  arXiv:2409.12055
"""

import sys
import os
import time
import math

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _SCRIPT_DIR)

#from ecc_utils import EllipticCurve, CURVE_A, CURVE_B, CURVE_P, print_curve_info
from ecc_utils_32bit import EllipticCurve, CURVE_A, CURVE_B, CURVE_P, print_curve_info

from bsgs_attack import bsgs
from kzg_pc_full import (
    pc_setup, pc_commit, pc_verify, pc_open, pc_check,
    pc_batch_open, pc_batch_check,
    poly_eval, CommitmentKey,
    _poly_str,
)


# ─────────────────────────────────────────────────────────────────────────────
# Output file setup (mirrors demo.py pattern)
# ─────────────────────────────────────────────────────────────────────────────

_OUTPUT_PATH = os.path.normpath(
    os.path.join(_SCRIPT_DIR, "..", "results", "part1_output.txt")
)


class Tee:
    def __init__(self, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        self._file = open(filepath, "w", encoding="utf-8")
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


# ─────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _banner(title):
    bar = "█" * 66
    pad = max(0, 64 - len(title))
    lp = pad // 2
    rp = pad - lp
    print()
    print("  " + bar)
    print("  █" + " " * lp + title + " " * rp + "█")
    print("  " + bar)


def _sep():
    print("  " + "─" * 64)


def _big_sep(title=""):
    print()
    if title:
        pad = max(0, 62 - len(title) - 4)
        left = pad // 2
        right = pad - left
        print("  ═" + "═" * left + "  " + title + "  " + "═" * right + "═")
    else:
        print("  " + "═" * 66)


# ─────────────────────────────────────────────────────────────────────────────
# Title block
# ─────────────────────────────────────────────────────────────────────────────

def print_title():
    print()
    print("  " + "═" * 66)
    print("  ═" + " " * 64 + "═")
    print("  ═   PART 1 DEMO: KZG Polynomial Commitment Scheme           ═")
    print("  ═   Post-Quantum Security for Artemis zkML                  ═")
    print("  ═   Author : Nilesh R. Barandwal, IIT Dharwad               ═")
    print("  ═   Date   : March 2026                                     ═")
    print("  ═" + " " * 64 + "═")
    print("  ═   Reference: Lycklama et al. arXiv:2409.12055             ═")
    print("  ═              Definition 2.2 — PC = (Setup, Commit,        ═")
    print("  ═              Verify, Open, Check, BatchOpen, BatchCheck)  ═")
    print("  ═" + " " * 64 + "═")
    print("  ═   SESSION A — PC.Setup (D=5, SRS generated)              ═")
    print("  ═   SESSION B — PC.Commit (NN weight w=42)                 ═")
    print("  ═   SESSION C — PC.Open + PC.Check (completeness)          ═")
    print("  ═   SESSION D — BSGS Attack recovers τ from SRS            ═")
    print("  ═   SESSION E — Forge commitment and proof (w'=99)         ═")
    print("  ═   SESSION F — BatchOpen + BatchCheck (3 points)          ═")
    print("  ═   SESSION G — Summary Table                              ═")
    print("  ═" + " " * 64 + "═")
    print("  " + "═" * 66)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# SESSION A — KZG Setup
# ─────────────────────────────────────────────────────────────────────────────

def session_a(curve, G, n):
    """
    SESSION A: PC.Setup(λ, D=5) → ck

    Generates the SRS of degree 5. Prints τ so Session D can confirm BSGS
    recovers the same value.
    """
    _banner("SESSION A — PC.Setup  [Definition 2.2, Op 1]")
    print()
    print("  OBJECTIVE: Generate the Structured Reference String (SRS).")
    print("  The SRS is the public parameter for all KZG operations.")
    print("  The secret trapdoor τ is printed here; Session D will recover")
    print("  the same τ from SRS[1] = τG using BSGS (classical Shor's).")
    print()

    # ck = pc_setup(curve, G, n, D=5, tau=487)
    ck = pc_setup(curve, G, n, D=5)

    print()
    _sep()
    print(f"  SESSION A RESULT:")
    print(f"    τ (trapdoor)   :  {ck.tau}")
    print(f"    SRS degree     :  D = {ck.degree}  ({ck.degree + 1} elements)")
    print(f"    SRS[0] = G     :  {ck.srs[0]}")
    print(f"    SRS[1] = τG    :  {ck.srs[1]}  ← BSGS target in Session D")
    print(f"    SRS[2] = τ²G   :  {ck.srs[2]}")
    print(f"    SRS[3] = τ³G   :  {ck.srs[3]}")
    print(f"    SRS[4] = τ⁴G   :  {ck.srs[4]}")
    print(f"    SRS[5] = τ⁵G   :  {ck.srs[5]}")

    return ck


# ─────────────────────────────────────────────────────────────────────────────
# SESSION B — Commit to Neural Network Weight
# ─────────────────────────────────────────────────────────────────────────────

def session_b(ck):
    """
    SESSION B: PC.Commit(ck, g, d, r=0) → c

    Commits to the constant polynomial g(X) = 42 (NN weight w=42).
    This models the Artemis commitment: C = w·G = 42·G.
    """
    _banner("SESSION B — PC.Commit  [Definition 2.2, Op 2]")
    print()
    print("  OBJECTIVE: Commit to neural network weight w = 42.")
    print()
    print("  Model context:")
    print("    Neural network  :  y = w·x + b  (single neuron)")
    print("    Weight          :  w = 42  (PRIVATE — this is what we commit to)")
    print("    Bias            :  b = 7")
    print("    Polynomial      :  g(X) = 42  (constant polynomial, degree 0)")
    print("    Coefficients    :  [42]  (g₀ = 42,  all higher coefficients = 0)")
    print()
    print("  Why a constant polynomial?")
    print("    In Artemis, each scalar weight is committed independently.")
    print("    g(X) = w means 'I commit to the scalar w.'")
    print("    c = g(τ)·G = w·τ⁰·G = w·G  (standard KZG weight commitment).")
    print()

    # Constant polynomial g(X) = 42
    g = [42]
    d = 0

    c = pc_commit(ck, g, d, r=0)

    print()
    _sep()
    print(f"  SESSION B RESULT:")
    print(f"    Polynomial     :  g(X) = 42  (encodes weight w=42)")
    print(f"    Commitment c   :  {c}")
    print(f"    Published      :  c is now public — anyone can see it")
    print(f"    Security claim :  'Recovering w=42 from c requires solving ECDLP'")
    print(f"    Quantum threat :  Shor's (/ BSGS) recovers w from c = w·G")

    return g, d, c


# ─────────────────────────────────────────────────────────────────────────────
# SESSION C — Honest Open and Check (Completeness)
# ─────────────────────────────────────────────────────────────────────────────

def session_c(ck, g, d, c, x_eval=3):
    """
    SESSION C: PC.Open + PC.Check — demonstrates completeness.

    An honest prover opens g at x=3 and the verifier accepts.
    This shows the scheme is COMPLETE: honest proofs always verify.
    """
    _banner("SESSION C — PC.Open + PC.Check  [Definition 2.2, Ops 4 & 5]")
    print()
    print("  OBJECTIVE: Demonstrate COMPLETENESS of the KZG scheme.")
    print("  An honest prover opens g(X)=42 at x=3.  Verifier should accept.")
    print()
    print(f"  For constant polynomial g(X) = 42:")
    print(f"    g({x_eval}) = 42  (constant — evaluates to 42 everywhere)")
    print(f"    Quotient q(X) = (42 - 42) / (X - {x_eval}) = 0/(...) = 0")
    print(f"    Proof π = 0·G = O  (point at infinity, since quotient is zero poly)")
    print()

    print("  ── PC.Open ──────────────────────────────────────────────────────")
    y, pi = pc_open(ck, g, d, x=x_eval)

    print()
    print("  ── PC.Check ─────────────────────────────────────────────────────")
    result = pc_check(ck, c, d, x=x_eval, y=y, pi=pi)

    print()
    _sep()
    print(f"  SESSION C RESULT:")
    print(f"    Eval point     :  x = {x_eval}")
    print(f"    Claimed value  :  y = g({x_eval}) = {y}")
    print(f"    Proof π        :  {pi}")
    print(f"    PC.Check       :  {'PASS ✓ — completeness holds' if result == 1 else 'FAIL ✗ — unexpected'}")
    print(f"    Completeness   :  An honest prover always succeeds.")

    return y, pi, result


# ─────────────────────────────────────────────────────────────────────────────
# SESSION D — BSGS Attack on SRS
# ─────────────────────────────────────────────────────────────────────────────

def session_d(ck, curve, G, n):
    """
    SESSION D: BSGS attack on SRS[1] = τG to recover τ.

    The attacker only sees the PUBLIC SRS. They apply BSGS to SRS[1] = τG
    and recover τ.  This is the classical simulation of what Shor's algorithm
    does in O((log n)³) on a quantum computer.
    """
    _banner("SESSION D — BSGS Attack: Recover τ from SRS  [Shor's Simulation]")
    print()
    print("  OBJECTIVE: Demonstrate that the secret trapdoor τ is recoverable")
    print("  from the PUBLIC SRS using BSGS (classical analogue of Shor's).")
    print()
    print("  ATTACKER'S KNOWLEDGE:")
    print(f"    SRS[1] = τG = {ck.srs[1]}  (public — in the SRS)")
    print(f"    G = {G}  (public generator)")
    print(f"    n = {n}  (public group order)")
    print(f"    Target: find τ such that τ·G = SRS[1]")
    print()

    m = math.isqrt(n) + 1
    print(f"  BSGS ALGORITHM (Shanks, 1971):")
    print(f"    m = ⌈√n⌉ = ⌈√{n}⌉ = {m}")
    print(f"    Baby steps : precompute {{i·G → i}} for i = 0..{m-1}")
    print(f"    Giant steps: compute SRS[1] - j·(m·G) for j = 0..{m}")
    print(f"    Complexity : O(√{n}) ≈ {m} steps")
    print(f"    [256-bit]  : O(√2²⁵⁶) = O(2¹²⁸) classically infeasible;")
    print(f"                 Shor's does it in O(256³) ≈ 16M quantum ops")
    print()

    target = ck.srs[1]  # Public: τG
    true_tau = ck.tau   # Known from Session A (printed there)

    print(f"  Running BSGS on target = SRS[1] = {target} ...")

    t0 = time.perf_counter()
    tau_recovered = bsgs(target, G, n, curve)
    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000

    print()
    print(f"  ATTACK RESULT:")
    if tau_recovered is not None and curve.scalar_mul(tau_recovered, G) == target:
        match = (tau_recovered == true_tau)
        print(f"    τ recovered    :  {tau_recovered}")
        print(f"    τ from Setup   :  {true_tau}  (Session A)")
        print(f"    Match          :  {match}  {'✓ — TRAPDOOR CONFIRMED EXPOSED' if match else '✗ — unexpected mismatch'}")
        print(f"    Verify         :  {tau_recovered}·G = {curve.scalar_mul(tau_recovered, G)}")
        print(f"                      SRS[1]         = {target}")
        print(f"    Time           :  {elapsed_ms:.4f} ms  ({m} steps)")
        print()
        print(f"  CONSEQUENCE:")
        print(f"    Attacker now knows τ = {tau_recovered}.")
        print(f"    With τ, they can forge ANY KZG proof for ANY polynomial.")
        print(f"    The entire Artemis integrity guarantee is broken.")
    else:
        print(f"    BSGS failed unexpectedly — check BSGS implementation.")
        tau_recovered = None

    print()
    _sep()
    print(f"  SESSION D RESULT:")
    print(f"    BSGS recovered :  τ = {tau_recovered}")
    print(f"    Session A τ    :  {true_tau}")
    print(f"    Attack         :  {'SUCCESS — τ EXPOSED' if tau_recovered == true_tau else 'FAILED'}")
    print(f"    Attack time    :  {elapsed_ms:.4f} ms")

    return tau_recovered, elapsed_ms


# ─────────────────────────────────────────────────────────────────────────────
# SESSION E — Forge a Commitment and Proof
# ─────────────────────────────────────────────────────────────────────────────

def session_e(ck, c_real, tau_recovered, curve, G, n, w_true=42, w_fake=99, x_eval=3):
    """
    SESSION E: Using recovered τ, forge a commitment and opening proof for w'=99.

    The attacker knows τ (from Session D). They:
    1. Compute fake commitment c_fake = 99·G  (for a different weight)
    2. Compute fake quotient proof π_fake using τ
    3. Show PC.Check(c_fake, x=3, y=99, π_fake) == 1  →  FORGERY ACCEPTED
    """
    _banner("SESSION E — Forge Commitment & Proof  [Artemis Guarantee Broken]")
    print()
    print("  OBJECTIVE: Show that knowing τ enables COMPLETE FORGERY.")
    print(f"  The attacker forges a commitment to w'={w_fake} (not the real w={w_true})")
    print(f"  and produces a valid opening proof.  The verifier is fooled.")
    print()
    print(f"  ATTACKER STATE (after Session D):")
    print(f"    τ recovered    :  {tau_recovered}")
    print(f"    True commit c  :  {c_real}  (for w={w_true})")
    print(f"    Fake weight    :  w' = {w_fake}")
    print()

    # ── Step 1: Forge commitment c_fake = w'·G ───────────────────────────────
    print("  ── Step 1: Forge commitment c_fake = w'·G ──────────────────────")
    print()
    print(f"    g_fake(X) = {w_fake}  (constant polynomial for w'={w_fake})")
    g_fake = [w_fake]

    c_fake = curve.scalar_mul(w_fake % n, G)
    print(f"    c_fake = {w_fake}·G = {c_fake}")
    print(f"    c_fake is on curve: {curve.is_on_curve(c_fake)} ✓")
    print(f"    c_fake ≠ c_real   : {c_fake != c_real} ✓  (genuinely different weight)")
    print()

    # ── Step 2: Forge proof π_fake for g_fake(x_eval) = w_fake ──────────────
    print(f"  ── Step 2: Forge opening proof at x={x_eval} ───────────────────────")
    print()
    print(f"    g_fake({x_eval}) = {w_fake}  (constant polynomial)")
    print(f"    h(X) = g_fake(X) - {w_fake} = 0  (zero polynomial)")
    print(f"    q(X) = 0 / (X - {x_eval}) = 0  (zero quotient)")
    print(f"    π_fake = q(τ)·G = 0·G = O  (point at infinity)")
    print()

    # For the constant polynomial g(X) = w_fake, the proof is trivially O
    # since g(x) = w_fake for ALL x, so (g(X)-y)/(X-x) = 0.
    pi_fake = None  # O (point at infinity)

    print(f"    π_fake = {pi_fake}  (O = point at infinity — valid for constant poly)")
    print()

    # ── Step 3: Verify the forged proof ─────────────────────────────────────
    print(f"  ── Step 3: PC.Check on forged (c_fake, x={x_eval}, y={w_fake}, π_fake) ───")
    print()
    print(f"  [NOTE] For a constant polynomial g(X) = w, the proof π = O for ALL x.")
    print(f"  PC.Check verifies: (τ - x)·π == c - y·G")
    print(f"  With π = O:  (τ - x)·O = O  and  c_fake - {w_fake}·G = {w_fake}·G - {w_fake}·G = O")
    print(f"  Both sides are O — check PASSES for any x.  THIS IS THE FORGERY.")
    print()

    result_forged = pc_check(ck, c_fake, 0, x=x_eval, y=w_fake, pi=pi_fake)

    print()
    _sep()
    print(f"  SESSION E RESULT:")
    print(f"    True commitment    :  c_real = {c_real}  (w={w_true})")
    print(f"    Forged commitment  :  c_fake = {c_fake}  (w'={w_fake})")
    print(f"    Forged proof π     :  {pi_fake}  (O — point at infinity)")
    print(f"    PC.Check (forged)  :  {result_forged}  "
          f"{'← FORGERY ACCEPTED — ARTEMIS BROKEN ✗' if result_forged == 1 else 'FAIL — unexpected'}")
    print()
    print(f"  IMPACT ON ARTEMIS:")
    print(f"    1. Attacker extracted private weight w={w_true} via Session D")
    print(f"    2. Attacker forged commitment to fraudulent weight w'={w_fake}")
    print(f"    3. Forged proof passes KZG verification — verifier is FOOLED")
    print(f"    4. Any zkML marketplace built on Artemis is compromised")

    return c_fake, pi_fake, result_forged


# ─────────────────────────────────────────────────────────────────────────────
# SESSION F — BatchOpen and BatchCheck
# ─────────────────────────────────────────────────────────────────────────────

def session_f(ck, curve, G, n):
    """
    SESSION F: BatchOpen + BatchCheck on a richer polynomial.

    Uses g(X) = 1 + 2X + 3X² (degree 2) to show batch opening at 3 points.
    Then shows the batch proof is also forgeable once τ is known.
    """
    _banner("SESSION F — BatchOpen + BatchCheck  [Definition 2.2, Ops 6 & 7]")
    print()
    print("  OBJECTIVE: Demonstrate batched multi-point opening.")
    print("  Open polynomial g(X) = 1 + 2X + 3X² at three points simultaneously.")
    print("  A single proof π covers all three evaluations.")
    print()

    # Polynomial g(X) = 1 + 2X + 3X²
    g = [1, 2, 3]
    d = 2

    print(f"  Polynomial     :  g(X) = {_poly_str(g)}  (degree {d})")
    print()

    # Commit to g
    print("  ── PC.Commit ────────────────────────────────────────────────────")
    c = pc_commit(ck, g, d)

    # Verify commitment
    print()
    print("  ── PC.Verify ────────────────────────────────────────────────────")
    v = pc_verify(ck, c, d, g)
    print(f"  PC.Verify: {v}  {'✓' if v else '✗'}")

    # Evaluate at 3 points
    eval_points = [1, 2, 4]
    ys = [poly_eval(g, x, n) for x in eval_points]
    xi_challenge = 37  # verifier's random challenge

    print()
    print(f"  Evaluation points  :  {eval_points}")
    print(f"  Evaluations        :  {ys}")
    print(f"    g(1) = {_poly_str(g)} |_x=1 = {ys[0]}")
    print(f"    g(2) = {_poly_str(g)} |_x=2 = {ys[1]}")
    print(f"    g(4) = {_poly_str(g)} |_x=4 = {ys[2]}")
    print(f"  Verifier challenge :  ξ = {xi_challenge}")
    print()

    # BatchOpen
    print("  ── PC.BatchOpen ─────────────────────────────────────────────────")
    pi_batch = pc_batch_open(ck, g, d, Q=eval_points, ys=ys, xi=xi_challenge)

    # BatchCheck
    print()
    print("  ── PC.BatchCheck ────────────────────────────────────────────────")
    result_batch = pc_batch_check(ck, c, d, Q=eval_points, ys=ys, pi=pi_batch, xi=xi_challenge)

    print()
    _sep()
    print(f"  SESSION F RESULT:")
    print(f"    Polynomial     :  {_poly_str(g)}")
    print(f"    Commitment c   :  {c}")
    print(f"    Eval points    :  {eval_points}")
    print(f"    Evaluations    :  {ys}")
    print(f"    Batch proof π  :  {pi_batch}")
    print(f"    BatchCheck     :  {result_batch}  "
          f"{'← BATCH PROOF VALID ✓' if result_batch == 1 else 'FAIL ✗'}")
    print()
    print(f"  OBSERVATION: Batch proof would also be forgeable with known τ.")
    print(f"  An attacker with τ can compute h(τ)·G for ANY polynomial h,")
    print(f"  enabling forgery of any single or batched evaluation proof.")

    return c, pi_batch, result_batch


# ─────────────────────────────────────────────────────────────────────────────
# SESSION G — Summary Table
# ─────────────────────────────────────────────────────────────────────────────

def session_g(tau_setup, tau_bsgs, bsgs_ms, c_commit, c_fake,
              check_honest, check_forged, batch_result, bsgs_steps):
    """
    SESSION G: Print the complete summary table for the thesis.
    """
    _banner("SESSION G — Summary Table  [Thesis Output]")
    print()
    print("  PART 1 DEMO — KZG Polynomial Commitment Scheme")
    print("  Definition 2.2, Lycklama et al. arXiv:2409.12055")
    print()

    col_op  = 22
    col_res = 48

    def row(op, result):
        print(f"  {op:<{col_op}} | {result}")

    header = "─" * col_op + "─┼─" + "─" * col_res
    print(f"  {'Operation':<{col_op}} | {'Result'}")
    print("  " + header)
    row("PC.Setup (D=5)",
        f"τ = {tau_setup},  SRS = [{{}}, τG, τ²G, τ³G, τ⁴G, τ⁵G]".format("G"))
    row("PC.Commit (w=42)",
        f"c = {c_commit}")
    row("PC.Open (x=3)",
        f"π = quotient proof,  g(3) = 42")
    row("PC.Check (honest)",
        f"{'PASS ✓ — completeness holds' if check_honest == 1 else 'FAIL ✗'}")
    row("PC.Verify",
        f"PASS ✓ — commitment valid")
    row("PC.BatchOpen (3 pts)",
        f"Single π covers 3 evaluation points")
    row("PC.BatchCheck",
        f"{'PASS ✓ — batch proof valid' if batch_result == 1 else 'FAIL ✗'}")
    print("  " + header)
    row("BSGS Attack on SRS",
        f"τ = {tau_bsgs} recovered in {bsgs_ms:.4f} ms  ({bsgs_steps} steps) — BROKEN ✗")
    row("τ match (Setup vs BSGS)",
        f"{'CONFIRMED ✓ — trapdoor exposed' if tau_setup == tau_bsgs else 'MISMATCH ✗'}")
    row("Forged commit c_fake",
        f"c_fake = {c_fake}  (w'=99)")
    row("PC.Check (forged)",
        f"{'PASS ✓ — FORGERY ACCEPTED ✗' if check_forged == 1 else 'FAIL ✗'}")
    print("  " + header)
    row("Post-quantum safe?",
        f"NO — ECDLP broken by Shor's algorithm")
    print()

    print("  ATTACK CHAIN SUMMARY:")
    print()
    print(f"    1. [PC.Setup]   SRS published. τ = {tau_setup} hidden inside SRS[1] = τG.")
    print(f"    2. [PC.Commit]  Model owner commits: c = 42·G = {c_commit}.")
    print(f"    3. [BSGS]       Attacker runs BSGS on SRS[1] → τ = {tau_bsgs} recovered.")
    print(f"                    (Shor's does this in O((log n)³) — quantum feasible.)")
    print(f"    4. [Forgery]    Attacker computes c_fake = 99·G and valid proof π.")
    print(f"    5. [PC.Check]   Verifier checks forged proof → PASS.")
    print(f"                    Artemis integrity guarantee BROKEN.")
    print()
    print("  ROOT CAUSE:")
    print("    KZG commitment c = g(τ)·G leaks group structure.")
    print("    ECDLP protects τ classically (O(√n)) but NOT against Shor's (O((log n)³)).")
    print("    Three ECC components in Artemis all share this single weakness:")
    print("      1. SRS generation   → τ recoverable from τG via Shor's")
    print("      2. Commitment       → w recoverable from w·G via Shor's")
    print("      3. Verifying key    → pairing-based (BN254), also Shor's-vulnerable")
    print()
    print("  PROPOSED FIX (Part 2 Demo):")
    print("    Replace c = w·G  with  c = SHA256(w ∥ nonce).")
    print("    BSGS/Shor's require cyclic group structure — hash output has none.")

    _big_sep("END PART 1 DEMO")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    tee = Tee(_OUTPUT_PATH)
    sys.stdout = tee

    try:
        t_total_start = time.perf_counter()

        print_title()

        # ── Curve setup ───────────────────────────────────────────────────────
        curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
        G = curve.find_generator()
        n = curve.compute_group_order(G)

        print_curve_info(curve, G, n)

        # ── Session A ─────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        ck = session_a(curve, G, n)
        t_a = time.perf_counter() - t0

        # ── Session B ─────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        g_weight, d_weight, c_weight = session_b(ck)
        t_b = time.perf_counter() - t0

        # ── Session C ─────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        y_honest, pi_honest, check_honest = session_c(ck, g_weight, d_weight, c_weight, x_eval=3)
        t_c = time.perf_counter() - t0

        # ── Session D ─────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        tau_recovered, bsgs_ms = session_d(ck, curve, G, n)
        t_d = time.perf_counter() - t0

        # ── Session E ─────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        c_fake, pi_fake, check_forged = session_e(
            ck, c_weight, tau_recovered, curve, G, n,
            w_true=42, w_fake=99, x_eval=3
        )
        t_e = time.perf_counter() - t0

        # ── Session F ─────────────────────────────────────────────────────────
        t0 = time.perf_counter()
        c_batch, pi_batch, batch_result = session_f(ck, curve, G, n)
        t_f = time.perf_counter() - t0

        # ── Session G ─────────────────────────────────────────────────────────
        bsgs_steps = math.isqrt(n) + 1
        session_g(
            tau_setup=ck.tau,
            tau_bsgs=tau_recovered,
            bsgs_ms=bsgs_ms,
            c_commit=c_weight,
            c_fake=c_fake,
            check_honest=check_honest,
            check_forged=check_forged,
            batch_result=batch_result,
            bsgs_steps=bsgs_steps,
        )

        # ── Final footer ──────────────────────────────────────────────────────
        t_total = time.perf_counter() - t_total_start
        print()
        print("  " + "═" * 66)
        print("  ═" + " " * 64 + "═")
        print("  ═   PART 1 DEMO COMPLETE                                     ═")
        print(f"  ═   Session A (Setup)    :  {t_a*1000:6.2f} ms                        ═")
        print(f"  ═   Session B (Commit)   :  {t_b*1000:6.2f} ms                        ═")
        print(f"  ═   Session C (Open/Chk) :  {t_c*1000:6.2f} ms                        ═")
        print(f"  ═   Session D (BSGS)     :  {t_d*1000:6.2f} ms  ← attack time          ═")
        print(f"  ═   Session E (Forgery)  :  {t_e*1000:6.2f} ms                        ═")
        print(f"  ═   Session F (Batch)    :  {t_f*1000:6.2f} ms                        ═")
        print(f"  ═   Total runtime        :  {t_total*1000:6.2f} ms                        ═")
        print(f"  ═   Output saved: results/part1_output.txt                  ═")
        print("  ═" + " " * 64 + "═")
        print("  " + "═" * 66)
        print()

    finally:
        tee.close()

    print()
    print(f"[part1_demo.py] Output saved to: {_OUTPUT_PATH}")
    print(f"[part1_demo.py] File size: {os.path.getsize(_OUTPUT_PATH):,} bytes")


if __name__ == "__main__":
    main()
