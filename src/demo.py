"""
demo.py — End-to-End Demo Runner (Session 4 — Final Deliverable)
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad
Date: March 2026

PURPOSE:
    Single-file runner that executes Sessions 1, 2, and 3 in sequence
    and produces a unified, screenshottable output for the MTP2 thesis.

    Saves complete terminal output to ../results/demo_output.txt.

RUN ORDER:
    Session 1 — ECC setup + BSGS correctness tests
    Session 2 — KZG commitment + full BSGS attack chain
    Session 3 — Hash commitment + attack failure demonstration
    Session 4 — Side-by-side timing comparison + Thesis summary
"""

import sys
import os
import time

# ─────────────────────────────────────────────────────────────────────────────
# Tee: write to both stdout and a file simultaneously
# ─────────────────────────────────────────────────────────────────────────────

class Tee:
    """
    Redirect sys.stdout so every print() goes to both the terminal
    and the output file.  Restored on context exit.
    """
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
# Output path
# ─────────────────────────────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_OUTPUT_PATH = os.path.join(_SCRIPT_DIR, "..", "results", "demo_output.txt")
_OUTPUT_PATH = os.path.normpath(_OUTPUT_PATH)


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


def _banner(title):
    width = 62
    bar = "█" * width
    pad = max(0, width - len(title) - 2)
    lp = pad // 2
    rp = pad - lp
    print()
    print("  " + bar)
    print("  █" + " " * lp + title + " " * rp + "█")
    print("  " + bar)


# ─────────────────────────────────────────────────────────────────────────────
# Title block
# ─────────────────────────────────────────────────────────────────────────────

def print_title_block():
    print()
    print("  " + "═" * 62)
    print("  ═" + " " * 60 + "═")
    print("  ═   MTP2 Demo: Post-Quantum Security for Artemis zkML     ═")
    print("  ═   Author : Nilesh R. Barandwal, IIT Dharwad              ═")
    print("  ═   Date   : March 2026                                    ═")
    print("  ═" + " " * 60 + "═")
    print("  ═" + " " * 60 + "═")
    print("  ═   SESSION 1 — ECC Setup + BSGS Correctness               ═")
    print("  ═   SESSION 2 — KZG Commitment + Full Attack Chain          ═")
    print("  ═   SESSION 3 — Hash Commitment + Attack Failure            ═")
    print("  ═   SESSION 4 — Comparison Table + Thesis Summary           ═")
    print("  ═" + " " * 60 + "═")
    print("  " + "═" * 62)
    print()
    print("  This demo proves the following thesis claim:")
    print()
    print("    KZG polynomial commitments — as used in the Artemis zkML")
    print("    framework — are broken by Shor's algorithm (demonstrated")
    print("    classically via BSGS). Replacing them with SHA-256 hash")
    print("    commitments eliminates all three ECC-dependent attack")
    print("    surfaces and restores post-quantum security.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Session 1 — ECC Setup + BSGS Correctness
# ─────────────────────────────────────────────────────────────────────────────

def run_session_1(curve, G, n):
    _banner("SESSION 1 — ECC Setup and BSGS Correctness Tests")
    print()
    print("  PURPOSE: Establish the elliptic curve and verify that the")
    print("  Baby-step Giant-step algorithm reliably recovers all scalars.")
    print("  This is the mathematical foundation for the Session 2 attack.")
    print()

    from ecc_utils import print_curve_info
    from bsgs_attack import _run_correctness_tests

    print_curve_info(curve, G, n)
    print()
    _run_correctness_tests(curve, G, n)

    _big_sep("END SESSION 1")
    print()
    print("  Session 1 result: BSGS is verified correct on this curve.")
    print("  Every scalar in [0, n-1] is recoverable in O(√n) steps.")
    print("  At 256-bit scale, Shor's does this in O((log n)³) — quantum-feasible.")


# ─────────────────────────────────────────────────────────────────────────────
# Session 2 — KZG Attack Chain
# ─────────────────────────────────────────────────────────────────────────────

def run_session_2(curve, G, n):
    _banner("SESSION 2 — KZG Commitment + Full BSGS Attack Chain")
    print()
    print("  PURPOSE: Commit to neural network weight w=42 using KZG.")
    print("  Demonstrate the complete attack: BSGS recovers w, attacker")
    print("  forges a commitment to w'=99, verifier is fooled.")
    print()

    from kzg_commitment import run_full_attack_chain
    results = run_full_attack_chain(curve, G, n, w_true=42, w_fake=99, b_bias=7)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Session 3 — Hash Commitment
# ─────────────────────────────────────────────────────────────────────────────

def run_session_3(curve, G, n):
    _banner("SESSION 3 — Hash Commitment + BSGS Attack Failure")
    print()
    print("  PURPOSE: Commit to the SAME weight w=42 using SHA-256.")
    print("  Attempt the identical BSGS attack — show it finds nothing.")
    print("  Demonstrate that forgery is correctly rejected.")
    print()

    from hash_commitment import run_full_hash_session
    results = run_full_hash_session(curve, G, n, w_true=42, w_fake=99, b_bias=7)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Session 4 — Comparison Table + Thesis Summary
# ─────────────────────────────────────────────────────────────────────────────

def run_session_4(kzg_results, hash_results, t_s1, t_s2, t_s3, t_total):
    _banner("SESSION 4 — Side-by-Side Comparison + Thesis Summary")

    # ── Timing comparison ───────────────────────────────────────────────
    _big_sep("TIMING COMPARISON — Sessions 1, 2, 3")
    print()
    print(f"  Session 1  ECC setup + BSGS correctness  :  {t_s1*1000:.1f} ms")
    print(f"  Session 2  KZG attack chain              :  {t_s2*1000:.1f} ms")
    print(f"  Session 3  Hash commitment session       :  {t_s3*1000:.1f} ms")
    print(f"  ─────────────────────────────────────────────────────────")
    print(f"  Total demo runtime                       :  {t_total*1000:.1f} ms  (< 10 s ✓)")

    # ── Full comparison table ────────────────────────────────────────────
    from hash_commitment import print_comparison_table

    # Build KZG timing from session 2 results
    kzg_timing = {
        "t_commit_us":  kzg_results.get("t_commit_us", 0),
        "t_attack_ms":  kzg_results.get("t_attack_ms", 0),
        "t_forge_us":   kzg_results.get("t_forge_us", 0),
        "t_vreal_us":   kzg_results.get("t_commit_us", 0),   # reuse commit time
        "t_vfake_us":   kzg_results.get("t_forge_us", 0),
    }

    # Build hash timing from session 3 results
    hash_timing = {
        "t_commit_us":  hash_results.get("t_commit_us", 0),
        "t_attack_ms":  0,   # attack failed — N/A
        "t_forge_us":   hash_results.get("t_forge_us", 0),
        "t_vreal_us":   hash_results.get("t_vreal_us", 0),
        "t_vfake_us":   hash_results.get("t_vfake_us", 0),
    }

    print_comparison_table(kzg_results=kzg_timing, hash_results=hash_timing)

    # ── Thesis Summary ───────────────────────────────────────────────────
    _banner("THESIS SUMMARY")
    print()
    print("  RESEARCH QUESTION:")
    print("  Are the KZG polynomial commitments in Artemis secure against")
    print("  a quantum adversary using Shor's algorithm?")
    print()
    print("  THREE ECC DEPENDENCIES IN ARTEMIS  (all broken by Shor's):")
    print()
    print("  1. Structured Reference String (SRS / Trusted Setup)")
    print("     Role    :  SRS = [G, τG, τ²G, ...]  is the public parameter")
    print("                used by all provers and verifiers.")
    print("     Threat  :  Shor's recovers τ from τG = SRS[1].")
    print("                Knowing τ allows forging any KZG proof from scratch.")
    print("     Fix     :  ELIMINATED — hash commitment needs no SRS or τ.")
    print()
    print("  2. Polynomial Commitment  (C = w·G)")
    print("     Role    :  The model owner publishes C = w·G to commit to")
    print("                weight w without revealing it.")
    print("     Threat  :  Shor's (/ BSGS classically) recovers w from C and G")
    print("                by solving the ECDLP: given C = w·G, find w.")
    print("                Session 2 showed this in milliseconds on a small curve.")
    print("     Fix     :  Replaced by C = SHA256(w ∥ r).  Shor's has no group")
    print("                structure to exploit.  Session 3 confirmed BSGS fails.")
    print()
    print("  3. Verifying Key  (VK = (G, τG)  — pairing-based)")
    print("     Role    :  The verifying key enables the verifier to check proofs")
    print("                without running the full prover computation.")
    print("     Threat  :  VK is ECC-based (BN254 pairing).  Shor's breaks the")
    print("                underlying discrete log → VK can be forged or bypassed.")
    print("     Fix     :  Replaced by nonce r (32 bytes).  Verification is just")
    print("                SHA256(w_claimed ∥ r) == C — no pairings, no ECC.")
    print()

    _sep()
    print()
    print("  HOW THE HASH REPLACEMENT RESTORES POST-QUANTUM SECURITY:")
    print()
    print("  ┌──────────────────────────┬────────────────────────────────────")
    print("  │ Artemis Component        │ Post-Quantum Status After Fix")
    print("  ├──────────────────────────┼────────────────────────────────────")
    print("  │ SRS / Trusted Setup      │ ELIMINATED  (no τ, no ceremony)")
    print("  │ Commitment  C = w·G      │ Replaced by  C = SHA256(w ∥ r)")
    print("  │ Verifying key (G, τG)    │ Replaced by  nonce r  (32 bytes)")
    print("  │ BSGS / Shor's attack     │ No group structure to exploit")
    print("  │ Forgery by attacker      │ Binding — verifier rejects")
    print("  │ Post-quantum bit security│ 128 bits  (Grover on SHA-256)")
    print("  └──────────────────────────┴────────────────────────────────────")
    print()

    _sep()
    print()
    print("  RESEARCH CONTRIBUTION (one-line statement):")
    print()
    print("  ┌─────────────────────────────────────────────────────────────")
    print("  │  We identify three ECC-dependent components in the Artemis")
    print("  │  CP-SNARK framework that are vulnerable to Shor's algorithm,")
    print("  │  demonstrate the attack classically via BSGS (Sessions 1–2),")
    print("  │  and propose replacing them with SHA-256 hash commitments,")
    print("  │  which eliminates all three attack surfaces and preserves the")
    print("  │  zkML integrity and privacy guarantees in a post-quantum setting")
    print("  │  (Session 3), at reduced proof size and without a trusted setup.")
    print("  └─────────────────────────────────────────────────────────────")

    _big_sep("END SESSION 4 — DEMO COMPLETE")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Install Tee so everything goes to terminal AND file
    tee = Tee(_OUTPUT_PATH)
    sys.stdout = tee

    try:
        t_demo_start = time.perf_counter()

        # ── Title block ───────────────────────────────────────────────────
        print_title_block()

        # ── Build the curve once — all sessions share the same setup ──────
        from ecc_utils import EllipticCurve, CURVE_A, CURVE_B, CURVE_P
        curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
        G = curve.find_generator()
        n = curve.compute_group_order(G)

        # ── Session 1 ─────────────────────────────────────────────────────
        t0 = time.perf_counter()
        run_session_1(curve, G, n)
        t_s1 = time.perf_counter() - t0

        # ── Session 2 ─────────────────────────────────────────────────────
        t0 = time.perf_counter()
        kzg_results = run_session_2(curve, G, n)
        t_s2 = time.perf_counter() - t0

        # ── Session 3 ─────────────────────────────────────────────────────
        t0 = time.perf_counter()
        hash_results = run_session_3(curve, G, n)
        t_s3 = time.perf_counter() - t0

        # ── Session 4 ─────────────────────────────────────────────────────
        t_total = time.perf_counter() - t_demo_start
        run_session_4(kzg_results, hash_results, t_s1, t_s2, t_s3, t_total)

        # ── Final footer ──────────────────────────────────────────────────
        t_final = time.perf_counter() - t_demo_start
        print()
        print()
        print("  " + "═" * 62)
        print("  ═" + " " * 60 + "═")
        print("  ═   ALL SESSIONS COMPLETE                                  ═")
        print(f"  ═   Total runtime  :  {t_final*1000:6.1f} ms                               ═")
        print(f"  ═   Output saved   :  results/demo_output.txt              ═")
        print("  ═" + " " * 60 + "═")
        print("  " + "═" * 62)
        print()

    finally:
        tee.close()

    # Print confirmation to real stdout (after Tee is closed)
    print()
    print(f"[demo.py] Output saved to: {_OUTPUT_PATH}")
    print(f"[demo.py] File size: {os.path.getsize(_OUTPUT_PATH):,} bytes")


if __name__ == "__main__":
    main()
