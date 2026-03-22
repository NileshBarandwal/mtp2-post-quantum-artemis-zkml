"""
neural_network.py — Neural Network Wrapper for Session 3
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad

SESSION 3 — Neural network y = w·x + b with hash-based commitment.

PURPOSE:
    Demonstrates the same single-neuron neural network from Sessions 1 and 2,
    now with a hash-based commitment to the weight w=42 instead of a KZG
    elliptic curve commitment.

    Shows the inference path:
        Input x → [Model: y = w·x + b] → Output y
        Weight w is committed: C_kzg = w·G  OR  C_hash = SHA256(w||r)

    Maps to Session 2 structure:
        pc_commit (KZG)  → hc_commit (Hash)
        C = w·G          → C = SHA256(w||r)
        BSGS breaks KZG  → BSGS fails on hash

NEURAL NETWORK MODEL:
    Architecture :  Single neuron (linear)
    Function     :  y = w · x + b
    Weight       :  w = 42  (committed value — same across all sessions)
    Bias         :  b = 7
    Commitment   :  KZG  (Session 2)  vs.  SHA-256 hash  (Session 3)
"""

import hashlib
import time

from ecc_utils import (
    EllipticCurve, CURVE_A, CURVE_B, CURVE_P,
    print_curve_info
)
from bsgs_attack import bsgs
from hash_commitment import (
    HashCommitmentSetup,
    hc_setup,
    hc_commit,
    hc_verify,
    print_comparison_table,
    _sep, _big_sep
)


# ─────────────────────────────────────────────────────────────────────────────
# Neural Network Model (same as Session 2)
# ─────────────────────────────────────────────────────────────────────────────

class SingleNeuron:
    """
    Single-neuron linear neural network: y = w · x + b

    This is the model whose weight is committed in Artemis.
    The model owner proves:
        "I have a model with committed weight C, and for input x it produces y."

    In Artemis CP-SNARK:
        The weight w is the private witness.
        The commitment C is the public input to the verifier.
        The ZK proof certifies: inference is correct without revealing w.

    Here we run BOTH the KZG-committed path (Session 2) and the
    hash-committed path (Session 3) for direct comparison.
    """
    def __init__(self, w, b=7):
        self.w = w    # Private weight
        self.b = b    # Bias term

    def forward(self, x):
        """Forward pass: y = w · x + b"""
        return self.w * x + self.b

    def __repr__(self):
        return f"SingleNeuron(w={self.w}, b={self.b})"


# ─────────────────────────────────────────────────────────────────────────────
# Inference with KZG Commitment  (Session 2 path)
# ─────────────────────────────────────────────────────────────────────────────

def run_kzg_inference(model, x_inputs, curve, G, n):
    """
    Run inference with KZG polynomial commitment on the weight.

    Shows the Session 2 commitment path:
        1. Commit:  C = w·G  (ECC scalar multiplication)
        2. Infer:   y = w·x + b  for each input x
        3. Note:    BSGS can recover w from C → privacy broken

    Returns: (C, inference_results)
    """
    _sep()
    print("  [KZG PATH — Session 2]  Neural network with ECC commitment")
    print()
    print(f"    Model         :  {model}")
    print(f"    Commitment    :  C = w·G  (elliptic curve point)")
    print()

    t0 = time.perf_counter()
    C_kzg = curve.scalar_mul(model.w % n, G)
    t1 = time.perf_counter()
    t_commit_us = (t1 - t0) * 1e6

    print(f"    w = {model.w}  →  C_kzg = {model.w}·G = {C_kzg}")
    print(f"    Commit time   :  {t_commit_us:.2f} µs")
    print(f"    Quantum risk  :  BSGS recovers w={model.w} from C_kzg in O(√n) steps")
    print()
    print(f"    Inference results (y = {model.w}·x + {model.b}):")
    print()

    results = []
    for x in x_inputs:
        y = model.forward(x)
        print(f"      x = {x:>4}  →  y = {model.w}·{x} + {model.b} = {y}")
        results.append((x, y))

    return C_kzg, results


# ─────────────────────────────────────────────────────────────────────────────
# Inference with Hash Commitment  (Session 3 path)
# ─────────────────────────────────────────────────────────────────────────────

def run_hash_inference(model, x_inputs, hc_setup_obj):
    """
    Run inference with hash-based commitment on the weight.

    Shows the Session 3 commitment path:
        1. Commit:  C = SHA256(w||r)  (hash function call)
        2. Infer:   y = w·x + b  for each input x  (same computation)
        3. Note:    BSGS has no attack surface → privacy preserved

    Returns: (C_hash, inference_results)
    """
    _sep()
    print("  [HASH PATH — Session 3]  Neural network with hash commitment")
    print()
    print(f"    Model         :  {model}")
    print(f"    Commitment    :  C = SHA256(w || r)  (hash digest)")
    print()

    t0 = time.perf_counter()
    w_bytes = model.w.to_bytes(8, byteorder='big')
    C_hash = hashlib.sha256(w_bytes + hc_setup_obj.nonce).hexdigest()
    t1 = time.perf_counter()
    t_commit_us = (t1 - t0) * 1e6

    print(f"    w = {model.w}  →  C_hash = SHA256({model.w}||r) = {C_hash}")
    print(f"    Commit time   :  {t_commit_us:.4f} µs")
    print(f"    Quantum risk  :  NONE  (BSGS has no group structure to exploit)")
    print()
    print(f"    Inference results (y = {model.w}·x + {model.b})  [same model]:")
    print()

    results = []
    for x in x_inputs:
        y = model.forward(x)
        print(f"      x = {x:>4}  →  y = {model.w}·{x} + {model.b} = {y}")
        results.append((x, y))

    return C_hash, results


# ─────────────────────────────────────────────────────────────────────────────
# Full Neural Network Session
# ─────────────────────────────────────────────────────────────────────────────

def run_neural_network_session(curve, G, n, w=42, b=7):
    """
    Full neural network demo showing both KZG and hash commitment paths.

    Mirrors the Session 2 neural network context from kzg_commitment.py
    and shows the Session 3 hash replacement side by side.

    Key insight: the neural network computation y = w·x + b is IDENTICAL
    in both cases. The only difference is how w is committed:
        Session 2: C = w·G   → breakable by BSGS/Shor's
        Session 3: C = SHA256(w||r) → no attack surface
    """
    _big_sep("NEURAL NETWORK DEMO — KZG vs Hash Commitment")
    print()
    print(f"  Model     :  y = w·x + b  =  y = {w}·x + {b}")
    print(f"  Weight    :  w = {w}  (private — committed, not revealed)")
    print(f"  Bias      :  b = {b}")
    print(f"  Inputs    :  x ∈ {{1, 2, 3, 5, 10, 100}}")
    print()
    print("  [Slide 14 — Step 1]  Neural network weight w is the private witness.")
    print("  [Slide 14 — Step 2]  Constraint: output = w · input + b")
    print("  The commitment proves the model is fixed WITHOUT revealing w.")
    print()

    model = SingleNeuron(w=w, b=b)
    x_inputs = [1, 2, 3, 5, 10, 100]

    # ── KZG path (Session 2) ───────────────────────────────────────────────
    _big_sep("KZG PATH — Session 2  (ECC-based, quantum-vulnerable)")
    C_kzg, kzg_results = run_kzg_inference(model, x_inputs, curve, G, n)

    m = __import__('math').isqrt(n) + 1
    print()
    _sep()
    print(f"  [BSGS CHECK]  Can the attacker recover w from C_kzg?")
    print()
    t0 = time.perf_counter()
    w_recovered = bsgs(C_kzg, G, n, curve)
    t1 = time.perf_counter()
    t_bsgs = (t1 - t0) * 1000
    if w_recovered is not None and curve.scalar_mul(w_recovered, G) == C_kzg:
        print(f"    BSGS recovered :  w = {w_recovered}  in {t_bsgs:.4f} ms  ← SECRET EXPOSED")
        print(f"    Attacker knows :  y = {w_recovered}·x + {b}  (the exact model)")
        print(f"    Privacy        :  BROKEN  (KZG commitment leaks w to quantum adversary)")
    else:
        print(f"    BSGS result    :  not recovered  (unexpected)")

    # ── Hash path (Session 3) ──────────────────────────────────────────────
    _big_sep("HASH PATH — Session 3  (SHA-256-based, post-quantum safe)")
    hc_setup_obj = hc_setup(verbose=False)

    C_hash, hash_results = run_hash_inference(model, x_inputs, hc_setup_obj)

    _sep()
    print(f"  [BSGS CHECK]  Can the attacker recover w from C_hash?")
    print()
    print(f"    C_hash = {C_hash}")
    print(f"    C_hash is a SHA-256 digest — NOT an EC point.")
    print(f"    BSGS requires target Q = w·G on the curve. C_hash is not such a point.")
    print(f"    Shor's algorithm requires a group element. SHA-256 output has no group.")
    print()
    print(f"    BSGS applicable :  NO  →  no cyclic group to exploit")
    print(f"    Attack result   :  FAILED  ← w={w} remains private")
    print(f"    Privacy         :  INTACT  (hash commitment is post-quantum safe)")
    print()

    # ── Side-by-side inference comparison ─────────────────────────────────
    _big_sep("INFERENCE COMPARISON  (y = w·x + b, same result both paths)")
    print()
    print(f"  {'x':>6}  │  {'KZG path':>12}  │  {'Hash path':>12}  │  {'Same?':>6}")
    print(f"  {'─'*6}  │  {'─'*12}  │  {'─'*12}  │  {'─'*6}")
    for (x1, y1), (x2, y2) in zip(kzg_results, hash_results):
        same = "✓" if y1 == y2 else "✗"
        print(f"  {x1:>6}  │  {y1:>12}  │  {y2:>12}  │  {same:>6}")
    print()
    print("  Inference results are IDENTICAL — the commitment scheme does not")
    print("  affect model accuracy. Only the privacy guarantee changes.")

    # ── Commitment comparison ──────────────────────────────────────────────
    _big_sep("COMMITMENT COMPARISON  (what the verifier sees)")
    print()
    print(f"  KZG commitment (Session 2):")
    print(f"    C_kzg  = {C_kzg}  (EC point)")
    print(f"    Type   : elliptic curve point — has group structure")
    print(f"    Risk   : BSGS/Shor's can solve w·G = C_kzg → w recovered")
    print()
    print(f"  Hash commitment (Session 3):")
    print(f"    C_hash = {C_hash}")
    print(f"    Type   : SHA-256 digest — no group structure")
    print(f"    Safe   : BSGS has no attack surface → w={w} remains hidden")
    print()
    print(f"  Both commit to the SAME weight w={w}.")
    print(f"  Only the hash-based commitment is safe against quantum adversaries.")

    _big_sep("END NEURAL NETWORK SESSION")

    return {
        "C_kzg": C_kzg,
        "C_hash": C_hash,
        "kzg_results": kzg_results,
        "hash_results": hash_results,
        "w_recovered_by_bsgs": w_recovered,
        "t_bsgs_ms": t_bsgs,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Build the curve (same parameters as Sessions 1 and 2)
    curve = EllipticCurve(CURVE_A, CURVE_B, CURVE_P)
    G = curve.find_generator()
    n = curve.compute_group_order(G)

    # Print curve parameters (same header as all sessions)
    print_curve_info(curve, G, n)

    # Run the neural network session
    results = run_neural_network_session(
        curve, G, n,
        w=42,    # Same weight as Sessions 1 and 2
        b=7,     # Same bias
    )

    # Print final side-by-side comparison table (KZG vs Hash)
    print_comparison_table(
        kzg_results={
            "t_commit_us": 0,      # Will be filled if run after kzg_commitment.py
            "t_attack_ms": results["t_bsgs_ms"],
            "t_forge_us": 0,
            "t_vreal_us": 0,
            "t_vfake_us": 0,
        },
        hash_results=None
    )
