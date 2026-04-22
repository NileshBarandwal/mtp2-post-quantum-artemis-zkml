"""
fri_commitment_poseidon.py — FRI-style Polynomial Commitment using Poseidon Hash
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad

This is the production-ready version of fri_commitment.py.
The ONLY change from fri_commitment.py is the hash function:
  SHA-256 (bytes-based)  →  Poseidon (field-arithmetic-based)

Everything else is identical:
  - All 7 PC operations (Setup, Commit, Verify, Open, Check, BatchOpen, BatchCheck)
  - Merkle tree structure
  - Path walking
  - Domain and nonce

Poseidon parameters (64-bit field):
  Prime:          p = 18446744073709551359  (poseidon.prime_64)
  State size:     t = 9
  Full rounds:    R_F = 8
  Partial rounds: R_P = 41
  S-box power:    alpha = 5  (x^5 over F_p)
  Input rate:     8 field elements per call

Security: collision resistance over F_p
  Classical: 2^64 (birthday bound on 64-bit outputs)
  Quantum:   2^32 (Grover's algorithm halves bit-security)

Note: For 128-bit post-quantum security, use Poseidon with a 256-bit
prime (e.g., BN254 scalar field). The 64-bit variant is used here to
match the elliptic curve field used in the BSGS experiments.
"""

import math
import os
import sys
import time

import poseidon as _poseidon_lib
from poseidon.hash import Poseidon as _PoseidonHasher


# ---------------------------------------------------------------------------
# Poseidon hash setup (initialised once at module load)
# ---------------------------------------------------------------------------

# 64-bit prime matching poseidon library's pre-computed parameters
POSEIDON_PRIME = _poseidon_lib.prime_64        # 18446744073709551359
_T             = 9                              # state width
_FULL_ROUND    = 8
_PARTIAL_ROUND = 41
_ALPHA         = 5                              # S-box: x^5

# Suppress noisy initialisation prints from the library
_old_stdout = sys.stdout
sys.stdout  = open(os.devnull, 'w')
_HASHER = _PoseidonHasher(
    p             = POSEIDON_PRIME,
    security_level= 64,
    alpha         = _ALPHA,
    input_rate    = _T - 1,
    t             = _T,
    full_round    = _FULL_ROUND,
    partial_round = _PARTIAL_ROUND,
    mds_matrix    = _poseidon_lib.matrix_64,
    rc_list       = _poseidon_lib.round_constants_64,
)
sys.stdout.close()
sys.stdout = _old_stdout


def _poseidon(field_elements: list) -> int:
    """
    Hash a list of field elements using Poseidon over F_p.
    Inputs are reduced mod POSEIDON_PRIME before hashing.
    Returns a single field element (int).
    """
    inputs = [int(x) % POSEIDON_PRIME for x in field_elements]
    result = _HASHER.run_hash(inputs)
    return int(result)


def _poseidon_to_bytes(field_elements: list) -> bytes:
    """
    Hash field elements with Poseidon and return as 8-byte big-endian bytes.
    Used wherever SHA-256 previously returned bytes (Merkle tree storage).
    """
    val = _poseidon(field_elements)
    return val.to_bytes(8, 'big')


# ---------------------------------------------------------------------------
# Polynomial evaluation
# ---------------------------------------------------------------------------

def poly_eval(coeffs, x):
    """Evaluate polynomial at x using Horner's method (plain integers)."""
    result = 0
    for c in reversed(coeffs):
        result = result * x + c
    return result


def _poly_str(coeffs):
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


# ---------------------------------------------------------------------------
# Merkle tree helpers (identical structure to SHA-256 version)
# ---------------------------------------------------------------------------

_ZERO_HASH = b'\x00' * 8   # 8-byte zero (matches Poseidon output size)


def _build_merkle_tree(leaf_hashes):
    """
    Build a complete binary Merkle tree from leaf hashes (bytes).
    Internal nodes: node = Poseidon(left_int, right_int) as bytes.
    """
    n = len(leaf_hashes)
    padded_n = 1
    while padded_n < n:
        padded_n <<= 1

    padded = list(leaf_hashes) + [_ZERO_HASH] * (padded_n - n)
    tree   = [_ZERO_HASH] * (2 * padded_n)

    for i in range(padded_n):
        tree[padded_n + i] = padded[i]

    for i in range(padded_n - 1, 0, -1):
        left  = int.from_bytes(tree[2 * i],     'big')
        right = int.from_bytes(tree[2 * i + 1], 'big')
        tree[i] = _poseidon_to_bytes([left, right])

    num_levels = int(math.log2(padded_n)) if padded_n > 1 else 0
    return tree, tree[1], padded_n, num_levels


def _get_merkle_path(tree, x):
    padded_n = len(tree) // 2
    idx = padded_n + x
    path = []
    while idx > 1:
        sibling = idx ^ 1
        path.append(tree[sibling])
        idx >>= 1
    return path


def _walk_merkle_path(root, x, leaf_hash, path, verbose=False):
    idx     = x
    current = leaf_hash
    steps   = []

    for i, sibling_hash in enumerate(path):
        l = int.from_bytes(current,      'big')
        r = int.from_bytes(sibling_hash, 'big')

        if idx % 2 == 0:
            new_current = _poseidon_to_bytes([l, r])
            side = "left"
        else:
            new_current = _poseidon_to_bytes([r, l])
            side = "right"

        steps.append({
            'level':   i + 1,
            'idx':     idx,
            'side':    side,
            'sibling': sibling_hash,
            'computed': new_current,
        })

        if verbose:
            print(f"    Step {i + 1}: pos={idx} ({side} child)")
            print(f"             sibling  = {sibling_hash.hex()}")
            print(f"             parent   = Poseidon({l}, {r})")
            print(f"             result   = {new_current.hex()}")

        current = new_current
        idx >>= 1

    result = 1 if current == root else 0
    return result, current, steps


# ---------------------------------------------------------------------------
# PC.Setup
# ---------------------------------------------------------------------------

def pc_setup(D):
    """
    PC.Setup(D) — Poseidon version.
    Nonce is a random 64-bit field element (instead of random bytes).
    """
    t0 = time.perf_counter()

    nonce_int = int.from_bytes(os.urandom(8), 'big') % POSEIDON_PRIME
    xs = list(range(D + 2))

    ck = {
        'domain':        xs,
        'D':             D,
        'nonce':         nonce_int,
        'hash_function': 'Poseidon (64-bit prime field)',
        'prime':         POSEIDON_PRIME,
        'domain_size':   len(xs),
    }

    elapsed_us = (time.perf_counter() - t0) * 1e6

    print()
    print("=" * 66)
    print("  PC.Setup  [FRI + Poseidon — Definition 2.2, Op 1]")
    print("=" * 66)
    print(f"  Degree bound     :  D = {D}")
    print(f"  Domain           :  xs = {xs}")
    print(f"  Domain size      :  D+2 = {len(xs)}  points")
    print(f"  Hash function    :  Poseidon (64-bit, t={_T}, alpha={_ALPHA})")
    print(f"  Prime field      :  p = {POSEIDON_PRIME}")
    print(f"  Nonce (field el) :  {nonce_int}  (random element of F_p)")
    print(f"  Setup time       :  {elapsed_us:.2f} µs")
    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │  No secret trapdoor. No trusted setup. No toxic waste.  │")
    print("  │  No SRS to generate. No ceremony required.              │")
    print("  │  Security: Poseidon collision resistance over F_p.      │")
    print("  └─────────────────────────────────────────────────────────┘")
    print("=" * 66)

    return ck, elapsed_us


# ---------------------------------------------------------------------------
# PC.Commit
# ---------------------------------------------------------------------------

def pc_commit(ck, g, d):
    """
    PC.Commit(ck, g, d) — Poseidon version.
    leaf[i] = Poseidon(g(xs[i]), nonce)  as 8-byte field element
    Internal: node = Poseidon(left, right)
    """
    t0 = time.perf_counter()

    xs    = ck['domain']
    nonce = ck['nonce']

    evals  = [poly_eval(g, x) for x in xs]
    leaves = [_poseidon_to_bytes([ev % POSEIDON_PRIME, nonce]) for ev in evals]
    tree, root, padded_n, num_levels = _build_merkle_tree(leaves)

    elapsed_us = (time.perf_counter() - t0) * 1e6

    print()
    print("-" * 66)
    print("  PC.Commit  [FRI+Poseidon — Merkle commitment]")
    print("-" * 66)
    print(f"  Polynomial g   :  g(X) = {_poly_str(g)}  (degree {d})")
    print(f"  Domain         :  xs = {xs}")
    print()
    print("  Step 1 — Evaluate g at all domain points:")
    for x, ev in zip(xs, evals):
        print(f"    g({x}) = {ev}")
    print()
    print("  Step 2 — Hash each evaluation with Poseidon:")
    print(f"    leaf[i] = Poseidon(g(xᵢ) mod p, nonce)")
    for i, (ev, lf) in enumerate(zip(evals, leaves)):
        print(f"    leaf[{i}] = Poseidon({ev % POSEIDON_PRIME}, {nonce}) = {lf.hex()}")
    print()
    print("  Step 3 — Build Merkle tree (internal nodes: Poseidon(left, right)):")
    print(f"    Padded leaf count : {padded_n}")
    print(f"    Number of levels  : {num_levels}")
    print(f"    Root              : {root.hex()}")
    print()
    print(f"  Commitment root  :  {root.hex()}")
    print(f"  Root size        :  {len(root)} bytes (Poseidon field element)")
    print(f"  Commit time      :  {elapsed_us:.2f} µs")
    print("-" * 66)

    return root, evals, tree, elapsed_us


# ---------------------------------------------------------------------------
# PC.Verify
# ---------------------------------------------------------------------------

def pc_verify(ck, root, g):
    t0 = time.perf_counter()

    xs    = ck['domain']
    nonce = ck['nonce']

    evals  = [poly_eval(g, x) for x in xs]
    leaves = [_poseidon_to_bytes([ev % POSEIDON_PRIME, nonce]) for ev in evals]
    _, new_root, _, _ = _build_merkle_tree(leaves)

    result     = 1 if new_root == root else 0
    elapsed_us = (time.perf_counter() - t0) * 1e6

    print()
    print("-" * 66)
    print("  PC.Verify  [Recompute and compare Poseidon Merkle root]")
    print("-" * 66)
    print(f"  Recomputed root  :  {new_root.hex()}")
    print(f"  Committed root   :  {root.hex()}")
    print(f"  Match            :  {new_root == root}")
    print(f"  PC.Verify        :  {result}  {'← VALID ✓' if result == 1 else '← INVALID ✗'}")
    print(f"  Verify time      :  {elapsed_us:.2f} µs")
    print("-" * 66)

    return result, elapsed_us


# ---------------------------------------------------------------------------
# PC.Open
# ---------------------------------------------------------------------------

def pc_open(ck, g, evals, merkle_tree, x, d):
    t0 = time.perf_counter()

    xs = ck['domain']
    y  = poly_eval(g, xs[x])
    path = _get_merkle_path(merkle_tree, x)

    elapsed_us = (time.perf_counter() - t0) * 1e6
    proof_size = len(path) * 8   # 8 bytes per Poseidon output

    print()
    print("-" * 66)
    print("  PC.Open  [Poseidon Merkle evaluation proof]")
    print("-" * 66)
    print(f"  Domain index   :  x = {x}  (xs[{x}] = {xs[x]})")
    print(f"  Evaluation     :  y = g({xs[x]}) = {y}")
    print(f"  Merkle path    :  {len(path)} sibling hashes ({proof_size} bytes)")
    for i, h in enumerate(path):
        print(f"    path[{i}] = {h.hex()}")
    print(f"  Open time      :  {elapsed_us:.2f} µs")
    print("-" * 66)

    return y, path, elapsed_us, proof_size


# ---------------------------------------------------------------------------
# PC.Check
# ---------------------------------------------------------------------------

def pc_check(ck, root, x, y, proof):
    t0 = time.perf_counter()

    nonce = ck['nonce']
    leaf  = _poseidon_to_bytes([int(y) % POSEIDON_PRIME, nonce])

    print()
    print("-" * 66)
    print("  PC.Check  [Walk Poseidon Merkle path from leaf to root]")
    print("-" * 66)
    print(f"  Claimed y       :  {y}")
    print(f"  Leaf hash       :  Poseidon({int(y) % POSEIDON_PRIME}, {nonce}) = {leaf.hex()}")
    print(f"  Merkle path     :  {len(proof)} sibling hashes")
    print()
    print("  Walking Merkle path:")

    result, computed_root, _ = _walk_merkle_path(root, x, leaf, proof, verbose=True)

    elapsed_us = (time.perf_counter() - t0) * 1e6

    print()
    print(f"  Computed root   :  {computed_root.hex()}")
    print(f"  Expected root   :  {root.hex()}")
    print(f"  Match           :  {computed_root == root}")
    print(f"  PC.Check        :  {result}  {'← VALID ✓' if result == 1 else '← INVALID ✗'}")
    print(f"  Check time      :  {elapsed_us:.2f} µs")
    print("-" * 66)

    return result, elapsed_us


# ---------------------------------------------------------------------------
# PC.BatchOpen
# ---------------------------------------------------------------------------

def pc_batch_open(ck, g, evals, merkle_tree, xs_list, d):
    t0 = time.perf_counter()

    xs    = ck['domain']
    pairs = []
    total_proof_size = 0

    print()
    print("-" * 66)
    print("  PC.BatchOpen  [Multiple Poseidon Merkle evaluation proofs]")
    print("-" * 66)
    print(f"  Opening at indices : {xs_list}")
    print(f"  Domain points      : {[xs[i] for i in xs_list]}")
    print()

    for x in xs_list:
        y    = poly_eval(g, xs[x])
        path = _get_merkle_path(merkle_tree, x)
        ps   = len(path) * 8
        total_proof_size += ps
        pairs.append((y, path))

        print(f"  ── x = {xs[x]} (index {x}) ──")
        print(f"    y = g({xs[x]}) = {y}")
        print(f"    Merkle path ({len(path)} hashes, {ps} bytes):")
        for i, h in enumerate(path):
            print(f"      path[{i}] = {h.hex()}")

    elapsed_us = (time.perf_counter() - t0) * 1e6

    print()
    print(f"  Total batch proof size :  {total_proof_size} bytes")
    print(f"  BatchOpen time         :  {elapsed_us:.2f} µs")
    print("-" * 66)

    return pairs, elapsed_us, total_proof_size


# ---------------------------------------------------------------------------
# PC.BatchCheck
# ---------------------------------------------------------------------------

def pc_batch_check(ck, root, xs_list, pairs):
    t0 = time.perf_counter()

    xs       = ck['domain']
    nonce    = ck['nonce']
    all_pass = True

    print()
    print("-" * 66)
    print("  PC.BatchCheck  [Verify all Poseidon Merkle evaluation proofs]")
    print("-" * 66)

    for x, (y, path) in zip(xs_list, pairs):
        leaf = _poseidon_to_bytes([int(y) % POSEIDON_PRIME, nonce])
        ok, computed_root, _ = _walk_merkle_path(root, x, leaf, path, verbose=False)
        status = "PASS ✓" if ok == 1 else "FAIL ✗"
        print(f"  x={xs[x]:2d} (idx {x}), y={y}: {status}   "
              f"root = {computed_root.hex()}")
        if ok != 1:
            all_pass = False

    overall    = 1 if all_pass else 0
    elapsed_us = (time.perf_counter() - t0) * 1e6

    print()
    print(f"  BatchCheck result  :  {overall}  "
          f"{'← ALL PROOFS VALID ✓' if overall == 1 else '← SOME PROOFS FAILED ✗'}")
    print(f"  BatchCheck time    :  {elapsed_us:.2f} µs")
    print("-" * 66)

    return overall, elapsed_us
