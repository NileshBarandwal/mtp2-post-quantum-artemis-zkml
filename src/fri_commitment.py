"""
fri_commitment.py — FRI-style Hash-based Polynomial Commitment Scheme
MTP2 Demo: Post-Quantum Security for Artemis zkML
Author: Nilesh R. Barandwal, IIT Dharwad
Date: March 2026

NOTE: Production implementation uses Poseidon hash (ZK-friendly, ~250 constraints
vs ~27,000 for SHA-256 inside ZK arithmetic circuits). SHA-256 is used here as a
prototype to demonstrate the structural post-quantum security properties of
FRI-based commitments.

Implements ALL operations from Definition 2.2 of:
  Lycklama et al., "Artemis: Efficient zkML with Batched Proof Aggregation"
  arXiv:2409.12055

  PC = (Setup, Commit, Verify, Open, Check, BatchOpen, BatchCheck)

KEY DIFFERENCE FROM KZG:
  KZG: commitment = w·G  (ECC point, group structure, ECDLP assumption)
  FRI: commitment = Merkle root of hashed evaluations (no group, collision resistance)

  BSGS / Shor's require a cyclic group with a generator G and a target Q = w·G.
  A SHA-256 Merkle root has NO group structure — these attacks cannot start.
"""

import hashlib
import math
import os
import time


# ---------------------------------------------------------------------------
# Hash function (SHA-256 as Poseidon stand-in)
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Polynomial evaluation (plain integers — evaluations feed into hash)
# ---------------------------------------------------------------------------

def poly_eval(coeffs, x):
    """
    Evaluate polynomial at x using Horner's method (plain integer arithmetic).
    coeffs = [a0, a1, a2, ...] → g(x) = a0 + a1·x + a2·x² + ...
    No modular reduction — evaluations go directly into SHA-256 input.
    """
    result = 0
    for c in reversed(coeffs):
        result = result * x + c
    return result


def _poly_str(coeffs):
    """Format polynomial coefficients as a human-readable string."""
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
# Merkle tree helpers
# ---------------------------------------------------------------------------

def _build_merkle_tree(leaf_hashes):
    """
    Build a complete binary Merkle tree from leaf hashes.

    Pads to the next power of 2 with zero-byte hashes.
    Storage: 1-indexed list; tree[1] = root, leaves at tree[padded_n .. 2*padded_n-1].

    Hashing: tree[i] = SHA256(tree[2i] || tree[2i+1])  for i = 1 .. padded_n-1

    Returns: (tree, root, padded_n, num_levels)
    """
    n = len(leaf_hashes)
    padded_n = 1
    while padded_n < n:
        padded_n <<= 1

    # Pad with zero hashes so tree is always a complete binary tree
    padded = list(leaf_hashes) + [b'\x00' * 32] * (padded_n - n)

    # 1-indexed tree allocation: index 0 is unused
    tree = [b'\x00' * 32] * (2 * padded_n)

    # Fill leaf level
    for i in range(padded_n):
        tree[padded_n + i] = padded[i]

    # Build internal nodes bottom-up
    for i in range(padded_n - 1, 0, -1):
        tree[i] = _sha256(tree[2 * i] + tree[2 * i + 1])

    num_levels = int(math.log2(padded_n)) if padded_n > 1 else 0
    return tree, tree[1], padded_n, num_levels


def _get_merkle_path(tree, x):
    """
    Extract Merkle authentication path for leaf at position x (0-indexed).

    The path is the list of sibling hashes from leaf level up to (but not
    including) the root.  Together with the leaf hash, this path allows
    recomputing the root.

    Returns: list of sibling hashes, one per Merkle level.
    """
    padded_n = len(tree) // 2
    idx = padded_n + x   # 1-indexed tree position of leaf x
    path = []
    while idx > 1:
        sibling = idx ^ 1   # flip last bit: left↔right sibling
        path.append(tree[sibling])
        idx >>= 1            # move to parent
    return path


def _walk_merkle_path(root, x, leaf_hash, path, verbose=False):
    """
    Walk Merkle authentication path from leaf to root.

    At each level: determine whether current node is left or right child
    (based on parity of current index), combine with sibling hash from path.

    Returns: (result, computed_root, steps_list)
      result: 1 if computed_root == root, else 0
    """
    idx = x          # 0-indexed leaf position (matches padded leaf index)
    current = leaf_hash
    steps = []

    for i, sibling_hash in enumerate(path):
        if idx % 2 == 0:                                 # left child
            new_current = _sha256(current + sibling_hash)
            side = "left"
        else:                                             # right child
            new_current = _sha256(sibling_hash + current)
            side = "right"

        steps.append({
            'level': i + 1,
            'idx': idx,
            'side': side,
            'sibling': sibling_hash,
            'computed': new_current,
        })

        if verbose:
            print(f"    Step {i + 1}: pos={idx} ({side} child)")
            print(f"             sibling  = {sibling_hash.hex()}")
            if idx % 2 == 0:
                print(f"             parent   = SHA256(current ‖ sibling)")
            else:
                print(f"             parent   = SHA256(sibling ‖ current)")
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
    PC.Setup(D) → (ck, timing_us)

    FRI-style setup: NO secret trapdoor τ, NO structured reference string (SRS),
    NO trusted setup ceremony, NO toxic waste.

    The only public parameter is a randomly sampled nonce (domain separator)
    and an explicit evaluation domain xs = [0, 1, 2, ..., D+1].

    Security basis: SHA-256 collision resistance (post-quantum: 2^128 under Grover).
    """
    t0 = time.perf_counter()

    nonce = os.urandom(16)
    xs = list(range(D + 2))

    ck = {
        'domain': xs,
        'D': D,
        'nonce': nonce,
        'hash_function': 'SHA-256 (Poseidon in production)',
        'domain_size': len(xs),
    }

    t1 = time.perf_counter()
    elapsed_us = (t1 - t0) * 1e6

    print()
    print("=" * 66)
    print("  PC.Setup  [FRI-style Hash-based — Definition 2.2, Op 1]")
    print("=" * 66)
    print(f"  Degree bound     :  D = {D}")
    print(f"  Domain           :  xs = {xs}")
    print(f"  Domain size      :  D+2 = {len(xs)}  points")
    print(f"  Hash function    :  {ck['hash_function']}")
    print(f"  Nonce            :  {nonce.hex()}  (public random, {len(nonce)} bytes)")
    print(f"  Nonce size       :  {len(nonce)} bytes")
    print()
    print(f"  Setup time       :  {elapsed_us:.2f} µs")
    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │  No secret trapdoor. No trusted setup. No toxic waste.  │")
    print("  │  No SRS to generate. No ceremony required.              │")
    print("  │  Security rests on SHA-256 collision resistance only.   │")
    print("  └─────────────────────────────────────────────────────────┘")
    print("=" * 66)

    return ck, elapsed_us


# ---------------------------------------------------------------------------
# PC.Commit
# ---------------------------------------------------------------------------

def pc_commit(ck, g, d):
    """
    PC.Commit(ck, g, d) → (root, evals, tree, timing_us)

    Steps:
      1. Evaluate polynomial g at all domain points: evals[i] = g(xs[i])
      2. Hash each evaluation:  leaf[i] = SHA256(str(evals[i]).encode() + nonce)
      3. Build Merkle tree bottom-up using SHA256(left ‖ right) at each level
      4. Root = Merkle root (32-byte SHA-256 hash, displayed as hex)
    """
    t0 = time.perf_counter()

    xs = ck['domain']
    nonce = ck['nonce']

    # Step 1: Evaluate polynomial at all domain points
    evals = [poly_eval(g, x) for x in xs]

    # Step 2: Hash each evaluation to produce Merkle leaves
    leaves = [_sha256(str(ev).encode() + nonce) for ev in evals]

    # Step 3: Build Merkle tree
    tree, root, padded_n, num_levels = _build_merkle_tree(leaves)

    t1 = time.perf_counter()
    elapsed_us = (t1 - t0) * 1e6

    print()
    print("─" * 66)
    print("  PC.Commit  [FRI — Merkle commitment to polynomial evaluations]")
    print("─" * 66)
    print(f"  Polynomial g   :  g(X) = {_poly_str(g)}  (degree {d})")
    print(f"  Coefficients   :  {g}")
    print(f"  Domain         :  xs = {xs}")
    print()

    # Step 1 printout
    print(f"  Step 1 — Evaluate g at all domain points:")
    for x, ev in zip(xs, evals):
        print(f"    g({x}) = {ev}")

    # Step 2 printout
    print()
    print(f"  Step 2 — Hash each evaluation:")
    print(f"    leaf[i] = SHA256(str(g(xᵢ)).encode() ‖ nonce)")
    for i, (ev, lf) in enumerate(zip(evals, leaves)):
        print(f"    leaf[{i}] = SHA256('{ev}' ‖ nonce) = {lf.hex()[:32]}...")

    # Step 3 printout — Merkle tree levels
    print()
    print(f"  Step 3 — Build Merkle tree:")
    print(f"    Padded leaf count : {padded_n}  (next power of 2 ≥ {len(xs)})")
    print(f"    Number of levels  : {num_levels}")
    print()

    # Leaf level
    print(f"    ── Leaf level (level {num_levels}, {padded_n} nodes) ──")
    for i in range(padded_n):
        h = tree[padded_n + i]
        marker = "  [real]" if i < len(xs) else "  [padding]"
        print(f"      [{i:2d}] = {h.hex()[:48]}...{marker}")

    # Internal levels (from leaves up to just below root)
    for lvl in range(num_levels - 1, 0, -1):
        nodes_here = 1 << lvl           # 2^lvl nodes at this level
        start_idx = nodes_here          # 1-indexed start
        print(f"    ── Level {lvl} ({nodes_here} nodes) ──")
        for i in range(start_idx, 2 * start_idx):
            print(f"      [{i:2d}] = {tree[i].hex()[:48]}...")

    # Root
    print(f"    ── Root (level 0) ──")
    print(f"      root = {root.hex()}")

    print()
    print(f"  Commitment root  :  {root.hex()}")
    print(f"  Root size        :  {len(root)} bytes  (SHA-256 output, fixed)")
    print(f"  Commit time      :  {elapsed_us:.2f} µs")
    print(f"  Proof size (open):  {num_levels} × 32 = {num_levels * 32} bytes  (Merkle path)")
    print("─" * 66)

    return root, evals, tree, elapsed_us


# ---------------------------------------------------------------------------
# PC.Verify
# ---------------------------------------------------------------------------

def pc_verify(ck, root, g):
    """
    PC.Verify(ck, root, g) → (result, timing_us)

    Recompute commitment from g and check that it matches the stored root.
    If root matches → commitment is valid (polynomial g was honestly committed).
    """
    t0 = time.perf_counter()

    xs = ck['domain']
    nonce = ck['nonce']

    evals = [poly_eval(g, x) for x in xs]
    leaves = [_sha256(str(ev).encode() + nonce) for ev in evals]
    _, new_root, _, _ = _build_merkle_tree(leaves)

    result = 1 if new_root == root else 0

    t1 = time.perf_counter()
    elapsed_us = (t1 - t0) * 1e6

    print()
    print("─" * 66)
    print("  PC.Verify  [Recompute and compare Merkle root]")
    print("─" * 66)
    print(f"  Recomputed root  :  {new_root.hex()}")
    print(f"  Committed root   :  {root.hex()}")
    print(f"  Match            :  {new_root == root}")
    print(f"  PC.Verify        :  {result}  {'← VALID ✓' if result == 1 else '← INVALID ✗'}")
    print(f"  Verify time      :  {elapsed_us:.2f} µs")
    print("─" * 66)

    return result, elapsed_us


# ---------------------------------------------------------------------------
# PC.Open
# ---------------------------------------------------------------------------

def pc_open(ck, g, evals, merkle_tree, x, d):
    """
    PC.Open(ck, g, evals, merkle_tree, x, d) → (y, path, timing_us, proof_size)

    Open polynomial at domain index x.
    y = g(xs[x]) is the evaluation; path is the Merkle authentication path.
    The path proves that leaf[x] was used to construct the committed root.
    """
    t0 = time.perf_counter()

    xs = ck['domain']
    y = poly_eval(g, xs[x])
    path = _get_merkle_path(merkle_tree, x)

    t1 = time.perf_counter()
    elapsed_us = (t1 - t0) * 1e6
    proof_size = len(path) * 32

    print()
    print("─" * 66)
    print("  PC.Open  [Merkle evaluation proof at point x]")
    print("─" * 66)
    print(f"  Domain index   :  x = {x}  (domain point xs[{x}] = {xs[x]})")
    print(f"  Evaluation     :  y = g({xs[x]}) = {y}")
    print(f"  Merkle path    :  {len(path)} sibling hashes")
    for i, h in enumerate(path):
        print(f"    path[{i}] = {h.hex()}")
    print()
    print(f"  Proof size     :  {len(path)} × 32 = {proof_size} bytes")
    print(f"  Open time      :  {elapsed_us:.2f} µs")
    print("─" * 66)

    return y, path, elapsed_us, proof_size


# ---------------------------------------------------------------------------
# PC.Check
# ---------------------------------------------------------------------------

def pc_check(ck, root, x, y, proof):
    """
    PC.Check(ck, root, x, y, proof) → (result, timing_us)

    Steps:
      1. Recompute leaf:  SHA256(str(y).encode() + nonce)
      2. Walk Merkle path from leaf to root using sibling hashes in proof
      3. Compare computed root against committed root
    """
    t0 = time.perf_counter()

    nonce = ck['nonce']

    leaf = _sha256(str(y).encode() + nonce)

    print()
    print("─" * 66)
    print("  PC.Check  [Walk Merkle path from leaf to root]")
    print("─" * 66)
    print(f"  Claimed y       :  {y}")
    print(f"  Leaf hash       :  SHA256('{y}' ‖ nonce) = {leaf.hex()}")
    print(f"  Merkle path     :  {len(proof)} sibling hashes")
    print()
    print("  Walking Merkle path:")

    result, computed_root, _ = _walk_merkle_path(root, x, leaf, proof, verbose=True)

    print()
    print(f"  Computed root   :  {computed_root.hex()}")
    print(f"  Expected root   :  {root.hex()}")
    print(f"  Match           :  {computed_root == root}")
    print(f"  PC.Check        :  {result}  {'← VALID ✓' if result == 1 else '← INVALID ✗'}")

    t1 = time.perf_counter()
    elapsed_us = (t1 - t0) * 1e6
    print(f"  Check time      :  {elapsed_us:.2f} µs")
    print("─" * 66)

    return result, elapsed_us


# ---------------------------------------------------------------------------
# PC.BatchOpen
# ---------------------------------------------------------------------------

def pc_batch_open(ck, g, evals, merkle_tree, xs_list, d):
    """
    PC.BatchOpen(ck, g, evals, merkle_tree, xs_list, d)
    → (pairs, timing_us, total_proof_size)

    Open polynomial at multiple domain indices simultaneously.
    Returns list of (y, merkle_path) pairs, one per evaluation point.
    """
    t0 = time.perf_counter()

    xs = ck['domain']
    pairs = []
    total_proof_size = 0

    print()
    print("─" * 66)
    print("  PC.BatchOpen  [Multiple evaluation proofs simultaneously]")
    print("─" * 66)
    domain_pts = [xs[i] for i in xs_list]
    print(f"  Opening at indices : {xs_list}")
    print(f"  Domain points      : {domain_pts}")
    print()

    for x in xs_list:
        y = poly_eval(g, xs[x])
        path = _get_merkle_path(merkle_tree, x)
        proof_size = len(path) * 32
        total_proof_size += proof_size
        pairs.append((y, path))

        print(f"  ── x = {xs[x]} (index {x}) ──")
        print(f"    y = g({xs[x]}) = {y}")
        print(f"    Merkle path ({len(path)} hashes, {proof_size} bytes):")
        for i, h in enumerate(path):
            print(f"      path[{i}] = {h.hex()}")

    t1 = time.perf_counter()
    elapsed_us = (t1 - t0) * 1e6

    print()
    print(f"  Total batch proof size :  {total_proof_size} bytes  "
          f"({len(xs_list)} openings × {total_proof_size // len(xs_list)} bytes each)")
    print(f"  BatchOpen time         :  {elapsed_us:.2f} µs")
    print("─" * 66)

    return pairs, elapsed_us, total_proof_size


# ---------------------------------------------------------------------------
# PC.BatchCheck
# ---------------------------------------------------------------------------

def pc_batch_check(ck, root, xs_list, pairs):
    """
    PC.BatchCheck(ck, root, xs_list, pairs) → (result, timing_us)

    Verify all evaluation proofs in batch.
    Returns 1 if ALL proofs are valid, else 0.
    """
    t0 = time.perf_counter()

    xs = ck['domain']
    nonce = ck['nonce']
    all_pass = True

    print()
    print("─" * 66)
    print("  PC.BatchCheck  [Verify all batch evaluation proofs]")
    print("─" * 66)

    for x, (y, path) in zip(xs_list, pairs):
        leaf = _sha256(str(y).encode() + nonce)
        ok, computed_root, _ = _walk_merkle_path(root, x, leaf, path, verbose=False)
        status = "PASS ✓" if ok == 1 else "FAIL ✗"
        print(f"  x={xs[x]:2d} (idx {x}), y={y:4d}: {status}   "
              f"root = {computed_root.hex()[:32]}...")
        if ok != 1:
            all_pass = False

    overall = 1 if all_pass else 0

    t1 = time.perf_counter()
    elapsed_us = (t1 - t0) * 1e6

    print()
    print(f"  BatchCheck result  :  {overall}  "
          f"{'← ALL PROOFS VALID ✓' if overall == 1 else '← SOME PROOFS FAILED ✗'}")
    print(f"  BatchCheck time    :  {elapsed_us:.2f} µs")
    print("─" * 66)

    return overall, elapsed_us
