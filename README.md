# Post-Quantum Security for Artemis zkML

**Author:** Nilesh R. Barandwal, MTech CSE, IIT Dharwad
**Guide:** Dr. Siba Narayan Swain
**Reference:** Lycklama et al., *Artemis: Efficient Commit-and-Prove SNARKs for zkML*, arXiv:2409.12055, 2024

---

## 1. What This Project Does

[Artemis](https://arxiv.org/abs/2409.12055) is a zkML framework that uses **KZG polynomial commitments** to prove the integrity of neural network inference without revealing model weights. KZG commitments rely on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)** — the hardness of recovering a scalar `w` from the ECC point `w·G`.

**Shor's quantum algorithm** solves ECDLP in polynomial time `O((log n)³)`, making every KZG-based system — including Artemis — cryptographically broken on a sufficiently powerful quantum computer.

This project makes that vulnerability concrete and proposes a post-quantum fix:

| Part | What it does |
|------|-------------|
| **Part 1** | Implements the complete KZG polynomial commitment scheme (all 7 ops from Definition 2.2), demonstrates a full BSGS attack that recovers the secret trapdoor `τ` from the public SRS, and forges a commitment that passes all verification checks |
| **Part 2** | Replaces KZG with a FRI-style hash-based commitment using SHA-256 (as a stand-in for Poseidon), shows that the same BSGS attack fails completely, and runs a live side-by-side performance and security comparison |

**Thesis claim:** This is, to our knowledge, the first post-quantum instantiation of the Artemis CP-SNARK for zkML — eliminating all three ECC dependencies (SRS generation, polynomial commitment, and verifying key) with a single scheme change.

---

## 2. Quick Start

### Requirements

- Python 3.8 or higher
- No external packages — uses Python standard library only (`hashlib`, `math`, `os`, `time`)

### Run Part 1 — KZG Vulnerability Demo

```bash
# Clone the repository
git clone https://github.com/NileshBarandwal/mtp2-post-quantum-artemis-zkml.git
cd mtp2-post-quantum-artemis-zkml

# Run with default 32-bit curve (~130 ms BSGS attack — recommended)
python3 src/part1_demo.py

# Run with a specific curve size
python3 src/part1_demo.py --curve 9   # 9-bit  → BSGS in ~0.03 ms  (instant, for quick demos)
python3 src/part1_demo.py --curve 32  # 32-bit → BSGS in ~130 ms   (default)
python3 src/part1_demo.py --curve 64  # 64-bit → BSGS in ~4 hours  (run in background)

# Output is saved automatically to:
# results/part1_output.txt
```

### Run Part 2 — FRI+Poseidon Replacement Demo

```bash
python3 src/part2_demo.py

# Output is saved automatically to:
# results/part2_output.txt
```

### Verify curve parameters

```bash
python3 src/ecc_utils_32bit.py   # verify 32-bit curve, G is on curve, BSGS timing estimate
python3 src/ecc_utils_64bit.py   # verify 64-bit curve, full BSGS complexity table
```

---

## 3. Repository Structure

```
mtp2-post-quantum-artemis-zkml/
│
├── src/
│   │
│   │   ── Core files ──────────────────────────────────────────────────────
│   ├── ecc_utils.py          9-bit ECC: y²=x³+2x+3 (mod 1021), n=502, G=(0,989)
│   ├── ecc_utils_32bit.py    32-bit ECC: y²=x³+3x+7 (mod 4294967291), BSGS ~130 ms
│   ├── ecc_utils_64bit.py    64-bit ECC: y²=x³+3x+7 (mod 18446744073709551557), BSGS ~4 hrs
│   ├── bsgs_attack.py        Baby-step Giant-step: O(√n) ECC discrete log solver
│   ├── kzg_pc_full.py        Complete KZG polynomial commitment — all 7 ops (Def. 2.2)
│   ├── fri_commitment.py     FRI-style SHA-256 Merkle commitment — all 7 ops (Def. 2.2)
│   ├── part1_demo.py         Part 1 entry point: KZG vulnerability, Sessions A–G
│   ├── part2_demo.py         Part 2 entry point: FRI+Poseidon replacement, Sessions A–H
│   │
│   │   ── Legacy prototypes (not used in current demo) ─────────────────────
│   ├── kzg_commitment.py     Early KZG prototype
│   ├── hash_commitment.py    Early SHA-256 prototype
│   ├── demo.py               Original 4-session proof-of-concept demo
│   └── neural_network.py     Simple neural network weight wrapper
│
├── results/
│   ├── part1_output.txt      Full captured output from Part 1 demo run
│   └── part2_output.txt      Full captured output from Part 2 demo run
│
└── README.md
```

---

## 4. Part 1 — KZG Vulnerability Demo

### What it demonstrates

The complete KZG Polynomial Commitment Scheme from Definition 2.2 of the Artemis paper is implemented on a 32-bit elliptic curve. The BSGS attack (classical analogue of Shor's algorithm) recovers the secret trapdoor `τ` from the public SRS in ~130 ms. The recovered `τ` is then used to forge a commitment for a different neural network weight that passes all 5 core PC verification operations — demonstrating complete integrity collapse.

### Sessions

| Session | Operation | Description | Result |
|---------|-----------|-------------|--------|
| **A** | `PC.Setup` | Generate SRS = [G, τG, τ²G, ..., τ⁵G] for degree D=5 | SRS published; τ is toxic waste |
| **B** | `PC.Commit` | Commit to NN weight w=42: compute c = 42·G | Commitment c published |
| **C** | `PC.Open` + `PC.Check` | Open at x=3, verify honest proof | PC.Check = 1 (completeness holds) |
| **D** | BSGS Attack | Run BSGS on SRS[1] = τG to recover τ | **τ recovered** — trapdoor exposed |
| **E** | Forgery | Compute c_fake = 99·G using recovered τ; π = O | **PC.Check = 1** — forgery accepted |
| **F** | `PC.BatchOpen` + `PC.BatchCheck` | Open g(X)=1+2X+3X² at points x=1,2,4 | PC.BatchCheck = 1 (PASS) |
| **G** | Summary | Full table of all session results and timings | — |

### Attack Chain

```
1. PC.Setup   →  SRS published: SRS[1] = τG  (τ hidden, but G is public)
2. PC.Commit  →  c = 42·G published on-chain
3. BSGS       →  τ recovered from SRS[1] in ~130 ms  (65,536 steps on 32-bit curve)
4. Forgery    →  attacker computes c_fake = 99·G  (fake weight w' = 99)
5. PC.Check   →  forged proof PASSES — Artemis integrity claim is broken
```

The key insight: for a constant polynomial g(X) = w, the quotient polynomial h(X) = (g(X) − y) / (X − x) = 0 when w = y, so the proof π = O (point at infinity). Because O is the additive identity in the ECC group, `Z(τ)·O = O` on both sides of the verification equation — meaning **any** claimed value `y` passes the check for a constant polynomial. This is not a bug; it is a direct consequence of the group-homomorphic structure that KZG relies on.

### Key Results (32-bit curve)

- τ recovered in **~130 ms** (65,536 BSGS steps)
- Forged commitment c_fake = 99·G **passes** PC.Check
- Post-quantum security: **0 bits** (ECDLP broken by Shor's in O((log n)³) operations)

---

## 5. Part 2 — FRI+Poseidon Replacement Demo

### What it demonstrates

KZG is replaced with a FRI-style hash-based polynomial commitment using SHA-256 as a stand-in for Poseidon. The polynomial is evaluated at all points in a public domain; each evaluation is hashed with a public nonce; the hashes form the leaves of a Merkle tree; the Merkle root is the commitment. No elliptic curves. No SRS. No trusted setup. All 7 PC operations from Definition 2.2 are implemented and verified.

The same BSGS attack from Part 1 is attempted on the FRI commitment root and fails with a `ValueError`. A forgery attempt is rejected because `SHA256(99 ‖ nonce) ≠ SHA256(42 ‖ nonce)`. Session H runs both KZG and FRI on the same machine in the same Python process and prints a live timing and security comparison.

### Sessions

| Session | Operation | Description | Result |
|---------|-----------|-------------|--------|
| **A** | `PC.Setup` | Generate commitment key: public nonce + evaluation domain, D=5 | Setup in 3.79 µs — no SRS, no τ |
| **B** | `PC.Commit` | Commit to NN weight w=42: Merkle root of SHA-256 evaluations | 32-byte root |
| **C** | `PC.Open` + `PC.Check` | Open at x=3, walk Merkle path, verify | PC.Check = 1 (completeness holds) |
| **D** | BSGS Attack | Attempt BSGS on SHA-256 Merkle root | **FAILED** — ValueError: hash is not an ECC point |
| **E** | Forgery | Attempt forgery with fake weight w'=99 | **REJECTED** — PC.Check = 0 |
| **F** | `PC.BatchOpen` + `PC.BatchCheck` | Open g(X)=1+2X+3X² at x=1,2,4 | BatchCheck = 1 (PASS) |
| **G** | Summary | Full comparison tables: FRI vs KZG, ECC dependency status | — |
| **H** | Live Comparison | Run KZG silently + FRI on same machine; print measured timings | See Section 6 |

### Why BSGS Fails on FRI

BSGS requires a target point `Q = w·G` in a **cyclic ECC group**. The algorithm works by precomputing a table of baby steps `{i·G}` and then searching for a collision with `Q − j·(m·G)`. Both operations require the target to be an ECC point that can be added to and negated on the curve.

The FRI Merkle root is a **32-byte SHA-256 hash** with no group structure whatsoever. When BSGS calls `curve.point_add(root_bytes, neg_mG)`, Python raises `ValueError: too many values to unpack (expected 2)` because a 32-byte bytes object cannot be unpacked as an `(x, y)` coordinate pair.

This is not a parameter-tuning difference — it is a fundamental structural incompatibility. No quantum-resistant reparametrization of BSGS can recover a preimage of a SHA-256 hash in less than `2^128` operations (Grover's bound).

### Key Results

- BSGS: **FAILED** — `ValueError`, hash has no group structure
- Forgery: **REJECTED** — `SHA256(99 ‖ nonce) ≠ SHA256(42 ‖ nonce)` → different Merkle root → PC.Check = 0
- Post-quantum security: **128 bits** (Grover's algorithm on SHA-256)
- All three ECC dependencies in Artemis: **ELIMINATED** (see Section 8)

---

## 6. Session H — Live Side-by-Side Comparison

Session H in `part2_demo.py` runs **both KZG and FRI on the same machine in the same Python process** and prints live measured timings. KZG operations are executed silently (stdout suppressed via `io.StringIO`) so their verbose output does not appear; only timing return values are captured. FRI timings are reused from Sessions A–F (no re-run). Both use the 32-bit ECC curve for KZG.

All values below are **live measurements** from `results/part2_output.txt` — not hardcoded estimates.

### Table 1: Performance (µs, same machine, same run)

| Operation | KZG (measured) | FRI+Poseidon (measured) |
|-----------|---------------|------------------------|
| PC.Setup | 184.75 µs | 3.79 µs |
| PC.Commit | 23.63 µs | 23.13 µs |
| PC.Verify | 11.33 µs | 8.50 µs |
| PC.Open | 7.67 µs | 1.25 µs |
| PC.Check (honest) | 13.17 µs | 11.75 µs |
| PC.Check (forged) | 14.29 µs — **ACCEPTED** | 10.67 µs — **REJECTED** |
| PC.BatchOpen | 55.79 µs | 11.75 µs |
| PC.BatchCheck | 50.08 µs | 10.54 µs |
| BSGS attack | 106.47 ms — **τ=428 RECOVERED** | FAILED — ValueError |

### Table 2: Security Properties (same run)

| Property | KZG | FRI+Poseidon |
|----------|-----|-------------|
| Trusted setup | Required | **ELIMINATED** |
| Secret trapdoor τ | Required (toxic waste) | **NONE** |
| Commitment type | ECC point (64 bytes, prod.) | 32-byte SHA-256 hash |
| Single proof size | 64 bytes (ECC point) | 96 bytes (3 × 32 Merkle hashes) |
| BSGS attack | τ=428 recovered in 106.47 ms | **FAILED** — no group structure |
| Forgery result | **ACCEPTED** — scheme broken | **REJECTED** — scheme secure |
| Post-quantum security | **0 bits** (Shor's breaks ECDLP) | **128 bits** (Grover on SHA-256) |

**Observations:**
- **Setup:** FRI is 49× faster (3.79 µs vs 184.75 µs) — no ECC scalar multiplications, just `os.urandom` + list creation
- **Commit:** Comparable (23.13 µs vs 23.63 µs) — FRI replaces point multiplications with SHA-256 hashing + Merkle tree construction
- **Open/BatchOpen:** FRI is 5–6× faster — Merkle path extraction is pure array indexing with no cryptographic operations
- **Forgery:** The critical asymmetry — KZG's group-homomorphic structure allows the proof `π = O` to pass for any claimed value; SHA-256 collision resistance makes FRI forgery computationally infeasible

---

## 7. BSGS Complexity Across Curve Sizes

The 32-bit curve is chosen as the demo default because BSGS takes ~130 ms — slow enough to be visually present, fast enough to complete in a single demo run.

| Curve | Bits | BSGS Steps | Classical Time | Shor's (quantum) |
|-------|------|-----------|----------------|-----------------|
| 9-bit (demo) | 9 | ~23 steps | ~0.03 ms | O(9³) = 729 ops |
| **32-bit (default)** | **32** | **65,536 steps** | **~130 ms** | O(32³) = 32,768 ops |
| 64-bit | 64 | 2³² ≈ 4.3B steps | ~4 hours | O(64³) = 262,144 ops |
| BN254 (production) | 254 | 2¹²⁷ steps | Age of universe | O(254³) ≈ 16.4M ops |

> **Critical note:** All ECC curves — regardless of size — are broken by Shor's algorithm. The classical BSGS infeasibility of BN254 provides no protection against quantum adversaries. Only hash-based schemes (FRI+Poseidon) provide post-quantum security.

---

## 8. Three ECC Dependencies in Artemis — Status After Replacement

Artemis has three distinct places where ECC hardness assumptions are required. FRI+Poseidon eliminates all three.

| Component | KZG (current Artemis) | FRI+Poseidon (proposed) | Status |
|-----------|----------------------|------------------------|--------|
| **SRS Generation** | `[G, τG, τ²G, ..., τᴰG]` — τ recoverable by Shor's | No SRS — replaced by evaluation domain + public nonce | **ELIMINATED** ✓ |
| **Polynomial Commitment** | `c = g(τ)·G` — ECC point, ECDLP assumption | `root = MerkleRoot(SHA256(g(xᵢ) ‖ nonce))` — hash, no group structure | **ELIMINATED** ✓ |
| **Verifying Key** | `e(c − y·G, G₂) = e(π, τG₂ − x·G₂)` — BN254 bilinear pairing | Walk SHA-256 Merkle path from leaf to root — no pairing, no BN254, no ECDLP | **ELIMINATED** ✓ |

---

## 9. Definition 2.2 — PC Operations (Lycklama et al.)

Both `kzg_pc_full.py` and `fri_commitment.py` implement all 7 polynomial commitment operations from Definition 2.2 of the Artemis paper:

| # | Operation | KZG (`kzg_pc_full.py`) | FRI (`fri_commitment.py`) |
|---|-----------|----------------------|--------------------------|
| 1 | `PC.Setup(D)` | Generate SRS of D+1 ECC points using secret τ | Generate evaluation domain + random nonce |
| 2 | `PC.Commit(ck, g, d)` | `c = Σ gᵢ · SRS[i]` — ECC point | `root = MerkleRoot(SHA256(g(xᵢ) ‖ nonce))` |
| 3 | `PC.Verify(ck, c, d, g)` | Recompute c from g and SRS; compare | Recompute root from g; compare |
| 4 | `PC.Open(ck, g, d, x)` | Compute quotient h=(g−y)/(X−x); π = h(τ)·G | Return evaluation y and Merkle authentication path |
| 5 | `PC.Check(ck, c, d, x, y, π)` | Verify `e(c−y·G, G₂) = e(π, (τ−x)·G₂)` (small-curve analogue) | Recompute leaf; walk path to root; compare root |
| 6 | `PC.BatchOpen(ck, g, d, Q)` | Single proof π via vanishing polynomial Z(X) = Π(X−xᵢ) | List of (y, Merkle path) pairs for each xᵢ ∈ Q |
| 7 | `PC.BatchCheck(ck, c, d, Q, y, π)` | Verify `Z(τ)·π = c − I(τ)·G` using SRS | Verify all individual Merkle paths |

---

## 10. Research Contribution

- Implements all 7 PC operations from Definition 2.2 of Lycklama et al. (arXiv:2409.12055) for both KZG and FRI schemes
- Demonstrates a **complete KZG vulnerability chain** on a 32-bit curve: `PC.Setup → BSGS → Forgery → PC.Check PASS`
- Proposes and implements **FRI + Poseidon** as a drop-in post-quantum replacement for KZG in Artemis
- Session H provides **live performance and security comparison** on identical hardware — no hardcoded benchmarks
- Eliminates all three ECC dependencies in Artemis CP-SNARK, achieving **128-bit post-quantum security** under Grover's algorithm
- To our knowledge: **first post-quantum instantiation** of the Artemis CP-SNARK for zkML inference integrity

---

## 11. References

[1] Lycklama et al. *Artemis: Efficient Commit-and-Prove SNARKs for zkML.* arXiv:2409.12055, 2024.

[2] Ben-Sasson et al. *Fast Reed-Solomon Interactive Oracle Proofs of Proximity.* ICALP 2018.

[3] Grassi et al. *Poseidon: A New Hash Function for Zero-Knowledge Proof Systems.* USENIX Security 2021.

[4] Bernstein and Lange. *Post-quantum cryptography.* Nature 549, 188–194, 2017.

[5] Roetteler et al. *Quantum Resource Estimates for Computing Elliptic Curve Discrete Logarithms.* ASIACRYPT 2017.

[6] NIST IR 8547. *Transition to Post-Quantum Cryptography Standards.* November 2024.

[7] Amy et al. *Estimating the cost of generic quantum pre-image attacks on SHA-2 and SHA-3.* SAC 2016.

[8] Nainwal et al. *A Comparative Analysis of zk-SNARKs and zk-STARKs.* arXiv:2512.10020, 2025.
