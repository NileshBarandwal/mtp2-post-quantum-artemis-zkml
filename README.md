# Post-Quantum Security for Artemis zkML

**Author:** Nilesh R. Barandwal, MTech CSE, IIT Dharwad
**Supervisor:** Dr. Siba Narayan Swain
**Date:** March 2026

## Description

This project demonstrates the post-quantum vulnerability of the KZG polynomial commitment scheme used in the Artemis zkML framework. The KZG scheme relies on the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP), which is efficiently solvable by Shor's quantum algorithm. Using a classical Baby-step Giant-step (BSGS) surrogate attack on a small elliptic curve, this demo makes the vulnerability concrete and observable. All seven polynomial commitment operations from Definition 2.2 of the Artemis paper are implemented and verified. The project further proposes FRI (Fast Reed–Solomon Interactive Oracle Proof) combined with the Poseidon hash function as a post-quantum replacement — a plausibly secure alternative that does not depend on any quantum-vulnerable hardness assumption.

## Project Structure

```
src/
  part1_demo.py       — Main entry point: runs the full Part 1 demonstration end-to-end
  kzg_pc_full.py      — Complete KZG polynomial commitment scheme (all 7 PC operations from Definition 2.2)
  bsgs_attack.py      — Baby-step Giant-step attack on ECDLP (quantum vulnerability surrogate)
  ecc_utils.py        — Small elliptic curve arithmetic over a finite field
results/
  part1_output.txt    — Captured output from Part 1 demonstration run
arthemis.pdf          — Lycklama et al. Artemis paper (arXiv:2409.12055)
ECC.pdf               — Reference material on elliptic curve cryptography
```

## How to Run

```bash
python3 src/part1_demo.py
```

## Reference

Lycklama et al., *Artemis: Efficient Integrity Verification of Neural Network Predictions*, arXiv:2409.12055, 2024.
