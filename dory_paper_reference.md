# Dory: Efficient, Transparent Arguments for Generalised Inner Products and Polynomial Commitments

**Author:** Jonathan Lee
**Published:** TCC 2021 (Theory of Cryptography Conference)
**IACR ePrint:** [2020/1274](https://eprint.iacr.org/2020/1274)
**Springer:** [LNCS vol 13043](https://link.springer.com/chapter/10.1007/978-3-030-90453-1_1)
**License:** Creative Commons Attribution (CC BY)

---

## Abstract

Dory is a transparent setup, public-coin interactive argument for proving correctness of an inner-pairing product between committed vectors of elements of the two source groups. For a product of vectors of length n, proofs consist of 6 log n target group elements, one element from each source group, and 3 scalars. Verifier work is dominated by an O(log n) multi-exponentiation in the target group and O(1) pairings. Security is reduced to the standard SXDH assumption in the standard model.

Dory is applied to build a multivariate polynomial commitment scheme via the Fiat-Shamir transform. For a dense polynomial with n coefficients:
- Prover work to compute a commitment is dominated by a multi-exponentiation in one source group of size n
- Prover work to show that a commitment to an evaluation is correct is O(n^(log 8/log 25)) in general, or O(n^(1/2)) for univariate or multilinear polynomials
- Communication complexity and Verifier work are both O(log n)

---

## Complexity Summary

| Metric | Complexity |
|--------|------------|
| Setup | Transparent (no toxic waste) |
| Proof size | 6 log n target group elements + O(1) |
| Verifier work | O(log n) multi-exp in G_T + O(1) pairings |
| Prover work (general) | O(n^(log 8/log 25)) ≈ O(n^0.65) |
| Prover work (univariate/multilinear) | O(√n) |
| Commitment size | 192 bytes (at n = 2²⁰) |
| Security assumption | SXDH (Symmetric External Diffie-Hellman) |

---

## Core Technical Contributions

### 1. Inner-Pairing-Product Commitments

Dory employs inner-pairing-product commitments utilizing both G₁ and G₂ groups. The groups must not equal each other for DDH to hold and the scheme to be binding. The commitment is expressed as an inner product: ⟨vector, commitment_key⟩.

For a pairing group (G₁, G₂, G_T):
- If the message is a vector in G₁, the commitment key is a vector in G₂
- If the message is a vector in G₂, the commitment key is a vector in G₁
- The commitment itself lives in G_T

This structure-preserving symmetry between messages and commitment keys is a key insight.

### 2. Recursive Folding (Reduce-and-Fold)

The core technique is the observation that for any vectors u_L, u_R, v_L, v_R and any non-zero scalar α:

```
⟨u_L || u_R, v_L || v_R⟩ = ⟨α·u_L + u_R, α⁻¹·v_L + v_R⟩ - α·⟨u_L, v_R⟩ - α⁻¹·⟨u_R, v_L⟩
```

This identity allows reducing a claim about the inner product ⟨u, v⟩ of vectors of length n to claims about inner products of vectors of length n/2.

**Protocol Flow:**
1. Prover sends cross-terms: L = ⟨u_L, v_R⟩ and R = ⟨u_R, v_L⟩
2. Verifier sends random challenge α
3. Both parties compute folded vectors: u' = α·u_L + u_R and v' = α⁻¹·v_L + v_R
4. Recurse until vectors have length 1
5. Final claim verified with a sigma protocol

The verifier uses homomorphic properties of the commitment scheme (with prover assistance) to find commitments to the shorter folded vectors.

### 3. Parallel Recursion for Logarithmic Verification

In addition to proving knowledge of u such that c_u = ⟨u, g⟩, the prover also shows knowledge of g such that c_g = ⟨g, Γ⟩. This is done via recursion by executing the protocol in parallel using the same randomness.

The key optimization doubles the rounds of interaction to 2 log n in order to keep the messages per round constant, achieving O(log n) verification.

### 4. Pre-processing with Matrix Commitments

Using matrix commitments (similar to Hyrax), the prover:
1. Computes Generalized Pedersen Commitments internally (rows of the coefficient matrix)
2. Generates an inner-pairing-product commitment of the commitment vector

**Pre-processing procedure (multi-round folding):**
- Round 1: Commits to g_L^(0) and g_R^(0) using public random key Γ^(1) ∈ G^(n/2), producing Δ_L^(1) and Δ_R^(1)
- Round i: Partitions Γ^(i−1) into Γ_L^(i−1) and Γ_R^(i−1), committing using Γ^(i) ∈ G^(n/2^i)

The commitment key update formula:
```
c_g^(i) = α_{i-1} · Δ_L^(i) + α_i · Δ_R^(i)
```

---

## Comparison with Related Work

### vs. Bulletproofs
- Like Bulletproofs, uses recursive folding
- Unlike Bulletproofs, instead of updating g directly, the verifier computes a commitment to it in constant time using homomorphism

### vs. Trusted Setup Schemes (KZG)
- Dory achieves similar asymptotics without trusted setup
- Previously, these asymptotics required trusted setup or concretely inefficient groups of unknown order

### vs. DARK/Pietrzak
- Dory avoids groups of unknown order which are concretely inefficient

---

## Concrete Performance (n = 2²⁰, single core)

| Operation | Cost |
|-----------|------|
| Commitment size | 192 bytes |
| Evaluation proof size | ~18 KB |
| Proof generation time | ~3 seconds |
| Verification time | ~25 ms |

**Batched evaluation (n = 2²⁰):**
| Metric | Marginal Cost |
|--------|---------------|
| Communication | < 1 KB |
| Prover time | ~300 ms |
| Verifier time | ~1 ms |

---

## Protocol Messages (per round)

In each round of the reduce-and-fold protocol, the prover sends:
- 6 target group elements (G_T)
- Cross-term products for the folding identity

Total proof: 6 log n target group elements + 1 G₁ element + 1 G₂ element + 3 scalars

---

## Security Model

- **Assumption:** SXDH (Symmetric External Diffie-Hellman)
- **Model:** Standard model (no random oracle for security, though Fiat-Shamir used for non-interactivity)
- **Properties:**
  - Computationally binding
  - Perfectly hiding (in the interactive version)
  - Knowledge sound

---

## Application to Polynomial Commitments

Dory constructs a multivariate polynomial commitment scheme:

1. **Commitment:** Interpret polynomial coefficients as a matrix, commit using the two-tiered scheme
2. **Evaluation:** Reduce polynomial evaluation to inner-pairing-product claims
3. **Non-interactivity:** Apply Fiat-Shamir transform

For multilinear polynomials (common in SNARKs), the structure enables O(√n) prover work for evaluation proofs.

---

## Integration with Jolt zkVM

Dory is used as the polynomial commitment scheme in Jolt, a RISC-V zkVM:
- The commitment key consists of random group elements generated by evaluating a cryptographic PRG
- Can be generated "on the fly" but explicit storage enables faster proving
- Space and Time's high-performance Dory implementation contributed to 6x speedup in Jolt

---

## References

1. Lee, J. (2021). Dory: Efficient, Transparent Arguments for Generalised Inner Products and Polynomial Commitments. In: Theory of Cryptography (TCC 2021), LNCS vol 13043, Springer.

2. IACR ePrint: https://eprint.iacr.org/2020/1274

3. Bünz, B., Maller, M., Mishra, P., Tyagi, N., & Vesely, P. (2019). Proofs for Inner Pairing Products and Applications. IACR ePrint 2019/1177.

4. Jolt zkVM: https://github.com/a16z/jolt

5. Thaler, J. Proofs, Arguments, and Zero-Knowledge (Section 15.4 covers Dory).
