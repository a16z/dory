2# Dory ZK vs Non-ZK: Deep Technical Analysis

This document provides a concrete analysis of the differences between transparent (non-ZK) and zero-knowledge versions of the Dory polynomial commitment scheme.

---

## 1. Overview: What Zero-Knowledge Means for Dory

In the **transparent (non-ZK)** Dory protocol:
- The prover reveals the polynomial evaluation `y` in clear
- All protocol messages directly contain the computed values
- The verifier learns `y` and can verify `C(r) = y`

In the **zero-knowledge (ZK)** Dory protocol:
- The prover commits to `y` without revealing it
- All protocol messages are **masked** with random blinds
- The verifier learns only that the prover knows a valid `(polynomial, evaluation)` pair

---

## 2. Core Technique: Blinding/Masking

### 2.1 The Masking Operation

For any group element `V` computed by the prover, the ZK version masks it:

```
V_masked = V + r·H
```

Where:
- `V` is the actual computed value (e.g., a pairing result in G_T)
- `r` is a random scalar sampled from the prover's private RNG
- `H` is a **blinding generator** (H_T, H_1, or H_2 depending on the group)

**Key Insight**: The blinding generators `H_T, H_1, H_2` must be linearly independent from the commitment generators `Γ_1, Γ_2`. This ensures:
1. The mask `r·H` looks random to the verifier
2. The binding property is preserved (prover can't find alternate openings)

### 2.2 Mode Abstraction

The implementation uses a `Mode` trait to unify ZK and non-ZK:

```rust
pub trait Mode: 'static {
    fn sample<F: Field, R: RngCore>(rng: &mut R) -> F;
    fn mask<G: Group>(value: G, base: &G, blind: &G::Scalar) -> G;
}

// Transparent: sample returns 0, mask returns value unchanged
impl Mode for Transparent {
    fn sample<F, R>(_rng: &mut R) -> F { F::zero() }
    fn mask<G>(value: G, _base: &G, _blind: &G::Scalar) -> G { value }
}

// ZK: sample returns random, mask adds blind
impl Mode for ZK {
    fn sample<F, R>(rng: &mut R) -> F { F::random(rng) }
    fn mask<G>(value: G, base: &G, blind: &G::Scalar) -> G { value + base.scale(blind) }
}
```

---

## 3. Protocol Differences by Phase

### 3.1 VMV (Vector-Matrix-Vector) Message

The VMV message initiates the evaluation proof. It contains `(C, D_2, E_1)`.

#### Transparent Version
```
C   = e(⟨T_vec, v_vec⟩, Γ_2,fin)
D_2 = e(⟨Γ_1, v_vec⟩, Γ_2,fin)
E_1 = ⟨T_vec, L_vec⟩
E_2 = y · Γ_2,fin                    // Computed by verifier from known y
```

#### ZK Version
```
C   = e(⟨T_vec, v_vec⟩, Γ_2,fin) + r_c · H_T
D_2 = e(⟨Γ_1, v_vec⟩, Γ_2,fin)  + r_d2 · H_T
E_1 = ⟨T_vec, L_vec⟩             + r_e1 · H_1
E_2 = y · Γ_2,fin                 + r_e2 · H_2    // Sent by prover (blinded)
y_com = y · Γ_1,fin               + r_y · H_1     // Commitment to evaluation
```

**Key Differences**:
1. All values masked with their respective blinding generators
2. `E_2` sent by prover (verifier can't compute it without knowing `y`)
3. Additional commitment `y_com` for proving `y` consistency
4. Requires **Σ_1 proof** to prove `E_2` and `y_com` commit to same `y`
5. Requires **Σ_2 proof** to prove the VMV relation holds

### 3.2 Reduce Rounds (First Message)

Each reduce round computes cross-terms for the folding. First message contains `(D_1L, D_1R, D_2L, D_2R, E_1β, E_2β)`.

#### Transparent Version
```
D_1L = e(v_1L, Γ_2')
D_1R = e(v_1R, Γ_2')
D_2L = e(Γ_1', v_2L)
D_2R = e(Γ_1', v_2R)
E_1β = ⟨Γ_1, s_2⟩
E_2β = ⟨Γ_2, s_1⟩
```

#### ZK Version
```
D_1L = e(v_1L, Γ_2') + r_d1l · H_T
D_1R = e(v_1R, Γ_2') + r_d1r · H_T
D_2L = e(Γ_1', v_2L) + r_d2l · H_T
D_2R = e(Γ_1', v_2R) + r_d2r · H_T
E_1β = ⟨Γ_1, s_2⟩               // Not masked (public generators)
E_2β = ⟨Γ_2, s_1⟩               // Not masked (public generators)
```

**Blind Sampling**: 4 new blinds per round: `r_d1l, r_d1r, r_d2l, r_d2r`

### 3.3 Reduce Rounds (Second Message)

Second message contains cross-products `(C_+, C_-, E_1+, E_1-, E_2+, E_2-)`.

#### Transparent Version
```
C_+  = e(v_1L, v_2R)
C_-  = e(v_1R, v_2L)
E_1+ = ⟨v_1L, s_2R⟩
E_1- = ⟨v_1R, s_2L⟩
E_2+ = ⟨s_1L, v_2R⟩
E_2- = ⟨s_1R, v_2L⟩
```

#### ZK Version
```
C_+  = e(v_1L, v_2R)  + r_c+ · H_T
C_-  = e(v_1R, v_2L)  + r_c- · H_T
E_1+ = ⟨v_1L, s_2R⟩   + r_e1+ · H_1
E_1- = ⟨v_1R, s_2L⟩   + r_e1- · H_1
E_2+ = ⟨s_1L, v_2R⟩   + r_e2+ · H_2
E_2- = ⟨s_1R, v_2L⟩   + r_e2- · H_2
```

**Blind Sampling**: 6 new blinds per round: `r_c+, r_c-, r_e1+, r_e1-, r_e2+, r_e2-`

### 3.4 Blind Accumulation

In ZK mode, the prover must track how blinds combine through the protocol.

After challenge `β` (first challenge):
```
r_C ← r_C + β·r_D2 + β⁻¹·r_D1
```

After challenge `α` (second challenge):
```
r_C  ← r_C + α·r_c+ + α⁻¹·r_c-
r_D1 ← α·r_d1l + r_d1r
r_D2 ← α⁻¹·r_d2l + r_d2r
r_E1 ← r_E1 + α·r_e1+ + α⁻¹·r_e1-
r_E2 ← r_E2 + α·r_e2+ + α⁻¹·r_e2-
```

After fold-scalars (challenge `γ`):
```
r_C ← r_C + γ·r_E2 + γ⁻¹·r_E1
```

### 3.5 Final Scalar Product

#### Transparent Version

Final message is `(E_1, E_2)`:
```
E_1 = v_1 + γ·s_1·H_1
E_2 = v_2 + γ⁻¹·s_2·H_2
```

Verification:
```
e(E_1 + d·Γ_1, E_2 + d⁻¹·Γ_2) = C' + χ_0 + d·D_2' + d⁻¹·D_1'
```

#### ZK Version

Final message is `(E_1, E_2)` plus a **Σ-protocol proof**.

The Σ-protocol proves knowledge of `(v_1, v_2, r_C, r_D1, r_D2)` satisfying:
- `C = e(v_1, v_2) + r_C·H_T`
- `D_1 = e(v_1, Γ_2) + r_D1·H_T`
- `D_2 = e(Γ_1, v_2) + r_D2·H_T`

**Σ-Protocol Steps**:

1. **Commitment Phase**: Prover samples `d_1 = s_d1·Γ_1`, `d_2 = s_d2·Γ_2` and blinds `r_P1, r_P2, r_Q, r_R`, then computes:
   ```
   P_1 = e(d_1, Γ_2) + r_P1·H_T
   P_2 = e(Γ_1, d_2) + r_P2·H_T
   Q   = e(d_1, v_2) + e(v_1, d_2) + r_Q·H_T
   R   = e(d_1, d_2) + r_R·H_T
   ```

2. **Challenge**: Verifier sends random `c` (or derived via Fiat-Shamir)

3. **Response Phase**: Prover computes:
   ```
   E_1 = d_1 + c·v_1
   E_2 = d_2 + c·v_2
   r_1 = r_P1 + c·r_D1
   r_2 = r_P2 + c·r_D2
   r_3 = r_R + c·r_Q + c²·r_C
   ```

4. **Verification**: Verifier checks:
   ```
   e(E_1 + d·Γ_1, E_2 + d⁻¹·Γ_2) = χ + R + c·Q + c²·C
                                  + d·P_2 + d·c·D_2
                                  + d⁻¹·P_1 + d⁻¹·c·D_1
                                  - (r_3 + d·r_2 + d⁻¹·r_1)·H_T
   ```

---

## 4. Additional ZK-Only Structures

### 4.1 Sigma1 Proof (VMV Consistency)

Proves knowledge of `(y, r_E2, r_y)` such that:
- `E_2 = y·Γ_2,fin + r_E2·H_2`
- `y_com = y·Γ_1,fin + r_y·H_1`

This is a standard Schnorr-like proof for DLOG equality across different bases.

### 4.2 Sigma2 Proof (VMV Relation)

Proves:
```
e(E_1, Γ_2,fin) - D_2 = e(H_1, t_1·Γ_2,fin + t_2·H_2)
```

Where `t_1 = r_E1 + r_v` and `t_2 = -r_D2`.

This proves the VMV constraint holds even with blinds.

---

## 5. Proof Size Comparison

| Component | Transparent | ZK |
|-----------|-------------|-----|
| VMV Message | 2 G_T + 1 G_1 | 2 G_T + 1 G_1 + 1 G_2 + 1 G_1 |
| Per Reduce Round | 4 G_T + 2 G_1 + 2 G_2 | Same (blinds absorbed) |
| Final Message | 1 G_1 + 1 G_2 | Same |
| Sigma1 Proof | - | 1 G_1 + 1 G_2 + 3 F |
| Sigma2 Proof | - | 1 G_T + 2 F |
| ScalarProduct Proof | - | 4 G_T + 1 G_1 + 1 G_2 + 3 F |

**Total Overhead for ZK**:
- +1 G_1, +2 G_2 elements
- +5 G_T elements
- +8 F scalars

---

## 6. Verification Complexity

### Transparent
- Per round: O(1) scalar mults in G_T
- Final: 4 pairings (batched)

### ZK
- Per round: Same (blind tracking is prover-side)
- Final: Same 4 pairings + Σ-protocol verification
- Additional: Sigma1 verification (2 scalar mults each in G_1, G_2)
- Additional: Sigma2 verification (1 pairing)

**Total**: ~5-6 pairings equivalent (vs 4 for transparent)

---

## 7. Security Properties

### Transparent Dory
- **Binding**: Computational (under SXDH)
- **Hiding**: None (evaluation is revealed)
- **Soundness**: Computational (knowledge sound under SXDH)

### ZK Dory
- **Binding**: Computational (under SXDH)
- **Hiding**: Statistical/Perfect (blinded messages are uniformly random)
- **Soundness**: Computational (knowledge sound under SXDH)
- **Zero-Knowledge**: Honest-Verifier Statistical ZK (HVSZK)

The ZK property is **HVSZK** (Honest-Verifier Statistical Zero-Knowledge):
- The simulator can produce transcripts indistinguishable from real ones
- Requires honest verifier (challenges are random)
- Fiat-Shamir makes it non-interactive, achieving NIZK in ROM

---

## 8. Implementation Summary

### State Changes (Prover)

```rust
pub struct DoryProverState<'a, E: PairingCurve, M: Mode = Transparent> {
    // ... existing fields ...

    // ZK blind accumulators (zero for Transparent)
    r_c: Scalar,    // Accumulated blind for C
    r_d1: Scalar,   // Accumulated blind for D1
    r_d2: Scalar,   // Accumulated blind for D2
    r_e1: Scalar,   // Accumulated blind for E1
    r_e2: Scalar,   // Accumulated blind for E2
    _mode: PhantomData<M>,
}
```

### Proof Changes

```rust
// Transparent proof
pub struct DoryProof<G1, G2, GT> {
    pub vmv_message: VMVMessage<G1, GT>,
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,
    pub final_message: ScalarProductMessage<G1, G2>,
}

// ZK proof adds Σ-proofs
pub struct ZkDoryProof<G1, G2, F, GT> {
    pub vmv_message: ZkVMVMessage<G1, G2, GT>,  // Includes E2, y_com
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,
    pub final_message: ScalarProductMessage<G1, G2>,
    pub sigma1_proof: Sigma1Proof<G1, G2, F>,
    pub sigma2_proof: Sigma2Proof<F, GT>,
    pub scalar_product_proof: ScalarProductProof<G1, G2, F, GT>,
}
```

---

## 9. Key Insights

1. **Blinding Generator Independence**: `H_T, H_1, H_2` must be sampled independently from `Γ_1, Γ_2`. In practice, derived from a hash of `Γ` or sampled from a separate random oracle.

2. **Blind Folding Mirrors Value Folding**: When values fold as `v' = α·v_L + v_R`, blinds fold as `r' = α·r_L + r_R`. This maintains the invariant that `v'_masked = v' + r'·H`.

3. **Σ-Protocols Are Necessary**: Simply masking isn't enough—the verifier needs to verify the final relation. The Σ-protocol proves knowledge of the witness without revealing the blinds.

4. **RNG vs Transcript for Blinds**: Blinds are sampled from private RNG (not transcript) because they must not affect challenge derivation. Challenges come from the transcript after appending the masked values.

5. **Additive vs Multiplicative Masking**: Dory uses additive masking (`V + r·H`) in groups. This is simpler than multiplicative approaches and works because group operations are efficient.

---

## References

1. Lee, J. (2021). "Dory: Efficient, Transparent Arguments for Generalised Inner Products and Polynomial Commitments." TCC 2021.
2. IACR ePrint: https://eprint.iacr.org/2020/1274
3. Thaler, J. "Proofs, Arguments, and Zero-Knowledge" Section 15.4
