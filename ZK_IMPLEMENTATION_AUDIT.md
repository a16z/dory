# Dory ZK Implementation Audit

This document compares the current implementation against the Dory paper's ZK requirements.

---

## Executive Summary

**Current State: Partially Implemented (Phase 1 Complete, Phase 2 Missing)**

The implementation has:
- ✅ Mode trait abstraction (`Transparent` / `ZK`)
- ✅ Blind sampling and masking for all protocol messages
- ✅ Blind accumulation logic in prover state
- ✅ Sigma proof structures defined (`Sigma1Proof`, `Sigma2Proof`, `ScalarProductProof`)
- ✅ Sigma proof generation functions implemented
- ✅ Sigma proof verification functions implemented

**Critical Gap**: The ZK proofs produce the **same proof type** as transparent proofs (`DoryProof`), and verification uses the **same code path** that reveals `y`. The Sigma proofs exist but are **not wired into the main API**.

---

## Detailed Analysis

### 1. Mode Trait ✅ CORRECT

**Implementation** (`src/mode.rs:14-65`):
```rust
pub trait Mode: 'static {
    fn sample<F: Field, R: RngCore>(rng: &mut R) -> F;
    fn mask<G: Group>(value: G, base: &G, blind: &G::Scalar) -> G;
}

impl Mode for Transparent {
    fn sample<F, R>(_rng: &mut R) -> F { F::zero() }
    fn mask<G>(value: G, _base: &G, _blind: &G::Scalar) -> G { value }
}

impl Mode for ZK {
    fn sample<F, R>(rng: &mut R) -> F { F::random(rng) }
    fn mask<G>(value: G, base: &G, blind: &G::Scalar) -> G { value + base.scale(blind) }
}
```

**Assessment**: Correct. Blinds sampled from RNG (not transcript), masking is additive.

---

### 2. VMV Message ⚠️ PARTIAL

**What's Implemented** (`src/evaluation_proof.rs:141-165`):
```rust
let r_c: F = Mo::sample(rng);
let r_d2: F = Mo::sample(rng);
let r_e1: F = Mo::sample(rng);
let r_e2: F = Mo::sample(rng);

let c = Mo::mask(c_raw, &setup.ht, &r_c);
let d2 = Mo::mask(d2_raw, &setup.ht, &r_d2);
let e1 = Mo::mask(e1_raw, &setup.h1, &r_e1);

let vmv_message = VMVMessage { c, d2, e1 };  // <-- Uses non-ZK struct!
```

**What's Missing**:

1. **`E_2` not computed/sent**: In ZK mode, the prover must send `E_2 = y·Γ_2,fin + r_e2·H_2`. Currently `r_e2` is sampled but `E_2` is not computed or included in the message.

2. **`y_com` not computed**: The commitment `y_com = y·Γ_1,fin + r_y·H_1` is not created.

3. **Wrong message type**: Uses `VMVMessage` instead of `ZkVMVMessage`.

**Required Fix**:
```rust
// In ZK mode:
let y = polynomial.evaluate(point);
let e2 = Mo::mask(setup.g2_vec[0].scale(&y), &setup.h2, &r_e2);
let r_y: F = Mo::sample(rng);
let y_com = setup.g1_vec[0].scale(&y) + setup.h1.scale(&r_y);

let vmv_message = ZkVMVMessage { c, d2, e1, e2, y_com };
```

---

### 3. Reduce Round First Message ✅ CORRECT

**Implementation** (`src/reduce_and_fold.rs:237-314`):
```rust
let r_d1_l: F = M::sample(rng);
let r_d1_r: F = M::sample(rng);
let r_d2_l: F = M::sample(rng);
let r_d2_r: F = M::sample(rng);

let d1_left = M::mask(d1_left_base, &self.setup.ht, &r_d1_l);
let d1_right = M::mask(d1_right_base, &self.setup.ht, &r_d1_r);
let d2_left = M::mask(d2_left_base, &self.setup.ht, &r_d2_l);
let d2_right = M::mask(d2_right_base, &self.setup.ht, &r_d2_r);
```

**Assessment**: Correct. D values properly masked with H_T.

---

### 4. Reduce Round Second Message ✅ CORRECT

**Implementation** (`src/reduce_and_fold.rs:351-414`):
```rust
let r_c_plus: F = M::sample(rng);
let r_c_minus: F = M::sample(rng);
let r_e1_plus: F = M::sample(rng);
// ... etc

let c_plus = M::mask(c_plus_base, &self.setup.ht, &r_c_plus);
let c_minus = M::mask(c_minus_base, &self.setup.ht, &r_c_minus);
let e1_plus = M::mask(e1_plus_base, &self.setup.h1, &r_e1_plus);
let e1_minus = M::mask(e1_minus_base, &self.setup.h1, &r_e1_minus);
let e2_plus = M::mask(e2_plus_base, &self.setup.h2, &r_e2_plus);
let e2_minus = M::mask(e2_minus_base, &self.setup.h2, &r_e2_minus);
```

**Assessment**: Correct. All values properly masked with respective generators.

---

### 5. Blind Accumulation ⚠️ ISSUE

**Implementation** (`src/reduce_and_fold.rs:340-343, 463-477`):

After first challenge (β):
```rust
self.r_c = self.r_c + self.r_d2 * *beta + self.r_d1 * beta_inv;
```

After second challenge (α):
```rust
self.r_c = self.r_c + r_c_plus * *alpha + r_c_minus * alpha_inv;
self.r_d1 = r_d1_l * *alpha + r_d1_r;
self.r_d2 = r_d2_l * alpha_inv + r_d2_r;
self.r_e1 = self.r_e1 + r_e1_plus * *alpha + r_e1_minus * alpha_inv;
self.r_e2 = self.r_e2 + r_e2_plus * *alpha + r_e2_minus * alpha_inv;
```

**Issue**: The first challenge uses `self.r_d1` and `self.r_d2`, but these are **not yet set** from message blinds at that point. They should be folded from per-round blinds.

**Paper says**:
- After β: `r_C ← r_C + β·(r_d2_l + r_d2_r) + β⁻¹·(r_d1_l + r_d1_r)` (sum of current round blinds)
- After α: `r_D1 ← α·r_d1_l + r_d1_r`, `r_D2 ← α⁻¹·r_d2_l + r_d2_r`

**Current Code** uses `self.r_d1` and `self.r_d2` in `apply_first_challenge`, but those are set in `apply_second_challenge`. This is **inverted** - the accumulation happens after the challenge where it should use the blinds, but uses prior round's accumulated values.

**Fix needed**: Pass message blinds to `apply_first_challenge` and use them directly, not the accumulated values.

---

### 6. Final Message ✅ CORRECT

**Implementation** (`src/reduce_and_fold.rs:486-515`):
```rust
let e1 = self.v1[0] + self.setup.h1.scale(&gamma_s1);
let e2 = self.v2[0] + self.setup.h2.scale(&gamma_inv_s2);

// ZK: final blind accumulation
self.r_c = self.r_c + self.r_e2 * *gamma + self.r_e1 * gamma_inv;
```

**Assessment**: Correct formula for final blind accumulation.

---

### 7. Scalar Product Σ-Protocol ✅ IMPLEMENTED (but not used)

**Implementation** (`src/reduce_and_fold.rs:551-619`):
```rust
pub fn scalar_product_proof<T, R>(&self, transcript: &mut T, rng: &mut R) -> ZkScalarProductProof<E> {
    // Sample d1, d2
    let s_d1 = F::random(rng);
    let s_d2 = F::random(rng);
    let d1 = gamma1.scale(&s_d1);
    let d2 = gamma2.scale(&s_d2);

    // Sample blinding scalars
    let r_p1 = F::random(rng);
    // ...

    // Compute P1, P2, Q, R
    let p1 = E::pair(&d1, &gamma2) + self.setup.ht.scale(&r_p1);
    // ...

    // Get challenge c
    let c = transcript.challenge_scalar(b"sigma_c");

    // Compute responses
    let e1 = d1 + v1.scale(&c);
    let e2 = d2 + v2.scale(&c);
    let r1 = r_p1 + c * self.r_d1;
    let r2 = r_p2 + c * self.r_d2;
    let r3 = r_r + c * r_q + c_sq * self.r_c;

    ScalarProductProof { p1, p2, q, r, e1, e2, r1, r2, r3 }
}
```

**Assessment**: Implementation looks correct per Dory paper.

**Issue**: This function exists but is **never called** in the proof generation flow.

---

### 8. Sigma1 Proof (VMV Consistency) ✅ IMPLEMENTED (but not used)

**Implementation** (`src/reduce_and_fold.rs:630-672`):
- Proves `E_2 = y·Γ_2,fin + r_E2·H_2`
- Proves `y_com = y·Γ_1,fin + r_y·H_1`

**Assessment**: Implementation looks correct.

**Issue**: Never called - no `y_com` is created in the main flow.

---

### 9. Sigma2 Proof (VMV Relation) ✅ IMPLEMENTED (but not used)

**Implementation** (`src/reduce_and_fold.rs:725-762`):
- Proves `e(E_1, Γ_2,fin) - D_2 = e(H_1, t_1·Γ_2,fin + t_2·H_2)`

**Assessment**: Implementation looks correct.

**Issue**: Never called.

---

### 10. Verification ❌ CRITICAL ISSUE

**Current verify path** (`src/evaluation_proof.rs:341`):
```rust
// E2 = y · Γ2,fin where Γ2,fin = g2_0
let e2 = setup.g2_0.scale(&evaluation);  // <-- REVEALS y!
```

**Problem**: Even when proving with `ZK` mode, verification:
1. Takes `evaluation` as a parameter (reveals y)
2. Computes `E_2` from `y` (doesn't use prover's blinded E_2)
3. Uses `verify_final` not `verify_final_zk`

**For true ZK**, verification should:
1. NOT take `evaluation` as input
2. Use prover's `E_2` from `ZkVMVMessage`
3. Verify Sigma1 proof to confirm `y_com` and `E_2` are consistent
4. Call `verify_final_zk` with the scalar product proof

---

### 11. Proof Structure ❌ NOT USED

**Defined** (`src/proof.rs:53-80`):
```rust
pub struct ZkDoryProof<G1, G2, F, GT> {
    pub vmv_message: ZkVMVMessage<G1, G2, GT>,
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,
    pub final_message: ScalarProductMessage<G1, G2>,
    pub sigma1_proof: Sigma1Proof<G1, G2, F>,
    pub sigma2_proof: Sigma2Proof<F, GT>,
    pub scalar_product_proof: ScalarProductProof<G1, G2, F, GT>,
    pub nu: usize,
    pub sigma: usize,
}
```

**Issue**: This struct is defined but:
1. No `create_zk_evaluation_proof` function produces it
2. No `verify_zk_evaluation_proof` function consumes it
3. Tests use regular `prove/verify` which produce/consume `DoryProof`

---

## Test Analysis

**Current ZK tests** (`tests/arkworks/zk.rs`):
```rust
let proof = prove::<_, BN254, ..., ZK, _>(...).unwrap();  // Returns DoryProof
verify::<_, BN254, ...>(tier_2, evaluation, &point, &proof, ...);  // Takes evaluation!
```

**What's being tested**: The masking of intermediate protocol messages.

**What's NOT tested**:
- Hiding the evaluation `y`
- Sigma proofs
- ZK verification path

The tests pass because the underlying **values** are correct (masked values unmask to correct values), but the protocol is not actually zero-knowledge since `y` is still revealed to the verifier.

---

## Summary of Issues

| Component | Status | Issue |
|-----------|--------|-------|
| Mode trait | ✅ | - |
| VMV masking | ✅ | Values masked correctly |
| VMV message type | ❌ | Uses `VMVMessage` not `ZkVMVMessage` |
| E_2 computation | ❌ | Not sent by prover in ZK mode |
| y_com computation | ❌ | Not created |
| Reduce masking | ✅ | All values masked correctly |
| Blind accumulation | ⚠️ | Order may be wrong in first challenge |
| Final masking | ✅ | Correct |
| ScalarProductProof | ✅ | Implemented correctly |
| Sigma1Proof | ✅ | Implemented correctly |
| Sigma2Proof | ✅ | Implemented correctly |
| ZkDoryProof struct | ✅ | Defined correctly |
| `prove` API (ZK) | ❌ | Returns `DoryProof`, not `ZkDoryProof` |
| `verify` API (ZK) | ❌ | Takes `evaluation` as input, reveals `y` |
| verify_final_zk | ✅ | Implemented but not used |

---

## Required Work to Complete ZK

### Phase 1: Fix Blind Accumulation Order
1. Modify `apply_first_challenge` to take message blinds
2. Use message blinds (sum) directly, not accumulated state

### Phase 2: Create ZK Proof Generation
1. Add `create_zk_evaluation_proof` function that:
   - Computes `E_2 = y·Γ_2,fin + r_e2·H_2`
   - Computes `y_com = y·Γ_1,fin + r_y·H_1`
   - Creates `ZkVMVMessage`
   - Generates `Sigma1Proof`
   - Generates `Sigma2Proof`
   - Generates `ScalarProductProof`
   - Returns `ZkDoryProof`

### Phase 3: Create ZK Verification
1. Add `verify_zk_evaluation_proof` function that:
   - Does NOT take `evaluation` as input
   - Verifies `Sigma1Proof`
   - Verifies `Sigma2Proof`
   - Uses prover's `E_2` from message
   - Calls `verify_final_zk` with scalar product proof

### Phase 4: Update Tests
1. Add tests that verify `y` is not revealed
2. Test that verification works without knowing `y`
3. Test Sigma proof soundness (invalid proofs rejected)

---

## Conclusion

The implementation has laid excellent groundwork with:
- Correct masking/blinding infrastructure
- Correct Sigma proof implementations
- Correct proof structures

But it's **incomplete** because the ZK code paths are not integrated into the main `prove`/`verify` API. Currently, using `ZK` mode only masks intermediate values but still reveals `y` to the verifier - it's not truly zero-knowledge.
