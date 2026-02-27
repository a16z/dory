# Zero-Knowledge Analysis of Dory PCS Implementation

This document audits every value the prover sends to the verifier (via the
Fiat-Shamir transcript or proof struct) and determines whether it is blinded,
public, or leaks witness information.

**Security model**: Honest-Verifier Zero-Knowledge (HVZK) in the Random Oracle
Model (ROM), which is standard for Fiat-Shamir-transformed protocols.

**Notation**:
- `Γ₁, Γ₂` — public setup generators in G₁, G₂
- `H₁, H₂` — blinding generators; `HT = e(H₁, H₂)`
- `r_*` — random blinding scalars sampled via `Mode::sample`
- `f` — the committed polynomial (the witness)
- `z` — the evaluation point; `y = f(z)` — the evaluation

---

## 0. Mode Dispatch (`mode.rs`)

The `Mode` trait controls all blinding:

| Mode | `sample()` | `mask(v, base, r)` |
|------|-----------|---------------------|
| `Transparent` | Returns `0` | Returns `v` (identity) |
| `ZK` | Returns `F::random(rng)` | Returns `v + base · r` |

**Every `M::mask(...)` call below is a no-op in Transparent mode.** The rest of
this document focuses exclusively on ZK mode (`feature = "zk"`).

---

## 1. Commitment Phase (`ark_poly.rs`)

### 1a. `commit()` — Transparent commitment

```
row_commit[i] = MSM(Γ₁, coeffs_row_i)          (no blinding)
tier2          = Σ e(row_commit[i], Γ₂[i])
```

**Verdict**: NOT hiding. The tier-1 row commitments are deterministic functions
of the polynomial coefficients. The tier-2 commitment is a deterministic pairing
aggregate.

### 1b. `commit_zk()` — ZK commitment

```
blind[i]       ← random                         (fresh per row)
row_commit[i]  = MSM(Γ₁, coeffs_row_i) + H₁ · blind[i]
tier2          = Σ e(row_commit[i], Γ₂[i])
```

**Verdict**: HIDING (Pedersen). Each row commitment is a Pedersen commitment
with independent randomness. The tier-2 commitment inherits computational
hiding from the DL-hard blinding in each row.

Returns `(tier2, row_commitments, blinds)` — the caller must keep `blinds`
secret and supply the blinded `row_commitments` to the prover.

---

## 2. VMV Phase (`evaluation_proof.rs:132–177`)

Four independent blinds are sampled:

```
r_c, r_d2, r_e1, r_e2 ← random
```

### 2a. `C` — Inner product value (GT)

```
C = e(MSM(row_comms, v_vec), Γ₂,fin) + r_c · HT
```

**Sent to transcript**: `vmv_c`
**Verdict**: BLINDED. Masked by `r_c · HT` with fresh randomness. Reveals
nothing about the polynomial's internal structure.

### 2b. `D₂` — Generator inner product (GT)

```
D₂ = e(MSM(Γ₁[..2^σ], v_vec), Γ₂,fin) + r_d2 · HT
```

**Sent to transcript**: `vmv_d2`
**Verdict**: BLINDED. `v_vec = Lᵀ × M` encodes the polynomial, but `r_d2 · HT`
masks the value. Computationally hiding under DL in GT.

### 2c. `E₁` — Row-scalar MSM (G₁)

```
E₁ = MSM(row_comms, left_vec) + r_e1 · H₁
```

**Sent to transcript**: `vmv_e1`
**Verdict**: BLINDED. Masked by `r_e1 · H₁`. Even if `row_comms` are
themselves blinded (via `commit_zk`), the additional `r_e1` ensures
independence.

### 2d. `E₂` — Evaluation commitment (G₂, ZK-only)

```
E₂ = Γ₂,fin · y + r_e2 · H₂
```

**Sent to transcript**: `vmv_e2`
**Verdict**: BLINDED. Pedersen commitment to the evaluation `y` with fresh
randomness `r_e2`. The verifier learns nothing about `y` from `E₂` alone.

In transparent mode, the verifier computes `e₂ = Γ₂,fin · y` directly from
the public evaluation — no commitment is needed.

### 2e. `y_com` — Evaluation Pedersen commitment (G₁, ZK-only)

```
y_com = Γ₁,fin · y + H₁ · r_y       (r_y ← random)
```

**Sent to transcript**: `vmv_y_com`
**Verdict**: BLINDED. Standard Pedersen commitment. Together with `E₂`, this
enables the Sigma1 proof (§4a) to attest that both commit to the same `y`
without revealing it.

---

## 3. Sigma Proofs (ZK-only, `reduce_and_fold.rs:452–570`)

### 3a. Sigma1 — Same-`y` proof

**Relation proved**: `E₂` and `y_com` commit to the same scalar `y`.

```
Prover:
  k₁, k₂, k₃ ← random
  a₁ = Γ₂,fin · k₁ + H₂ · k₂
  a₂ = Γ₁,fin · k₁ + H₁ · k₃
  (append a₁, a₂ → transcript)
  c = H(transcript)
  z₁ = k₁ + c·y,  z₂ = k₂ + c·r_e2,  z₃ = k₃ + c·r_y

Verifier checks:
  Γ₂,fin · z₁ + H₂ · z₂  ==  a₁ + c · E₂
  Γ₁,fin · z₁ + H₁ · z₃  ==  a₂ + c · y_com
```

**Sent**: `(a₁, a₂, z₁, z₂, z₃)`
**Verdict**: HVZK. Standard Sigma protocol with 3 random nonces. The
simulator picks `z₁, z₂, z₃` uniformly, then programs `a₁, a₂` to satisfy
the verification equations. Response distribution is identical to real proofs.

### 3b. Sigma2 — VMV consistency proof

**Relation proved**: `e(E₁, Γ₂,fin) − D₂` lies in the span of `H₁`, i.e.,
the difference between `E₁`'s and `D₂`'s blinding is consistent:
`e(E₁, Γ₂,fin) − D₂ = e(H₁, r_e1 · Γ₂,fin + (−r_d2) · H₂)`.

```
Prover:
  k₁, k₂ ← random
  a = e(H₁, Γ₂,fin · k₁ + H₂ · k₂)
  (append a → transcript)
  c = H(transcript)
  z₁ = k₁ + c · r_e1,  z₂ = k₂ + c · (−r_d2)

Verifier checks:
  e(H₁, Γ₂,fin · z₁ + H₂ · z₂)  ==  a + c · (e(E₁, Γ₂,fin) − D₂)
```

**Sent**: `(a, z₁, z₂)`
**Verdict**: HVZK. Standard 2-nonce Sigma protocol. Simulatable by the same
strategy as Sigma1.

---

## 4. Reduce-and-Fold Rounds (`reduce_and_fold.rs`)

Each round `t` (of `σ` total) produces two messages and consumes two
challenges `(βₜ, αₜ)`.

### 4a. First Reduce Message (6 values per round)

**Per-round blinds sampled**:
```
round_d1[0], round_d1[1] ← random
round_d2[0], round_d2[1] ← random
```

| Value | Formula | Blinding | Verdict |
|-------|---------|----------|---------|
| `D₁L` | `e(v₁L, Γ₂') + round_d1[0] · HT` | `round_d1[0]` | **BLINDED** |
| `D₁R` | `e(v₁R, Γ₂') + round_d1[1] · HT` | `round_d1[1]` | **BLINDED** |
| `D₂L` | `e(Γ₁', v₂L) + round_d2[0] · HT` | `round_d2[0]` | **BLINDED** |
| `D₂R` | `e(Γ₁', v₂R) + round_d2[1] · HT` | `round_d2[1]` | **BLINDED** |
| `E₁β` | `MSM(Γ₁, s₂)` | **NONE** | **PUBLIC** (see below) |
| `E₂β` | `MSM(Γ₂, s₁)` | **NONE** | **PUBLIC** (see below) |

**E₁β and E₂β are not masked**, but `s₁` and `s₂` are scalar vectors derived
solely from the evaluation point coordinates and the Fiat-Shamir challenges
(both public to the verifier). The generators `Γ₁, Γ₂` are public setup
parameters. Therefore:

- `E₁β = MSM(Γ₁, s₂)` is a deterministic, publicly computable value.
- `E₂β = MSM(Γ₂, s₁)` is a deterministic, publicly computable value.
- **No polynomial information leaks through these values.**

> **Note for committed-point applications**: If the evaluation point `z` is
> committed rather than public, the verifier could in principle reconstruct
> `E₁β` and `E₂β` only if they knew `z`. Since these values appear in the
> proof, a third party observing the proof (but not knowing `z`) could use
> `E₁β`, `E₂β` to recover information about the evaluation point.
> However, the standard Dory verification API (`verify()`) takes `point` as
> a **public input**. Hiding the point requires an additional protocol layer
> on top of Dory (e.g., proving in ZK that the committed point was used).

### 4b. Second Reduce Message (6 values per round)

**Per-round blinds sampled**:
```
round_c[0], round_c[1]   ← random
round_e1[0], round_e1[1] ← random
round_e2[0], round_e2[1] ← random
```

| Value | Formula | Blinding | Verdict |
|-------|---------|----------|---------|
| `C₊` | `e(v₁L, v₂R) + round_c[0] · HT` | `round_c[0]` | **BLINDED** |
| `C₋` | `e(v₁R, v₂L) + round_c[1] · HT` | `round_c[1]` | **BLINDED** |
| `E₁₊` | `MSM(v₁L, s₂R) + round_e1[0] · H₁` | `round_e1[0]` | **BLINDED** |
| `E₁₋` | `MSM(v₁R, s₂L) + round_e1[1] · H₁` | `round_e1[1]` | **BLINDED** |
| `E₂₊` | `MSM(v₂R, s₁L) + round_e2[0] · H₂` | `round_e2[0]` | **BLINDED** |
| `E₂₋` | `MSM(v₂L, s₁R) + round_e2[1] · H₂` | `round_e2[1]` | **BLINDED** |

**Verdict**: All six values are independently blinded with fresh randomness.
The cross-products `e(v₁L, v₂R)` etc. encode polynomial information but are
fully hidden by the masks.

### 4c. Blinding Accumulation

After each challenge application, the prover accumulates blinds:

```
After β:   r_c ← r_c + β · r_d2 + β⁻¹ · r_d1

After α:   r_c  ← r_c + α · round_c[0] + α⁻¹ · round_c[1]
           r_d1 ← α · round_d1[0] + round_d1[1]
           r_d2 ← α⁻¹ · round_d2[0] + round_d2[1]
           r_e1 ← r_e1 + α · round_e1[0] + α⁻¹ · round_e1[1]
           r_e2 ← r_e2 + α · round_e2[0] + α⁻¹ · round_e2[1]
```

This tracking is correct: the accumulated blinds mirror the verifier's
accumulation of the GT/G₁/G₂ elements, ensuring that the final scalar
product proof can account for all blinding contributions.

---

## 5. Final Message (`reduce_and_fold.rs:381–420`)

After `γ` is derived from the transcript:

```
r_final1, r_final2 ← random          (zero in Transparent mode)

E₁_final = v₁[0] + (γ · s₁[0] + r_final1) · H₁
E₂_final = v₂[0] + (γ⁻¹ · s₂[0] + r_final2) · H₂

r_c ← r_c + γ · r_e2 + γ⁻¹ · r_e1
```

**Sent to transcript**: `final_e1`, `final_e2`

In ZK mode, `r_final1` and `r_final2` are fresh random scalars that mask the
deterministic offset `γ · s₁[0]` (resp. `γ⁻¹ · s₂[0]`), preventing recovery
of the folded vectors `v₁[0]` and `v₂[0]`.

These blinds do **not** need to be tracked in the accumulated `r_c` because
`verify_final_zk` does not use the final message elements in the pairing check
— it uses the scalar product proof's blinded `e₁, e₂` instead. The final
message values serve only as entropy for the Fiat-Shamir `d` challenge.

In Transparent mode, `r_final1 = r_final2 = 0` (via `Mode::sample`), so the
transparent verification path (`verify_final`) is unaffected.

**Verdict**: **BLINDED** (ZK mode). The folded vectors `v₁[0]`, `v₂[0]`
cannot be recovered from the proof.

---

## 6. Scalar Product Proof (ZK-only, `reduce_and_fold.rs:411–448`)

Generated **before** `compute_final_message`, using the current `v₁[0], v₂[0]`:

```
sd₁, sd₂ ← random
d₁ = Γ₁,₀ · sd₁,     d₂ = Γ₂,₀ · sd₂

rp₁, rp₂, rq, rr ← random
p₁ = e(d₁, Γ₂,₀) + rp₁ · HT
p₂ = e(Γ₁,₀, d₂) + rp₂ · HT
q  = e(d₁, v₂) + e(v₁, d₂) + rq · HT
r  = e(d₁, d₂) + rr · HT

(append p₁, p₂, q, r → transcript)
c = H(transcript)                         ← Fiat-Shamir challenge

Response:
  e₁ = d₁ + v₁ · c           (blinded by d₁)
  e₂ = d₂ + v₂ · c           (blinded by d₂)
  r₁ = rp₁ + c · r_d1        (blinded by rp₁)
  r₂ = rp₂ + c · r_d2        (blinded by rp₂)
  r₃ = rr + c · rq + c² · r_c (blinded by rr, rq)
```

**Sent**: `(p₁, p₂, q, r, e₁, e₂, r₁, r₂, r₃)`

**Verdict**: HVZK. This is a batched Sigma protocol for the relation:

```
e(v₁, v₂) + r_c · HT = C_accumulated
e(v₁, Γ₂,₀) + r_d1 · HT = D₁_accumulated
e(Γ₁,₀, v₂) + r_d2 · HT = D₂_accumulated
```

The 4 commitments `(p₁, p₂, q, r)` are independently blinded. The responses
are standard Sigma-protocol responses. A simulator can produce
indistinguishable transcripts by choosing responses first and computing
commitments.

### Interaction with Final Message

Since the final message is now independently blinded (§5), `v₁[0]` and `v₂[0]`
cannot be recovered. This means the scalar product proof's blinding commitments
`d₁, d₂` remain hidden, preserving the full HVZK property of the Sigma
protocol.

---

## 7. Verification Paths

### 7a. Transparent Final Check (`verify_final`)

```
LHS = e(E₁ + d·Γ₁,₀, E₂ + d⁻¹·Γ₂,₀)     (4 pairings batched)
RHS = C + s₁·s₂·HT + χ₀ + d·D₂ + d⁻¹·D₁ + d²·D₂_init
```

All values on both sides are unblinded → no ZK.

### 7b. ZK Final Check (`verify_final_zk`)

```
LHS = e(sp.e₁ + d·Γ₁,₀,  sp.e₂ + d⁻¹·Γ₂,₀)
RHS = χ₀ + sp.r + c·sp.q + c²·C
    + d·(sp.p₂ + c·D₂) + d⁻¹·(sp.p₁ + c·D₁)
    − HT·(sp.r₃ + d·sp.r₂ + d⁻¹·sp.r₁)
```

Uses `sp.e₁/e₂` (randomly blinded) instead of `final_message.e₁/e₂`.
The random scalar `d` (derived after `final_e1, final_e2` are appended to the
transcript) batches 4 verification equations into one pairing.

**Note**: `final_message.e1/e2` are appended to the transcript purely for
Fiat-Shamir entropy — the actual verification uses the scalar product proof's
blinded elements.

---

## 8. Summary Table

| Proof Element | Group | Blinded? | Blind Source | Leaks Polynomial Info? |
|---------------|-------|----------|-------------|----------------------|
| **VMV C** | GT | Yes | `r_c · HT` | No |
| **VMV D₂** | GT | Yes | `r_d2 · HT` | No |
| **VMV E₁** | G₁ | Yes | `r_e1 · H₁` | No |
| **VMV E₂** (ZK) | G₂ | Yes | `r_e2 · H₂` | No |
| **y_com** (ZK) | G₁ | Yes | `r_y · H₁` | No |
| **Sigma1** (a₁,a₂,z₁,z₂,z₃) | mixed | HVZK | `k₁,k₂,k₃` | No |
| **Sigma2** (a,z₁,z₂) | GT,F,F | HVZK | `k₁,k₂` | No |
| **D₁L, D₁R** | GT | Yes | `round_d1[·] · HT` | No |
| **D₂L, D₂R** | GT | Yes | `round_d2[·] · HT` | No |
| **E₁β** | G₁ | No | — | No (public: MSM(Γ₁, s₂)) |
| **E₂β** | G₂ | No | — | No (public: MSM(Γ₂, s₁)) |
| **C₊, C₋** | GT | Yes | `round_c[·] · HT` | No |
| **E₁₊, E₁₋** | G₁ | Yes | `round_e1[·] · H₁` | No |
| **E₂₊, E₂₋** | G₂ | Yes | `round_e2[·] · H₂` | No |
| **E₁_final** | G₁ | Yes | `r_final1 · H₁` | No |
| **E₂_final** | G₂ | Yes | `r_final2 · H₂` | No |
| **SP p₁,p₂,q,r** | GT | Yes | `rp₁,rp₂,rq,rr` | No |
| **SP e₁,e₂** | G₁,G₂ | Yes | `d₁ + v₁·c` | No |
| **SP r₁,r₂,r₃** | F | Yes | Sigma response | No |

---

## 9. Blinding Budget

Per proof (with `σ` rounds):

| Phase | Blinds Sampled | Count |
|-------|---------------|-------|
| VMV | `r_c, r_d2, r_e1, r_e2` | 4 |
| VMV (ZK) | `r_y` | 1 |
| Sigma1 | `k₁, k₂, k₃` | 3 |
| Sigma2 | `k₁, k₂` | 2 |
| Per round (×σ) | `round_d1[2], round_d2[2], round_c[2], round_e1[2], round_e2[2]` | 10σ |
| Final message | `r_final1, r_final2` | 2 |
| Scalar product | `sd₁, sd₂, rp₁, rp₂, rq, rr` | 6 |

**Total**: `18 + 10σ` random field elements per proof.

---

## 10. Conclusions

### What IS hidden (ZK mode)

1. **All polynomial coefficients** — no intermediate message reveals any
   individual coefficient or coefficient relation beyond the public evaluation.

2. **The evaluation value `y`** — hidden behind Pedersen commitments `E₂` and
   `y_com`, with consistency proven via Sigma1.

3. **Internal protocol state** — all round messages involving `v₁, v₂`
   cross-products and MSMs are independently blinded.

4. **The accumulated blinding** `r_c` — correctly tracked through all challenge
   transformations and consumed by the scalar product proof.

### What is NOT hidden

1. **The evaluation point `z`** — passed as a public input to `verify()`.
   `E₁β` and `E₂β` are computable from `z` + setup, so they don't leak
   anything the verifier doesn't already know. In a committed-point protocol,
   these would need an additional hiding layer.

2. **Matrix dimensions `ν, σ`** — stored in the proof struct as `nu, sigma`.
   These reveal the matrix layout used for the polynomial but not the
   polynomial itself.

### Overall Verdict

The implementation achieves **computational HVZK in the Random Oracle Model**
when the `zk` feature is enabled. Every protocol message that encodes
polynomial-dependent information is masked by independent randomness, with one
exception (`E₁β/E₂β` which are public, not polynomial-dependent). The three
Sigma sub-protocols (Sigma1, Sigma2, scalar product) are all standard and HVZK.
The final message elements are independently blinded, preventing recovery of
the folded vectors `v₁[0], v₂[0]`.
