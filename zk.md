# Zero-Knowledge Dory Implementation Guide

Integrate ZK into existing functions via `Mode` trait. No new protocol functions.

---

## Part 1: Mode Trait

```rust
// src/mode.rs

pub trait Mode<F: Field>: 'static {
    fn sample<T: Transcript>(transcript: &mut T, label: &[u8]) -> F;
    fn mask<G: Group<Scalar = F>>(value: G, base: &G, blind: &F) -> G;
}

pub struct Transparent;

impl<F: Field> Mode<F> for Transparent {
    fn sample<T: Transcript>(_: &mut T, _: &[u8]) -> F { F::ZERO }
    fn mask<G: Group<Scalar = F>>(value: G, _: &G, _: &F) -> G { value }
}

#[cfg(feature = "zk")]
pub struct ZK;

#[cfg(feature = "zk")]
impl<F: Field> Mode<F> for ZK {
    fn sample<T: Transcript>(transcript: &mut T, label: &[u8]) -> F {
        transcript.challenge_scalar(label)
    }
    fn mask<G: Group<Scalar = F>>(value: G, base: &G, blind: &F) -> G {
        value.add(&base.scale(blind))
    }
}
```

---

## Part 2: Existing Struct Changes

```diff
// src/reduce_and_fold.rs

-pub struct DoryProverState<'a, E: PairingCurve> {
+pub struct DoryProverState<'a, E: PairingCurve, M: Mode<E::Scalar> = Transparent> {
     pub v1: Vec<E::G1>,
     pub v2: Vec<E::G2>,
     pub v2_scalars: Option<Vec<E::Scalar>>,
     pub s1: Vec<E::Scalar>,
     pub s2: Vec<E::Scalar>,
     pub num_rounds: usize,
     pub setup: &'a ProverSetup<E>,
+
+    // Blinds (zero for Transparent, accumulated for ZK)
+    pub r_c: E::Scalar,
+    pub r_d1: E::Scalar,
+    pub r_d2: E::Scalar,
+    pub r_e1: E::Scalar,
+    pub r_e2: E::Scalar,
+    _mode: PhantomData<M>,
 }
```

---

## Part 3: Existing `reduce_round` Changes

```diff
-impl<'a, E: PairingCurve> DoryProverState<'a, E> {
+impl<'a, E: PairingCurve, M: Mode<E::Scalar>> DoryProverState<'a, E, M> {
     pub fn reduce_round<T: Transcript<Curve = E>>(
         &mut self,
         transcript: &mut T,
     ) -> (...) {
         let half = self.v1.len() / 2;
         let (v1_l, v1_r) = self.v1.split_at(half);
         let (v2_l, v2_r) = self.v2.split_at(half);
         let g2_prime = &self.setup.g2_vec[..half];
         let g1_prime = &self.setup.g1_vec[..half];

+        // ZK: sample blinds
+        let r_d1_l = M::sample(transcript, b"r_d1_l");
+        let r_d1_r = M::sample(transcript, b"r_d1_r");
+        let r_d2_l = M::sample(transcript, b"r_d2_l");
+        let r_d2_r = M::sample(transcript, b"r_d2_r");

-        let d1_left = E::multi_pair(v1_l, g2_prime);
-        let d1_right = E::multi_pair(v1_r, g2_prime);
-        let d2_left = E::multi_pair(g1_prime, v2_l);
-        let d2_right = E::multi_pair(g1_prime, v2_r);
+        // ZK: mask pairing results
+        let d1_left = M::mask(E::multi_pair(v1_l, g2_prime), &self.setup.ht, &r_d1_l);
+        let d1_right = M::mask(E::multi_pair(v1_r, g2_prime), &self.setup.ht, &r_d1_r);
+        let d2_left = M::mask(E::multi_pair(g1_prime, v2_l), &self.setup.ht, &r_d2_l);
+        let d2_right = M::mask(E::multi_pair(g1_prime, v2_r), &self.setup.ht, &r_d2_r);

         // ... e1_beta, e2_beta unchanged ...

         let first_msg = FirstReduceMessage { d1_left, d1_right, d2_left, d2_right, e1_beta, e2_beta };
         transcript.append_serde(b"first", &first_msg);

         let beta = transcript.challenge_scalar(b"beta");
         let beta_inv = beta.inv().unwrap();

         // ... vector updates unchanged ...

+        // ZK: accumulate blinds
+        self.r_c = self.r_c
+            .add(&r_d2_l.add(&r_d2_r).mul(&beta))
+            .add(&r_d1_l.add(&r_d1_r).mul(&beta_inv));

+        // ZK: sample second round blinds
+        let r_c_plus = M::sample(transcript, b"r_c+");
+        let r_c_minus = M::sample(transcript, b"r_c-");
+        let r_e1_plus = M::sample(transcript, b"r_e1+");
+        let r_e1_minus = M::sample(transcript, b"r_e1-");
+        let r_e2_plus = M::sample(transcript, b"r_e2+");
+        let r_e2_minus = M::sample(transcript, b"r_e2-");

-        let c_plus = E::multi_pair(v1_l, v2_r);
-        let c_minus = E::multi_pair(v1_r, v2_l);
-        let e1_plus = G1Routines::msm(v1_l, s2_r);
-        let e1_minus = G1Routines::msm(v1_r, s2_l);
-        let e2_plus = G2Routines::msm(v2_r, s1_l);
-        let e2_minus = G2Routines::msm(v2_l, s1_r);
+        // ZK: mask cross terms
+        let c_plus = M::mask(E::multi_pair(v1_l, v2_r), &self.setup.ht, &r_c_plus);
+        let c_minus = M::mask(E::multi_pair(v1_r, v2_l), &self.setup.ht, &r_c_minus);
+        let e1_plus = M::mask(G1Routines::msm(v1_l, s2_r), &self.setup.h1, &r_e1_plus);
+        let e1_minus = M::mask(G1Routines::msm(v1_r, s2_l), &self.setup.h1, &r_e1_minus);
+        let e2_plus = M::mask(G2Routines::msm(v2_r, s1_l), &self.setup.h2, &r_e2_plus);
+        let e2_minus = M::mask(G2Routines::msm(v2_l, s1_r), &self.setup.h2, &r_e2_minus);

         // ... second_msg, alpha challenge, vector folding unchanged ...

+        // ZK: update accumulated blinds
+        self.r_c = self.r_c
+            .add(&r_c_plus.mul(&alpha))
+            .add(&r_c_minus.mul(&alpha_inv));
+        self.r_d1 = r_d1_l.mul(&alpha).add(&r_d1_r);
+        self.r_d2 = r_d2_l.mul(&alpha_inv).add(&r_d2_r);
+        self.r_e1 = self.r_e1
+            .add(&r_e1_plus.mul(&alpha))
+            .add(&r_e1_minus.mul(&alpha_inv));
+        self.r_e2 = self.r_e2
+            .add(&r_e2_plus.mul(&alpha))
+            .add(&r_e2_minus.mul(&alpha_inv));

         self.num_rounds -= 1;
         (first_msg, second_msg)
     }
```

---

## Part 4: Existing `fold_scalars` Changes

```diff
     pub fn fold_scalars(&mut self, gamma: &E::Scalar) {
         let gamma_inv = gamma.inv().unwrap();
         self.v1[0] = self.v1[0].add(&self.setup.h1.scale(&gamma.mul(&self.s1[0])));
         self.v2[0] = self.v2[0].add(&self.setup.h2.scale(&gamma_inv.mul(&self.s2[0])));
+
+        // ZK: final blind accumulation
+        self.r_c = self.r_c
+            .add(&self.r_e2.mul(gamma))
+            .add(&self.r_e1.mul(&gamma_inv));
     }
```

---

## Part 5: Existing `compute_vmv_message` Changes

```diff
-pub fn compute_vmv_message<E, T>(
+pub fn compute_vmv_message<E, T, M: Mode<E::Scalar>>(
     row_commitments: &[E::G1],
     v_vec: &[E::Scalar],
     left_vec: &[E::Scalar],
     setup: &ProverSetup<E>,
     transcript: &mut T,
-) -> VMVMessage<E::G1, E::GT>
+) -> (VMVMessage<E::G1, E::GT>, E::Scalar, E::Scalar, E::Scalar, E::Scalar)
 where
     E: PairingCurve,
     T: Transcript<Curve = E>,
 {
+    let r_c = M::sample(transcript, b"vmv_r_c");
+    let r_d2 = M::sample(transcript, b"vmv_r_d2");
+    let r_e1 = M::sample(transcript, b"vmv_r_e1");
+    let r_e2 = M::sample(transcript, b"vmv_r_e2");

     let v_dot_t0 = G1Routines::msm(row_commitments, v_vec);
-    let c = E::pair(&v_dot_t0, &setup.g2_vec[0]);
+    let c = M::mask(E::pair(&v_dot_t0, &setup.g2_vec[0]), &setup.ht, &r_c);

     let g1_dot_v = G1Routines::msm(&setup.g1_vec[..v_vec.len()], v_vec);
-    let d2 = E::pair(&g1_dot_v, &setup.g2_vec[0]);
+    let d2 = M::mask(E::pair(&g1_dot_v, &setup.g2_vec[0]), &setup.ht, &r_d2);

-    let e1 = G1Routines::msm(row_commitments, left_vec);
+    let e1 = M::mask(G1Routines::msm(row_commitments, left_vec), &setup.h1, &r_e1);

-    VMVMessage { c, d2, e1 }
+    (VMVMessage { c, d2, e1 }, r_c, r_d2, r_e1, r_e2)
 }
```

---

## Part 6: Existing `scalar_product` Changes

```diff
     pub fn scalar_product(&self) -> (E::G1, E::G2) {
         (self.v1[0], self.v2[0])
     }
+
+    // ZK-only: Σ-protocol for final step
+    #[cfg(feature = "zk")]
+    pub fn scalar_product_zk<T: Transcript<Curve = E>>(&self, transcript: &mut T) -> ScalarProductProof<E>
+    where
+        M: Mode<E::Scalar>,  // Only callable when M = ZK
+    {
+        // ... Σ-protocol using self.r_c, self.r_d1, self.r_d2 ...
+    }
```

---

## Part 7: Usage

```rust
// Transparent (default) - unchanged call sites
let state: DoryProverState<E> = DoryProverState::new(...);
// or explicitly:
let state: DoryProverState<E, Transparent> = DoryProverState::new(...);

// ZK mode
#[cfg(feature = "zk")]
let state: DoryProverState<E, ZK> = DoryProverState::new_zk(...);
```

---

## Part 8: Summary

| Mode | `M::sample()` | `M::mask()` |
|------|---------------|-------------|
| `Transparent` | `F::ZERO` | `value` (identity) |
| `ZK` | `transcript.challenge_scalar()` | `value + base*blind` |

**Integration pattern**:
1. Add `M: Mode<E::Scalar>` parameter to existing structs/functions
2. Insert `M::sample()` before operations needing blinds
3. Wrap computed values with `M::mask(value, base, &blind)`
4. Add blind accumulation after challenges

For `Transparent`: sample returns zero, mask returns value unchanged, accumulation is `0 + 0*x = 0`.

---

## Part 9: ZK-Only Additions

Only these are truly new (feature-gated):

```rust
#[cfg(feature = "zk")]
pub struct ScalarProductProof<E: PairingCurve> { ... }

#[cfg(feature = "zk")]
pub struct Sigma1Proof<E: PairingCurve> { ... }

#[cfg(feature = "zk")]
pub struct Sigma2Proof<E: PairingCurve> { ... }
```

---

## Part 10: Checklist

- [ ] Add `Mode` trait to `src/mode.rs`
- [ ] Add `M: Mode` parameter to `DoryProverState`
- [ ] Add blind fields (`r_c`, `r_d1`, `r_d2`, `r_e1`, `r_e2`) to state
- [ ] Modify `reduce_round`: insert `M::sample()` and `M::mask()` calls
- [ ] Modify `fold_scalars`: add blind accumulation
- [ ] Modify `compute_vmv_message`: add sampling and masking
- [ ] Add `scalar_product_zk` impl for `DoryProverState<E, ZK>`
- [ ] Add `ScalarProductProof`, `Sigma1Proof`, `Sigma2Proof` (ZK only)

---

## References

- IACR 2020/1274: "Dory: Efficient, Transparent arguments for Generalised Inner Products and Polynomial Commitments"
