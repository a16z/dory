//! Opening proof protocol - prover and verifier state management
//!
//! This module contains the state machines for the interactive Dory protocol.
//! The prover maintains vectors and computes messages, while the verifier
//! maintains accumulated values and verifies messages.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use crate::error::DoryError;
use crate::messages::*;
use crate::mode::{Mode, Transparent};
use crate::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::setup::{ProverSetup, VerifierSetup};
use std::marker::PhantomData;

#[cfg(feature = "zk")]
use crate::primitives::transcript::Transcript;

type Scalar<E> = <<E as PairingCurve>::G1 as Group>::Scalar;

/// Prover state for the Dory opening protocol
///
/// Maintains the current state of the prover during the interactive protocol.
/// The state consists of vectors that get folded in each round.
pub struct DoryProverState<'a, E: PairingCurve, M: Mode = Transparent> {
    /// Current v1 vector (G1 elements)
    v1: Vec<E::G1>,

    /// Current v2 vector (G2 elements)
    v2: Vec<E::G2>,

    /// For first round only: scalars used to construct v2 from fixed base h2
    v2_scalars: Option<Vec<<E::G1 as Group>::Scalar>>,

    /// Current s1 vector (scalars)
    s1: Vec<<E::G1 as Group>::Scalar>,

    /// Current s2 vector (scalars)
    s2: Vec<<E::G1 as Group>::Scalar>,

    /// Number of rounds remaining (log₂ of vector length)
    num_rounds: usize,

    /// Reference to prover setup
    setup: &'a ProverSetup<E>,

    // ZK accumulated blinds (zero in Transparent mode)
    r_c: Scalar<E>,
    r_d1: Scalar<E>,
    r_d2: Scalar<E>,
    r_e1: Scalar<E>,
    r_e2: Scalar<E>,
    // Per-round blinds stored between compute and apply
    round_d1: [Scalar<E>; 2],
    round_d2: [Scalar<E>; 2],
    round_c: [Scalar<E>; 2],
    round_e1: [Scalar<E>; 2],
    round_e2: [Scalar<E>; 2],

    _mode: PhantomData<M>,
}

/// Verifier state for the Dory opening protocol
///
/// Maintains the current accumulated values during verification.
/// These values get updated based on prover messages and challenges.
pub struct DoryVerifierState<E: PairingCurve> {
    /// Inner product accumulator
    c: E::GT,

    /// Commitment to v1: ⟨v1, Γ2⟩
    d1: E::GT,

    /// Commitment to v2: ⟨Γ1, v2⟩
    d2: E::GT,

    /// Extended protocol: commitment to s1
    e1: E::G1,

    /// Extended protocol: commitment to s2
    e2: E::G2,

    /// Initial e1 from VMV message
    /// Used in verify_final to batch the VMV constraint: D₂_init = e(E₁_init, H₂)
    e1_init: E::G1,

    /// Initial d2 from VMV message
    /// Used in verify_final to batch the VMV constraint: D₂_init = e(E₁_init, H₂)
    d2_init: E::GT,

    /// Accumulated scalar for s1 after folding across rounds
    s1_acc: <E::G1 as Group>::Scalar,

    /// Accumulated scalar for s2 after folding across rounds
    s2_acc: <E::G1 as Group>::Scalar,

    /// Per-round coordinates for s1 (length = num_rounds). Order matches folding order.
    s1_coords: Vec<<E::G1 as Group>::Scalar>,

    /// Per-round coordinates for s2 (length = num_rounds). Order matches folding order.
    s2_coords: Vec<<E::G1 as Group>::Scalar>,

    /// Number of rounds remaining for indexing setup arrays
    num_rounds: usize,

    /// Reference to verifier setup
    setup: VerifierSetup<E>,
}

impl<'a, E: PairingCurve, M: Mode> DoryProverState<'a, E, M>
where
    <E::G1 as Group>::Scalar: Field,
    E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
{
    /// Create new prover state
    ///
    /// # Parameters
    /// - `v1`: Initial G1 vector
    /// - `v2`: Initial G2 vector
    /// - `v2_scalars`: Optional scalars where v2 = h2 * scalars; enables MSM+pair in first round
    /// - `s1`: Initial scalar vector for G1 side
    /// - `s2`: Initial scalar vector for G2 side
    /// - `setup`: Prover setup parameters
    pub fn new(
        v1: Vec<E::G1>,
        v2: Vec<E::G2>,
        v2_scalars: Option<Vec<<E::G1 as Group>::Scalar>>,
        s1: Vec<<E::G1 as Group>::Scalar>,
        s2: Vec<<E::G1 as Group>::Scalar>,
        setup: &'a ProverSetup<E>,
    ) -> Self {
        debug_assert_eq!(v1.len(), v2.len(), "v1 and v2 must have equal length");
        debug_assert_eq!(v1.len(), s1.len(), "v1 and s1 must have equal length");
        debug_assert_eq!(v1.len(), s2.len(), "v1 and s2 must have equal length");
        debug_assert!(
            v1.len().is_power_of_two(),
            "vector length must be power of 2"
        );
        if let Some(sc) = v2_scalars.as_ref() {
            debug_assert_eq!(sc.len(), v2.len(), "v2_scalars must match v2 length");
        }

        let num_rounds = v1.len().trailing_zeros() as usize;
        let z = Scalar::<E>::zero();

        Self {
            v1,
            v2,
            v2_scalars,
            s1,
            s2,
            num_rounds,
            setup,
            r_c: z,
            r_d1: z,
            r_d2: z,
            r_e1: z,
            r_e2: z,
            round_d1: [z; 2],
            round_d2: [z; 2],
            round_c: [z; 2],
            round_e1: [z; 2],
            round_e2: [z; 2],
            _mode: PhantomData,
        }
    }

    /// Set initial VMV blinds (r_c, r_d2, r_e1, r_e2).
    pub fn set_initial_blinds(
        &mut self,
        r_c: Scalar<E>,
        r_d2: Scalar<E>,
        r_e1: Scalar<E>,
        r_e2: Scalar<E>,
    ) {
        (self.r_c, self.r_d2, self.r_e1, self.r_e2) = (r_c, r_d2, r_e1, r_e2);
    }

    /// Compute first reduce message for current round
    ///
    /// Computes D1L, D1R, D2L, D2R, E1β, E2β based on current state.
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_first_message")]
    pub fn compute_first_message<M1, M2, R>(
        &mut self,
        rng: &mut R,
    ) -> FirstReduceMessage<E::G1, E::G2, E::GT>
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        R: rand_core::RngCore,
    {
        assert!(
            self.num_rounds > 0,
            "Not enough rounds left in prover state"
        );

        let n2 = 1 << (self.num_rounds - 1); // n/2

        // Split vectors into left and right halves
        let (v1_l, v1_r) = self.v1.split_at(n2);
        let (v2_l, v2_r) = self.v2.split_at(n2);

        // Get collapsed generator vectors of length n/2
        let g1_prime = &self.setup.g1_vec[..n2];
        let g2_prime = &self.setup.g2_vec[..n2];

        // Sample round blinds (zero in Transparent mode)
        self.round_d1 = [M::sample(rng), M::sample(rng)];
        self.round_d2 = [M::sample(rng), M::sample(rng)];

        // D₁L = ⟨v₁L, Γ₂'⟩, D₁R = ⟨v₁R, Γ₂'⟩
        let ht = &self.setup.ht;
        let d1_left = M::mask(
            E::multi_pair_g2_setup(v1_l, g2_prime),
            ht,
            &self.round_d1[0],
        );
        let d1_right = M::mask(
            E::multi_pair_g2_setup(v1_r, g2_prime),
            ht,
            &self.round_d1[1],
        );

        // D₂L = ⟨Γ₁', v₂L⟩, D₂R = ⟨Γ₁', v₂R⟩
        // If v2 was constructed as h2 * scalars (first round), compute MSM(Γ₁', scalars) then one pairing.
        let (d2_left_base, d2_right_base) = if let Some(scalars) = self.v2_scalars.as_ref() {
            let (s_l, s_r) = scalars.split_at(n2);
            let sum_left = M1::msm(g1_prime, s_l);
            let sum_right = M1::msm(g1_prime, s_r);
            let g2_fin = &self.setup.g2_vec[0];
            (E::pair(&sum_left, g2_fin), E::pair(&sum_right, g2_fin))
        } else {
            (
                E::multi_pair_g1_setup(g1_prime, v2_l),
                E::multi_pair_g1_setup(g1_prime, v2_r),
            )
        };
        let d2_left = M::mask(d2_left_base, ht, &self.round_d2[0]);
        let d2_right = M::mask(d2_right_base, ht, &self.round_d2[1]);

        // Compute E values for extended protocol: MSMs with scalar vectors
        // E₁β = ⟨Γ₁, s₂⟩
        let e1_beta = M1::msm(&self.setup.g1_vec[..1 << self.num_rounds], &self.s2[..]);

        // E₂β = ⟨Γ₂, s₁⟩
        let e2_beta = M2::msm(&self.setup.g2_vec[..1 << self.num_rounds], &self.s1[..]);

        FirstReduceMessage {
            d1_left,
            d1_right,
            d2_left,
            d2_right,
            e1_beta,
            e2_beta,
        }
    }

    /// Apply first challenge (beta) and combine vectors
    ///
    /// Updates the state by combining with generators scaled by beta.
    #[tracing::instrument(skip_all, name = "DoryProverState::apply_first_challenge")]
    pub fn apply_first_challenge<M1, M2>(&mut self, beta: &<E::G1 as Group>::Scalar)
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
    {
        let beta_inv = (*beta).inv().expect("beta must be invertible");

        let n = 1 << self.num_rounds;

        // Combine: v₁ ← v₁ + β·Γ₁
        M1::fixed_scalar_mul_bases_then_add(&self.setup.g1_vec[..n], &mut self.v1, beta);

        // Combine: v₂ ← v₂ + β⁻¹·Γ₂
        M2::fixed_scalar_mul_bases_then_add(&self.setup.g2_vec[..n], &mut self.v2, &beta_inv);

        // After first combine, the `v2_scalars` optimization does not apply.
        self.v2_scalars = None;

        // Accumulate blinds: rC ← rC + β·rD2 + β⁻¹·rD1
        self.r_c = self.r_c + self.r_d2 * *beta + self.r_d1 * beta_inv;
    }

    /// Compute second reduce message for current round
    ///
    /// Computes C+, C-, E1+, E1-, E2+, E2- based on current state.
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_second_message")]
    pub fn compute_second_message<M1, M2, R>(
        &mut self,
        rng: &mut R,
    ) -> SecondReduceMessage<E::G1, E::G2, E::GT>
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        R: rand_core::RngCore,
    {
        let n2 = 1 << (self.num_rounds - 1); // n/2

        // Split all vectors into left and right halves
        let (v1_l, v1_r) = self.v1.split_at(n2);
        let (v2_l, v2_r) = self.v2.split_at(n2);
        let (s1_l, s1_r) = self.s1.split_at(n2);
        let (s2_l, s2_r) = self.s2.split_at(n2);

        // Sample round blinds (zero in Transparent mode)
        self.round_c = [M::sample(rng), M::sample(rng)];
        self.round_e1 = [M::sample(rng), M::sample(rng)];
        self.round_e2 = [M::sample(rng), M::sample(rng)];

        // C₊ = ⟨v₁L, v₂R⟩, C₋ = ⟨v₁R, v₂L⟩
        let ht = &self.setup.ht;
        let c_plus = M::mask(E::multi_pair(v1_l, v2_r), ht, &self.round_c[0]);
        let c_minus = M::mask(E::multi_pair(v1_r, v2_l), ht, &self.round_c[1]);

        // Compute E terms for extended protocol: cross products with scalars
        let e1_plus = M::mask(M1::msm(v1_l, s2_r), &self.setup.h1, &self.round_e1[0]);
        let e1_minus = M::mask(M1::msm(v1_r, s2_l), &self.setup.h1, &self.round_e1[1]);
        let e2_plus = M::mask(M2::msm(v2_r, s1_l), &self.setup.h2, &self.round_e2[0]);
        let e2_minus = M::mask(M2::msm(v2_l, s1_r), &self.setup.h2, &self.round_e2[1]);

        SecondReduceMessage {
            c_plus,
            c_minus,
            e1_plus,
            e1_minus,
            e2_plus,
            e2_minus,
        }
    }

    /// Apply second challenge (alpha) and fold vectors
    ///
    /// Reduces the vector size by half using the alpha challenge.
    #[tracing::instrument(skip_all, name = "DoryProverState::apply_second_challenge")]
    pub fn apply_second_challenge<M1: DoryRoutines<E::G1>, M2: DoryRoutines<E::G2>>(
        &mut self,
        alpha: &<E::G1 as Group>::Scalar,
    ) {
        let alpha_inv = (*alpha).inv().expect("alpha must be invertible");
        let n2 = 1 << (self.num_rounds - 1); // n/2

        // Fold v₁: v₁ ← α·v₁L + v₁R
        let (v1_l, v1_r) = self.v1.split_at_mut(n2);
        M1::fixed_scalar_mul_vs_then_add(v1_l, v1_r, alpha);
        self.v1.truncate(n2);

        // Fold v₂: v₂ ← α⁻¹·v₂L + v₂R
        let (v2_l, v2_r) = self.v2.split_at_mut(n2);
        M2::fixed_scalar_mul_vs_then_add(v2_l, v2_r, &alpha_inv);
        self.v2.truncate(n2);

        // Fold s₁: s₁ ← α·s₁L + s₁R
        let (s1_l, s1_r) = self.s1.split_at_mut(n2);
        M1::fold_field_vectors(s1_l, s1_r, alpha);
        self.s1.truncate(n2);

        // Fold s₂: s₂ ← α⁻¹·s₂L + s₂R
        let (s2_l, s2_r) = self.s2.split_at_mut(n2);
        M1::fold_field_vectors(s2_l, s2_r, &alpha_inv);
        self.s2.truncate(n2);

        // Update accumulated blinds from stored round blinds
        self.r_c = self.r_c + self.round_c[0] * *alpha + self.round_c[1] * alpha_inv;
        self.r_d1 = self.round_d1[0] * *alpha + self.round_d1[1];
        self.r_d2 = self.round_d2[0] * alpha_inv + self.round_d2[1];
        self.r_e1 = self.r_e1 + self.round_e1[0] * *alpha + self.round_e1[1] * alpha_inv;
        self.r_e2 = self.r_e2 + self.round_e2[0] * *alpha + self.round_e2[1] * alpha_inv;

        // Decrement round counter
        self.num_rounds -= 1;
    }

    /// Compute final scalar product message
    ///
    /// Applies fold-scalars transformation and returns the final E1, E2 elements.
    /// Must be called when num_rounds=0 (vectors are size 1).
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_final_message")]
    pub fn compute_final_message<M1, M2>(
        &mut self,
        gamma: &<E::G1 as Group>::Scalar,
    ) -> ScalarProductMessage<E::G1, E::G2>
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
    {
        debug_assert_eq!(self.num_rounds, 0, "num_rounds must be 0 for final message");
        debug_assert_eq!(self.v1.len(), 1, "v1 must have length 1");
        debug_assert_eq!(self.v2.len(), 1, "v2 must have length 1");

        let gamma_inv = (*gamma).inv().expect("gamma must be invertible");

        // Apply fold-scalars transform:
        // E₁ = v₁ + γ·s₁·H₁
        let gamma_s1 = *gamma * self.s1[0];
        let e1 = self.v1[0] + self.setup.h1.scale(&gamma_s1);

        // E₂ = v₂ + γ⁻¹·s₂·H₂
        let gamma_inv_s2 = gamma_inv * self.s2[0];
        let e2 = self.v2[0] + self.setup.h2.scale(&gamma_inv_s2);

        // Final blind accumulation: r_c ← r_c + γ·r_e2 + γ⁻¹·r_e1
        self.r_c = self.r_c + self.r_e2 * *gamma + self.r_e1 * gamma_inv;

        ScalarProductMessage { e1, e2 }
    }

    /// Generate ZK scalar product proof. Must be called BEFORE `compute_final_message`.
    #[cfg(feature = "zk")]
    pub fn scalar_product_proof<T: Transcript<Curve = E>, R: rand_core::RngCore>(
        &self,
        transcript: &mut T,
        rng: &mut R,
    ) -> ScalarProductProof<E::G1, E::G2, Scalar<E>, E::GT> {
        let (v1, v2) = (self.v1[0], self.v2[0]);
        let (g1, g2) = (self.setup.g1_vec[0], self.setup.g2_vec[0]);
        let ht = &self.setup.ht;
        let mut r = || -> Scalar<E> { Field::random(rng) };
        let (sd1, sd2) = (r(), r());
        let (d1, d2) = (g1.scale(&sd1), g2.scale(&sd2));
        let (rp1, rp2, rq, rr) = (r(), r(), r(), r());
        let p1 = E::pair(&d1, &g2) + ht.scale(&rp1);
        let p2 = E::pair(&g1, &d2) + ht.scale(&rp2);
        let q = E::pair(&d1, &v2) + E::pair(&v1, &d2) + ht.scale(&rq);
        let rr_val = E::pair(&d1, &d2) + ht.scale(&rr);
        for (label, val) in [
            (b"sigma_p1" as &[u8], &p1),
            (b"sigma_p2", &p2),
            (b"sigma_q", &q),
            (b"sigma_r", &rr_val),
        ] {
            transcript.append_serde(label, val);
        }
        let c = transcript.challenge_scalar(b"sigma_c");
        ScalarProductProof {
            p1,
            p2,
            q,
            r: rr_val,
            e1: d1 + v1.scale(&c),
            e2: d2 + v2.scale(&c),
            r1: rp1 + c * self.r_d1,
            r2: rp2 + c * self.r_d2,
            r3: rr + c * rq + c * c * self.r_c,
        }
    }
}

/// Generate Sigma1 proof: proves knowledge of (y, rE2, ry).
#[cfg(feature = "zk")]
pub fn generate_sigma1_proof<E, T, R>(
    y: &Scalar<E>,
    r_e2: &Scalar<E>,
    r_y: &Scalar<E>,
    setup: &ProverSetup<E>,
    transcript: &mut T,
    rng: &mut R,
) -> Sigma1Proof<E::G1, E::G2, Scalar<E>>
where
    E: PairingCurve,
    T: Transcript<Curve = E>,
    R: rand_core::RngCore,
    Scalar<E>: Field,
    E::G2: Group<Scalar = Scalar<E>>,
{
    let (g2_fin, g1_fin) = (&setup.g2_vec[0], &setup.g1_vec[0]);
    let (k1, k2, k3) = (
        Scalar::<E>::random(rng),
        Scalar::<E>::random(rng),
        Scalar::<E>::random(rng),
    );
    let a1 = g2_fin.scale(&k1) + setup.h2.scale(&k2);
    let a2 = g1_fin.scale(&k1) + setup.h1.scale(&k3);
    transcript.append_serde(b"sigma1_a1", &a1);
    transcript.append_serde(b"sigma1_a2", &a2);
    let c = transcript.challenge_scalar(b"sigma1_c");
    Sigma1Proof {
        a1,
        a2,
        z1: k1 + c * *y,
        z2: k2 + c * *r_e2,
        z3: k3 + c * *r_y,
    }
}

/// Verify Sigma1 proof.
#[cfg(feature = "zk")]
pub fn verify_sigma1_proof<E: PairingCurve, T: Transcript<Curve = E>>(
    e2: &E::G2,
    y_commit: &E::G1,
    proof: &Sigma1Proof<E::G1, E::G2, Scalar<E>>,
    setup: &VerifierSetup<E>,
    transcript: &mut T,
) -> Result<(), DoryError>
where
    Scalar<E>: Field,
    E::G2: Group<Scalar = Scalar<E>>,
{
    transcript.append_serde(b"sigma1_a1", &proof.a1);
    transcript.append_serde(b"sigma1_a2", &proof.a2);
    let c = transcript.challenge_scalar(b"sigma1_c");
    if setup.g2_0.scale(&proof.z1) + setup.h2.scale(&proof.z2) != proof.a1 + e2.scale(&c) {
        return Err(DoryError::InvalidProof);
    }
    if setup.g1_0.scale(&proof.z1) + setup.h1.scale(&proof.z3) != proof.a2 + y_commit.scale(&c) {
        return Err(DoryError::InvalidProof);
    }
    Ok(())
}

/// Generate Sigma2 proof: proves e(E1, Γ2,fin) - D2 = e(H1, t1·Γ2,fin + t2·H2).
#[cfg(feature = "zk")]
pub fn generate_sigma2_proof<E, T, R>(
    t1: &Scalar<E>,
    t2: &Scalar<E>,
    setup: &ProverSetup<E>,
    transcript: &mut T,
    rng: &mut R,
) -> Sigma2Proof<Scalar<E>, E::GT>
where
    E: PairingCurve,
    T: Transcript<Curve = E>,
    R: rand_core::RngCore,
    Scalar<E>: Field,
    E::G2: Group<Scalar = Scalar<E>>,
    E::GT: Group<Scalar = Scalar<E>>,
{
    let (k1, k2) = (Scalar::<E>::random(rng), Scalar::<E>::random(rng));
    let a = E::pair(
        &setup.h1,
        &(setup.g2_vec[0].scale(&k1) + setup.h2.scale(&k2)),
    );
    transcript.append_serde(b"sigma2_a", &a);
    let c = transcript.challenge_scalar(b"sigma2_c");
    Sigma2Proof {
        a,
        z1: k1 + c * *t1,
        z2: k2 + c * *t2,
    }
}

/// Verify Sigma2 proof.
#[cfg(feature = "zk")]
pub fn verify_sigma2_proof<E: PairingCurve, T: Transcript<Curve = E>>(
    e1: &E::G1,
    d2: &E::GT,
    proof: &Sigma2Proof<Scalar<E>, E::GT>,
    setup: &VerifierSetup<E>,
    transcript: &mut T,
) -> Result<(), DoryError>
where
    Scalar<E>: Field,
    E::G2: Group<Scalar = Scalar<E>>,
    E::GT: Group<Scalar = Scalar<E>>,
{
    transcript.append_serde(b"sigma2_a", &proof.a);
    let c = transcript.challenge_scalar(b"sigma2_c");
    let expected = E::pair(e1, &setup.g2_0) - *d2;
    let lhs = E::pair(
        &setup.h1,
        &(setup.g2_0.scale(&proof.z1) + setup.h2.scale(&proof.z2)),
    );
    if lhs == proof.a + expected.scale(&c) {
        Ok(())
    } else {
        Err(DoryError::InvalidProof)
    }
}

impl<E: PairingCurve> DoryVerifierState<E> {
    /// Create new verifier state
    ///
    /// # Parameters
    /// - `c`: Initial inner product value
    /// - `d1`: Initial d1 value (from VMV)
    /// - `d2`: Initial d2 value (from VMV)
    /// - `e1`: Initial e1 value
    /// - `e2`: Initial e2 value
    ///
    /// Construct verifier state for O(1) accumulation
    ///
    /// - `s1_coords`: Per-round coordinates for s1 (right_vec in prover)
    /// - `s2_coords`: Per-round coordinates for s2 (left_vec in prover)
    /// - `num_rounds`: Number of rounds
    /// - `setup`: Verifier setup parameters
    ///
    /// Note: `e1` and `d2` are stored both as initial values (for batched VMV check)
    /// and as accumulators (updated during reduce rounds)
    /// this is because the VMV check happens before the folding rounds, so we need to save
    /// the value for the final batched pairing check.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        c: E::GT,
        d1: E::GT,
        d2: E::GT,
        e1: E::G1,
        e2: E::G2,
        s1_coords: Vec<<E::G1 as Group>::Scalar>,
        s2_coords: Vec<<E::G1 as Group>::Scalar>,
        num_rounds: usize,
        setup: VerifierSetup<E>,
    ) -> Self {
        debug_assert_eq!(s1_coords.len(), num_rounds);
        debug_assert_eq!(s2_coords.len(), num_rounds);

        Self {
            c,
            d1,
            d2,
            e1,
            e2,
            e1_init: e1,
            d2_init: d2,
            s1_acc: <E::G1 as Group>::Scalar::one(),
            s2_acc: <E::G1 as Group>::Scalar::one(),
            s1_coords,
            s2_coords,
            num_rounds,
            setup,
        }
    }

    /// Process one round of the Dory-Reduce verification protocol
    ///
    /// Takes both reduce messages and both challenges, updates all state values.
    /// This implements the extended Dory-Reduce algorithm from sections 3.2 & 4.2.
    #[tracing::instrument(skip_all, name = "DoryVerifierState::process_round")]
    pub fn process_round(
        &mut self,
        first_msg: &FirstReduceMessage<E::G1, E::G2, E::GT>,
        second_msg: &SecondReduceMessage<E::G1, E::G2, E::GT>,
        alpha: &<E::G1 as Group>::Scalar,
        beta: &<E::G1 as Group>::Scalar,
    ) where
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
        E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
        <E::G1 as Group>::Scalar: Field,
    {
        assert!(self.num_rounds > 0, "No rounds remaining");

        let alpha_inv = (*alpha).inv().expect("alpha must be invertible");
        let beta_inv = (*beta).inv().expect("beta must be invertible");

        // Update C: C' ← C + χᵢ + β·D₂ + β⁻¹·D₁ + α·C₊ + α⁻¹·C₋
        let chi = &self.setup.chi[self.num_rounds];
        self.c = self.c + chi;
        self.c = self.c + self.d2.scale(beta);
        self.c = self.c + self.d1.scale(&beta_inv);
        self.c = self.c + second_msg.c_plus.scale(alpha);
        self.c = self.c + second_msg.c_minus.scale(&alpha_inv);

        // Update D₁: D₁' ← α·D₁L + D₁R + α·β·Δ₁L + β·Δ₁R
        let delta_1l = &self.setup.delta_1l[self.num_rounds];
        let delta_1r = &self.setup.delta_1r[self.num_rounds];
        let alpha_beta = *alpha * *beta;
        self.d1 = first_msg.d1_left.scale(alpha);
        self.d1 = self.d1 + first_msg.d1_right;
        self.d1 = self.d1 + delta_1l.scale(&alpha_beta);
        self.d1 = self.d1 + delta_1r.scale(beta);

        // Update D₂: D₂' ← α⁻¹·D₂L + D₂R + α⁻¹·β⁻¹·Δ₂L + β⁻¹·Δ₂R
        let delta_2l = &self.setup.delta_2l[self.num_rounds];
        let delta_2r = &self.setup.delta_2r[self.num_rounds];
        let alpha_inv_beta_inv = alpha_inv * beta_inv;
        self.d2 = first_msg.d2_left.scale(&alpha_inv);
        self.d2 = self.d2 + first_msg.d2_right;
        self.d2 = self.d2 + delta_2l.scale(&alpha_inv_beta_inv);
        self.d2 = self.d2 + delta_2r.scale(&beta_inv);

        // Update E₁: E₁' ← E₁ + β·E₁β + α·E₁₊ + α⁻¹·E₁₋
        self.e1 = self.e1 + first_msg.e1_beta.scale(beta);
        self.e1 = self.e1 + second_msg.e1_plus.scale(alpha);
        self.e1 = self.e1 + second_msg.e1_minus.scale(&alpha_inv);

        // Update E₂: E₂' ← E₂ + β⁻¹·E₂β + α·E₂₊ + α⁻¹·E₂₋
        self.e2 = self.e2 + first_msg.e2_beta.scale(&beta_inv);
        self.e2 = self.e2 + second_msg.e2_plus.scale(alpha);
        self.e2 = self.e2 + second_msg.e2_minus.scale(&alpha_inv);

        // Update folded scalars in O(1): s1_acc *= (α·(1−y_t) + y_t), s2_acc *= (α⁻¹·(1−x_t) + x_t)
        // Endianness note: s*_coords are stored in increasing dimension index (little-endian by dimension).
        // Folding processes the most significant dimension first (MSB-first), so we index from the end: idx = num_rounds - 1.
        let idx = self.num_rounds - 1;
        let y_t = self.s1_coords[idx];
        let x_t = self.s2_coords[idx];
        let one = <E::G1 as Group>::Scalar::one();
        let s1_term = (*alpha) * (one - y_t) + y_t;
        let s2_term = alpha_inv * (one - x_t) + x_t;
        self.s1_acc = self.s1_acc * s1_term;
        self.s2_acc = self.s2_acc * s2_term;

        // Decrement round counter
        self.num_rounds -= 1;
    }

    /// Verify final scalar product message (4 pairings batched with VMV check).
    #[tracing::instrument(skip_all, name = "DoryVerifierState::verify_final")]
    pub fn verify_final(
        &mut self,
        msg: &ScalarProductMessage<E::G1, E::G2>,
        gamma: &<E::G1 as Group>::Scalar,
        d: &<E::G1 as Group>::Scalar,
    ) -> Result<(), DoryError>
    where
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
        E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
        <E::G1 as Group>::Scalar: Field,
    {
        debug_assert_eq!(
            self.num_rounds, 0,
            "num_rounds must be 0 for final verification"
        );

        let gamma_inv = (*gamma).inv().expect("gamma must be invertible");
        let d_inv = (*d).inv().expect("d must be invertible");
        let d_sq = *d * *d;
        let neg_gamma = -*gamma;
        let neg_gamma_inv = -gamma_inv;

        // Compute RHS (non-pairing GT terms):
        // T = C + (s₁·s₂)·HT + χ₀ + d·D₂ + d⁻¹·D₁ + d²·D₂_init
        // The d²·D₂_init term is the deferred VMV check contribution.
        // We use d² instead of d to ensure independence from the d·D₂ term.
        let s_product = self.s1_acc * self.s2_acc;
        let mut rhs = self.c + self.setup.ht.scale(&s_product);
        rhs = rhs + self.setup.chi[0];
        rhs = rhs + self.d2.scale(d);
        rhs = rhs + self.d1.scale(&d_inv);
        rhs = rhs + self.d2_init.scale(&d_sq);

        // Pair 1: (E₁_final + d·Γ₁₀, E₂_final + d⁻¹·Γ₂₀)
        let p1_g1 = msg.e1 + self.setup.g1_0.scale(d);
        let p1_g2 = msg.e2 + self.setup.g2_0.scale(&d_inv);

        // Pair 2: (H₁, (-γ)·(E₂_acc + (d⁻¹·s₁)·Γ₂₀))
        let d_inv_s1 = d_inv * self.s1_acc;
        let g2_term = self.e2 + self.setup.g2_0.scale(&d_inv_s1);
        let p2_g1 = self.setup.h1;
        let p2_g2 = g2_term.scale(&neg_gamma);

        // Pair 3: ((-γ⁻¹)·(E₁_acc + (d·s₂)·Γ₁₀), H₂)
        let d_s2 = *d * self.s2_acc;
        let g1_term = self.e1 + self.setup.g1_0.scale(&d_s2);
        let p3_g1 = g1_term.scale(&neg_gamma_inv);
        let p3_g2 = self.setup.h2;

        // Pair 4: (d²·E₁_init, Γ2,fin) - deferred VMV check
        let p4_g1 = self.e1_init.scale(&d_sq);
        let p4_g2 = self.setup.g2_0;

        let lhs = E::multi_pair(&[p1_g1, p2_g1, p3_g1, p4_g1], &[p1_g2, p2_g2, p3_g2, p4_g2]);

        if lhs == rhs {
            Ok(())
        } else {
            Err(DoryError::InvalidProof)
        }
    }

    #[cfg(feature = "zk")]
    pub fn verify_final_zk(
        &mut self,
        proof: &ScalarProductProof<E::G1, E::G2, Scalar<E>, E::GT>,
        c: &Scalar<E>,
        d: &Scalar<E>,
    ) -> Result<(), DoryError>
    where
        E::G2: Group<Scalar = Scalar<E>>,
        E::GT: Group<Scalar = Scalar<E>>,
        Scalar<E>: Field,
    {
        let d_inv = (*d).inv().expect("d must be invertible");
        let c_sq = *c * *c;
        let lhs = E::pair(
            &(proof.e1 + self.setup.g1_0.scale(d)),
            &(proof.e2 + self.setup.g2_0.scale(&d_inv)),
        );
        let mut rhs = self.setup.chi[0] + proof.r + proof.q.scale(c) + self.c.scale(&c_sq);
        rhs = rhs + proof.p2.scale(d) + self.d2.scale(&(*d * *c));
        rhs = rhs + proof.p1.scale(&d_inv) + self.d1.scale(&(d_inv * *c));
        rhs = rhs
            - self
                .setup
                .ht
                .scale(&(proof.r3 + *d * proof.r2 + d_inv * proof.r1));
        if lhs == rhs {
            Ok(())
        } else {
            Err(DoryError::InvalidProof)
        }
    }
}
