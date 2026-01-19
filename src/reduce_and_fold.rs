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
use crate::mode::ZK;
#[cfg(feature = "zk")]
use crate::primitives::transcript::Transcript;

/// Prover state for the Dory opening protocol
///
/// Maintains the current state of the prover during the interactive protocol.
/// The state consists of vectors that get folded in each round.
///
/// The `M` parameter controls whether the proof is transparent or zero-knowledge:
/// - `Transparent` (default): No blinding, produces non-hiding proofs
/// - `ZK` (requires `zk` feature): Samples blinds from transcript for hiding proofs
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

    // ZK blind accumulators (zero for Transparent mode)
    /// Accumulated blind for C (inner product)
    r_c: <E::G1 as Group>::Scalar,
    /// Accumulated blind for D1
    r_d1: <E::G1 as Group>::Scalar,
    /// Accumulated blind for D2
    r_d2: <E::G1 as Group>::Scalar,
    /// Accumulated blind for E1
    r_e1: <E::G1 as Group>::Scalar,
    /// Accumulated blind for E2
    r_e2: <E::G1 as Group>::Scalar,

    /// Phantom data for mode marker
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

/// Type alias for first message with blinds (r_d1_l, r_d1_r, r_d2_l, r_d2_r)
pub type FirstMessageWithBlinds<E> = (
    FirstReduceMessage<<E as PairingCurve>::G1, <E as PairingCurve>::G2, <E as PairingCurve>::GT>,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
);

/// Type alias for second message with blinds (r_c_plus, r_c_minus, r_e1_plus, r_e1_minus, r_e2_plus, r_e2_minus)
pub type SecondMessageWithBlinds<E> = (
    SecondReduceMessage<<E as PairingCurve>::G1, <E as PairingCurve>::G2, <E as PairingCurve>::GT>,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
);

/// Type alias for accumulated blinds (r_c, r_d1, r_d2)
pub type Blinds<E> = (
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <<E as PairingCurve>::G1 as Group>::Scalar,
);

/// Type alias for ZK scalar product proof
#[cfg(feature = "zk")]
pub type ZkScalarProductProof<E> = ScalarProductProof<
    <E as PairingCurve>::G1,
    <E as PairingCurve>::G2,
    <<E as PairingCurve>::G1 as Group>::Scalar,
    <E as PairingCurve>::GT,
>;

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

        Self {
            v1,
            v2,
            v2_scalars,
            s1,
            s2,
            num_rounds,
            setup,
            r_c: <E::G1 as Group>::Scalar::zero(),
            r_d1: <E::G1 as Group>::Scalar::zero(),
            r_d2: <E::G1 as Group>::Scalar::zero(),
            r_e1: <E::G1 as Group>::Scalar::zero(),
            r_e2: <E::G1 as Group>::Scalar::zero(),
            _mode: PhantomData,
        }
    }

    /// Create new prover state with initial blinds (for VMV message blinds)
    ///
    /// Used when the VMV message computation samples initial blinds.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_blinds(
        v1: Vec<E::G1>,
        v2: Vec<E::G2>,
        v2_scalars: Option<Vec<<E::G1 as Group>::Scalar>>,
        s1: Vec<<E::G1 as Group>::Scalar>,
        s2: Vec<<E::G1 as Group>::Scalar>,
        setup: &'a ProverSetup<E>,
        r_c: <E::G1 as Group>::Scalar,
        r_d2: <E::G1 as Group>::Scalar,
        r_e1: <E::G1 as Group>::Scalar,
        r_e2: <E::G1 as Group>::Scalar,
    ) -> Self {
        let mut state = Self::new(v1, v2, v2_scalars, s1, s2, setup);
        state.r_c = r_c;
        state.r_d2 = r_d2;
        state.r_e1 = r_e1;
        state.r_e2 = r_e2;
        state
    }

    /// Compute first reduce message for current round
    ///
    /// Computes D1L, D1R, D2L, D2R, E1β, E2β based on current state.
    /// In ZK mode, samples blinds and masks the D values.
    ///
    /// Returns the message and the four sampled blinds (r_d1_l, r_d1_r, r_d2_l, r_d2_r)
    /// which are needed by `apply_first_challenge` to accumulate blinds.
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_first_message")]
    pub fn compute_first_message<M1, M2, R>(&self, rng: &mut R) -> FirstMessageWithBlinds<E>
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

        // ZK: sample blinds from RNG (zero for Transparent mode)
        let r_d1_l: <E::G1 as Group>::Scalar = M::sample(rng);
        let r_d1_r: <E::G1 as Group>::Scalar = M::sample(rng);
        let r_d2_l: <E::G1 as Group>::Scalar = M::sample(rng);
        let r_d2_r: <E::G1 as Group>::Scalar = M::sample(rng);

        // Compute D values: multi-pairings between v-vectors and generators
        // D₁L = ⟨v₁L, Γ₂'⟩, D₁R = ⟨v₁R, Γ₂'⟩ - g2_prime is from setup, use cached version
        let d1_left_base = E::multi_pair_g2_setup(v1_l, g2_prime);
        let d1_right_base = E::multi_pair_g2_setup(v1_r, g2_prime);

        // D₂L = ⟨Γ₁', v₂L⟩, D₂R = ⟨Γ₁', v₂R⟩
        // If v2 was constructed as Γ2,fin * scalars (first round), compute MSM(Γ₁', scalars) then one pairing.
        // Γ2,fin = g2_vec[0] (commitment base, NOT h2 which is the blinding generator)
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

        // ZK: mask D values (identity for Transparent mode)
        let d1_left = M::mask(d1_left_base, &self.setup.ht, &r_d1_l);
        let d1_right = M::mask(d1_right_base, &self.setup.ht, &r_d1_r);
        let d2_left = M::mask(d2_left_base, &self.setup.ht, &r_d2_l);
        let d2_right = M::mask(d2_right_base, &self.setup.ht, &r_d2_r);

        // Compute E values for extended protocol: MSMs with scalar vectors
        // E₁β = ⟨Γ₁, s₂⟩
        let e1_beta = M1::msm(&self.setup.g1_vec[..1 << self.num_rounds], &self.s2[..]);

        // E₂β = ⟨Γ₂, s₁⟩
        let e2_beta = M2::msm(&self.setup.g2_vec[..1 << self.num_rounds], &self.s1[..]);

        let msg = FirstReduceMessage {
            d1_left,
            d1_right,
            d2_left,
            d2_right,
            e1_beta,
            e2_beta,
        };

        (msg, r_d1_l, r_d1_r, r_d2_l, r_d2_r)
    }

    /// Apply first challenge (beta) and combine vectors
    ///
    /// Updates the state by combining with generators scaled by beta.
    /// Also accumulates blinds: rC ← rC + β·rD2 + β⁻¹·rD1
    #[tracing::instrument(skip_all, name = "DoryProverState::apply_first_challenge")]
    pub fn apply_first_challenge<M1, M2>(&mut self, beta: &<E::G1 as Group>::Scalar)
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        let beta_inv = (*beta).inv().expect("beta must be invertible");

        let n = 1 << self.num_rounds;

        // Combine: v₁ ← v₁ + β·Γ₁
        M1::fixed_scalar_mul_bases_then_add(&self.setup.g1_vec[..n], &mut self.v1, beta);

        // Combine: v₂ ← v₂ + β⁻¹·Γ₂
        M2::fixed_scalar_mul_bases_then_add(&self.setup.g2_vec[..n], &mut self.v2, &beta_inv);

        // After first combine, the `v2_scalars` optimization does not apply.
        self.v2_scalars = None;

        // ZK: accumulate blinds using accumulated rD1, rD2 (not message blinds)
        // rC ← rC + β·rD2 + β⁻¹·rD1
        self.r_c = self.r_c + self.r_d2 * *beta + self.r_d1 * beta_inv;
    }

    /// Compute second reduce message for current round
    ///
    /// Computes C+, C-, E1+, E1-, E2+, E2- based on current state.
    /// In ZK mode, samples blinds and masks the values.
    ///
    /// Returns the message and six sampled blinds needed by `apply_second_challenge`.
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_second_message")]
    #[allow(clippy::type_complexity)]
    pub fn compute_second_message<M1, M2, R>(&self, rng: &mut R) -> SecondMessageWithBlinds<E>
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

        // ZK: sample blinds from RNG (zero for Transparent mode)
        let r_c_plus: <E::G1 as Group>::Scalar = M::sample(rng);
        let r_c_minus: <E::G1 as Group>::Scalar = M::sample(rng);
        let r_e1_plus: <E::G1 as Group>::Scalar = M::sample(rng);
        let r_e1_minus: <E::G1 as Group>::Scalar = M::sample(rng);
        let r_e2_plus: <E::G1 as Group>::Scalar = M::sample(rng);
        let r_e2_minus: <E::G1 as Group>::Scalar = M::sample(rng);

        // Compute C terms: cross products of v-vectors
        // C₊ = ⟨v₁L, v₂R⟩
        let c_plus_base = E::multi_pair(v1_l, v2_r);
        // C₋ = ⟨v₁R, v₂L⟩
        let c_minus_base = E::multi_pair(v1_r, v2_l);

        // ZK: mask C values
        let c_plus = M::mask(c_plus_base, &self.setup.ht, &r_c_plus);
        let c_minus = M::mask(c_minus_base, &self.setup.ht, &r_c_minus);

        // Compute E terms for extended protocol: cross products with scalars
        // E₁₊ = ⟨v₁L, s₂R⟩
        let e1_plus_base = M1::msm(v1_l, s2_r);
        // E₁₋ = ⟨v₁R, s₂L⟩
        let e1_minus_base = M1::msm(v1_r, s2_l);
        // E₂₊ = ⟨s₁L, v₂R⟩
        let e2_plus_base = M2::msm(v2_r, s1_l);
        // E₂₋ = ⟨s₁R, v₂L⟩
        let e2_minus_base = M2::msm(v2_l, s1_r);

        // ZK: mask E values
        let e1_plus = M::mask(e1_plus_base, &self.setup.h1, &r_e1_plus);
        let e1_minus = M::mask(e1_minus_base, &self.setup.h1, &r_e1_minus);
        let e2_plus = M::mask(e2_plus_base, &self.setup.h2, &r_e2_plus);
        let e2_minus = M::mask(e2_minus_base, &self.setup.h2, &r_e2_minus);

        let msg = SecondReduceMessage {
            c_plus,
            c_minus,
            e1_plus,
            e1_minus,
            e2_plus,
            e2_minus,
        };

        (
            msg, r_c_plus, r_c_minus, r_e1_plus, r_e1_minus, r_e2_plus, r_e2_minus,
        )
    }

    /// Apply second challenge (alpha) and fold vectors
    ///
    /// Reduces the vector size by half using the alpha challenge.
    /// Also accumulates blinds from compute_first_message and compute_second_message.
    #[tracing::instrument(skip_all, name = "DoryProverState::apply_second_challenge")]
    #[allow(clippy::too_many_arguments)]
    pub fn apply_second_challenge<M1, M2>(
        &mut self,
        alpha: &<E::G1 as Group>::Scalar,
        r_d1_l: <E::G1 as Group>::Scalar,
        r_d1_r: <E::G1 as Group>::Scalar,
        r_d2_l: <E::G1 as Group>::Scalar,
        r_d2_r: <E::G1 as Group>::Scalar,
        r_c_plus: <E::G1 as Group>::Scalar,
        r_c_minus: <E::G1 as Group>::Scalar,
        r_e1_plus: <E::G1 as Group>::Scalar,
        r_e1_minus: <E::G1 as Group>::Scalar,
        r_e2_plus: <E::G1 as Group>::Scalar,
        r_e2_minus: <E::G1 as Group>::Scalar,
    ) where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
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

        // ZK: update accumulated blinds
        // r_c ← r_c + α·r_c+ + α⁻¹·r_c-
        self.r_c = self.r_c + r_c_plus * *alpha + r_c_minus * alpha_inv;
        // r_d1 ← α·r_d1_l + r_d1_r
        self.r_d1 = r_d1_l * *alpha + r_d1_r;
        // r_d2 ← α⁻¹·r_d2_l + r_d2_r
        self.r_d2 = r_d2_l * alpha_inv + r_d2_r;
        // r_e1 ← r_e1 + α·r_e1+ + α⁻¹·r_e1-
        self.r_e1 = self.r_e1 + r_e1_plus * *alpha + r_e1_minus * alpha_inv;
        // r_e2 ← r_e2 + α·r_e2+ + α⁻¹·r_e2-
        self.r_e2 = self.r_e2 + r_e2_plus * *alpha + r_e2_minus * alpha_inv;

        // Decrement round counter
        self.num_rounds -= 1;
    }

    /// Compute final scalar product message
    ///
    /// Applies fold-scalars transformation and returns the final E1, E2 elements.
    /// Must be called when num_rounds=0 (vectors are size 1).
    ///
    /// Also accumulates the final blind: r_c ← r_c + γ·r_e2 + γ⁻¹·r_e1
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_final_message")]
    pub fn compute_final_message<M1, M2>(
        &mut self,
        gamma: &<E::G1 as Group>::Scalar,
    ) -> ScalarProductMessage<E::G1, E::G2>
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
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

        // ZK: final blind accumulation
        // r_c ← r_c + γ·r_e2 + γ⁻¹·r_e1
        self.r_c = self.r_c + self.r_e2 * *gamma + self.r_e1 * gamma_inv;

        ScalarProductMessage { e1, e2 }
    }

    /// Get accumulated blinds (for ZK mode Σ-protocol)
    ///
    /// Returns (r_c, r_d1, r_d2) which are needed for the ZK scalar product proof.
    pub fn blinds(&self) -> Blinds<E> {
        (self.r_c, self.r_d1, self.r_d2)
    }

    /// Generate ZK scalar product proof (Σ-protocol) - internal version
    ///
    /// This is callable from any Mode but only produces meaningful proofs in ZK mode.
    /// In Transparent mode, all blinds are zero, so the proof is trivial.
    ///
    /// Must be called BEFORE `compute_final_message` because that method modifies r_c,
    /// but the Σ-protocol needs the pre-fold-scalars blinds.
    #[cfg(feature = "zk")]
    pub fn scalar_product_proof_internal<
        T: crate::primitives::transcript::Transcript<Curve = E>,
        R: rand_core::RngCore,
    >(
        &self,
        transcript: &mut T,
        rng: &mut R,
    ) -> crate::messages::ScalarProductProof<E::G1, E::G2, <E::G1 as Group>::Scalar, E::GT> {
        debug_assert_eq!(self.v1.len(), 1, "v1 must be length 1 after folding");
        debug_assert_eq!(self.v2.len(), 1, "v2 must be length 1 after folding");

        let v1 = self.v1[0];
        let v2 = self.v2[0];
        let gamma1 = self.setup.g1_vec[0];
        let gamma2 = self.setup.g2_vec[0];

        type F<E> = <<E as PairingCurve>::G1 as Group>::Scalar;

        // Sample random scalars from RNG (private to prover)
        let s_d1: F<E> = Field::random(rng);
        let s_d2: F<E> = Field::random(rng);
        let d1 = gamma1.scale(&s_d1);
        let d2 = gamma2.scale(&s_d2);

        // Sample blinding scalars from RNG (private to prover)
        let r_p1: F<E> = Field::random(rng);
        let r_p2: F<E> = Field::random(rng);
        let r_q: F<E> = Field::random(rng);
        let r_r: F<E> = Field::random(rng);

        // Compute first message: P1, P2, Q, R
        // P1 = e(d1, Γ2) + rP1·HT
        let p1 = E::pair(&d1, &gamma2) + self.setup.ht.scale(&r_p1);
        // P2 = e(Γ1, d2) + rP2·HT
        let p2 = E::pair(&gamma1, &d2) + self.setup.ht.scale(&r_p2);
        // Q = e(d1, v2) + e(v1, d2) + rQ·HT
        let q = E::pair(&d1, &v2) + E::pair(&v1, &d2) + self.setup.ht.scale(&r_q);
        // R = e(d1, d2) + rR·HT
        let r = E::pair(&d1, &d2) + self.setup.ht.scale(&r_r);

        // Append first message to transcript and derive challenge
        transcript.append_serde(b"sigma_p1", &p1);
        transcript.append_serde(b"sigma_p2", &p2);
        transcript.append_serde(b"sigma_q", &q);
        transcript.append_serde(b"sigma_r", &r);
        let c = transcript.challenge_scalar(b"sigma_c");

        // Compute response: E1, E2, r1, r2, r3
        // E1 = d1 + c·v1
        let e1 = d1 + v1.scale(&c);
        // E2 = d2 + c·v2
        let e2 = d2 + v2.scale(&c);
        // r1 = rP1 + c·rD1
        let r1 = r_p1 + c * self.r_d1;
        // r2 = rP2 + c·rD2
        let r2 = r_p2 + c * self.r_d2;
        // r3 = rR + c·rQ + c²·rC
        let c_sq = c * c;
        let r3 = r_r + c * r_q + c_sq * self.r_c;

        crate::messages::ScalarProductProof {
            p1,
            p2,
            q,
            r,
            e1,
            e2,
            r1,
            r2,
            r3,
        }
    }
}

/// ZK-specific methods for DoryProverState
///
/// These methods are only available when the `zk` feature is enabled and
/// the prover state is parameterized with the `ZK` mode marker.
#[cfg(feature = "zk")]
impl<E: PairingCurve> DoryProverState<'_, E, ZK>
where
    <E::G1 as Group>::Scalar: Field,
    E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
{
    /// Generate ZK scalar product proof (Σ-protocol)
    ///
    /// Proves knowledge of (v1, v2, rC, rD1, rD2) for relation L1:
    /// - C = e(v1, v2) + rC·HT
    /// - D1 = e(v1, Γ2) + rD1·HT
    /// - D2 = e(Γ1, v2) + rD2·HT
    ///
    /// Must be called after `compute_final_message` when v1 and v2 are length 1.
    ///
    /// # Parameters
    /// - `transcript`: Fiat-Shamir transcript for deriving challenge
    /// - `rng`: Random number generator for sampling private blinds
    ///
    /// # Returns
    /// `ScalarProductProof` containing (P1, P2, Q, R, E1, E2, r1, r2, r3)
    pub fn scalar_product_proof<T: Transcript<Curve = E>, R: rand_core::RngCore>(
        &self,
        transcript: &mut T,
        rng: &mut R,
    ) -> ZkScalarProductProof<E> {
        debug_assert_eq!(self.v1.len(), 1, "v1 must be length 1 after folding");
        debug_assert_eq!(self.v2.len(), 1, "v2 must be length 1 after folding");

        let v1 = self.v1[0];
        let v2 = self.v2[0];
        let gamma1 = self.setup.g1_vec[0];
        let gamma2 = self.setup.g2_vec[0];

        type F<E> = <<E as PairingCurve>::G1 as Group>::Scalar;

        // Sample random scalars from RNG (private to prover)
        let s_d1: F<E> = Field::random(rng);
        let s_d2: F<E> = Field::random(rng);
        let d1 = gamma1.scale(&s_d1);
        let d2 = gamma2.scale(&s_d2);

        // Sample blinding scalars from RNG (private to prover)
        let r_p1: F<E> = Field::random(rng);
        let r_p2: F<E> = Field::random(rng);
        let r_q: F<E> = Field::random(rng);
        let r_r: F<E> = Field::random(rng);

        // Compute first message: P1, P2, Q, R
        // P1 = e(d1, Γ2) + rP1·HT
        let p1 = E::pair(&d1, &gamma2) + self.setup.ht.scale(&r_p1);
        // P2 = e(Γ1, d2) + rP2·HT
        let p2 = E::pair(&gamma1, &d2) + self.setup.ht.scale(&r_p2);
        // Q = e(d1, v2) + e(v1, d2) + rQ·HT
        let q = E::pair(&d1, &v2) + E::pair(&v1, &d2) + self.setup.ht.scale(&r_q);
        // R = e(d1, d2) + rR·HT
        let r = E::pair(&d1, &d2) + self.setup.ht.scale(&r_r);

        // Append first message to transcript and derive challenge
        transcript.append_serde(b"sigma_p1", &p1);
        transcript.append_serde(b"sigma_p2", &p2);
        transcript.append_serde(b"sigma_q", &q);
        transcript.append_serde(b"sigma_r", &r);
        let c = transcript.challenge_scalar(b"sigma_c");

        // Compute response: E1, E2, r1, r2, r3
        // E1 = d1 + c·v1
        let e1 = d1 + v1.scale(&c);
        // E2 = d2 + c·v2
        let e2 = d2 + v2.scale(&c);
        // r1 = rP1 + c·rD1
        let r1 = r_p1 + c * self.r_d1;
        // r2 = rP2 + c·rD2
        let r2 = r_p2 + c * self.r_d2;
        // r3 = rR + c·rQ + c²·rC
        let c_sq = c * c;
        let r3 = r_r + c * r_q + c_sq * self.r_c;

        ScalarProductProof {
            p1,
            p2,
            q,
            r,
            e1,
            e2,
            r1,
            r2,
            r3,
        }
    }
}

/// Generate Sigma1 proof: proves knowledge of (y, rE2) such that E2 = y·Γ2,fin + rE2·H2
///
/// Also proves yC = y·Γ1,fin + ry·H1 for commitment consistency.
///
/// # Generator semantics
/// - Γ1,fin = g1_vec\[0\], Γ2,fin = g2_vec\[0\] (commitment bases)
/// - H1 = h1, H2 = h2 (blinding bases, linearly independent from Γ_fin)
#[cfg(feature = "zk")]
pub fn generate_sigma1_proof<E, T, R>(
    y: &<E::G1 as Group>::Scalar,
    r_e2: &<E::G1 as Group>::Scalar,
    r_y: &<E::G1 as Group>::Scalar,
    setup: &ProverSetup<E>,
    transcript: &mut T,
    rng: &mut R,
) -> Sigma1Proof<E::G1, E::G2, <E::G1 as Group>::Scalar>
where
    E: PairingCurve,
    <E::G1 as Group>::Scalar: Field,
    E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    T: Transcript<Curve = E>,
    R: rand_core::RngCore,
{
    // Γ2,fin = g2_vec[0], Γ1,fin = g1_vec[0]
    let g2_fin = &setup.g2_vec[0];
    let g1_fin = &setup.g1_vec[0];

    // Sample random k1, k2, k3 from RNG (private to prover)
    let k1 = <E::G1 as Group>::Scalar::random(rng);
    let k2 = <E::G1 as Group>::Scalar::random(rng);
    let k3 = <E::G1 as Group>::Scalar::random(rng);

    // A1 = k1·Γ2,fin + k2·H2 (commitment for E2 relation)
    let a1 = g2_fin.scale(&k1) + setup.h2.scale(&k2);
    // A2 = k1·Γ1,fin + k3·H1 (commitment for yC relation)
    let a2 = g1_fin.scale(&k1) + setup.h1.scale(&k3);

    // Append commitments to transcript
    transcript.append_serde(b"sigma1_a1", &a1);
    transcript.append_serde(b"sigma1_a2", &a2);

    // Get challenge
    let c = transcript.challenge_scalar(b"sigma1_c");

    // Compute responses
    let z1 = k1 + c * *y;
    let z2 = k2 + c * *r_e2;
    let z3 = k3 + c * *r_y;

    Sigma1Proof { a1, a2, z1, z2, z3 }
}

/// Verify Sigma1 proof
///
/// # Generator semantics
/// - g1_0 = Γ1,fin, g2_0 = Γ2,fin (commitment bases in verifier setup)
/// - h1 = H1, h2 = H2 (blinding bases)
#[cfg(feature = "zk")]
pub fn verify_sigma1_proof<E, T>(
    e2: &E::G2,
    y_commit: &E::G1,
    proof: &Sigma1Proof<E::G1, E::G2, <E::G1 as Group>::Scalar>,
    setup: &VerifierSetup<E>,
    transcript: &mut T,
) -> Result<(), DoryError>
where
    E: PairingCurve,
    <E::G1 as Group>::Scalar: Field,
    E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    T: Transcript<Curve = E>,
{
    // Reconstruct challenge
    transcript.append_serde(b"sigma1_a1", &proof.a1);
    transcript.append_serde(b"sigma1_a2", &proof.a2);
    let c = transcript.challenge_scalar(b"sigma1_c");

    // Check E2 relation: z1·Γ2,fin + z2·H2 = A1 + c·E2
    // Γ2,fin = g2_0, H2 = h2
    let lhs1 = setup.g2_0.scale(&proof.z1) + setup.h2.scale(&proof.z2);
    let rhs1 = proof.a1 + e2.scale(&c);
    if lhs1 != rhs1 {
        return Err(DoryError::InvalidProof);
    }

    // Check yC relation: z1·Γ1,fin + z3·H1 = A2 + c·yC
    // Γ1,fin = g1_0, H1 = h1
    let lhs2 = setup.g1_0.scale(&proof.z1) + setup.h1.scale(&proof.z3);
    let rhs2 = proof.a2 + y_commit.scale(&c);
    if lhs2 != rhs2 {
        return Err(DoryError::InvalidProof);
    }

    Ok(())
}

/// Generate Sigma2 proof: proves e(E1, Γ2,fin) - D2 = e(H1, t1·Γ2,fin + t2·H2)
///
/// Where t1 = rE1 + rv and t2 = -rD2.
///
/// # Generator semantics
/// - Γ2,fin = g2_vec\[0\] (commitment base)
/// - H1 = h1, H2 = h2 (blinding bases)
#[cfg(feature = "zk")]
pub fn generate_sigma2_proof<E, T, R>(
    t1: &<E::G1 as Group>::Scalar, // rE1 + rv
    t2: &<E::G1 as Group>::Scalar, // -rD2
    setup: &ProverSetup<E>,
    transcript: &mut T,
    rng: &mut R,
) -> Sigma2Proof<<E::G1 as Group>::Scalar, E::GT>
where
    E: PairingCurve,
    <E::G1 as Group>::Scalar: Field,
    E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
    T: Transcript<Curve = E>,
    R: rand_core::RngCore,
{
    // Γ2,fin = g2_vec[0]
    let g2_fin = &setup.g2_vec[0];

    // Sample random k1, k2 from RNG (private to prover)
    let k1 = <E::G1 as Group>::Scalar::random(rng);
    let k2 = <E::G1 as Group>::Scalar::random(rng);

    // A = e(H1, k1·Γ2,fin + k2·H2)
    let g2_term = g2_fin.scale(&k1) + setup.h2.scale(&k2);
    let a = E::pair(&setup.h1, &g2_term);

    // Append commitment to transcript
    transcript.append_serde(b"sigma2_a", &a);

    // Get challenge
    let c = transcript.challenge_scalar(b"sigma2_c");

    // Compute responses
    let z1 = k1 + c * *t1;
    let z2 = k2 + c * *t2;

    Sigma2Proof { a, z1, z2 }
}

/// Verify Sigma2 proof: e(E1, Γ2,fin) - D2 = e(H1, t1·Γ2,fin + t2·H2)
///
/// # Generator semantics
/// - g2_0 = Γ2,fin (commitment base in verifier setup)
/// - h1 = H1, h2 = H2 (blinding bases)
#[cfg(feature = "zk")]
pub fn verify_sigma2_proof<E, T>(
    e1: &E::G1,
    d2: &E::GT,
    proof: &Sigma2Proof<<E::G1 as Group>::Scalar, E::GT>,
    setup: &VerifierSetup<E>,
    transcript: &mut T,
) -> Result<(), DoryError>
where
    E: PairingCurve,
    <E::G1 as Group>::Scalar: Field,
    E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
    T: Transcript<Curve = E>,
{
    // Reconstruct challenge
    transcript.append_serde(b"sigma2_a", &proof.a);
    let c = transcript.challenge_scalar(b"sigma2_c");

    // Compute expected value: e(E1, Γ2,fin) - D2
    // Γ2,fin = g2_0
    let e1_pair = E::pair(e1, &setup.g2_0);
    let expected = e1_pair - *d2;

    // Check: e(H1, z1·Γ2,fin + z2·H2) = A + c·expected
    // Γ2,fin = g2_0, H2 = h2
    let g2_term = setup.g2_0.scale(&proof.z1) + setup.h2.scale(&proof.z2);
    let lhs = E::pair(&setup.h1, &g2_term);
    let rhs = proof.a + expected.scale(&c);

    if lhs == rhs {
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

    /// Verify final scalar product message
    ///
    /// Applies fold-scalars transformation and checks the final pairing equation.
    /// Must be called when num_rounds=0 after all reduce rounds are complete.
    ///
    /// # Generator semantics
    /// - g1_0, g2_0: Final generators (Γ1,fin, Γ2,fin) used as commitment bases
    /// - h1, h2: Blinding generators (H1, H2) used for zero-knowledge masking
    ///
    /// # Non-optimized Protocol Equations
    ///
    /// ## VMV Check (batched together with the final pairing check)
    ///
    /// The VMV protocol requires: `D₂_init = e(E₁_init, Γ2,fin)` = `e(E₁_init, g2_0)`
    ///
    /// This was originally checked as a standalone pairing in `verify_evaluation_proof`.
    /// We defer it here to batch with other pairings.
    ///
    /// ## Fold-Scalars Updates
    ///
    /// ```text
    /// C' ← C + (s₁·s₂)·HT + γ·e(H₁, E₂) + γ⁻¹·e(E₁, H₂)
    /// D₁' ← D₁ + e(H₁, (s₁·γ)·Γ₂₀)
    /// D₂' ← D₂ + e((s₂·γ⁻¹)·Γ₁₀, H₂)
    /// ```
    ///
    /// ## Final Verification
    ///
    /// ```text
    /// e(E₁ + d·Γ₁₀, E₂ + d⁻¹·Γ₂₀) = C' + χ₀ + d·D₂' + d⁻¹·D₁'
    /// ```
    ///
    /// # Multi-Pairing Optimization
    ///
    /// ## Batching the VMV Check
    ///
    /// We use random linear combination with challenge `d²` to defer the VMV check.
    /// The VMV check uses Γ2,fin (g2_0), separate from the fold-scalars blinding which uses H₂ (h2).
    ///
    /// ## Final Combined Check (4 pairings)
    ///
    /// ```text
    /// e(E₁_final + d·Γ₁₀, E₂_final + d⁻¹·Γ₂₀)           // Pair 1: main verification
    ///   · e(H₁, (-γ)·(E₂_acc + (d⁻¹·s₁)·Γ₂₀))           // Pair 2: γ·e(H₁, E₂) term
    ///   · e((-γ⁻¹)·(E₁_acc + (d·s₂)·Γ₁₀), H₂)           // Pair 3: γ⁻¹·e(E₁, H₂) term
    ///   · e(d²·E₁_init, Γ2,fin)                          // Pair 4: deferred VMV check
    ///   = T + d²·D₂_init
    /// ```
    ///
    /// This is 4 miller loops + 1 final exponentiation (vs 7+ for naive check)
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
        // This is the fold-scalars γ⁻¹·e(E₁, H₂) term - uses H₂ (h2)
        let d_s2 = *d * self.s2_acc;
        let g1_term = self.e1 + self.setup.g1_0.scale(&d_s2);
        let p3_g1 = g1_term.scale(&neg_gamma_inv);
        let p3_g2 = self.setup.h2;

        // Pair 4: (d²·E₁_init, Γ2,fin)
        // This is the deferred VMV check: d²·e(E₁_init, Γ2,fin) - uses Γ2,fin (g2_0)
        let p4_g1 = self.e1_init.scale(&d_sq);
        let p4_g2 = self.setup.g2_0;

        // Multi-pairing: 4 miller loops + 1 final exponentiation
        let lhs = E::multi_pair(&[p1_g1, p2_g1, p3_g1, p4_g1], &[p1_g2, p2_g2, p3_g2, p4_g2]);

        if lhs == rhs {
            Ok(())
        } else {
            Err(DoryError::InvalidProof)
        }
    }

    /// Verify final scalar product with ZK proof (Σ-protocol)
    ///
    /// Verifies knowledge of (v1, v2, rC, rD1, rD2) for relation L1:
    /// - C = e(v1, v2) + rC·HT
    /// - D1 = e(v1, Γ2) + rD1·HT
    /// - D2 = e(Γ1, v2) + rD2·HT
    ///
    /// Verification equation from Dory paper:
    /// e(E1 + d·Γ1, E2 + d⁻¹·Γ2) = χ + R + c·Q + c²·C + d·P2 + d·c·D2
    ///                            + d⁻¹·P1 + d⁻¹·c·D1 - (r3 + d·r2 + d⁻¹·r1)·HT
    ///
    /// # Parameters
    /// - `proof`: ZK Σ-protocol proof containing (P1, P2, Q, R, E1, E2, r1, r2, r3)
    /// - `d`: Final batching challenge from transcript
    /// - `transcript`: Fiat-Shamir transcript for deriving challenge c
    #[cfg(feature = "zk")]
    #[tracing::instrument(skip_all, name = "DoryVerifierState::verify_final_zk")]
    pub fn verify_final_zk<T: Transcript<Curve = E>>(
        &mut self,
        proof: &ZkScalarProductProof<E>,
        d: &<E::G1 as Group>::Scalar,
        transcript: &mut T,
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

        let d_inv = (*d).inv().expect("d must be invertible");

        // Reconstruct challenge c from transcript (must match prover's derivation)
        transcript.append_serde(b"sigma_p1", &proof.p1);
        transcript.append_serde(b"sigma_p2", &proof.p2);
        transcript.append_serde(b"sigma_q", &proof.q);
        transcript.append_serde(b"sigma_r", &proof.r);
        let c = transcript.challenge_scalar(b"sigma_c");
        let c_sq = c * c;

        // LHS: e(E1 + d·Γ1, E2 + d⁻¹·Γ2)
        let lhs_g1 = proof.e1 + self.setup.g1_0.scale(d);
        let lhs_g2 = proof.e2 + self.setup.g2_0.scale(&d_inv);
        let lhs = E::pair(&lhs_g1, &lhs_g2);

        // RHS: χ + R + c·Q + c²·C + d·P2 + d·c·D2 + d⁻¹·P1 + d⁻¹·c·D1 - (r3 + d·r2 + d⁻¹·r1)·HT
        let mut rhs = self.setup.chi[0]; // χ
        rhs = rhs + proof.r; // + R
        rhs = rhs + proof.q.scale(&c); // + c·Q
        rhs = rhs + self.c.scale(&c_sq); // + c²·C
        rhs = rhs + proof.p2.scale(d); // + d·P2
        rhs = rhs + self.d2.scale(&(*d * c)); // + d·c·D2
        rhs = rhs + proof.p1.scale(&d_inv); // + d⁻¹·P1
        rhs = rhs + self.d1.scale(&(d_inv * c)); // + d⁻¹·c·D1

        // Blind correction: -(r3 + d·r2 + d⁻¹·r1)·HT
        let r_total = proof.r3 + *d * proof.r2 + d_inv * proof.r1;
        rhs = rhs - self.setup.ht.scale(&r_total);

        if lhs == rhs {
            Ok(())
        } else {
            Err(DoryError::InvalidProof)
        }
    }

    /// Verify final scalar product with ZK proof using pre-derived challenge
    ///
    /// Same as `verify_final_zk` but takes the challenge `c` as a parameter
    /// instead of deriving it from transcript. Use when the caller needs to
    /// control transcript ordering (e.g., appending P1..R before final_message).
    #[cfg(feature = "zk")]
    #[tracing::instrument(skip_all, name = "DoryVerifierState::verify_final_zk_with_challenge")]
    pub fn verify_final_zk_with_challenge(
        &mut self,
        proof: &ZkScalarProductProof<E>,
        c: &<E::G1 as Group>::Scalar,
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

        let d_inv = (*d).inv().expect("d must be invertible");
        let c_sq = *c * *c;

        // LHS: e(E1 + d·Γ1, E2 + d⁻¹·Γ2)
        let lhs_g1 = proof.e1 + self.setup.g1_0.scale(d);
        let lhs_g2 = proof.e2 + self.setup.g2_0.scale(&d_inv);
        let lhs = E::pair(&lhs_g1, &lhs_g2);

        // RHS: χ + R + c·Q + c²·C + d·P2 + d·c·D2 + d⁻¹·P1 + d⁻¹·c·D1 - (r3 + d·r2 + d⁻¹·r1)·HT
        let mut rhs = self.setup.chi[0];
        rhs = rhs + proof.r;
        rhs = rhs + proof.q.scale(c);
        rhs = rhs + self.c.scale(&c_sq);
        rhs = rhs + proof.p2.scale(d);
        rhs = rhs + self.d2.scale(&(*d * *c));
        rhs = rhs + proof.p1.scale(&d_inv);
        rhs = rhs + self.d1.scale(&(d_inv * *c));

        // Blind correction: -(r3 + d·r2 + d⁻¹·r1)·HT
        let r_total = proof.r3 + *d * proof.r2 + d_inv * proof.r1;
        rhs = rhs - self.setup.ht.scale(&r_total);

        if lhs == rhs {
            Ok(())
        } else {
            Err(DoryError::InvalidProof)
        }
    }
}
