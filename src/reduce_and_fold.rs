//! Opening proof protocol - prover and verifier state management
//!
//! This module contains the state machines for the interactive Dory protocol.
//! The prover maintains vectors and computes messages, while the verifier
//! maintains accumulated values and verifies messages.

use crate::error::DoryError;
use crate::messages::*;
use crate::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::setup::{ProverSetup, VerifierSetup};

/// Prover state for the Dory opening protocol
///
/// Maintains the current state of the prover during the interactive protocol.
/// The state consists of vectors that get folded in each round.
pub struct DoryProverState<'a, E: PairingCurve> {
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
    nu: usize,

    /// Reference to prover setup
    setup: &'a ProverSetup<E>,
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

    /// Accumulated scalar for s1 after folding across rounds
    s1_acc: <E::G1 as Group>::Scalar,

    /// Accumulated scalar for s2 after folding across rounds
    s2_acc: <E::G1 as Group>::Scalar,

    /// Per-round coordinates for s1 (length = nu). Order must match folding order.
    s1_coords: Vec<<E::G1 as Group>::Scalar>,

    /// Per-round coordinates for s2 (length = nu). Order must match folding order.
    s2_coords: Vec<<E::G1 as Group>::Scalar>,

    /// Current round number for indexing setup arrays
    nu: usize,

    /// Reference to verifier setup
    setup: VerifierSetup<E>,
}

impl<'a, E: PairingCurve> DoryProverState<'a, E> {
    /// Create new prover state
    ///
    /// # Parameters
    /// - `v1`: Initial G1 vector
    /// - `v2`: Initial G2 vector
    /// - `v2_scalars`: Use the scalars in the first round to avoid a multi-pairing by instead performing a (cheaper) MSM + Pairing
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

        let nu = v1.len().trailing_zeros() as usize;

        Self {
            v1,
            v2,
            v2_scalars,
            s1,
            s2,
            nu,
            setup,
        }
    }

    /// Compute first reduce message for current round
    ///
    /// Computes D1L, D1R, D2L, D2R, E1β, E2β based on current state.
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_first_message")]
    pub fn compute_first_message<M1, M2>(&self) -> FirstReduceMessage<E::G1, E::G2, E::GT>
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        assert!(self.nu > 0, "Not enough rounds left in prover state");

        let n2 = 1 << (self.nu - 1); // n/2

        // Split vectors into left and right halves
        let (v1_l, v1_r) = self.v1.split_at(n2);
        let (v2_l, v2_r) = self.v2.split_at(n2);

        // Get collapsed generator vectors of length n/2
        let g1_prime = &self.setup.g1_vec[..n2];
        let g2_prime = &self.setup.g2_vec[..n2];

        // Compute D values: multi-pairings between v-vectors and generators
        // D₁L = ⟨v₁L, Γ₂'⟩, D₁R = ⟨v₁R, Γ₂'⟩
        let d1_left = E::multi_pair(v1_l, g2_prime);
        let d1_right = E::multi_pair(v1_r, g2_prime);

        // D₂L = ⟨Γ₁', v₂L⟩, D₂R = ⟨Γ₁', v₂R⟩
        // In the first round, v2 = h2 * scalars, so we can compute this as the Pairing of MSM(Γ₁', scalars)
        let (d2_left, d2_right) = if let Some(scalars) = self.v2_scalars.as_ref() {
            let (s_l, s_r) = scalars.split_at(n2);
            let sum_left = M1::msm(g1_prime, s_l);
            let sum_right = M1::msm(g1_prime, s_r);
            (
                E::pair(&sum_left, &self.setup.h2),
                E::pair(&sum_right, &self.setup.h2),
            )
        } else {
            (E::multi_pair(g1_prime, v2_l), E::multi_pair(g1_prime, v2_r))
        };

        // Compute E values for extended protocol: MSMs with scalar vectors
        // E₁β = ⟨Γ₁, s₂⟩
        let e1_beta = M1::msm(&self.setup.g1_vec[..1 << self.nu], &self.s2[..]);

        // E₂β = ⟨Γ₂, s₁⟩
        let e2_beta = M2::msm(&self.setup.g2_vec[..1 << self.nu], &self.s1[..]);

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
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
        <E::G1 as Group>::Scalar: Field,
    {
        let beta_inv = (*beta).inv().expect("beta must be invertible");

        let n = 1 << self.nu;

        // Combine: v₁ ← v₁ + β·Γ₁
        for i in 0..n {
            self.v1[i] = self.v1[i] + self.setup.g1_vec[i].scale(beta);
        }

        // Combine: v₂ ← v₂ + β⁻¹·Γ₂
        for i in 0..n {
            self.v2[i] = self.v2[i] + self.setup.g2_vec[i].scale(&beta_inv);
        }

        // After first combine, the `v2_scalars` optimization does not apply.
        self.v2_scalars = None;
    }

    /// Compute second reduce message for current round
    ///
    /// Computes C+, C-, E1+, E1-, E2+, E2- based on current state.
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_second_message")]
    pub fn compute_second_message<M1, M2>(&self) -> SecondReduceMessage<E::G1, E::G2, E::GT>
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        let n2 = 1 << (self.nu - 1); // n/2

        // Split all vectors into left and right halves
        let (v1_l, v1_r) = self.v1.split_at(n2);
        let (v2_l, v2_r) = self.v2.split_at(n2);
        let (s1_l, s1_r) = self.s1.split_at(n2);
        let (s2_l, s2_r) = self.s2.split_at(n2);

        // Compute C terms: cross products of v-vectors
        // C₊ = ⟨v₁L, v₂R⟩
        let c_plus = E::multi_pair(v1_l, v2_r);
        // C₋ = ⟨v₁R, v₂L⟩
        let c_minus = E::multi_pair(v1_r, v2_l);

        // Compute E terms for extended protocol: cross products with scalars
        // E₁₊ = ⟨v₁L, s₂R⟩
        let e1_plus = M1::msm(v1_l, s2_r);
        // E₁₋ = ⟨v₁R, s₂L⟩
        let e1_minus = M1::msm(v1_r, s2_l);
        // E₂₊ = ⟨s₁L, v₂R⟩
        let e2_plus = M2::msm(v2_r, s1_l);
        // E₂₋ = ⟨s₁R, v₂L⟩
        let e2_minus = M2::msm(v2_l, s1_r);

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
    pub fn apply_second_challenge<M1, M2>(&mut self, alpha: &<E::G1 as Group>::Scalar)
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
        <E::G1 as Group>::Scalar: Field,
    {
        let alpha_inv = (*alpha).inv().expect("alpha must be invertible");
        let n2 = 1 << (self.nu - 1); // n/2

        // Fold v₁: v₁ ← α·v₁L + v₁R (optimized with DoryRoutines)
        let (v1_l, v1_r) = self.v1.split_at_mut(n2);
        M1::fixed_scalar_mul_vs_then_add(v1_l, v1_r, alpha);
        self.v1.truncate(n2);

        // Fold v₂: v₂ ← α⁻¹·v₂L + v₂R (optimized with DoryRoutines)
        let (v2_l, v2_r) = self.v2.split_at_mut(n2);
        M2::fixed_scalar_mul_vs_then_add(v2_l, v2_r, &alpha_inv);
        self.v2.truncate(n2);

        // Fold s₁: s₁ ← α·s₁L + s₁R
        let (s1_l, s1_r) = self.s1.split_at_mut(n2);
        for i in 0..n2 {
            s1_l[i] = s1_l[i] * alpha + s1_r[i];
        }
        self.s1.truncate(n2);

        // Fold s₂: s₂ ← α⁻¹·s₂L + s₂R
        let (s2_l, s2_r) = self.s2.split_at_mut(n2);
        for i in 0..n2 {
            s2_l[i] = s2_l[i] * alpha_inv + s2_r[i];
        }
        self.s2.truncate(n2);

        // Decrement round counter
        self.nu -= 1;
    }

    /// Compute final scalar product message
    ///
    /// Applies fold-scalars transformation and returns the final E1, E2 elements.
    /// Must be called when nu=0 (vectors are size 1).
    #[tracing::instrument(skip_all, name = "DoryProverState::compute_final_message")]
    pub fn compute_final_message<M1, M2>(
        self,
        gamma: &<E::G1 as Group>::Scalar,
    ) -> ScalarProductMessage<E::G1, E::G2>
    where
        M1: DoryRoutines<E::G1>,
        M2: DoryRoutines<E::G2>,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
        <E::G1 as Group>::Scalar: Field,
    {
        debug_assert_eq!(self.nu, 0, "nu must be 0 for final message");
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

        ScalarProductMessage { e1, e2 }
    }
}

impl<E: PairingCurve> DoryVerifierState<E> {
    /// Create new verifier state
    ///
    /// # Parameters
    /// - `c`: Initial inner product value
    /// - `d1`: Initial d1 value (typically from VMV)
    /// - `d2`: Initial d2 value (typically from VMV)
    /// - `e1`: Initial e1 value
    /// - `e2`: Initial e2 value
    /// - `s1_coords`: Per-round coordinates for s1 (right_vec in prover)
    /// - `s2_coords`: Per-round coordinates for s2 (left_vec in prover)
    /// - `nu`: Number of rounds
    /// - `setup`: Verifier setup parameters
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        c: E::GT,
        d1: E::GT,
        d2: E::GT,
        e1: E::G1,
        e2: E::G2,
        s1_coords: Vec<<E::G1 as Group>::Scalar>,
        s2_coords: Vec<<E::G1 as Group>::Scalar>,
        nu: usize,
        setup: VerifierSetup<E>,
    ) -> Self {
        debug_assert_eq!(s1_coords.len(), nu);
        debug_assert_eq!(s2_coords.len(), nu);

        Self {
            c,
            d1,
            d2,
            e1,
            e2,
            s1_acc: <E::G1 as Group>::Scalar::one(),
            s2_acc: <E::G1 as Group>::Scalar::one(),
            s1_coords,
            s2_coords,
            nu,
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
        assert!(self.nu > 0, "No rounds remaining");

        let alpha_inv = (*alpha).inv().expect("alpha must be invertible");
        let beta_inv = (*beta).inv().expect("beta must be invertible");

        // Update C: C' ← C + χᵢ + β·D₂ + β⁻¹·D₁ + α·C₊ + α⁻¹·C₋
        let chi = &self.setup.chi[self.nu];
        self.c = self.c + chi;
        self.c = self.c + self.d2.scale(beta);
        self.c = self.c + self.d1.scale(&beta_inv);
        self.c = self.c + second_msg.c_plus.scale(alpha);
        self.c = self.c + second_msg.c_minus.scale(&alpha_inv);

        // Update D₁: D₁' ← α·D₁L + D₁R + α·β·Δ₁L + β·Δ₁R
        let delta_1l = &self.setup.delta_1l[self.nu];
        let delta_1r = &self.setup.delta_1r[self.nu];
        let alpha_beta = *alpha * *beta;
        self.d1 = first_msg.d1_left.scale(alpha);
        self.d1 = self.d1 + first_msg.d1_right;
        self.d1 = self.d1 + delta_1l.scale(&alpha_beta);
        self.d1 = self.d1 + delta_1r.scale(beta);

        // Update D₂: D₂' ← α⁻¹·D₂L + D₂R + α⁻¹·β⁻¹·Δ₂L + β⁻¹·Δ₂R
        let delta_2l = &self.setup.delta_2l[self.nu];
        let delta_2r = &self.setup.delta_2r[self.nu];
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
        // Current round index is derived from remaining rounds: we fold highest-indexed dimension first, hence idx = nu - 1.
        let idx = self.nu - 1;
        let y_t = self.s1_coords[idx];
        let x_t = self.s2_coords[idx];
        let one = <E::G1 as Group>::Scalar::one();
        let s1_term = (*alpha) * (one - y_t) + y_t;
        let s2_term = alpha_inv * (one - x_t) + x_t;
        self.s1_acc = self.s1_acc * s1_term;
        self.s2_acc = self.s2_acc * s2_term;

        // Decrement round counter
        self.nu -= 1;
    }

    /// Verify final scalar product message
    ///
    /// Applies fold-scalars transformation and checks the final pairing equation.
    /// Must be called when nu=0 after all reduce rounds are complete.
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
        debug_assert_eq!(self.nu, 0, "nu must be 0 for final verification");

        let gamma_inv = (*gamma).inv().expect("gamma must be invertible");
        let d_inv = (*d).inv().expect("d must be invertible");

        // Apply fold-scalars: update C, D₁, D₂ with gamma challenge

        // C' ← C + s₁·s₂·HT + γ·e(H₁, E₂) + γ⁻¹·e(E₁, H₂)
        let s_product = self.s1_acc * self.s2_acc;
        self.c = self.c + self.setup.ht.scale(&s_product);

        let pairing_h1_e2 = E::pair(&self.setup.h1, &self.e2);
        let pairing_e1_h2 = E::pair(&self.e1, &self.setup.h2);
        self.c = self.c + pairing_h1_e2.scale(gamma);
        self.c = self.c + pairing_e1_h2.scale(&gamma_inv);

        // D₁' ← D₁ + e(H₁, Γ₂₀ · s₁_final · γ)
        let scalar_for_g2_in_d1 = self.s1_acc * gamma;
        let g2_0_scaled = self.setup.g2_0.scale(&scalar_for_g2_in_d1);
        let pairing_h1_g2 = E::pair(&self.setup.h1, &g2_0_scaled);
        self.d1 = self.d1 + pairing_h1_g2;

        // D₂' ← D₂ + e(Γ₁₀ · s₂_final · γ⁻¹, H₂)
        let scalar_for_g1_in_d2 = self.s2_acc * gamma_inv;
        let g1_0_scaled = self.setup.g1_0.scale(&scalar_for_g1_in_d2);
        let pairing_g1_h2 = E::pair(&g1_0_scaled, &self.setup.h2);
        self.d2 = self.d2 + pairing_g1_h2;

        // Final pairing check with d challenge:
        // e(E₁ + d·Γ₁₀, E₂ + d⁻¹·Γ₂₀) = C + χ[0] + d·D₂ + d⁻¹·D₁

        // Left side: e(msg.e1 + d·g1_0, msg.e2 + d⁻¹·g2_0)
        let e1_modified = msg.e1 + self.setup.g1_0.scale(d);
        let e2_modified = msg.e2 + self.setup.g2_0.scale(&d_inv);
        let lhs = E::pair(&e1_modified, &e2_modified);

        // Right side: C + χ[0] + d·D₂ + d⁻¹·D₁
        let mut rhs = self.c;
        rhs = rhs + self.setup.chi[0];
        rhs = rhs + self.d2.scale(d);
        rhs = rhs + self.d1.scale(&d_inv);

        if lhs == rhs {
            Ok(())
        } else {
            Err(DoryError::InvalidProof)
        }
    }
}
