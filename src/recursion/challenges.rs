//! Pre-computed Fiat-Shamir challenges for parallel verification.
//!
//! This module provides infrastructure to separate challenge derivation from
//! group operations, enabling parallel execution of the expensive arithmetic.
//!
//! # Motivation
//!
//! In Dory verification, Fiat-Shamir challenges depend only on proof messages,
//! not on computed group elements. This means all challenges can be derived
//! in a single sequential pass over the proof, after which the group operations
//! can be executed in parallel.
//!
//! # Usage
//!
//! ```ignore
//! use dory_pcs::recursion::challenges::precompute_challenges;
//!
//! // Phase 1: Pre-compute all challenges (sequential, fast - just hashing)
//! let challenges = precompute_challenges(&proof, &mut transcript)?;
//!
//! // Phase 2: Build AST / execute operations with known scalars (can parallelize)
//! // Upstream crate (e.g., Jolt) handles this with their own parallel backend
//! ```

use crate::error::DoryError;
use crate::primitives::arithmetic::{Field, Group, PairingCurve};
use crate::primitives::transcript::Transcript;
use crate::proof::DoryProof;

/// Challenges for a single reduce-and-fold round.
///
/// Each round produces two challenges from the Fiat-Shamir transcript:
/// - `beta`: derived after the first message (d1_left, d1_right, d2_left, d2_right, e1_beta, e2_beta)
/// - `alpha`: derived after the second message (c_plus, c_minus, e1_plus, e1_minus, e2_plus, e2_minus)
#[derive(Debug, Clone)]
pub struct RoundChallenges<F> {
    /// Beta challenge (after first message).
    pub beta: F,
    /// Alpha challenge (after second message).
    pub alpha: F,
}

impl<F: Field> RoundChallenges<F> {
    /// Compute commonly used derived values.
    ///
    /// Returns `(alpha_inv, beta_inv, alpha * beta, alpha_inv * beta_inv)`.
    ///
    /// # Panics
    /// Panics if alpha or beta is zero (astronomically unlikely for random challenges).
    #[inline]
    pub fn derived(&self) -> (F, F, F, F) {
        let alpha_inv = self.alpha.inv().expect("alpha must be invertible");
        let beta_inv = self.beta.inv().expect("beta must be invertible");
        let alpha_beta = self.alpha * self.beta;
        let alpha_inv_beta_inv = alpha_inv * beta_inv;
        (alpha_inv, beta_inv, alpha_beta, alpha_inv_beta_inv)
    }
}

/// All Fiat-Shamir challenges for a Dory verification.
///
/// This struct contains all challenges derived from the transcript,
/// enabling parallel execution of group operations.
#[derive(Debug, Clone)]
pub struct ChallengeSet<F> {
    /// Per-round challenges (one entry per reduce-and-fold round).
    pub rounds: Vec<RoundChallenges<F>>,
    /// Gamma challenge (derived after all rounds, before final message).
    pub gamma: F,
    /// D challenge (derived after final message).
    pub d: F,
}

impl<F: Field> ChallengeSet<F> {
    /// Number of rounds.
    #[inline]
    pub fn num_rounds(&self) -> usize {
        self.rounds.len()
    }

    /// Compute derived values for the final phase.
    ///
    /// Returns `(gamma_inv, d_inv)`.
    ///
    /// # Panics
    /// Panics if gamma or d is zero.
    #[inline]
    pub fn final_derived(&self) -> (F, F) {
        let gamma_inv = self.gamma.inv().expect("gamma must be invertible");
        let d_inv = self.d.inv().expect("d must be invertible");
        (gamma_inv, d_inv)
    }
}

/// Pre-compute all Fiat-Shamir challenges from a Dory proof.
///
/// This function performs a single sequential pass over the proof,
/// appending all messages to the transcript and deriving all challenges.
/// The transcript is mutated to its final state.
///
/// After calling this, the returned `ChallengeSet` contains all scalars
/// needed for verification, enabling parallel execution of group operations.
///
/// # Parameters
/// - `proof`: The Dory proof to verify
/// - `transcript`: Fiat-Shamir transcript (will be mutated)
///
/// # Returns
/// `ChallengeSet` containing all challenges for the verification.
///
/// # Errors
/// Returns `DoryError` if the proof structure is invalid.
pub fn precompute_challenges<F, E, T>(
    proof: &DoryProof<E::G1, E::G2, E::GT>,
    transcript: &mut T,
) -> Result<ChallengeSet<F>, DoryError>
where
    F: Field,
    E: PairingCurve,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    T: Transcript<Curve = E>,
{
    let num_rounds = proof.sigma;

    // Append VMV message
    let vmv_message = &proof.vmv_message;
    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);

    // Process each round
    let mut rounds = Vec::with_capacity(num_rounds);

    for round in 0..num_rounds {
        let first_msg = &proof.first_messages[round];
        let second_msg = &proof.second_messages[round];

        // Append first message and derive beta
        transcript.append_serde(b"d1_left", &first_msg.d1_left);
        transcript.append_serde(b"d1_right", &first_msg.d1_right);
        transcript.append_serde(b"d2_left", &first_msg.d2_left);
        transcript.append_serde(b"d2_right", &first_msg.d2_right);
        transcript.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript.append_serde(b"e2_beta", &first_msg.e2_beta);
        let beta = transcript.challenge_scalar(b"beta");

        // Append second message and derive alpha
        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);
        let alpha = transcript.challenge_scalar(b"alpha");

        rounds.push(RoundChallenges { beta, alpha });
    }

    // Derive gamma
    let gamma = transcript.challenge_scalar(b"gamma");

    // Append final message and derive d
    transcript.append_serde(b"final_e1", &proof.final_message.e1);
    transcript.append_serde(b"final_e2", &proof.final_message.e2);
    let d = transcript.challenge_scalar(b"d");

    Ok(ChallengeSet { rounds, gamma, d })
}

// Tests are in tests/arkworks/recursion.rs to access test utilities
