//! Evaluation proof generation and verification using Eval-VMV-RE protocol
//!
//! Implements the full proof generation and verification by:
//! 1. Computing VMV message (C, D2, E1)
//! 2. Running max(nu, sigma) rounds of inner product protocol (reduce and fold)
//! 3. Producing final scalar product message
//!
//! ## Matrix Layout
//!
//! Supports flexible matrix layouts with constraint nu ≤ sigma:
//! - **Square matrices** (nu = sigma): Traditional layout, e.g., 16×16 for nu=4, sigma=4
//! - **Non-square matrices** (nu < sigma): Wider layouts, e.g., 8×16 for nu=3, sigma=4
//!
//! The protocol automatically pads shorter dimensions and uses max(nu, sigma) rounds
//! in the reduce-and-fold phase.
//!
//! ## Homomorphic Properties
//!
//! The evaluation proof protocol preserves the homomorphic properties of Dory commitments.
//! This enables proving evaluations of linear combinations:
//!
//! ```text
//! Com(r₁·P₁ + r₂·P₂) = r₁·Com(P₁) + r₂·Com(P₂)
//! ```
//!
//! See `examples/homomorphic.rs` for a complete demonstration.

use crate::error::DoryError;
use crate::messages::VMVMessage;
use crate::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::primitives::poly::MultilinearLagrange;
use crate::primitives::transcript::Transcript;
use crate::proof::DoryProof;
use crate::reduce_and_fold::{DoryProverState, DoryVerifierState};
use crate::setup::{ProverSetup, VerifierSetup};

/// Create evaluation proof for a polynomial at a point
///
/// Implements Eval-VMV-RE protocol from Dory Section 5.
/// The protocol proves that polynomial(point) = evaluation via the VMV relation:
/// evaluation = L^T × M × R
///
/// # Algorithm
/// 1. Compute or use provided row commitments (Tier 1 commitment)
/// 2. Split evaluation point into left and right vectors
/// 3. Compute v_vec (column evaluations)
/// 4. Create VMV message (C, D2, E1)
/// 5. Initialize prover state for inner product / reduce-and-fold protocol
/// 6. Run max(nu, sigma) rounds of reduce-and-fold (with automatic padding for non-square):
///    - First reduce: compute message and apply beta challenge (reduce)
///    - Second reduce: compute message and apply alpha challenge (fold)
/// 7. Compute final scalar product message
///
/// # Parameters
/// - `polynomial`: Polynomial to prove evaluation for
/// - `point`: Evaluation point (length nu + sigma)
/// - `row_commitments`: Optional precomputed row commitments from polynomial.commit()
/// - `nu`: Log₂ of number of rows (constraint: nu ≤ sigma)
/// - `sigma`: Log₂ of number of columns
/// - `setup`: Prover setup
/// - `transcript`: Fiat-Shamir transcript for challenge generation
///
/// # Returns
/// Complete Dory proof containing VMV message, reduce messages, and final message
///
/// # Errors
/// Returns error if dimensions are invalid (nu > sigma) or protocol fails
///
/// # Matrix Layout
/// Supports both square (nu = sigma) and non-square (nu < sigma) matrices.
/// For non-square matrices, vectors are automatically padded to length 2^sigma.
#[allow(clippy::type_complexity)]
#[tracing::instrument(skip_all, name = "create_evaluation_proof")]
pub fn create_evaluation_proof<F, E, M1, M2, T, P>(
    polynomial: &P,
    point: &[F],
    row_commitments: Option<Vec<E::G1>>,
    nu: usize,
    sigma: usize,
    setup: &ProverSetup<E>,
    transcript: &mut T,
) -> Result<DoryProof<E::G1, E::G2, E::GT>, DoryError>
where
    F: Field,
    E: PairingCurve,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    M1: DoryRoutines<E::G1>,
    M2: DoryRoutines<E::G2>,
    T: Transcript<Curve = E>,
    P: MultilinearLagrange<F>,
{
    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension {
            expected: nu + sigma,
            actual: point.len(),
        });
    }

    // Validate matrix dimensions: nu must be ≤ sigma (rows ≤ columns)
    if nu > sigma {
        return Err(DoryError::InvalidSize {
            expected: sigma,
            actual: nu,
        });
    }

    let row_commitments = if let Some(rc) = row_commitments {
        rc
    } else {
        let (_commitment, rc) = polynomial.commit::<E, M1>(nu, sigma, setup)?;
        rc
    };

    let _span_eval_vecs = tracing::span!(
        tracing::Level::DEBUG,
        "compute_evaluation_vectors",
        nu,
        sigma
    )
    .entered();
    let (left_vec, right_vec) = polynomial.compute_evaluation_vectors(point, nu, sigma);
    drop(_span_eval_vecs);

    let v_vec = polynomial.vector_matrix_product(&left_vec, nu, sigma);

    let mut padded_row_commitments = row_commitments.clone();
    if nu < sigma {
        padded_row_commitments.resize(1 << sigma, E::G1::identity());
    }

    let _span_vmv =
        tracing::span!(tracing::Level::DEBUG, "compute_vmv_message", nu, sigma).entered();

    // C = e(⟨row_commitments, v_vec⟩, h₂)
    let t_vec_v = M1::msm(&padded_row_commitments, &v_vec);
    let c = E::pair(&t_vec_v, &setup.h2);

    // D₂ = e(⟨Γ₁[sigma], v_vec⟩, h₂)
    let g1_bases_at_sigma = &setup.g1_vec[..1 << sigma];
    let gamma1_v = M1::msm(g1_bases_at_sigma, &v_vec);
    let d2 = E::pair(&gamma1_v, &setup.h2);

    // E₁ = ⟨row_commitments, left_vec⟩
    let e1 = M1::msm(&row_commitments, &left_vec);

    let vmv_message = VMVMessage { c, d2, e1 };
    drop(_span_vmv);

    let _span_transcript = tracing::span!(tracing::Level::DEBUG, "vmv_transcript").entered();
    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);
    drop(_span_transcript);

    let _span_init = tracing::span!(
        tracing::Level::DEBUG,
        "fixed_base_vector_scalar_mul_h2",
        nu,
        sigma
    )
    .entered();

    // v₂ = v_vec · Γ₂,fin (each scalar scales g_fin)
    let v2 = {
        let _span =
            tracing::span!(tracing::Level::DEBUG, "fixed_base_vector_scalar_mul_h2").entered();
        M2::fixed_base_vector_scalar_mul(&setup.h2, &v_vec)
    };

    let mut padded_right_vec = right_vec.clone();
    let mut padded_left_vec = left_vec.clone();
    if nu < sigma {
        padded_right_vec.resize(1 << sigma, F::zero());
        padded_left_vec.resize(1 << sigma, F::zero());
    }

    let mut prover_state = DoryProverState::new(
        padded_row_commitments, // v1 = T_vec_prime (row commitments, padded)
        v2,                     // v2 = v_vec · g_fin
        Some(v_vec),            // v2_scalars for first-round MSM+pair optimization
        padded_right_vec,       // s1 = right_vec (padded)
        padded_left_vec,        // s2 = left_vec (padded)
        setup,
    );
    drop(_span_init);

    let num_rounds = nu.max(sigma);
    let mut first_messages = Vec::with_capacity(num_rounds);
    let mut second_messages = Vec::with_capacity(num_rounds);

    for _round in 0..num_rounds {
        let first_msg = prover_state.compute_first_message::<M1, M2>();

        transcript.append_serde(b"d1_left", &first_msg.d1_left);
        transcript.append_serde(b"d1_right", &first_msg.d1_right);
        transcript.append_serde(b"d2_left", &first_msg.d2_left);
        transcript.append_serde(b"d2_right", &first_msg.d2_right);
        transcript.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript.append_serde(b"e2_beta", &first_msg.e2_beta);

        let beta = transcript.challenge_scalar(b"beta");
        prover_state.apply_first_challenge::<M1, M2>(&beta);

        first_messages.push(first_msg);

        let second_msg = prover_state.compute_second_message::<M1, M2>();

        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);

        let alpha = transcript.challenge_scalar(b"alpha");
        prover_state.apply_second_challenge::<M1, M2>(&alpha);

        second_messages.push(second_msg);
    }

    let gamma = transcript.challenge_scalar(b"gamma");
    let final_message = prover_state.compute_final_message::<M1, M2>(&gamma);

    // We grab d challenge at the end (despite it being unused) to keep transcript states in-sync post proof.
    let _d = transcript.challenge_scalar(b"d");

    Ok(DoryProof {
        vmv_message,
        first_messages,
        second_messages,
        final_message,
        nu,
        sigma,
    })
}

/// Verify an evaluation proof
///
/// Verifies that a committed polynomial evaluates to the claimed value at the given point.
/// Works with both square and non-square matrix layouts (nu ≤ sigma).
///
/// # Algorithm
/// 1. Extract VMV message from proof
/// 2. Check sigma protocol 2: d2 = e(e1, h2)
/// 3. Compute e2 = h2 * evaluation
/// 4. Initialize verifier state with commitment and VMV message
/// 5. Run max(nu, sigma) rounds of reduce-and-fold verification (with automatic padding)
/// 6. Derive gamma and d challenges
/// 7. Verify final scalar product message
///
/// # Parameters
/// - `commitment`: Polynomial commitment (in GT) - can be a homomorphically combined commitment
/// - `evaluation`: Claimed evaluation result
/// - `point`: Evaluation point (length must equal proof.nu + proof.sigma)
/// - `proof`: Evaluation proof to verify (contains nu and sigma dimensions)
/// - `setup`: Verifier setup
/// - `transcript`: Fiat-Shamir transcript for challenge generation
///
/// # Returns
/// `Ok(())` if proof is valid, `Err(DoryError)` otherwise
///
/// # Homomorphic Verification
/// This function can verify proofs for homomorphically combined polynomials.
/// The commitment parameter should be the combined commitment, and the evaluation
/// should be the evaluation of the combined polynomial.
///
/// # Errors
/// Returns `DoryError::InvalidProof` if verification fails, or other variants
/// if the input parameters are incorrect (e.g., point dimension mismatch).
#[tracing::instrument(skip_all, name = "verify_evaluation_proof")]
pub fn verify_evaluation_proof<F, E, M1, M2, T>(
    commitment: E::GT,
    evaluation: F,
    point: &[F],
    proof: &DoryProof<E::G1, E::G2, E::GT>,
    setup: VerifierSetup<E>,
    transcript: &mut T,
) -> Result<(), DoryError>
where
    F: Field,
    E: PairingCurve,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    M1: DoryRoutines<E::G1>,
    M2: DoryRoutines<E::G2>,
    T: Transcript<Curve = E>,
{
    let nu = proof.nu;
    let sigma = proof.sigma;

    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension {
            expected: nu + sigma,
            actual: point.len(),
        });
    }

    let vmv_message = &proof.vmv_message;
    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);

    let pairing_check = E::pair(&vmv_message.e1, &setup.h2);
    if vmv_message.d2 != pairing_check {
        return Err(DoryError::InvalidProof);
    }

    let e2 = setup.h2.scale(&evaluation);

    // Folded-scalar accumulation with per-round coordinates.
    // num_rounds = sigma (we fold column dimensions).
    let num_rounds = sigma;
    // s1 (right/prover): the σ column coordinates in natural order (LSB→MSB).
    // No padding here: the verifier folds across the σ column dimensions.
    // With MSB-first folding, these coordinates are only consumed after the first σ−ν rounds,
    // which correspond to the padded MSB dimensions on the left tensor, matching the prover.
    let col_coords = &point[..sigma];
    let s1_coords: Vec<F> = col_coords.to_vec();
    // s2 (left/prover): the ν row coordinates in natural order, followed by zeros for the extra
    // MSB dimensions. Conceptually this is s ⊗ [1,0]^(σ−ν): under MSB-first folds, the first
    // σ−ν rounds multiply s2 by α⁻¹ while contributing no right halves (since those entries are 0).
    let mut s2_coords: Vec<F> = vec![F::zero(); sigma];
    let row_coords = &point[sigma..sigma + nu];
    s2_coords[..nu].copy_from_slice(&row_coords[..nu]);

    let mut verifier_state = DoryVerifierState::new(
        vmv_message.c,  // c from VMV message
        commitment,     // d1 = commitment
        vmv_message.d2, // d2 from VMV message
        vmv_message.e1, // e1 from VMV message
        e2,             // e2 computed from evaluation
        s1_coords,      // s1: columns c0..c_{σ−1} (LSB→MSB), no padding; folded across σ dims
        s2_coords,      // s2: rows r0..r_{ν−1} then zeros in MSB dims (emulates s ⊗ [1,0]^(σ−ν))
        num_rounds,
        setup.clone(),
    );

    for round in 0..num_rounds {
        let first_msg = &proof.first_messages[round];
        let second_msg = &proof.second_messages[round];

        transcript.append_serde(b"d1_left", &first_msg.d1_left);
        transcript.append_serde(b"d1_right", &first_msg.d1_right);
        transcript.append_serde(b"d2_left", &first_msg.d2_left);
        transcript.append_serde(b"d2_right", &first_msg.d2_right);
        transcript.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript.append_serde(b"e2_beta", &first_msg.e2_beta);
        let beta = transcript.challenge_scalar(b"beta");

        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);
        let alpha = transcript.challenge_scalar(b"alpha");

        verifier_state.process_round(first_msg, second_msg, &alpha, &beta);
    }

    let gamma = transcript.challenge_scalar(b"gamma");
    let d = transcript.challenge_scalar(b"d");

    verifier_state.verify_final(&proof.final_message, &gamma, &d)
}
