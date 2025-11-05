//! Evaluation proof generation and verification using Eval-VMV-RE protocol
//!
//! Implements the full proof generation and verification by:
//! 1. Computing VMV message (C, D2, E1)
//! 2. Running log(n) rounds of inner product protocol (reduce and fold)
//! 3. Producing final scalar product message

use crate::error::DoryError;
use crate::messages::VMVMessage;
use crate::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::primitives::poly::{compute_left_right_vectors, MultilinearLagrange};
use crate::primitives::transcript::Transcript;
use crate::proof::DoryProof;
use crate::reduce_and_fold::DoryVerifierState;
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
/// 6. Run nu rounds of reduce-and-fold:
///    - First reduce: compute message and apply beta challenge (reduce)
///    - Second reduce: compute message and apply alpha challenge (fold)
/// 7. Compute final scalar product message
///
/// # Parameters
/// - `polynomial`: Polynomial to prove evaluation for
/// - `point`: Evaluation point (length nu + sigma)
/// - `row_commitments`: Optional precomputed row commitments from polynomial.commit()
/// - `nu`: Log₂ of number of rows
/// - `sigma`: Log₂ of number of columns
/// - `setup`: Prover setup
/// - `transcript`: Fiat-Shamir transcript for challenge generation
///
/// # Returns
/// Complete Dory proof containing VMV message, reduce messages, and final message
///
/// # Errors
/// Returns error if dimensions are invalid or protocol fails
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
    // Validate inputs
    let expected_len = 1 << (nu + sigma);
    if polynomial.coefficients().len() != expected_len {
        return Err(DoryError::InvalidSize {
            expected: expected_len,
            actual: polynomial.coefficients().len(),
        });
    }
    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension {
            expected: nu + sigma,
            actual: point.len(),
        });
    }

    // Step 1: Compute row commitments if not provided (Tier 1 commitment)
    let row_commitments = if let Some(rc) = row_commitments {
        rc
    } else {
        let (_commitment, rc) = polynomial.commit::<E, M1>(nu, sigma, setup)?;
        rc
    };

    // Step 2: Split point into left and right vectors
    let (left_vec, right_vec) = polynomial.compute_evaluation_vectors(point, nu, sigma);

    // Step 3: Compute v_vec (column-wise evaluations): v[j] = Σᵢ left[i] × coeffs[i][j]
    let v_vec = polynomial.vector_matrix_product(&left_vec, nu, sigma);

    // Step 4: Create VMV message (C, D2, E1)
    // C = e(⟨row_commitments, v_vec⟩, h₂)
    let t_vec_v = M1::msm(&row_commitments, &v_vec);
    let c = E::pair(&t_vec_v, &setup.h2);

    // D₂ = e(⟨Γ₁[nu], v_vec⟩, h₂)
    let g1_bases_at_nu = &setup.g1_vec[..1 << nu];
    let gamma1_v = M1::msm(g1_bases_at_nu, &v_vec);
    let d2 = E::pair(&gamma1_v, &setup.h2);

    // E₁ = ⟨row_commitments, left_vec⟩
    let e1 = M1::msm(&row_commitments, &left_vec);

    let vmv_message = VMVMessage { c, d2, e1 };

    // Append VMV message to transcript
    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);

    // Step 5: Transform v_vec into G2 elements for inner product protocol
    // v₂ = v_vec · Γ₂,fin (each scalar scales g_fin)
    let v2 = M2::fixed_base_vector_scalar_mul(&setup.h2, &v_vec);

    let mut prover_state = crate::reduce_and_fold::DoryProverState::new(
        row_commitments, // v1 = T_vec_prime (row commitments)
        v2,              // v2 = v_vec · g_fin
        right_vec,       // s1 = right_vec
        left_vec,        // s2 = left_vec
        setup,
    );

    // Step 6: Run nu rounds of inner product protocol (reduce and fold)
    let mut first_messages = Vec::with_capacity(nu);
    let mut second_messages = Vec::with_capacity(nu);

    for _round in 0..nu {
        // First reduce: compute message
        let first_msg = prover_state.compute_first_message::<M1, M2>();

        // Append first message to transcript
        transcript.append_serde(b"d1_left", &first_msg.d1_left);
        transcript.append_serde(b"d1_right", &first_msg.d1_right);
        transcript.append_serde(b"d2_left", &first_msg.d2_left);
        transcript.append_serde(b"d2_right", &first_msg.d2_right);
        transcript.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript.append_serde(b"e2_beta", &first_msg.e2_beta);

        let beta = transcript.challenge_scalar(b"beta");

        // Apply beta: combine step
        prover_state.apply_first_challenge::<M1, M2>(&beta);

        first_messages.push(first_msg);

        // Second reduce: compute message
        let second_msg = prover_state.compute_second_message::<M1, M2>();

        // Append second message to transcript
        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);

        let alpha = transcript.challenge_scalar(b"alpha");

        // Apply alpha: fold step (halves vector size)
        prover_state.apply_second_challenge::<M1, M2>(&alpha);

        second_messages.push(second_msg);
    }

    // Step 7: Compute final scalar product message
    let gamma = transcript.challenge_scalar(b"gamma");
    let final_message = prover_state.compute_final_message::<M1, M2>(&gamma);

    Ok(DoryProof {
        vmv_message,
        first_messages,
        second_messages,
        final_message,
    })
}

/// Verify an evaluation proof
///
/// Verifies that a committed polynomial evaluates to the claimed value at the given point.
///
/// # Algorithm
/// 1. Extract VMV message from proof
/// 2. Check sigma protocol 2: d2 = e(e1, h2)
/// 3. Compute e2 = h2 * evaluation
/// 4. Initialize verifier state with commitment and VMV message
/// 5. Run nu rounds of reduce-and-fold verification
/// 6. Derive gamma and d challenges
/// 7. Verify final scalar product message
///
/// # Parameters
/// - `commitment`: Polynomial commitment (in GT)
/// - `evaluation`: Claimed evaluation result
/// - `point`: Evaluation point (length nu + sigma)
/// - `proof`: Evaluation proof to verify
/// - `nu`: Log₂ of number of rows
/// - `sigma`: Log₂ of number of columns
/// - `setup`: Verifier setup
/// - `transcript`: Fiat-Shamir transcript for challenge generation
///
/// # Returns
/// `Ok(())` if proof is valid, `Err(DoryError)` otherwise
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, name = "verify_evaluation_proof")]
pub fn verify_evaluation_proof<F, E, M1, M2, T>(
    commitment: E::GT,
    evaluation: F,
    point: &[F],
    proof: &DoryProof<E::G1, E::G2, E::GT>,
    nu: usize,
    sigma: usize,
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
    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension {
            expected: nu + sigma,
            actual: point.len(),
        });
    }

    // Step 1: Extract VMV message and append to transcript
    let vmv_message = &proof.vmv_message;
    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);

    // Step 2: Check sigma protocol 2: d2 = e(e1, h2)
    // This sigma protocol is very tricky and easy to miss in the paper!
    let pairing_check = E::pair(&vmv_message.e1, &setup.h2);
    if vmv_message.d2 != pairing_check {
        return Err(DoryError::InvalidProof);
    }

    // Step 3: Compute e2 = h2 * evaluation (verifier-side optimization)
    let e2 = setup.h2.scale(&evaluation);

    // Step 4: Compute tensors (left_vec and right_vec) from evaluation point
    // The verifier needs these to fold during the protocol
    let (s2_tensor, s1_tensor) = compute_left_right_vectors(point, sigma, nu);

    // Step 5: Initialize verifier state
    // d1 = commitment (T in the paper)
    let mut verifier_state = DoryVerifierState::new(
        vmv_message.c,  // c from VMV message
        commitment,     // d1 = commitment
        vmv_message.d2, // d2 from VMV message
        vmv_message.e1, // e1 from VMV message
        e2,             // e2 computed from evaluation
        s1_tensor,      // right_vec from prover (folded as s1)
        s2_tensor,      // left_vec from prover (folded as s2)
        nu,
        setup.clone(), // Clone setup for verifier state
    );

    // Step 5: Run nu rounds of reduce-and-fold verification
    for round in 0..nu {
        let first_msg = &proof.first_messages[round];
        let second_msg = &proof.second_messages[round];

        // Append first message to transcript and derive beta
        transcript.append_serde(b"d1_left", &first_msg.d1_left);
        transcript.append_serde(b"d1_right", &first_msg.d1_right);
        transcript.append_serde(b"d2_left", &first_msg.d2_left);
        transcript.append_serde(b"d2_right", &first_msg.d2_right);
        transcript.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript.append_serde(b"e2_beta", &first_msg.e2_beta);
        let beta = transcript.challenge_scalar(b"beta");

        // Append second message to transcript and derive alpha
        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);
        let alpha = transcript.challenge_scalar(b"alpha");

        // Process round with both challenges
        verifier_state.process_round(first_msg, second_msg, &alpha, &beta);
    }

    // Step 6: Derive gamma and d challenges for final verification
    let gamma = transcript.challenge_scalar(b"gamma");
    let d = transcript.challenge_scalar(b"d");

    // Step 7: Verify final message
    verifier_state.verify_final(&proof.final_message, &gamma, &d)
}
