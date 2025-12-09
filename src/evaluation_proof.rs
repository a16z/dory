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

#[cfg(feature = "recursion")]
use crate::recursion::{WitnessBackend, WitnessGenerator};

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

    transcript.append_serde(b"final_e1", &final_message.e1);
    transcript.append_serde(b"final_e2", &final_message.e2);

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

    // # NOTE: The VMV check `vmv_message.d2 == e(vmv_message.e1, setup.h2)` is deferred
    // to verify_final where it's batched with other pairings using random linear
    // combination with challenge `d`. See verify_final documentation for details.

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

    transcript.append_serde(b"final_e1", &proof.final_message.e1);
    transcript.append_serde(b"final_e2", &proof.final_message.e2);

    let d = transcript.challenge_scalar(b"d");

    verifier_state.verify_final(&proof.final_message, &gamma, &d)
}

/// Verify an evaluation proof with automatic operation tracing.
///
/// This function verifies a Dory evaluation proof while automatically tracing
/// all expensive arithmetic operations through the provided
/// [`TraceContext`](crate::recursion::TraceContext). The context determines the behavior:
///
/// - **Witness Generation Mode**: All operations are computed and their witnesses
///   are recorded in the context's collector.
/// - **Hint-Based Mode**: Operations use pre-computed hints when available,
///   falling back to computation with a warning when hints are missing.
///
/// # Parameters
/// - `commitment`: Polynomial commitment (in GT)
/// - `evaluation`: Claimed evaluation result
/// - `point`: Evaluation point (length must equal proof.nu + proof.sigma)
/// - `proof`: Evaluation proof to verify
/// - `setup`: Verifier setup
/// - `transcript`: Fiat-Shamir transcript for challenge generation
/// - `ctx`: Trace context (from `TraceContext::for_witness_gen()` or `TraceContext::for_hints()`)
///
/// # Returns
/// `Ok(())` if proof is valid, `Err(DoryError)` otherwise.
///
/// After verification, call `ctx.finalize()` to get the collected witnesses
/// (in witness generation mode) or check `ctx.had_missing_hints()` to see
/// if any hints were missing (in hint-based mode).
///
/// # Errors
/// Returns `DoryError::InvalidProof` if verification fails, or
/// `DoryError::InvalidPointDimension` if point length doesn't match proof dimensions.
///
/// # Panics
/// Panics if transcript challenge scalars (alpha, beta, gamma, d) are zero
/// (if this happens, go buy a lottery ticket)
///
/// # Example
///
/// ```ignore
/// use std::rc::Rc;
/// use dory_pcs::recursion::TraceContext;
///
/// // Witness generation mode
/// let ctx = Rc::new(TraceContext::for_witness_gen());
/// verify_recursive(commitment, evaluation, &point, &proof, setup.clone(), &mut transcript, ctx.clone())?;
/// let witnesses = Rc::try_unwrap(ctx).ok().unwrap().finalize();
///
/// // Hint-based mode
/// let hints = witnesses.to_hints::<E>();
/// let ctx = Rc::new(TraceContext::for_hints(hints));
/// verify_recursive(commitment, evaluation, &point, &proof, setup, &mut transcript, ctx)?;
///
/// TODO(markosg04) this unrolls all the reduce_and_fold fns. We could make it more ergonomic by not unrolling.
/// ```
#[cfg(feature = "recursion")]
#[tracing::instrument(skip_all, name = "verify_recursive")]
#[allow(clippy::too_many_arguments)]
pub fn verify_recursive<F, E, M1, M2, T, W, Gen>(
    commitment: E::GT,
    evaluation: F,
    point: &[F],
    proof: &DoryProof<E::G1, E::G2, E::GT>,
    setup: VerifierSetup<E>,
    transcript: &mut T,
    ctx: crate::recursion::CtxHandle<W, E, Gen>,
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
    W: WitnessBackend,
    Gen: WitnessGenerator<W, E>,
{
    use crate::recursion::{TraceG1, TraceG2, TraceGT, TracePairing};
    use std::rc::Rc;

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

    // Create trace operators
    let pairing = TracePairing::new(Rc::clone(&ctx));

    // VMV check pairing: d2 == e(e1, h2)
    let e1_trace = TraceG1::new(vmv_message.e1, Rc::clone(&ctx));
    let h2_trace = TraceG2::new(setup.h2, Rc::clone(&ctx));
    let pairing_check = pairing.pair(&e1_trace, &h2_trace);

    if vmv_message.d2 != *pairing_check.inner() {
        return Err(DoryError::InvalidProof);
    }

    // e2 = h2 * evaluation (traced G2 scalar mul)
    let e2 = h2_trace.scale(&evaluation);

    let num_rounds = sigma;
    let col_coords = &point[..sigma];
    let s1_coords: Vec<F> = col_coords.to_vec();
    let mut s2_coords: Vec<F> = vec![F::zero(); sigma];
    let row_coords = &point[sigma..sigma + nu];
    s2_coords[..nu].copy_from_slice(&row_coords[..nu]);

    // Initialize traced verifier state
    let mut c = TraceGT::new(vmv_message.c, Rc::clone(&ctx));
    let mut d1 = TraceGT::new(commitment, Rc::clone(&ctx));
    let mut d2 = TraceGT::new(vmv_message.d2, Rc::clone(&ctx));
    let mut e1 = TraceG1::new(vmv_message.e1, Rc::clone(&ctx));
    let mut e2_state = e2;
    let mut s1_acc = F::one();
    let mut s2_acc = F::one();
    let mut remaining_rounds = num_rounds;

    ctx.set_num_rounds(num_rounds);

    // Process each round with automatic tracing
    for round in 0..num_rounds {
        ctx.advance_round();
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

        let alpha_inv = alpha.inv().expect("alpha must be invertible");
        let beta_inv = beta.inv().expect("beta must be invertible");

        // Update C with traced operations
        let chi = &setup.chi[remaining_rounds];
        c = c + TraceGT::new(*chi, Rc::clone(&ctx));

        // d2.scale(beta) - traced GT exp
        let d2_scaled = d2.scale(&beta);
        // c + d2_scaled - traced GT mul (via Add impl)
        c = c + d2_scaled;

        // d1.scale(beta_inv) - traced GT exp
        let d1_scaled = d1.scale(&beta_inv);
        c = c + d1_scaled;

        // c_plus.scale(alpha) - traced GT exp
        let c_plus_trace = TraceGT::new(second_msg.c_plus, Rc::clone(&ctx));
        let c_plus_scaled = c_plus_trace.scale(&alpha);
        c = c + c_plus_scaled;

        // c_minus.scale(alpha_inv) - traced GT exp
        let c_minus_trace = TraceGT::new(second_msg.c_minus, Rc::clone(&ctx));
        let c_minus_scaled = c_minus_trace.scale(&alpha_inv);
        c = c + c_minus_scaled;

        // Update D1 (GT operations - traced via scale and add)
        let delta_1l = &setup.delta_1l[remaining_rounds];
        let delta_1r = &setup.delta_1r[remaining_rounds];
        let alpha_beta = alpha * beta;
        let d1_left_trace = TraceGT::new(first_msg.d1_left, Rc::clone(&ctx));
        d1 = d1_left_trace.scale(&alpha);
        d1 = d1 + TraceGT::new(first_msg.d1_right, Rc::clone(&ctx));
        let delta_1l_trace = TraceGT::new(*delta_1l, Rc::clone(&ctx));
        d1 = d1 + delta_1l_trace.scale(&alpha_beta);
        let delta_1r_trace = TraceGT::new(*delta_1r, Rc::clone(&ctx));
        d1 = d1 + delta_1r_trace.scale(&beta);

        // Update D2 (GT operations - traced via scale and add)
        let delta_2l = &setup.delta_2l[remaining_rounds];
        let delta_2r = &setup.delta_2r[remaining_rounds];
        let alpha_inv_beta_inv = alpha_inv * beta_inv;
        let d2_left_trace = TraceGT::new(first_msg.d2_left, Rc::clone(&ctx));
        d2 = d2_left_trace.scale(&alpha_inv);
        d2 = d2 + TraceGT::new(first_msg.d2_right, Rc::clone(&ctx));
        let delta_2l_trace = TraceGT::new(*delta_2l, Rc::clone(&ctx));
        d2 = d2 + delta_2l_trace.scale(&alpha_inv_beta_inv);
        let delta_2r_trace = TraceGT::new(*delta_2r, Rc::clone(&ctx));
        d2 = d2 + delta_2r_trace.scale(&beta_inv);

        // Update E1 (G1 operations - traced via scale)
        let e1_beta_trace = TraceG1::new(first_msg.e1_beta, Rc::clone(&ctx));
        let e1_beta_scaled = e1_beta_trace.scale(&beta);
        e1 = e1 + e1_beta_scaled;
        let e1_plus_trace = TraceG1::new(second_msg.e1_plus, Rc::clone(&ctx));
        e1 = e1 + e1_plus_trace.scale(&alpha);
        let e1_minus_trace = TraceG1::new(second_msg.e1_minus, Rc::clone(&ctx));
        e1 = e1 + e1_minus_trace.scale(&alpha_inv);

        // Update E2 (G2 operations - traced via scale)
        let e2_beta_trace = TraceG2::new(first_msg.e2_beta, Rc::clone(&ctx));
        let e2_beta_scaled = e2_beta_trace.scale(&beta_inv);
        e2_state = e2_state + e2_beta_scaled;
        let e2_plus_trace = TraceG2::new(second_msg.e2_plus, Rc::clone(&ctx));
        e2_state = e2_state + e2_plus_trace.scale(&alpha);
        let e2_minus_trace = TraceG2::new(second_msg.e2_minus, Rc::clone(&ctx));
        e2_state = e2_state + e2_minus_trace.scale(&alpha_inv);

        // Update scalar accumulators (field ops, not traced)
        let idx = remaining_rounds - 1;
        let y_t = s1_coords[idx];
        let x_t = s2_coords[idx];
        let one = F::one();
        let s1_term = alpha * (one - y_t) + y_t;
        let s2_term = alpha_inv * (one - x_t) + x_t;
        s1_acc = s1_acc * s1_term;
        s2_acc = s2_acc * s2_term;

        remaining_rounds -= 1;
    }

    ctx.enter_final();

    let gamma = transcript.challenge_scalar(b"gamma");
    let d_challenge = transcript.challenge_scalar(b"d");

    let gamma_inv = gamma.inv().expect("gamma must be invertible");
    let d_inv = d_challenge.inv().expect("d must be invertible");

    // Final verification with tracing
    let s_product = s1_acc * s2_acc;
    let ht_trace = TraceGT::new(setup.ht, Rc::clone(&ctx));
    let ht_scaled = ht_trace.scale(&s_product);
    c = c + ht_scaled;

    // Traced pairings
    let h1_trace = TraceG1::new(setup.h1, Rc::clone(&ctx));
    let pairing_h1_e2 = pairing.pair(&h1_trace, &e2_state);
    let pairing_e1_h2 = pairing.pair(&e1, &h2_trace);

    c = c + pairing_h1_e2.scale(&gamma);
    c = c + pairing_e1_h2.scale(&gamma_inv);

    // D1 update with traced operations
    let scalar_for_g2_in_d1 = s1_acc * gamma;
    let g2_0_trace = TraceG2::new(setup.g2_0, Rc::clone(&ctx));
    let g2_0_scaled = g2_0_trace.scale(&scalar_for_g2_in_d1);

    let pairing_h1_g2 = pairing.pair(&h1_trace, &g2_0_scaled);
    d1 = d1 + pairing_h1_g2;

    // D2 update with traced operations
    let scalar_for_g1_in_d2 = s2_acc * gamma_inv;
    let g1_0_trace = TraceG1::new(setup.g1_0, Rc::clone(&ctx));
    let g1_0_scaled = g1_0_trace.scale(&scalar_for_g1_in_d2);

    let pairing_g1_h2 = pairing.pair(&g1_0_scaled, &h2_trace);
    d2 = d2 + pairing_g1_h2;

    // Final pairing check
    let e1_final = TraceG1::new(proof.final_message.e1, Rc::clone(&ctx));
    let g1_0_d_scaled = g1_0_trace.scale(&d_challenge);
    let e1_modified = e1_final + g1_0_d_scaled;

    let e2_final = TraceG2::new(proof.final_message.e2, Rc::clone(&ctx));
    let g2_0_d_inv_scaled = g2_0_trace.scale(&d_inv);
    let e2_modified = e2_final + g2_0_d_inv_scaled;

    let lhs = pairing.pair(&e1_modified, &e2_modified);

    let mut rhs = c;
    rhs = rhs + TraceGT::new(setup.chi[0], Rc::clone(&ctx));
    rhs = rhs + d2.scale(&d_challenge);
    rhs = rhs + d1.scale(&d_inv);

    if *lhs.inner() == *rhs.inner() {
        Ok(())
    } else {
        Err(DoryError::InvalidProof)
    }
}
