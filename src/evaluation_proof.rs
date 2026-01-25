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
use crate::reduce_and_fold::DoryProverState;
use crate::setup::{ProverSetup, VerifierSetup};

#[cfg(feature = "recursion")]
use crate::recursion::{TracingBackend, WitnessBackend, WitnessGenerator};

use crate::primitives::backend::{NativeBackend, VerifierBackend};

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
    let mut backend = NativeBackend::<E>::new();
    verify_with_backend(
        commitment,
        evaluation,
        point,
        proof,
        setup,
        transcript,
        &mut backend,
    )
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
/// - `ctx`: Trace context (from `TraceContext::for_witness_gen()` or `TraceContext::for_symbolic()`)
///
/// # Returns
/// `Ok(())` if proof is valid, `Err(DoryError)` otherwise.
///
/// After verification:
/// - In witness generation mode, call `ctx.finalize()` to get collected witnesses
/// - In symbolic mode, call `ctx.take_ast()` to get the proof obligations AST
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
/// // Witness generation mode (for prover)
/// let ctx = Rc::new(TraceContext::for_witness_gen());
/// verify_recursive(commitment, evaluation, &point, &proof, setup.clone(), &mut transcript, ctx.clone())?;
/// let witnesses = Rc::try_unwrap(ctx).ok().unwrap().finalize();
///
/// // Symbolic mode (for verifier recursion)
/// let ctx = Rc::new(TraceContext::for_symbolic());
/// verify_recursive(commitment, evaluation, &point, &proof, setup, &mut transcript, ctx.clone())?;
/// let ast = ctx.take_ast().unwrap(); // AST contains proof obligations
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
    let mut backend = TracingBackend::new(ctx);
    verify_with_backend(
        commitment,
        evaluation,
        point,
        proof,
        setup,
        transcript,
        &mut backend,
    )
}

/// Unified verification function generic over backend.
///
/// This contains all verification logic once, avoiding code duplication between
/// native and tracing verification paths. Both `verify_evaluation_proof` and
/// `verify_recursive` delegate to this function with their respective backends.
///
/// External crates (e.g., Jolt) can use this with custom backends for:
/// - AST-only construction (no group ops, just build the verification DAG)
/// - Challenge replay (use precomputed challenges, skip transcript hashing)
/// - Custom witness strategies
///
/// # Errors
///
/// Returns `DoryError::InvalidPointDimension` if `point.len() != nu + sigma`.
/// Returns `DoryError::InvalidProof` if the final GT equality check fails.
///
/// # Panics
///
/// Panics if any of the transcript challenge scalars (`alpha`, `beta`, `gamma`, `d`)
/// are zero and thus not invertible. This is cryptographically negligible.
#[inline]
pub fn verify_with_backend<F, E, T, B>(
    commitment: E::GT,
    evaluation: F,
    point: &[F],
    proof: &DoryProof<E::G1, E::G2, E::GT>,
    setup: VerifierSetup<E>,
    transcript: &mut T,
    backend: &mut B,
) -> Result<(), DoryError>
where
    F: Field,
    E: PairingCurve,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    T: Transcript<Curve = E>,
    B: VerifierBackend<Curve = E, Scalar = F>,
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

    // VMV check `d2 == e(e1, h2)` is deferred to final multi-pairing via d² scaling

    // Wrap setup elements
    let h2 = backend.wrap_g2_setup(setup.h2, "h2", None);

    // e2 = h2 * evaluation
    let mut e2 = backend.g2_scale(&h2, &evaluation);

    let num_rounds = sigma;
    let col_coords = &point[..sigma];
    let s1_coords: Vec<F> = col_coords.to_vec();
    let mut s2_coords: Vec<F> = vec![F::zero(); sigma];
    let row_coords = &point[sigma..sigma + nu];
    s2_coords[..nu].copy_from_slice(&row_coords[..nu]);

    // Wrap proof elements for state
    let mut c = backend.wrap_gt_proof(vmv_message.c, "vmv.c");
    let mut d1 = backend.wrap_gt_proof(commitment, "commitment");
    let mut d2 = backend.wrap_gt_proof(vmv_message.d2, "vmv.d2");
    let mut e1 = backend.wrap_g1_proof(vmv_message.e1, "vmv.e1");

    // Track initial VMV values for deferred check (batched in final multi-pairing)
    let e1_init = backend.wrap_g1_proof(vmv_message.e1, "vmv.e1_init");
    let d2_init = backend.wrap_gt_proof(vmv_message.d2, "vmv.d2_init");

    let mut s1_acc = F::one();
    let mut s2_acc = F::one();
    let mut remaining_rounds = num_rounds;

    // Lifecycle: set total rounds (used by TracingBackend)
    backend.set_num_rounds(num_rounds);

    // Process each round
    for round in 0..num_rounds {
        backend.advance_round();
        let first_msg = &proof.first_messages[round];
        let second_msg = &proof.second_messages[round];

        // Append first message to transcript
        transcript.append_serde(b"d1_left", &first_msg.d1_left);
        transcript.append_serde(b"d1_right", &first_msg.d1_right);
        transcript.append_serde(b"d2_left", &first_msg.d2_left);
        transcript.append_serde(b"d2_right", &first_msg.d2_right);
        transcript.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript.append_serde(b"e2_beta", &first_msg.e2_beta);
        let beta = transcript.challenge_scalar(b"beta");

        // Append second message to transcript
        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);
        let alpha = transcript.challenge_scalar(b"alpha");

        let alpha_inv = alpha.inv().expect("alpha must be invertible");
        let beta_inv = beta.inv().expect("beta must be invertible");

        // Update C: C += χ + β·D₂ + β⁻¹·D₁ + α·C₊ + α⁻¹·C₋
        let chi = backend.wrap_gt_setup(setup.chi[remaining_rounds], "chi", Some(remaining_rounds));
        c = backend.gt_mul(&c, &chi);
        let d2_scaled = backend.gt_scale(&d2, &beta);
        c = backend.gt_mul(&c, &d2_scaled);
        let d1_scaled = backend.gt_scale(&d1, &beta_inv);
        c = backend.gt_mul(&c, &d1_scaled);
        let c_plus = backend.wrap_gt_proof_round(second_msg.c_plus, round, false, "c_plus");
        let c_plus_scaled = backend.gt_scale(&c_plus, &alpha);
        c = backend.gt_mul(&c, &c_plus_scaled);
        let c_minus = backend.wrap_gt_proof_round(second_msg.c_minus, round, false, "c_minus");
        let c_minus_scaled = backend.gt_scale(&c_minus, &alpha_inv);
        c = backend.gt_mul(&c, &c_minus_scaled);

        // Update D1: D₁ = α·D₁ₗ + D₁ᵣ + αβ·Δ₁ₗ + β·Δ₁ᵣ
        let alpha_beta = alpha * beta;
        let d1_left = backend.wrap_gt_proof_round(first_msg.d1_left, round, true, "d1_left");
        d1 = backend.gt_scale(&d1_left, &alpha);
        let d1_right = backend.wrap_gt_proof_round(first_msg.d1_right, round, true, "d1_right");
        d1 = backend.gt_mul(&d1, &d1_right);
        let delta_1l = backend.wrap_gt_setup(
            setup.delta_1l[remaining_rounds],
            "delta_1l",
            Some(remaining_rounds),
        );
        let delta_1l_scaled = backend.gt_scale(&delta_1l, &alpha_beta);
        d1 = backend.gt_mul(&d1, &delta_1l_scaled);
        let delta_1r = backend.wrap_gt_setup(
            setup.delta_1r[remaining_rounds],
            "delta_1r",
            Some(remaining_rounds),
        );
        let delta_1r_scaled = backend.gt_scale(&delta_1r, &beta);
        d1 = backend.gt_mul(&d1, &delta_1r_scaled);

        // Update D2: D₂ = α⁻¹·D₂ₗ + D₂ᵣ + α⁻¹β⁻¹·Δ₂ₗ + β⁻¹·Δ₂ᵣ
        let alpha_inv_beta_inv = alpha_inv * beta_inv;
        let d2_left = backend.wrap_gt_proof_round(first_msg.d2_left, round, true, "d2_left");
        d2 = backend.gt_scale(&d2_left, &alpha_inv);
        let d2_right = backend.wrap_gt_proof_round(first_msg.d2_right, round, true, "d2_right");
        d2 = backend.gt_mul(&d2, &d2_right);
        let delta_2l = backend.wrap_gt_setup(
            setup.delta_2l[remaining_rounds],
            "delta_2l",
            Some(remaining_rounds),
        );
        let delta_2l_scaled = backend.gt_scale(&delta_2l, &alpha_inv_beta_inv);
        d2 = backend.gt_mul(&d2, &delta_2l_scaled);
        let delta_2r = backend.wrap_gt_setup(
            setup.delta_2r[remaining_rounds],
            "delta_2r",
            Some(remaining_rounds),
        );
        let delta_2r_scaled = backend.gt_scale(&delta_2r, &beta_inv);
        d2 = backend.gt_mul(&d2, &delta_2r_scaled);

        // Update E1: E₁ += β·E₁β + α·E₁₊ + α⁻¹·E₁₋
        let e1_beta_msg = backend.wrap_g1_proof_round(first_msg.e1_beta, round, true, "e1_beta");
        let e1_beta_scaled = backend.g1_scale(&e1_beta_msg, &beta);
        e1 = backend.g1_add(&e1, &e1_beta_scaled);
        let e1_plus = backend.wrap_g1_proof_round(second_msg.e1_plus, round, false, "e1_plus");
        let e1_plus_scaled = backend.g1_scale(&e1_plus, &alpha);
        e1 = backend.g1_add(&e1, &e1_plus_scaled);
        let e1_minus = backend.wrap_g1_proof_round(second_msg.e1_minus, round, false, "e1_minus");
        let e1_minus_scaled = backend.g1_scale(&e1_minus, &alpha_inv);
        e1 = backend.g1_add(&e1, &e1_minus_scaled);

        // Update E2: E₂ += β⁻¹·E₂β + α·E₂₊ + α⁻¹·E₂₋
        let e2_beta_msg = backend.wrap_g2_proof_round(first_msg.e2_beta, round, true, "e2_beta");
        let e2_beta_scaled = backend.g2_scale(&e2_beta_msg, &beta_inv);
        e2 = backend.g2_add(&e2, &e2_beta_scaled);
        let e2_plus = backend.wrap_g2_proof_round(second_msg.e2_plus, round, false, "e2_plus");
        let e2_plus_scaled = backend.g2_scale(&e2_plus, &alpha);
        e2 = backend.g2_add(&e2, &e2_plus_scaled);
        let e2_minus = backend.wrap_g2_proof_round(second_msg.e2_minus, round, false, "e2_minus");
        let e2_minus_scaled = backend.g2_scale(&e2_minus, &alpha_inv);
        e2 = backend.g2_add(&e2, &e2_minus_scaled);

        // Update scalar accumulators
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

    // Lifecycle: enter final phase (used by TracingBackend)
    backend.enter_final();

    // Final verification phase
    let gamma = transcript.challenge_scalar(b"gamma");

    transcript.append_serde(b"final_e1", &proof.final_message.e1);
    transcript.append_serde(b"final_e2", &proof.final_message.e2);

    let d_challenge = transcript.challenge_scalar(b"d");

    let gamma_inv = gamma.inv().expect("gamma must be invertible");
    let d_inv = d_challenge.inv().expect("d must be invertible");
    let d_sq = d_challenge * d_challenge;
    let neg_gamma = -gamma;
    let neg_gamma_inv = -gamma_inv;

    // Setup elements for final check
    let g1_0 = backend.wrap_g1_setup(setup.g1_0, "g1_0", None);
    let g2_0 = backend.wrap_g2_setup(setup.g2_0, "g2_0", None);
    let h1 = backend.wrap_g1_setup(setup.h1, "h1", None);
    let ht = backend.wrap_gt_setup(setup.ht, "ht", None);
    let chi_0 = backend.wrap_gt_setup(setup.chi[0], "chi", Some(0));

    // Compute RHS: T = C + (s₁·s₂)·HT + χ₀ + d·D₂ + d⁻¹·D₁ + d²·D₂_init
    let s_product = s1_acc * s2_acc;
    let ht_scaled = backend.gt_scale(&ht, &s_product);
    let mut rhs = backend.gt_mul(&c, &ht_scaled);
    rhs = backend.gt_mul(&rhs, &chi_0);
    let d2_final = backend.gt_scale(&d2, &d_challenge);
    rhs = backend.gt_mul(&rhs, &d2_final);
    let d1_final = backend.gt_scale(&d1, &d_inv);
    rhs = backend.gt_mul(&rhs, &d1_final);
    let d2_init_scaled = backend.gt_scale(&d2_init, &d_sq);
    rhs = backend.gt_mul(&rhs, &d2_init_scaled);

    // Build 3 pairs for multi-pairing

    // Pair 1: (E₁_final + d·Γ₁₀, E₂_final + d⁻¹·Γ₂₀)
    let e1_final = backend.wrap_g1_proof(proof.final_message.e1, "final.e1");
    let e2_final = backend.wrap_g2_proof(proof.final_message.e2, "final.e2");
    let g1_0_scaled = backend.g1_scale(&g1_0, &d_challenge);
    let p1_g1 = backend.g1_add(&e1_final, &g1_0_scaled);
    let g2_0_scaled = backend.g2_scale(&g2_0, &d_inv);
    let p1_g2 = backend.g2_add(&e2_final, &g2_0_scaled);

    // Pair 2: (H₁, (-γ)·(E₂_acc + (d⁻¹·s₁)·Γ₂₀))
    let d_inv_s1 = d_inv * s1_acc;
    let g2_0_s1 = backend.g2_scale(&g2_0, &d_inv_s1);
    let g2_term = backend.g2_add(&e2, &g2_0_s1);
    let p2_g1 = h1;
    let p2_g2 = backend.g2_scale(&g2_term, &neg_gamma);

    // Pair 3: ((-γ⁻¹)·(E₁_acc + (d·s₂)·Γ₁₀) + d²·E₁_init, H₂)
    let d_s2 = d_challenge * s2_acc;
    let g1_0_s2 = backend.g1_scale(&g1_0, &d_s2);
    let g1_term = backend.g1_add(&e1, &g1_0_s2);
    let g1_term_scaled = backend.g1_scale(&g1_term, &neg_gamma_inv);
    let e1_init_scaled = backend.g1_scale(&e1_init, &d_sq);
    let p3_g1 = backend.g1_add(&g1_term_scaled, &e1_init_scaled);
    let p3_g2 = h2;

    // Multi-pairing
    let lhs = backend.multi_pair(&[p1_g1, p2_g1, p3_g1], &[p1_g2, p2_g2, p3_g2]);

    // Final equality check
    backend.gt_eq(&lhs, &rhs)
}
