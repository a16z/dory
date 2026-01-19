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
use crate::mode::Mode;
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
/// - `rng`: Random number generator for sampling blinds (ZK mode only)
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
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, name = "create_evaluation_proof")]
pub fn create_evaluation_proof<F, E, M1, M2, T, P, Mo, R>(
    polynomial: &P,
    point: &[F],
    row_commitments: Option<Vec<E::G1>>,
    nu: usize,
    sigma: usize,
    setup: &ProverSetup<E>,
    transcript: &mut T,
    rng: &mut R,
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
    Mo: Mode,
    R: rand_core::RngCore,
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

    // Sample VMV blinds (zero in Transparent mode, random in ZK mode)
    let r_c: F = Mo::sample(rng);
    let r_d2: F = Mo::sample(rng);
    let r_e1: F = Mo::sample(rng);
    let r_e2: F = Mo::sample(rng);

    // Γ2,fin = g2_vec[0] (commitment base, distinct from H2 = h2 for blinding)
    let g2_fin = &setup.g2_vec[0];

    // C = e(⟨row_commitments, v_vec⟩, Γ2,fin) + r_c·HT
    let t_vec_v = M1::msm(&padded_row_commitments, &v_vec);
    let c_raw = E::pair(&t_vec_v, g2_fin);
    let c = Mo::mask(c_raw, &setup.ht, &r_c);

    // D₂ = e(⟨Γ₁[sigma], v_vec⟩, Γ2,fin) + r_d2·HT
    let g1_bases_at_sigma = &setup.g1_vec[..1 << sigma];
    let gamma1_v = M1::msm(g1_bases_at_sigma, &v_vec);
    let d2_raw = E::pair(&gamma1_v, g2_fin);
    let d2 = Mo::mask(d2_raw, &setup.ht, &r_d2);

    // E₁ = ⟨row_commitments, left_vec⟩ + r_e1·H₁
    let e1_raw = M1::msm(&row_commitments, &left_vec);
    let e1 = Mo::mask(e1_raw, &setup.h1, &r_e1);

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

    // v₂ = v_vec · Γ₂,fin (each scalar scales Γ2,fin = g2_vec[0])
    let v2 = {
        let _span =
            tracing::span!(tracing::Level::DEBUG, "fixed_base_vector_scalar_mul_g2_fin").entered();
        M2::fixed_base_vector_scalar_mul(g2_fin, &v_vec)
    };

    let mut padded_right_vec = right_vec.clone();
    let mut padded_left_vec = left_vec.clone();
    if nu < sigma {
        padded_right_vec.resize(1 << sigma, F::zero());
        padded_left_vec.resize(1 << sigma, F::zero());
    }

    // Create prover state with initial blinds from VMV
    let mut prover_state: DoryProverState<'_, E, Mo> = DoryProverState::new_with_blinds(
        padded_row_commitments, // v1 = T_vec_prime (row commitments, padded)
        v2,                     // v2 = v_vec · g_fin
        Some(v_vec),            // v2_scalars for first-round MSM+pair optimization
        padded_right_vec,       // s1 = right_vec (padded)
        padded_left_vec,        // s2 = left_vec (padded)
        setup,
        r_c,  // Initial r_c from VMV
        r_d2, // Initial r_d2 from VMV
        r_e1, // Initial r_e1 from VMV
        r_e2, // Initial r_e2 from VMV
    );
    drop(_span_init);

    let num_rounds = nu.max(sigma);
    let mut first_messages = Vec::with_capacity(num_rounds);
    let mut second_messages = Vec::with_capacity(num_rounds);

    for _round in 0..num_rounds {
        let (first_msg, r_d1_l, r_d1_r, r_d2_l, r_d2_r) =
            prover_state.compute_first_message::<M1, M2, R>(rng);

        transcript.append_serde(b"d1_left", &first_msg.d1_left);
        transcript.append_serde(b"d1_right", &first_msg.d1_right);
        transcript.append_serde(b"d2_left", &first_msg.d2_left);
        transcript.append_serde(b"d2_right", &first_msg.d2_right);
        transcript.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript.append_serde(b"e2_beta", &first_msg.e2_beta);

        let beta = transcript.challenge_scalar(b"beta");
        // apply_first_challenge uses accumulated blinds (self.r_d1, self.r_d2)
        prover_state.apply_first_challenge::<M1, M2>(&beta);

        first_messages.push(first_msg);

        let (second_msg, r_c_plus, r_c_minus, r_e1_plus, r_e1_minus, r_e2_plus, r_e2_minus) =
            prover_state.compute_second_message::<M1, M2, R>(rng);

        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);

        let alpha = transcript.challenge_scalar(b"alpha");
        // apply_second_challenge folds message blinds into accumulated blinds
        prover_state.apply_second_challenge::<M1, M2>(
            &alpha, r_d1_l, r_d1_r, r_d2_l, r_d2_r, r_c_plus, r_c_minus, r_e1_plus, r_e1_minus,
            r_e2_plus, r_e2_minus,
        );

        second_messages.push(second_msg);
    }

    let gamma = transcript.challenge_scalar(b"gamma");

    // In ZK mode, generate Σ-protocol proof BEFORE compute_final_message
    // because compute_final_message modifies r_c but the Σ-protocol needs
    // the pre-fold-scalars blinds.
    #[cfg(feature = "zk")]
    let scalar_product_proof =
        if std::any::TypeId::of::<Mo>() == std::any::TypeId::of::<crate::mode::ZK>() {
            // scalar_product_proof appends P1, P2, Q, R to transcript and derives challenge c
            Some(prover_state.scalar_product_proof_internal(transcript, rng))
        } else {
            None
        };
    #[cfg(not(feature = "zk"))]
    let _ = rng; // suppress unused warning when zk feature is disabled

    let final_message = prover_state.compute_final_message::<M1, M2>(&gamma);

    transcript.append_serde(b"final_e1", &final_message.e1);
    transcript.append_serde(b"final_e2", &final_message.e2);

    let _d = transcript.challenge_scalar(b"d");

    Ok(DoryProof {
        vmv_message,
        first_messages,
        second_messages,
        final_message,
        #[cfg(feature = "zk")]
        scalar_product_proof,
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
///
/// # Panics
/// May panic in ZK mode if internal state is inconsistent (should not occur in normal use).
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

    // # NOTE: The VMV check `vmv_message.d2 == e(vmv_message.e1, Γ2,fin)` is deferred
    // to verify_final where it's batched with other pairings using random linear
    // combination with challenge `d`. See verify_final documentation for details.

    // E2 = y · Γ2,fin where Γ2,fin = g2_0 (distinct from H2 = h2 for blinding)
    let e2 = setup.g2_0.scale(&evaluation);

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

    // In ZK mode, append Σ-protocol values and derive c BEFORE appending final message
    // (must match prover's transcript order)
    #[cfg(feature = "zk")]
    let zk_challenge_c = if let Some(ref sigma_proof) = proof.scalar_product_proof {
        transcript.append_serde(b"sigma_p1", &sigma_proof.p1);
        transcript.append_serde(b"sigma_p2", &sigma_proof.p2);
        transcript.append_serde(b"sigma_q", &sigma_proof.q);
        transcript.append_serde(b"sigma_r", &sigma_proof.r);
        Some(transcript.challenge_scalar(b"sigma_c"))
    } else {
        None
    };

    transcript.append_serde(b"final_e1", &proof.final_message.e1);
    transcript.append_serde(b"final_e2", &proof.final_message.e2);

    let d = transcript.challenge_scalar(b"d");

    // Use verify_final_zk when scalar_product_proof is present
    #[cfg(feature = "zk")]
    if let Some(ref sigma_proof) = proof.scalar_product_proof {
        let c = zk_challenge_c.expect("c should be derived when scalar_product_proof is present");
        return verifier_state.verify_final_zk_with_challenge(sigma_proof, &c, &d);
    }

    verifier_state.verify_final(&proof.final_message, &gamma, &d)
}

/// Create a zero-knowledge evaluation proof that hides the evaluation y
///
/// Unlike `create_evaluation_proof`, this function produces a proof where
/// the evaluation y is NOT revealed. Instead, the proof contains:
/// - `y_com`: A commitment to y that the verifier can use
/// - Sigma proofs that prove consistency without revealing y
///
/// # Returns
/// A tuple of (ZkDoryProof, y_com) where y_com is the commitment to the evaluation
/// that can be given to the verifier.
///
/// # Errors
/// Returns `DoryError` if dimensions are invalid or proof generation fails.
#[cfg(feature = "zk")]
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, name = "create_zk_evaluation_proof")]
pub fn create_zk_evaluation_proof<F, E, M1, M2, T, P, R>(
    polynomial: &P,
    point: &[F],
    row_commitments: Option<Vec<E::G1>>,
    nu: usize,
    sigma: usize,
    setup: &ProverSetup<E>,
    transcript: &mut T,
    rng: &mut R,
) -> Result<(crate::proof::ZkDoryProof<E::G1, E::G2, F, E::GT>, E::G1), DoryError>
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
    R: rand_core::RngCore,
{
    use crate::messages::ZkVMVMessage;
    use crate::mode::ZK;
    use crate::proof::ZkDoryProof;
    use crate::reduce_and_fold::{generate_sigma1_proof, generate_sigma2_proof};

    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension {
            expected: nu + sigma,
            actual: point.len(),
        });
    }

    if nu > sigma {
        return Err(DoryError::InvalidSize {
            expected: sigma,
            actual: nu,
        });
    }

    // Compute row commitments if not provided
    let row_comms = match row_commitments {
        Some(comms) => comms,
        None => {
            let (_commitment, rc) = polynomial.commit::<E, M1>(nu, sigma, setup)?;
            rc
        }
    };

    // Compute evaluation vectors and v_vec
    let (left_vec, right_vec) = polynomial.compute_evaluation_vectors(point, nu, sigma);
    let v_vec = polynomial.vector_matrix_product(&left_vec, nu, sigma);

    // Pad row commitments for non-square matrices
    let mut padded_row_commitments = row_comms.clone();
    if nu < sigma {
        padded_row_commitments.resize(1 << sigma, E::G1::identity());
    }

    // Compute y = polynomial(point)
    let y = polynomial.evaluate(point);

    // Compute v2 = v_vec scaled by Γ2,fin
    let g2_fin = &setup.g2_vec[0];
    let v2 = M2::fixed_base_vector_scalar_mul(g2_fin, &v_vec);

    // Pad vectors for non-square matrices
    let mut padded_right_vec = right_vec.clone();
    let mut padded_left_vec = left_vec.clone();
    if nu < sigma {
        padded_right_vec.resize(1 << sigma, F::zero());
        padded_left_vec.resize(1 << sigma, F::zero());
    }

    // Sample blinds for VMV message
    let r_c: F = ZK::sample(rng);
    let r_d2: F = ZK::sample(rng);
    let r_e1: F = ZK::sample(rng);
    let r_e2: F = ZK::sample(rng);
    let r_y: F = ZK::sample(rng);

    // Compute VMV message components with masking
    // C = e(⟨T_vec', v_vec⟩, Γ2,fin) + r_c·HT
    let t_dot_v = M1::msm(&padded_row_commitments, &v_vec);
    let c_raw = E::pair(&t_dot_v, g2_fin);
    let c = ZK::mask(c_raw, &setup.ht, &r_c);

    // D2 = e(⟨Γ1, v_vec⟩, Γ2,fin) + r_d2·HT
    let g1_bases_at_sigma = &setup.g1_vec[..1 << sigma];
    let g1_dot_v = M1::msm(g1_bases_at_sigma, &v_vec);
    let d2_raw = E::pair(&g1_dot_v, g2_fin);
    let d2 = ZK::mask(d2_raw, &setup.ht, &r_d2);

    // E1 = ⟨T_vec', L_vec⟩ + r_e1·H1
    let e1_raw = M1::msm(&row_comms, &left_vec);
    let e1 = ZK::mask(e1_raw, &setup.h1, &r_e1);

    // E2 = y·Γ2,fin + r_e2·H2 (prover computes, not verifier!)
    let e2_raw = g2_fin.scale(&y);
    let e2 = ZK::mask(e2_raw, &setup.h2, &r_e2);

    // y_com = y·Γ1,fin + r_y·H1 (commitment to evaluation)
    let y_com = setup.g1_vec[0].scale(&y) + setup.h1.scale(&r_y);

    let zk_vmv_message = ZkVMVMessage {
        c,
        d2,
        e1,
        e2,
        y_com,
    };

    // Append VMV message to transcript
    transcript.append_serde(b"vmv_c", &zk_vmv_message.c);
    transcript.append_serde(b"vmv_d2", &zk_vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &zk_vmv_message.e1);
    transcript.append_serde(b"vmv_e2", &zk_vmv_message.e2);
    transcript.append_serde(b"vmv_y_com", &zk_vmv_message.y_com);

    // Generate Sigma1 proof (proves y_com and E2 commit to same y)
    let sigma1_proof = generate_sigma1_proof::<E, T, R>(&y, &r_e2, &r_y, setup, transcript, rng);

    // Generate Sigma2 proof (proves VMV relation: e(E1, Γ2,fin) - D2 = e(H1, t1·Γ2,fin + t2·H2))
    // t1 = r_e1 (since we're using rv=0 for row commitment blinds in this simplified version)
    // t2 = -r_d2
    let t1 = r_e1;
    let t2 = -r_d2;
    let sigma2_proof = generate_sigma2_proof::<E, T, R>(&t1, &t2, setup, transcript, rng);

    // Initialize prover state
    let mut prover_state: DoryProverState<'_, E, ZK> = DoryProverState::new_with_blinds(
        padded_row_commitments,
        v2,
        Some(v_vec),
        padded_right_vec,
        padded_left_vec,
        setup,
        r_c,
        r_d2,
        r_e1,
        r_e2,
    );

    let num_rounds = nu.max(sigma);
    let mut first_messages = Vec::with_capacity(num_rounds);
    let mut second_messages = Vec::with_capacity(num_rounds);

    // Run reduce-and-fold rounds
    for _round in 0..num_rounds {
        let (first_msg, r_d1_l, r_d1_r, r_d2_l, r_d2_r) =
            prover_state.compute_first_message::<M1, M2, R>(rng);

        transcript.append_serde(b"d1_left", &first_msg.d1_left);
        transcript.append_serde(b"d1_right", &first_msg.d1_right);
        transcript.append_serde(b"d2_left", &first_msg.d2_left);
        transcript.append_serde(b"d2_right", &first_msg.d2_right);
        transcript.append_serde(b"e1_beta", &first_msg.e1_beta);
        transcript.append_serde(b"e2_beta", &first_msg.e2_beta);

        let beta = transcript.challenge_scalar(b"beta");
        prover_state.apply_first_challenge::<M1, M2>(&beta);

        first_messages.push(first_msg);

        let (second_msg, r_c_plus, r_c_minus, r_e1_plus, r_e1_minus, r_e2_plus, r_e2_minus) =
            prover_state.compute_second_message::<M1, M2, R>(rng);

        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);

        let alpha = transcript.challenge_scalar(b"alpha");
        prover_state.apply_second_challenge::<M1, M2>(
            &alpha, r_d1_l, r_d1_r, r_d2_l, r_d2_r, r_c_plus, r_c_minus, r_e1_plus, r_e1_minus,
            r_e2_plus, r_e2_minus,
        );

        second_messages.push(second_msg);
    }

    let gamma = transcript.challenge_scalar(b"gamma");

    // Generate scalar product proof before compute_final_message modifies r_c
    let scalar_product_proof = prover_state.scalar_product_proof_internal(transcript, rng);

    let final_message = prover_state.compute_final_message::<M1, M2>(&gamma);

    transcript.append_serde(b"final_e1", &final_message.e1);
    transcript.append_serde(b"final_e2", &final_message.e2);

    let _d = transcript.challenge_scalar(b"d");

    Ok((
        ZkDoryProof {
            vmv_message: zk_vmv_message,
            first_messages,
            second_messages,
            final_message,
            sigma1_proof,
            sigma2_proof,
            scalar_product_proof,
            nu,
            sigma,
        },
        y_com,
    ))
}

/// Verify a zero-knowledge evaluation proof without knowing y
///
/// Unlike `verify_evaluation_proof`, this function does NOT take the evaluation y.
/// Instead, it verifies that:
/// 1. The prover knows y such that polynomial(point) = y
/// 2. y_com is a valid commitment to y
///
/// # Parameters
/// - `commitment`: Polynomial commitment (Tier 2)
/// - `y_com`: Commitment to the evaluation (from proof generation)
/// - `point`: Evaluation point
/// - `proof`: ZK evaluation proof
/// - `setup`: Verifier setup
/// - `transcript`: Fiat-Shamir transcript
///
/// # Errors
/// Returns `DoryError::InvalidProof` if verification fails, or other variants
/// if the input parameters are incorrect.
#[cfg(feature = "zk")]
#[tracing::instrument(skip_all, name = "verify_zk_evaluation_proof")]
pub fn verify_zk_evaluation_proof<F, E, M1, M2, T>(
    commitment: E::GT,
    y_com: E::G1,
    point: &[F],
    proof: &crate::proof::ZkDoryProof<E::G1, E::G2, F, E::GT>,
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
    use crate::reduce_and_fold::{verify_sigma1_proof, verify_sigma2_proof};

    let nu = proof.nu;
    let sigma = proof.sigma;

    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension {
            expected: nu + sigma,
            actual: point.len(),
        });
    }

    let vmv_message = &proof.vmv_message;

    // Append VMV message to transcript (same order as prover)
    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);
    transcript.append_serde(b"vmv_e2", &vmv_message.e2);
    transcript.append_serde(b"vmv_y_com", &vmv_message.y_com);

    // Verify y_com from proof matches provided y_com
    if vmv_message.y_com != y_com {
        return Err(DoryError::InvalidProof);
    }

    // Verify Sigma1 proof (proves E2 and y_com commit to same y)
    verify_sigma1_proof::<E, T>(
        &vmv_message.e2,
        &y_com,
        &proof.sigma1_proof,
        &setup,
        transcript,
    )?;

    // Verify Sigma2 proof (proves VMV relation holds with blinds)
    verify_sigma2_proof::<E, T>(
        &vmv_message.e1,
        &vmv_message.d2,
        &proof.sigma2_proof,
        &setup,
        transcript,
    )?;

    // Use E2 from prover's message (not computed from y!)
    let e2 = vmv_message.e2;

    // Folded-scalar accumulation
    let num_rounds = sigma;
    let col_coords = &point[..sigma];
    let s1_coords: Vec<F> = col_coords.to_vec();
    let mut s2_coords: Vec<F> = vec![F::zero(); sigma];
    let row_coords = &point[sigma..sigma + nu];
    s2_coords[..nu].copy_from_slice(&row_coords[..nu]);

    let mut verifier_state = DoryVerifierState::new(
        vmv_message.c,
        commitment,
        vmv_message.d2,
        vmv_message.e1,
        e2,
        s1_coords,
        s2_coords,
        num_rounds,
        setup.clone(),
    );

    // Process reduce rounds
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

    let _gamma = transcript.challenge_scalar(b"gamma");

    // Derive challenge c from scalar product proof (same as prover)
    transcript.append_serde(b"sigma_p1", &proof.scalar_product_proof.p1);
    transcript.append_serde(b"sigma_p2", &proof.scalar_product_proof.p2);
    transcript.append_serde(b"sigma_q", &proof.scalar_product_proof.q);
    transcript.append_serde(b"sigma_r", &proof.scalar_product_proof.r);
    let c = transcript.challenge_scalar(b"sigma_c");

    transcript.append_serde(b"final_e1", &proof.final_message.e1);
    transcript.append_serde(b"final_e2", &proof.final_message.e2);

    let d = transcript.challenge_scalar(b"d");

    // Verify final with ZK scalar product proof
    verifier_state.verify_final_zk_with_challenge(&proof.scalar_product_proof, &c, &d)
}
