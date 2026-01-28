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

#[cfg(feature = "zk")]
use crate::mode::ZK;

/// Create evaluation proof for a polynomial at a point
///
/// Implements Eval-VMV-RE protocol from Dory Section 5.
/// The protocol proves that polynomial(point) = evaluation via the VMV relation:
/// evaluation = L^T × M × R
///
/// # Mode Parameter
/// - `Transparent`: Non-hiding proof, evaluation revealed to verifier
/// - `ZK` (requires `zk` feature): Zero-knowledge proof, evaluation hidden
///
/// # Algorithm
/// 1. Compute or use provided row commitments (Tier 1 commitment)
/// 2. Split evaluation point into left and right vectors
/// 3. Compute v_vec (column evaluations)
/// 4. Create VMV message (C, D2, E1) with mode-specific blinding
/// 5. In ZK mode: compute y_com, E2, and sigma proofs
/// 6. Run max(nu, sigma) rounds of reduce-and-fold
/// 7. Compute final scalar product message
///
/// # Returns
/// Complete Dory proof. In ZK mode, proof contains y_com for verifier.
///
/// # Errors
/// Returns error if dimensions are invalid (nu > sigma) or protocol fails
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
) -> Result<(DoryProof<E::G1, E::G2, E::GT>, Option<F>), DoryError>
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

    if nu > sigma {
        return Err(DoryError::InvalidSize {
            expected: sigma,
            actual: nu,
        });
    }

    let row_commitments = match row_commitments {
        Some(rc) => rc,
        None => {
            let (_commitment, rc) = polynomial.commit::<E, M1>(nu, sigma, setup)?;
            rc
        }
    };

    let (left_vec, right_vec) = polynomial.compute_evaluation_vectors(point, nu, sigma);
    let v_vec = polynomial.vector_matrix_product(&left_vec, nu, sigma);

    let mut padded_row_commitments = row_commitments.clone();
    if nu < sigma {
        padded_row_commitments.resize(1 << sigma, E::G1::identity());
    }

    // Sample VMV blinds (zero in Transparent mode, random in ZK mode)
    let r_c: F = Mo::sample(rng);
    let r_d2: F = Mo::sample(rng);
    let r_e1: F = Mo::sample(rng);
    let r_e2: F = Mo::sample(rng);

    let g2_fin = &setup.g2_vec[0];

    // C = e(⟨row_commitments, v_vec⟩, Γ2,fin) + r_c·HT
    let t_vec_v = M1::msm(&padded_row_commitments, &v_vec);
    let c = Mo::mask(E::pair(&t_vec_v, g2_fin), &setup.ht, &r_c);

    // D₂ = e(⟨Γ₁[sigma], v_vec⟩, Γ2,fin) + r_d2·HT
    let g1_bases = &setup.g1_vec[..1 << sigma];
    let d2 = Mo::mask(
        E::pair(&M1::msm(g1_bases, &v_vec), g2_fin),
        &setup.ht,
        &r_d2,
    );

    // E₁ = ⟨row_commitments, left_vec⟩ + r_e1·H₁
    let e1 = Mo::mask(M1::msm(&row_commitments, &left_vec), &setup.h1, &r_e1);

    let vmv_message = VMVMessage { c, d2, e1 };

    transcript.append_serde(b"vmv_c", &vmv_message.c);
    transcript.append_serde(b"vmv_d2", &vmv_message.d2);
    transcript.append_serde(b"vmv_e1", &vmv_message.e1);

    // ZK mode: compute y, y_com, E2, and sigma proofs
    #[cfg(feature = "zk")]
    let (zk_e2, zk_y_com, zk_sigma1, zk_sigma2, zk_y_blinding) =
        if std::any::TypeId::of::<Mo>() == std::any::TypeId::of::<ZK>() {
            use crate::reduce_and_fold::{generate_sigma1_proof, generate_sigma2_proof};

            let y = polynomial.evaluate(point);
            let r_y: F = Mo::sample(rng);

            // E2 = y·Γ2,fin + r_e2·H2
            let e2 = Mo::mask(g2_fin.scale(&y), &setup.h2, &r_e2);
            // y_com = y·Γ1,fin + r_y·H1
            let y_com = setup.g1_vec[0].scale(&y) + setup.h1.scale(&r_y);

            transcript.append_serde(b"vmv_e2", &e2);
            transcript.append_serde(b"vmv_y_com", &y_com);

            let sigma1 = generate_sigma1_proof::<E, T, R>(&y, &r_e2, &r_y, setup, transcript, rng);
            let t1 = r_e1;
            let t2 = -r_d2;
            let sigma2 = generate_sigma2_proof::<E, T, R>(&t1, &t2, setup, transcript, rng);

            (Some(e2), Some(y_com), Some(sigma1), Some(sigma2), Some(r_y))
        } else {
            (None, None, None, None, None)
        };

    // v₂ = v_vec · Γ₂,fin
    let v2 = M2::fixed_base_vector_scalar_mul(g2_fin, &v_vec);

    let mut padded_right_vec = right_vec;
    let mut padded_left_vec = left_vec;
    if nu < sigma {
        padded_right_vec.resize(1 << sigma, F::zero());
        padded_left_vec.resize(1 << sigma, F::zero());
    }

    let mut prover_state: DoryProverState<'_, E, Mo> = DoryProverState::new_with_blinds(
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

    for _round in 0..num_rounds {
        let (first_msg, d1_blinds, d2_blinds) =
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

        let (second_msg, c_blinds, e1_blinds, e2_blinds) =
            prover_state.compute_second_message::<M1, M2, R>(rng);

        transcript.append_serde(b"c_plus", &second_msg.c_plus);
        transcript.append_serde(b"c_minus", &second_msg.c_minus);
        transcript.append_serde(b"e1_plus", &second_msg.e1_plus);
        transcript.append_serde(b"e1_minus", &second_msg.e1_minus);
        transcript.append_serde(b"e2_plus", &second_msg.e2_plus);
        transcript.append_serde(b"e2_minus", &second_msg.e2_minus);

        let alpha = transcript.challenge_scalar(b"alpha");
        prover_state.apply_second_challenge::<M1, M2>(
            &alpha, d1_blinds, d2_blinds, c_blinds, e1_blinds, e2_blinds,
        );
        second_messages.push(second_msg);
    }

    let gamma = transcript.challenge_scalar(b"gamma");

    // Generate scalar product proof in ZK mode
    #[cfg(feature = "zk")]
    let scalar_product_proof = if std::any::TypeId::of::<Mo>() == std::any::TypeId::of::<ZK>() {
        Some(prover_state.scalar_product_proof_internal(transcript, rng))
    } else {
        None
    };

    let final_message = prover_state.compute_final_message::<M1, M2>(&gamma);

    transcript.append_serde(b"final_e1", &final_message.e1);
    transcript.append_serde(b"final_e2", &final_message.e2);
    let _d = transcript.challenge_scalar(b"d");

    let proof = DoryProof {
        vmv_message,
        first_messages,
        second_messages,
        final_message,
        nu,
        sigma,
        #[cfg(feature = "zk")]
        e2: zk_e2,
        #[cfg(feature = "zk")]
        y_com: zk_y_com,
        #[cfg(feature = "zk")]
        sigma1_proof: zk_sigma1,
        #[cfg(feature = "zk")]
        sigma2_proof: zk_sigma2,
        #[cfg(feature = "zk")]
        scalar_product_proof,
    };

    #[cfg(feature = "zk")]
    return Ok((proof, zk_y_blinding));

    #[cfg(not(feature = "zk"))]
    Ok((proof, None))
}

/// Verify an evaluation proof
///
/// Verifies that a committed polynomial evaluates to the claimed value at the given point.
/// Works with both square and non-square matrix layouts (nu ≤ sigma).
///
/// # Verification Modes
/// - **Transparent**: Takes evaluation `y` as input, computes E2 = y·Γ2,fin
/// - **ZK**: Takes `y_com` (from proof.y_com), uses E2 from proof, verifies sigma proofs
///
/// # Parameters
/// - `commitment`: Polynomial commitment (in GT)
/// - `evaluation`: Claimed evaluation (transparent) or None (ZK uses proof.y_com)
/// - `point`: Evaluation point (length must equal proof.nu + proof.sigma)
/// - `proof`: Evaluation proof to verify
/// - `setup`: Verifier setup
/// - `transcript`: Fiat-Shamir transcript for challenge generation
///
/// # Errors
/// Returns `DoryError::InvalidProof` if verification fails.
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

    // Determine E2 based on proof mode (ZK vs transparent)
    #[cfg(feature = "zk")]
    let (e2, is_zk) = if let (Some(proof_e2), Some(y_com)) = (&proof.e2, &proof.y_com) {
        use crate::reduce_and_fold::{verify_sigma1_proof, verify_sigma2_proof};

        transcript.append_serde(b"vmv_e2", proof_e2);
        transcript.append_serde(b"vmv_y_com", y_com);

        // Verify sigma proofs
        if let Some(ref sigma1) = proof.sigma1_proof {
            verify_sigma1_proof::<E, T>(proof_e2, y_com, sigma1, &setup, transcript)?;
        }
        if let Some(ref sigma2) = proof.sigma2_proof {
            verify_sigma2_proof::<E, T>(
                &vmv_message.e1,
                &vmv_message.d2,
                sigma2,
                &setup,
                transcript,
            )?;
        }

        (*proof_e2, true)
    } else {
        (setup.g2_0.scale(&evaluation), false)
    };

    #[cfg(not(feature = "zk"))]
    let (e2, _is_zk) = (setup.g2_0.scale(&evaluation), false);

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

    // ZK mode: verify with scalar product proof
    #[cfg(feature = "zk")]
    if is_zk {
        if let Some(ref sigma_proof) = proof.scalar_product_proof {
            transcript.append_serde(b"sigma_p1", &sigma_proof.p1);
            transcript.append_serde(b"sigma_p2", &sigma_proof.p2);
            transcript.append_serde(b"sigma_q", &sigma_proof.q);
            transcript.append_serde(b"sigma_r", &sigma_proof.r);
            let c = transcript.challenge_scalar(b"sigma_c");

            transcript.append_serde(b"final_e1", &proof.final_message.e1);
            transcript.append_serde(b"final_e2", &proof.final_message.e2);
            let d = transcript.challenge_scalar(b"d");

            return verifier_state.verify_final_zk_with_challenge(sigma_proof, &c, &d);
        }
    }

    // Transparent mode
    transcript.append_serde(b"final_e1", &proof.final_message.e1);
    transcript.append_serde(b"final_e2", &proof.final_message.e2);
    let d = transcript.challenge_scalar(b"d");

    let _ = gamma; // Used in verify_final
    verifier_state.verify_final(&proof.final_message, &gamma, &d)
}
