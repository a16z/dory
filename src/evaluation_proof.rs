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
use crate::mode::Mode;
use crate::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::primitives::poly::MultilinearLagrange;
use crate::primitives::transcript::ProverTranscript;
use crate::reduce_and_fold::{DoryProverState, DoryVerifierState};
use crate::setup::{ProverSetup, VerifierSetup};

/// Create evaluation proof for a polynomial at a point
///
/// Implements Eval-VMV-RE protocol from Dory Section 5.
/// The protocol proves that polynomial(point) = evaluation via the VMV relation:
/// evaluation = L^T × M × R
///
/// All proof elements are absorbed into the transcript. The transcript's NARG
/// string IS the proof — no separate proof struct is returned.
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
/// - `commit_blind`: GT-level blinding scalar from `commit()`. Ignored when
///   `row_commitments` is `None` (the blind is computed internally in that case).
/// - `nu`: Log₂ of number of rows (constraint: nu ≤ sigma)
/// - `sigma`: Log₂ of number of columns
/// - `setup`: Prover setup
/// - `transcript`: Fiat-Shamir transcript for challenge generation
///
/// # Returns
/// In ZK mode, returns the blinding scalar `r_y`; in transparent mode, `None`.
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
pub fn create_evaluation_proof<F, E, M1, M2, T, P, Mo>(
    polynomial: &P,
    point: &[F],
    row_commitments: Option<Vec<E::G1>>,
    commit_blind: F,
    nu: usize,
    sigma: usize,
    setup: &ProverSetup<E>,
    transcript: &mut T,
) -> Result<Option<F>, DoryError>
where
    F: Field,
    E: PairingCurve,
    E::G1: Group<Scalar = F>,
    E::G2: Group<Scalar = F>,
    E::GT: Group<Scalar = F>,
    M1: DoryRoutines<E::G1>,
    M2: DoryRoutines<E::G2>,
    T: ProverTranscript<E>,
    P: MultilinearLagrange<F>,
    Mo: Mode,
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

    // Public inputs: bind nu and sigma to the sponge state
    transcript.public_u32(nu as u32);
    transcript.public_u32(sigma as u32);

    let (row_commitments, commit_blind) = match row_commitments {
        Some(rc) => (rc, commit_blind),
        None => {
            let (_, rc, blind) = polynomial.commit::<E, Mo, M1>(nu, sigma, setup)?;
            (rc, blind)
        }
    };

    let (left_vec, right_vec) = polynomial.compute_evaluation_vectors(point, nu, sigma);
    let v_vec = polynomial.vector_matrix_product(&left_vec, nu, sigma);

    let mut padded_row_commitments = row_commitments.clone();
    if nu < sigma {
        padded_row_commitments.resize(1 << sigma, E::G1::identity());
    }

    // Sample VMV blinds (zero in Transparent, random in ZK)
    let (r_c, r_d2, r_e1, r_e2): (F, F, F, F) =
        (Mo::sample(), Mo::sample(), Mo::sample(), Mo::sample());

    let g2_fin = &setup.g2_vec[0];

    // C = e(⟨row_commitments, v_vec⟩, Γ2,fin) + r_c·HT
    let t_vec_v = M1::msm(&padded_row_commitments, &v_vec);
    let c = Mo::mask(E::pair(&t_vec_v, g2_fin), &setup.ht, &r_c);

    // D₂ = e(⟨Γ₁[sigma], v_vec⟩, Γ2,fin) + r_d2·HT
    let d2 = Mo::mask(
        E::pair(&M1::msm(&setup.g1_vec[..1 << sigma], &v_vec), g2_fin),
        &setup.ht,
        &r_d2,
    );

    // E₁ = ⟨row_commitments, left_vec⟩ + r_e1·H₁
    let e1 = Mo::mask(M1::msm(&row_commitments, &left_vec), &setup.h1, &r_e1);

    // Absorb VMV message
    transcript.absorb_gt(&c);
    transcript.absorb_gt(&d2);
    transcript.absorb_g1(&e1);

    #[cfg(feature = "zk")]
    let zk_r_y = if Mo::BLINDING {
        use crate::reduce_and_fold::{generate_sigma1_proof, generate_sigma2_proof};
        let y = polynomial.evaluate(point);
        let r_y: F = Mo::sample();
        let e2 = Mo::mask(g2_fin.scale(&y), &setup.h2, &r_e2);
        let y_com = setup.g1_vec[0].scale(&y) + setup.h1.scale(&r_y);
        transcript.absorb_g2(&e2);
        transcript.absorb_g1(&y_com);
        generate_sigma1_proof::<E, T>(&y, &r_e2, &r_y, setup, transcript);
        generate_sigma2_proof::<E, T>(&r_e1, &-r_d2, setup, transcript);
        Some(r_y)
    } else {
        None
    };

    // v₂ = v_vec · Γ₂,fin (each scalar scales g_fin)
    let v2 = M2::fixed_base_vector_scalar_mul(g2_fin, &v_vec);

    let mut padded_right_vec = right_vec.clone();
    let mut padded_left_vec = left_vec.clone();
    if nu < sigma {
        padded_right_vec.resize(1 << sigma, F::zero());
        padded_left_vec.resize(1 << sigma, F::zero());
    }

    let mut prover_state: DoryProverState<'_, E, Mo> = DoryProverState::new(
        padded_row_commitments, // v1 = T_vec_prime (row commitments, padded)
        v2,                     // v2 = v_vec · g_fin
        Some(v_vec),            // v2_scalars for first-round MSM+pair optimization
        padded_right_vec,       // s1 = right_vec (padded)
        padded_left_vec,        // s2 = left_vec (padded)
        setup,
    );
    prover_state.set_initial_blinds(commit_blind, r_c, r_d2, r_e1, r_e2);

    let num_rounds = sigma;

    for _round in 0..num_rounds {
        let first_msg = prover_state.compute_first_message::<M1, M2>();

        transcript.absorb_gt(&first_msg.d1_left);
        transcript.absorb_gt(&first_msg.d1_right);
        transcript.absorb_gt(&first_msg.d2_left);
        transcript.absorb_gt(&first_msg.d2_right);
        transcript.absorb_g1(&first_msg.e1_beta);
        transcript.absorb_g2(&first_msg.e2_beta);

        let beta = transcript.squeeze_scalar();
        prover_state.apply_first_challenge::<M1, M2>(&beta);

        let second_msg = prover_state.compute_second_message::<M1, M2>();

        transcript.absorb_gt(&second_msg.c_plus);
        transcript.absorb_gt(&second_msg.c_minus);
        transcript.absorb_g1(&second_msg.e1_plus);
        transcript.absorb_g1(&second_msg.e1_minus);
        transcript.absorb_g2(&second_msg.e2_plus);
        transcript.absorb_g2(&second_msg.e2_minus);

        let alpha = transcript.squeeze_scalar();
        prover_state.apply_second_challenge::<M1, M2>(&alpha);
    }

    let gamma = transcript.squeeze_scalar();

    #[cfg(feature = "zk")]
    if Mo::BLINDING {
        prover_state.scalar_product_proof(transcript);
    }

    let final_message = prover_state.compute_final_message::<M1, M2>(&gamma);

    transcript.absorb_g1(&final_message.e1);
    transcript.absorb_g2(&final_message.e2);
    let _d = transcript.squeeze_scalar();

    #[cfg(feature = "zk")]
    return Ok(zk_r_y);
    #[cfg(not(feature = "zk"))]
    Ok(None)
}

/// Verify an evaluation proof
///
/// Verifies that a committed polynomial evaluates to the claimed value at the given point.
/// Works with both square and non-square matrix layouts (nu ≤ sigma).
///
/// Proof elements are read from the NARG transcript — no separate proof struct is needed.
///
/// # Algorithm
/// 1. Read VMV message from transcript
/// 2. Compute e2 = Γ2,fin * evaluation (or read from transcript in ZK mode)
/// 3. Initialize verifier state with commitment and VMV message
/// 4. Read reduce messages from transcript for max(nu, sigma) rounds
/// 5. Derive gamma and d challenges
/// 6. Verify final scalar product message
///
/// # Parameters
/// - `commitment`: Polynomial commitment (in GT) - can be a homomorphically combined commitment
/// - `evaluation`: Claimed evaluation result
/// - `point`: Evaluation point (length must equal nu + sigma)
/// - `nu`: Log₂ of number of rows
/// - `sigma`: Log₂ of number of columns
/// - `setup`: Verifier setup
/// - `transcript`: Fiat-Shamir verifier transcript (reads from NARG string)
///
/// # Returns
/// `Ok(())` if proof is valid, `Err(DoryError)` otherwise
///
/// # Errors
/// Returns `DoryError::InvalidProof` if verification fails, or other variants
/// if the input parameters are incorrect (e.g., point dimension mismatch).
#[tracing::instrument(skip_all, name = "verify_evaluation_proof")]
pub fn verify_evaluation_proof<F, E, M1, M2, T, Mo>(
    commitment: E::GT,
    evaluation: F,
    point: &[F],
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
    T: crate::primitives::transcript::VerifierTranscript<E>,
    Mo: Mode,
{
    if point.len() != nu + sigma {
        return Err(DoryError::InvalidPointDimension {
            expected: nu + sigma,
            actual: point.len(),
        });
    }

    // Public inputs: bind nu and sigma to the sponge state
    transcript.public_u32(nu as u32)?;
    transcript.public_u32(sigma as u32)?;

    // Read VMV message from transcript
    let vmv_c = transcript.read_gt()?;
    let vmv_d2 = transcript.read_gt()?;
    let vmv_e1 = transcript.read_g1()?;

    #[cfg(feature = "zk")]
    let e2 = if Mo::BLINDING {
        use crate::reduce_and_fold::{verify_sigma1_proof, verify_sigma2_proof};
        let pe2 = transcript.read_g2()?;
        let yc = transcript.read_g1()?;
        verify_sigma1_proof::<E, T>(&pe2, &yc, &setup, transcript)?;
        verify_sigma2_proof::<E, T>(&vmv_e1, &vmv_d2, &setup, transcript)?;
        pe2
    } else {
        setup.g2_0.scale(&evaluation)
    };
    #[cfg(not(feature = "zk"))]
    let e2 = setup.g2_0.scale(&evaluation);

    // num_rounds = sigma (we fold column dimensions).
    let num_rounds = sigma;

    // Bounds check: reject proofs that exceed setup capacity.
    let max_rounds = setup.max_log_n / 2;
    if num_rounds > max_rounds {
        return Err(DoryError::InvalidProof);
    }

    // s1 (right/prover): the σ column coordinates in natural order (LSB→MSB).
    let s1_coords: Vec<F> = point[..sigma].to_vec();
    // s2 (left/prover): the ν row coordinates in natural order, followed by zeros.
    let mut s2_coords: Vec<F> = vec![F::zero(); sigma];
    s2_coords[..nu].copy_from_slice(&point[sigma..sigma + nu]);

    let mut verifier_state = DoryVerifierState::new(
        vmv_c,      // c from VMV message
        commitment, // d1 = commitment
        vmv_d2,     // d2 from VMV message
        vmv_e1,     // e1 from VMV message
        e2,         // e2 computed from evaluation or read from transcript
        s1_coords,
        s2_coords,
        num_rounds,
        setup.clone(),
    );

    for _round in 0..num_rounds {
        // Read first reduce message from transcript
        let first_msg = crate::messages::FirstReduceMessage {
            d1_left: transcript.read_gt()?,
            d1_right: transcript.read_gt()?,
            d2_left: transcript.read_gt()?,
            d2_right: transcript.read_gt()?,
            e1_beta: transcript.read_g1()?,
            e2_beta: transcript.read_g2()?,
        };
        let beta = transcript.squeeze_scalar()?;

        // Read second reduce message from transcript
        let second_msg = crate::messages::SecondReduceMessage {
            c_plus: transcript.read_gt()?,
            c_minus: transcript.read_gt()?,
            e1_plus: transcript.read_g1()?,
            e1_minus: transcript.read_g1()?,
            e2_plus: transcript.read_g2()?,
            e2_minus: transcript.read_g2()?,
        };
        let alpha = transcript.squeeze_scalar()?;

        verifier_state.process_round(&first_msg, &second_msg, &alpha, &beta)?;
    }

    let gamma = transcript.squeeze_scalar()?;

    // In ZK mode: read scalar product proof from transcript before deriving d.
    #[cfg(feature = "zk")]
    let zk_data = if Mo::BLINDING {
        let p1 = transcript.read_gt()?;
        let p2 = transcript.read_gt()?;
        let q = transcript.read_gt()?;
        let r = transcript.read_gt()?;
        let sigma_c = transcript.squeeze_scalar()?;
        let sp_e1 = transcript.read_g1()?;
        let sp_e2 = transcript.read_g2()?;
        let r1 = transcript.read_field()?;
        let r2 = transcript.read_field()?;
        let r3 = transcript.read_field()?;
        let sp = crate::messages::ScalarProductProof {
            p1,
            p2,
            q,
            r,
            e1: sp_e1,
            e2: sp_e2,
            r1,
            r2,
            r3,
        };
        Some((sp, sigma_c))
    } else {
        None
    };

    // Read final message from transcript and derive d.
    let final_e1 = transcript.read_g1()?;
    let final_e2 = transcript.read_g2()?;
    let final_message = crate::messages::ScalarProductMessage {
        e1: final_e1,
        e2: final_e2,
    };
    let d = transcript.squeeze_scalar()?;

    #[cfg(feature = "zk")]
    let zk = zk_data.as_ref().map(|(sp, c)| (sp, c));
    #[cfg(not(feature = "zk"))]
    let zk: Option<(&crate::messages::ScalarProductProof<_, _, _, _>, _)> = None;

    verifier_state.verify_final(&final_message, &gamma, &d, zk)
}
