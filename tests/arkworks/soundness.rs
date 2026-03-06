//! Comprehensive soundness tests for Dory PCS
//!
//! With the spongefish NARG API, proofs are opaque byte arrays.
//! Soundness is tested by corrupting the proof bytes in various ways
//! and verifying that the verifier rejects them.

use super::*;
use ark_bn254::Fr;
use ark_ff::UniformRand;
use dory_pcs::backends::arkworks::{ArkFr, ArkGT};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, verify, Transparent};

#[allow(clippy::type_complexity)]
fn create_valid_proof(
    size: usize,
    nu: usize,
    sigma: usize,
) -> (
    ProverSetup<BN254>,
    VerifierSetup<BN254>,
    ArkworksPolynomial,
    Vec<ArkFr>,
    ArkGT,
    ArkFr,
    Vec<u8>,
) {
    let (prover_setup, verifier_setup) = test_setup_pair(nu + sigma + 2);
    let poly = random_polynomial(size);
    let point = random_point(nu + sigma);
    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover,
    )
    .unwrap();
    let evaluation = poly.evaluate(&point);
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    (
        prover_setup,
        verifier_setup,
        poly,
        point,
        tier_2,
        evaluation,
        proof_bytes,
    )
}

/// Helper: attempt verification with given proof bytes, including `check_eof()`.
fn try_verify(
    commitment: ArkGT,
    evaluation: ArkFr,
    point: &[ArkFr],
    nu: usize,
    sigma: usize,
    verifier_setup: VerifierSetup<BN254>,
    proof_bytes: &[u8],
) -> Result<(), dory_pcs::DoryError> {
    let mut verifier = test_verifier(sigma, proof_bytes);
    verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        commitment,
        evaluation,
        point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    )?;
    verifier
        .check_eof()
        .map_err(|e| dory_pcs::DoryError::SpongeVerification(format!("{e:?}")))
}

// ---------------------------------------------------------------------------
// 1. Wrong commitment
// ---------------------------------------------------------------------------

#[test]
fn test_soundness_wrong_commitment() {
    let nu = 4;
    let sigma = 4;
    let (prover_setup, verifier_setup, _, _, _, _, _) = create_valid_proof(256, nu, sigma);

    let poly1 = random_polynomial(256);
    let poly2 = random_polynomial(256);
    let point = random_point(nu + sigma);

    let (commitment1, _, _) = poly1
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let (_, tier_1_poly2, commit_blind2) = poly2
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly2,
        &point,
        tier_1_poly2,
        commit_blind2,
        nu,
        sigma,
        &prover_setup,
        &mut prover,
    )
    .unwrap();
    let evaluation = poly2.evaluate(&point);
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let result = try_verify(
        commitment1,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &proof_bytes,
    );

    assert!(
        result.is_err(),
        "Should fail when commitment doesn't match proof"
    );
}

// ---------------------------------------------------------------------------
// 2. Byte-level tampering: flip random bytes in proof
// ---------------------------------------------------------------------------

#[test]
fn test_soundness_byte_tampering() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, commitment, evaluation, proof_bytes) =
        create_valid_proof(256, nu, sigma);

    let positions_to_flip = [
        0,
        1,
        proof_bytes.len() / 4,
        proof_bytes.len() / 2,
        proof_bytes.len() - 1,
    ];

    for &pos in &positions_to_flip {
        if pos >= proof_bytes.len() {
            continue;
        }
        let mut tampered = proof_bytes.clone();
        tampered[pos] ^= 0xFF;

        let result = try_verify(
            commitment,
            evaluation,
            &point,
            nu,
            sigma,
            verifier_setup.clone(),
            &tampered,
        );

        assert!(
            result.is_err(),
            "Should fail with byte flipped at position {pos}"
        );
    }
}

#[test]
fn test_soundness_flip_sampled_bytes() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, commitment, evaluation, proof_bytes) =
        create_valid_proof(256, nu, sigma);

    // Sample positions throughout the proof rather than flipping every byte
    let len = proof_bytes.len();
    let positions = [
        0,
        1,
        len / 8,
        len / 4,
        len / 3,
        len / 2,
        2 * len / 3,
        3 * len / 4,
        7 * len / 8,
        len - 2,
        len - 1,
    ];

    for &pos in &positions {
        let mut tampered = proof_bytes.clone();
        tampered[pos] ^= 0xFF;

        let result = try_verify(
            commitment,
            evaluation,
            &point,
            nu,
            sigma,
            verifier_setup.clone(),
            &tampered,
        );

        assert!(
            result.is_err(),
            "Should fail with byte flipped at position {pos}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Truncated proof
// ---------------------------------------------------------------------------

#[test]
fn test_soundness_truncated_proof() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, commitment, evaluation, proof_bytes) =
        create_valid_proof(256, nu, sigma);

    let truncation_points = [0, 1, proof_bytes.len() / 2, proof_bytes.len() - 1];

    for &len in &truncation_points {
        if len >= proof_bytes.len() {
            continue;
        }
        let truncated = &proof_bytes[..len];

        let result = try_verify(
            commitment,
            evaluation,
            &point,
            nu,
            sigma,
            verifier_setup.clone(),
            truncated,
        );

        assert!(
            result.is_err(),
            "Should fail with proof truncated to {len} bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Extra bytes appended — caught by check_eof on checked verifier
// ---------------------------------------------------------------------------

#[test]
fn test_soundness_extra_bytes_rejected_by_length_check() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, tier_2, eval, proof_bytes) =
        create_valid_proof(256, nu, sigma);

    // Valid proof passes check_eof
    let mut verifier = test_verifier(sigma, &proof_bytes);
    verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        eval,
        &point,
        nu,
        sigma,
        verifier_setup.clone(),
        &mut verifier,
    )
    .unwrap();
    assert!(verifier.check_eof().is_ok());

    // Appending even one byte fails check_eof
    let mut extended = proof_bytes.clone();
    extended.push(0x00);
    let mut verifier = test_verifier(sigma, &extended);
    verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        eval,
        &point,
        nu,
        sigma,
        verifier_setup.clone(),
        &mut verifier,
    )
    .unwrap();
    assert!(verifier.check_eof().is_err());

    // Truncated also fails
    let truncated = &proof_bytes[..proof_bytes.len() - 1];
    let mut verifier = test_verifier(sigma, truncated);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        eval,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 5. Wrong evaluation value
// ---------------------------------------------------------------------------

#[test]
fn test_soundness_wrong_evaluation() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, commitment, _, proof_bytes) =
        create_valid_proof(256, nu, sigma);

    let wrong_evaluation = ArkFr(Fr::rand(&mut rand::thread_rng()));

    let result = try_verify(
        commitment,
        wrong_evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &proof_bytes,
    );

    assert!(result.is_err(), "Should fail with wrong evaluation");
}

#[test]
fn test_soundness_zero_evaluation() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, commitment, evaluation, proof_bytes) =
        create_valid_proof(256, nu, sigma);

    use dory_pcs::primitives::arithmetic::Field;
    let zero_eval = ArkFr::zero();

    // Only test if the real evaluation is non-zero (almost certainly true for random poly)
    if evaluation != zero_eval {
        let result = try_verify(
            commitment,
            zero_eval,
            &point,
            nu,
            sigma,
            verifier_setup,
            &proof_bytes,
        );

        assert!(
            result.is_err(),
            "Should fail with zero evaluation for non-zero poly"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Proof from one instance used with another's commitment
// ---------------------------------------------------------------------------

#[test]
fn test_soundness_cross_instance_proof() {
    let nu = 4;
    let sigma = 4;

    let (_, verifier_setup1, _, point1, commitment1, evaluation1, _proof_bytes1) =
        create_valid_proof(256, nu, sigma);
    let (_, _verifier_setup2, _, _point2, _commitment2, _evaluation2, proof_bytes2) =
        create_valid_proof(256, nu, sigma);

    // Use proof from instance 2 with commitment/evaluation/point from instance 1
    let result = try_verify(
        commitment1,
        evaluation1,
        &point1,
        nu,
        sigma,
        verifier_setup1,
        &proof_bytes2,
    );

    assert!(
        result.is_err(),
        "Should fail when using proof from a different instance"
    );
}

#[test]
fn test_soundness_cross_instance_swapped_commitment() {
    let nu = 4;
    let sigma = 4;

    let (_, _verifier_setup1, _, _point1, commitment1, _evaluation1, _proof_bytes1) =
        create_valid_proof(256, nu, sigma);
    let (_, verifier_setup2, _, point2, _commitment2, evaluation2, proof_bytes2) =
        create_valid_proof(256, nu, sigma);

    // Use commitment from instance 1 with proof/evaluation/point from instance 2
    let result = try_verify(
        commitment1,
        evaluation2,
        &point2,
        nu,
        sigma,
        verifier_setup2,
        &proof_bytes2,
    );

    assert!(
        result.is_err(),
        "Should fail with swapped commitment from another instance"
    );
}

// ---------------------------------------------------------------------------
// 7. Empty proof bytes
// ---------------------------------------------------------------------------

#[test]
fn test_soundness_empty_proof() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, commitment, evaluation, _proof_bytes) =
        create_valid_proof(256, nu, sigma);

    let result = try_verify(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &[],
    );

    assert!(result.is_err(), "Should fail with empty proof bytes");
}

// ---------------------------------------------------------------------------
// Additional: random garbage proof and zeroed proof
// ---------------------------------------------------------------------------

#[test]
fn test_soundness_random_garbage_proof() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, commitment, evaluation, proof_bytes) =
        create_valid_proof(256, nu, sigma);

    let garbage: Vec<u8> = (0..proof_bytes.len())
        .map(|_| rand::random::<u8>())
        .collect();

    let result = try_verify(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &garbage,
    );

    assert!(
        result.is_err(),
        "Should fail with random garbage proof bytes"
    );
}

#[test]
fn test_soundness_zeroed_proof() {
    let nu = 4;
    let sigma = 4;
    let (_, verifier_setup, _, point, commitment, evaluation, proof_bytes) =
        create_valid_proof(256, nu, sigma);

    let zeroed = vec![0u8; proof_bytes.len()];

    let result = try_verify(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &zeroed,
    );

    assert!(result.is_err(), "Should fail with zeroed proof");
}
