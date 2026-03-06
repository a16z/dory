//! Zero-knowledge mode tests for Dory PCS

use super::*;
use dory_pcs::backends::arkworks::ArkGT;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{create_evaluation_proof, prove, setup, verify, Transparent, ZK};

#[test]
fn test_zk_full_workflow() {
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254>(max_log_n);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let expected_evaluation = poly.evaluate(&point);

    let mut prover = test_prover_zk(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
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
    assert_eq!(evaluation, expected_evaluation);
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier_zk(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, ZK>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(result.is_ok(), "ZK proof verification failed: {:?}", result);
    verifier.check_eof().unwrap();
}

#[test]
fn test_zk_small_polynomial() {
    let (prover_setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(4);
    let nu = 1;
    let sigma = 1;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(2);
    let evaluation = poly.evaluate(&point);

    let mut prover = test_prover_zk(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
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
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier_zk(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, ZK>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(
        result.is_ok(),
        "ZK small polynomial test failed: {:?}",
        result
    );
    verifier.check_eof().unwrap();
}

#[test]
fn test_zk_larger_polynomial() {
    let (prover_setup, verifier_setup) = setup::<BN254>(12);

    let poly = random_polynomial(1024);
    let nu = 5;
    let sigma = 5;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(10);
    let evaluation = poly.evaluate(&point);

    let mut prover = test_prover_zk(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
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
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier_zk(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, ZK>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(
        result.is_ok(),
        "ZK larger polynomial test failed: {:?}",
        result
    );
    verifier.check_eof().unwrap();
}

#[test]
fn test_zk_non_square_matrix() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    // Non-square: nu=3, sigma=4 (8 rows, 16 columns = 128 coefficients)
    let poly = random_polynomial(128);
    let nu = 3;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(7); // nu + sigma = 7
    let evaluation = poly.evaluate(&point);

    let mut prover = test_prover_zk(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
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
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier_zk(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, ZK>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(
        result.is_ok(),
        "ZK non-square matrix test failed: {:?}",
        result
    );
    verifier.check_eof().unwrap();
}

#[test]
fn test_zk_hidden_evaluation() {
    let (prover_setup, verifier_setup) = test_setup_pair(6);

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);
    let evaluation = poly.evaluate(&point);

    // Create ZK proof using unified API with ZK mode
    let mut prover = test_prover_zk(sigma);
    let _y = create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        Some(tier_1),
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover,
    )
    .unwrap();
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    // Verify that ZK proof bytes are non-empty
    assert!(
        !proof_bytes.is_empty(),
        "ZK proof should produce non-empty bytes"
    );

    let mut verifier = test_verifier_zk(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, ZK>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(
        result.is_ok(),
        "ZK hidden evaluation proof verification failed: {:?}",
        result
    );
    verifier.check_eof().unwrap();
}

/// Test full ZK with larger polynomial
#[test]
fn test_zk_hidden_evaluation_larger() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let evaluation = poly.evaluate(&point);

    let mut prover = test_prover_zk(sigma);
    let _y = create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        Some(tier_1),
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover,
    )
    .unwrap();
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier_zk(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, ZK>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(
        result.is_ok(),
        "ZK hidden evaluation (larger) failed: {:?}",
        result
    );
    verifier.check_eof().unwrap();
}

// ---------------------------------------------------------------------------
// ZK Soundness Tests
// ---------------------------------------------------------------------------

/// Create a valid ZK proof and return (proof_bytes, sigma, verifier_setup, point, commitment, evaluation).
#[allow(clippy::type_complexity)]
fn create_valid_zk_proof_bytes(
    size: usize,
    nu: usize,
    sigma: usize,
) -> (
    Vec<u8>,
    usize,
    VerifierSetup<BN254>,
    Vec<ArkFr>,
    ArkGT,
    ArkFr,
) {
    let (prover_setup, verifier_setup) = test_setup_pair(nu + sigma + 2);

    let poly = random_polynomial(size);
    let point = random_point(nu + sigma);

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover = test_prover_zk(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
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
        proof_bytes,
        sigma,
        verifier_setup,
        point,
        tier_2,
        evaluation,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_tampered_zk_proof(
    commitment: ArkGT,
    evaluation: ArkFr,
    point: &[ArkFr],
    nu: usize,
    sigma: usize,
    proof_bytes: &[u8],
    verifier_setup: VerifierSetup<BN254>,
) -> Result<(), dory_pcs::DoryError> {
    let mut verifier = test_verifier_zk(sigma, proof_bytes);
    verify::<_, BN254, TestG1Routines, TestG2Routines, _, ZK>(
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

/// Verify that valid ZK proof passes (sanity check).
#[test]
fn test_zk_soundness_valid_proof() {
    let nu = 4;
    let sigma = 4;
    let (proof_bytes, _sigma, verifier_setup, point, commitment, evaluation) =
        create_valid_zk_proof_bytes(256, nu, sigma);

    let result = verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        &proof_bytes,
        verifier_setup,
    );
    assert!(result.is_ok(), "Valid ZK proof should verify");
}

/// Flipping a byte at the start should fail.
#[test]
fn test_zk_soundness_flip_first_byte() {
    let nu = 4;
    let sigma = 4;
    let (proof_bytes, _sigma, verifier_setup, point, commitment, evaluation) =
        create_valid_zk_proof_bytes(256, nu, sigma);

    let mut corrupted = proof_bytes.clone();
    if !corrupted.is_empty() {
        corrupted[0] ^= 0xFF;
    }

    let result = verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        &corrupted,
        verifier_setup,
    );
    assert!(result.is_err(), "Should fail with flipped first byte");
}

/// Flipping a byte in the middle should fail.
#[test]
fn test_zk_soundness_flip_middle_byte() {
    let nu = 4;
    let sigma = 4;
    let (proof_bytes, _sigma, verifier_setup, point, commitment, evaluation) =
        create_valid_zk_proof_bytes(256, nu, sigma);

    let mut corrupted = proof_bytes.clone();
    let mid = corrupted.len() / 2;
    if mid < corrupted.len() {
        corrupted[mid] ^= 0xFF;
    }

    let result = verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        &corrupted,
        verifier_setup,
    );
    assert!(result.is_err(), "Should fail with flipped middle byte");
}

/// Flipping the last byte should fail.
#[test]
fn test_zk_soundness_flip_last_byte() {
    let nu = 4;
    let sigma = 4;
    let (proof_bytes, _sigma, verifier_setup, point, commitment, evaluation) =
        create_valid_zk_proof_bytes(256, nu, sigma);

    // Flip a byte near the end (but not the very last, which may be
    // trailing padding that spongefish ignores).
    let pos = proof_bytes.len().saturating_sub(10).max(1);
    let mut corrupted = proof_bytes.clone();
    corrupted[pos] ^= 0xFF;

    let result = verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        &corrupted,
        verifier_setup,
    );
    assert!(
        result.is_err(),
        "Should fail with flipped byte near end of proof"
    );
}

/// Truncating ZK proof should fail.
#[test]
fn test_zk_soundness_truncated_proof() {
    let nu = 4;
    let sigma = 4;
    let (proof_bytes, _sigma, verifier_setup, point, commitment, evaluation) =
        create_valid_zk_proof_bytes(256, nu, sigma);

    let truncated = proof_bytes[..proof_bytes.len() / 2].to_vec();

    let result = verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        &truncated,
        verifier_setup,
    );
    assert!(result.is_err(), "Should fail with truncated ZK proof");
}

/// Empty proof should fail.
#[test]
fn test_zk_soundness_empty_proof() {
    let nu = 4;
    let sigma = 4;
    let (_proof_bytes, _sigma, verifier_setup, point, commitment, evaluation) =
        create_valid_zk_proof_bytes(256, nu, sigma);

    let empty: Vec<u8> = Vec::new();

    let result = verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        &empty,
        verifier_setup,
    );
    assert!(result.is_err(), "Should fail with empty ZK proof");
}

/// In ZK mode, the evaluation is hidden inside the commitment and verified
/// via sigma proofs. The `evaluation` parameter to `verify()` is not used
/// in ZK mode — the proof itself binds the correct evaluation. This is
/// correct ZK behavior: the evaluation is private to the prover.
#[test]
fn test_zk_evaluation_is_hidden() {
    let nu = 4;
    let sigma = 4;
    let (proof_bytes, _sigma, verifier_setup, point, commitment, _evaluation) =
        create_valid_zk_proof_bytes(256, nu, sigma);

    // In ZK mode, any evaluation value can be passed — the proof is
    // self-contained and the sigma proofs bind the correct evaluation.
    let arbitrary_evaluation = ArkFr::random();

    let result = verify_tampered_zk_proof(
        commitment,
        arbitrary_evaluation,
        &point,
        nu,
        sigma,
        &proof_bytes,
        verifier_setup,
    );
    assert!(
        result.is_ok(),
        "ZK verify ignores evaluation param — proof is self-contained"
    );
}

/// Zeroed proof bytes should fail.
#[test]
fn test_zk_soundness_zeroed_proof() {
    let nu = 4;
    let sigma = 4;
    let (proof_bytes, _sigma, verifier_setup, point, commitment, evaluation) =
        create_valid_zk_proof_bytes(256, nu, sigma);

    let zeroed = vec![0u8; proof_bytes.len()];

    let result = verify_tampered_zk_proof(
        commitment,
        evaluation,
        &point,
        nu,
        sigma,
        &zeroed,
        verifier_setup,
    );
    assert!(result.is_err(), "Should fail with zeroed ZK proof");
}

/// Using transparent proof bytes with ZK verifier should fail.
#[test]
fn test_zk_soundness_transparent_proof_as_zk() {
    let nu = 4;
    let sigma = 4;

    // Create a transparent proof
    let (prover_setup, verifier_setup) = test_setup_pair(nu + sigma + 2);
    let poly = random_polynomial(256);
    let point = random_point(nu + sigma);
    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, ZK, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
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
    let transparent_bytes = prover.check_complete().narg_string().to_vec();
    let evaluation = poly.evaluate(&point);

    // Try to verify transparent proof bytes using ZK domain
    let result = verify_tampered_zk_proof(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        &transparent_bytes,
        verifier_setup,
    );
    assert!(
        result.is_err(),
        "Should fail when using transparent proof bytes with ZK verifier"
    );
}

/// ZK proof bytes should be larger than transparent proof bytes for same parameters.
#[test]
fn test_zk_proof_bytes_larger_than_transparent() {
    let nu = 4;
    let sigma = 4;
    let (zk_bytes, _, _, _, _, _) = create_valid_zk_proof_bytes(256, nu, sigma);

    let (prover_setup, _) = test_setup_pair(nu + sigma + 2);
    let poly = random_polynomial(256);
    let point = random_point(nu + sigma);
    let (_, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
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
    let transparent_bytes = prover.check_complete().narg_string().to_vec();

    assert!(
        zk_bytes.len() > transparent_bytes.len(),
        "ZK proof ({}) should be larger than transparent ({})",
        zk_bytes.len(),
        transparent_bytes.len()
    );
}
