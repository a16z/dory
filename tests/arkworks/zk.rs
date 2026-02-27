//! Zero-knowledge mode tests for Dory PCS

use super::*;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{create_evaluation_proof, prove, setup, verify, Transparent, ZK};

#[test]
fn test_zk_full_workflow() {
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254>(max_log_n);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let expected_evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();
    let evaluation = poly.evaluate(&point);
    assert_eq!(evaluation, expected_evaluation);

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_ok(), "ZK proof verification failed: {:?}", result);
}

#[test]
fn test_zk_small_polynomial() {
    let (prover_setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(4);
    let nu = 1;
    let sigma = 1;

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(2);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK small polynomial test failed: {:?}",
        result
    );
}

#[test]
fn test_zk_larger_polynomial() {
    let (prover_setup, verifier_setup) = setup::<BN254>(12);

    let poly = random_polynomial(1024);
    let nu = 5;
    let sigma = 5;

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(10);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK larger polynomial test failed: {:?}",
        result
    );
}

#[test]
fn test_zk_non_square_matrix() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    // Non-square: nu=3, sigma=4 (8 rows, 16 columns = 128 coefficients)
    let poly = random_polynomial(128);
    let nu = 3;
    let sigma = 4;

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(7); // nu + sigma = 7
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK non-square matrix test failed: {:?}",
        result
    );
}

#[test]
fn test_zk_hidden_evaluation() {
    let (prover_setup, verifier_setup) = test_setup_pair(6);

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);
    let evaluation = poly.evaluate(&point);

    // Create ZK proof using unified API with ZK mode
    let mut prover_transcript = fresh_transcript();
    let (proof, _) = create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        Some(tier_1),
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    assert!(proof.y_com.is_some(), "ZK proof should contain y_com");
    assert!(proof.e2.is_some(), "ZK proof should contain e2");

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK hidden evaluation proof verification failed: {:?}",
        result
    );
}

/// Test that tampered e2 in proof is rejected
#[test]
fn test_zk_tampered_e2_rejected() {
    use dory_pcs::primitives::arithmetic::Group;

    let (prover_setup, verifier_setup) = test_setup_pair(6);

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (mut proof, _) =
        create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
            &poly,
            &point,
            Some(tier_1),
            nu,
            sigma,
            &prover_setup,
            &mut prover_transcript,
        )
        .unwrap();

    // Tamper with e2 in the proof
    if let Some(ref mut e2) = proof.e2 {
        *e2 = *e2 + prover_setup.h2.scale(&ArkFr::from_u64(42));
    }

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Verification should fail with tampered e2");
}

/// Test full ZK with larger polynomial
#[test]
fn test_zk_hidden_evaluation_larger() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, _) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = create_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK>(
        &poly,
        &point,
        Some(tier_1),
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK hidden evaluation (larger) failed: {:?}",
        result
    );
}
