//! Zero-knowledge mode tests for Dory PCS

use super::*;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{create_zk_evaluation_proof, prove, setup, verify, verify_zk_evaluation_proof, ZK};

#[test]
fn test_zk_full_workflow() {
    let mut rng = rand::thread_rng();
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let expected_evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
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
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = test_setup_pair(4);

    let poly = random_polynomial(4);
    let nu = 1;
    let sigma = 1;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(2);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
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
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 12);

    let poly = random_polynomial(1024);
    let nu = 5;
    let sigma = 5;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(10);
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
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
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    // Non-square: nu=3, sigma=4 (8 rows, 16 columns = 128 coefficients)
    let poly = random_polynomial(128);
    let nu = 3;
    let sigma = 4;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(7); // nu + sigma = 7
    let evaluation = poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, ZK, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
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

/// Test the full ZK API where y is hidden from the verifier
#[test]
fn test_zk_hidden_evaluation() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = test_setup_pair(6);

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);

    // Create ZK proof - returns (proof, y_com) instead of revealing y
    let mut prover_transcript = fresh_transcript();
    let (zk_proof, y_com) =
        create_zk_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
            &poly,
            &point,
            Some(tier_1),
            nu,
            sigma,
            &prover_setup,
            &mut prover_transcript,
            &mut rng,
        )
        .unwrap();

    // Verify ZK proof - verifier does NOT receive y, only y_com
    let mut verifier_transcript = fresh_transcript();
    let result = verify_zk_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        y_com,
        &point,
        &zk_proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK hidden evaluation proof verification failed: {:?}",
        result
    );
}

/// Test that wrong y_com is rejected
#[test]
fn test_zk_wrong_y_com_rejected() {
    use dory_pcs::primitives::arithmetic::Group;

    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = test_setup_pair(6);

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(4);

    let mut prover_transcript = fresh_transcript();
    let (zk_proof, y_com) =
        create_zk_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
            &poly,
            &point,
            Some(tier_1),
            nu,
            sigma,
            &prover_setup,
            &mut prover_transcript,
            &mut rng,
        )
        .unwrap();

    // Tamper with y_com - add a random element
    let wrong_y_com = y_com + prover_setup.h1.scale(&ArkFr::from_u64(42));

    let mut verifier_transcript = fresh_transcript();
    let result = verify_zk_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        wrong_y_com,
        &point,
        &zk_proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err(), "Verification should fail with wrong y_com");
}

/// Test full ZK with larger polynomial
#[test]
fn test_zk_hidden_evaluation_larger() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);

    let mut prover_transcript = fresh_transcript();
    let (zk_proof, y_com) =
        create_zk_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _, _, _>(
            &poly,
            &point,
            Some(tier_1),
            nu,
            sigma,
            &prover_setup,
            &mut prover_transcript,
            &mut rng,
        )
        .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify_zk_evaluation_proof::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        y_com,
        &point,
        &zk_proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(
        result.is_ok(),
        "ZK hidden evaluation (larger) failed: {:?}",
        result
    );
}
