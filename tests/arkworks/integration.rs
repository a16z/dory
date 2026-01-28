//! End-to-end integration tests

use super::*;
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify, Transparent};

#[test]
fn test_full_workflow() {
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
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
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

    assert!(result.is_ok());
}

#[test]
fn test_workflow_without_precommitment() {
    let mut rng = rand::thread_rng();
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let poly = random_polynomial(256);
    let point = random_point(8);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
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

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_ok());
}

#[test]
fn test_batched_proofs() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    for i in 0..5 {
        let point = random_point(8);

        let mut prover_transcript = Blake2bTranscript::new(format!("test-{}", i).as_bytes());
        let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
            &poly,
            &point,
            tier_1.clone(),
            nu,
            sigma,
            &prover_setup,
            &mut prover_transcript,
            &mut rng,
        )
        .unwrap();
        let evaluation = poly.evaluate(&point);

        let mut verifier_transcript = Blake2bTranscript::new(format!("test-{}", i).as_bytes());
        let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
            tier_2,
            evaluation,
            &point,
            &proof,
            verifier_setup.clone(),
            &mut verifier_transcript,
        );

        assert!(result.is_ok(), "Proof {} should verify", i);
    }
}

#[test]
fn test_linear_polynomial() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    let coefficients: Vec<ArkFr> = (0..256).map(|i| ArkFr::from_u64(i as u64)).collect();
    let poly = ArkworksPolynomial::new(coefficients);

    let point = vec![
        ArkFr::from_u64(2),
        ArkFr::from_u64(3),
        ArkFr::from_u64(5),
        ArkFr::from_u64(7),
        ArkFr::from_u64(11),
        ArkFr::from_u64(13),
        ArkFr::from_u64(17),
        ArkFr::from_u64(19),
    ];

    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
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
    let expected_eval = poly.evaluate(&point);
    assert_eq!(evaluation, expected_eval);

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_ok());
}

#[test]
fn test_zero_polynomial() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    let poly = constant_polynomial(0, 8);
    let point = random_point(8);

    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
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
    assert_eq!(evaluation, ArkFr::zero());

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_ok());
}

#[test]
fn test_soundness_wrong_commitment() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    let poly1 = random_polynomial(256);
    let poly2 = random_polynomial(256);
    let point = random_point(8);

    let nu = 4;
    let sigma = 4;

    let (commitment1, _) = poly1
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let (_, tier_1_poly2) = poly2
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
        &poly2,
        &point,
        tier_1_poly2,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
    )
    .unwrap();
    let evaluation = poly2.evaluate(&point);

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment1,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_err());
}
