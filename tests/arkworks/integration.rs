//! End-to-end integration tests

use super::*;
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify, Transparent};

#[test]
fn test_full_workflow() {
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254>(max_log_n);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    let point = random_point(8);
    let expected_evaluation = poly.evaluate(&point);

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
    let evaluation = poly.evaluate(&point);
    assert_eq!(evaluation, expected_evaluation);
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(result.is_ok());
    verifier.check_eof().unwrap();
}

#[test]
fn test_workflow_without_precommitment() {
    let max_log_n = 10;

    let (prover_setup, verifier_setup) = setup::<BN254>(max_log_n);

    let poly = random_polynomial(256);
    let point = random_point(8);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
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
    let evaluation = poly.evaluate(&point);
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(result.is_ok());
    verifier.check_eof().unwrap();
}

#[test]
fn test_batched_proofs() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    let poly = random_polynomial(256);
    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &prover_setup)
        .unwrap();

    for _i in 0..5 {
        let point = random_point(8);

        let mut prover = test_prover(sigma);
        let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1.clone(),
            commit_blind,
            nu,
            sigma,
            &prover_setup,
            &mut prover,
        )
        .unwrap();
        let evaluation = poly.evaluate(&point);
        let proof_bytes = prover.check_complete().narg_string().to_vec();

        let mut verifier = test_verifier(sigma, &proof_bytes);
        let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
            tier_2,
            evaluation,
            &point,
            nu,
            sigma,
            verifier_setup.clone(),
            &mut verifier,
        );

        assert!(result.is_ok(), "Proof should verify");
        verifier.check_eof().unwrap();
    }
}

#[test]
fn test_linear_polynomial() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

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

    let (tier_2, tier_1, commit_blind) = poly
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

    let evaluation = poly.evaluate(&point);
    let expected_eval = poly.evaluate(&point);
    assert_eq!(evaluation, expected_eval);
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(result.is_ok());
    verifier.check_eof().unwrap();
}

#[test]
fn test_zero_polynomial() {
    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    let poly = constant_polynomial(0, 8);
    let point = random_point(8);

    let nu = 4;
    let sigma = 4;

    let (tier_2, tier_1, commit_blind) = poly
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

    let evaluation = poly.evaluate(&point);
    assert_eq!(evaluation, ArkFr::zero());
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier(sigma, &proof_bytes);
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(result.is_ok());
    verifier.check_eof().unwrap();
}
