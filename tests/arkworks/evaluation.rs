//! Evaluation proof tests

use super::*;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, verify};

#[test]
fn test_evaluation_proof_small() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let result = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
    );
    assert!(result.is_ok());

    let proof = result.unwrap();
    let evaluation = poly.evaluate(&point);

    let mut verifier_transcript = fresh_transcript();
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(verify_result.is_ok());
}

#[test]
fn test_evaluation_proof_with_precomputed_commitment() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let result = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
    );
    assert!(result.is_ok());

    let proof = result.unwrap();
    let evaluation = poly.evaluate(&point);

    let mut verifier_transcript = fresh_transcript();
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(verify_result.is_ok());
}

#[test]
fn test_evaluation_proof_constant_polynomial() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = constant_polynomial(7, 4);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let expected_eval = poly.evaluate(&point);
    assert_eq!(expected_eval, ArkFr::from_u64(7));

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
    )
    .unwrap();

    let evaluation = poly.evaluate(&point);
    assert_eq!(evaluation, ArkFr::from_u64(7));

    let mut verifier_transcript = fresh_transcript();
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(verify_result.is_ok());
}

#[test]
fn test_evaluation_proof_wrong_evaluation_fails() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
    )
    .unwrap();

    let evaluation = poly.evaluate(&point);
    let wrong_evaluation = evaluation + ArkFr::one();

    let mut verifier_transcript = fresh_transcript();
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        wrong_evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(verify_result.is_err());
}

#[test]
fn test_evaluation_proof_different_sizes() {
    {
        let setup = test_setup(4);
        let verifier_setup = setup.to_verifier_setup();

        let poly = random_polynomial(4);
        let point = random_point(2);

        let (tier_2, tier_1) = poly.commit::<BN254, TestG1Routines>(1, 1, &setup).unwrap();

        let mut prover_transcript = fresh_transcript();
        let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
            &poly,
            &point,
            tier_1,
            1,
            1,
            &setup,
            &mut prover_transcript,
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

    {
        let setup = test_setup(8);
        let verifier_setup = setup.to_verifier_setup();

        let poly = random_polynomial(64);
        let point = random_point(6);

        let (tier_2, tier_1) = poly.commit::<BN254, TestG1Routines>(3, 3, &setup).unwrap();

        let mut prover_transcript = fresh_transcript();
        let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
            &poly,
            &point,
            tier_1,
            3,
            3,
            &setup,
            &mut prover_transcript,
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
}

#[test]
fn test_multiple_evaluations_same_commitment() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    for _ in 0..3 {
        let point = random_point(4);

        let mut prover_transcript = fresh_transcript();
        let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
            &poly,
            &point,
            tier_1.clone(),
            nu,
            sigma,
            &setup,
            &mut prover_transcript,
        )
        .unwrap();

        let evaluation = poly.evaluate(&point);

        let mut verifier_transcript = fresh_transcript();
        let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
            tier_2,
            evaluation,
            &point,
            &proof,
            verifier_setup.clone(),
            &mut verifier_transcript,
        );
        assert!(result.is_ok());
    }
}
