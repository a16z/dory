//! Evaluation proof tests

use super::*;
use dory::primitives::poly::Polynomial;
use dory::{prove, verify};

#[test]
fn test_evaluation_proof_small() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let mut prover_transcript = fresh_transcript();
    let result = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        None,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
    );
    assert!(result.is_ok());

    let (commitment, evaluation, proof) = result.unwrap();

    let mut verifier_transcript = fresh_transcript();
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        nu,
        sigma,
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
        Some(DoryCommitment::new(tier_2, tier_1)),
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
    );
    assert!(result.is_ok());

    let (returned_commitment, evaluation, proof) = result.unwrap();
    assert_eq!(tier_2, returned_commitment);

    let mut verifier_transcript = fresh_transcript();
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        nu,
        sigma,
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

    let mut prover_transcript = fresh_transcript();
    let (commitment, evaluation, proof) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        None,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
    )
    .unwrap();

    assert_eq!(evaluation, ArkFr::from_u64(7));

    let mut verifier_transcript = fresh_transcript();
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        evaluation,
        &point,
        &proof,
        nu,
        sigma,
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

    let mut prover_transcript = fresh_transcript();
    let (commitment, evaluation, proof) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        None,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
    )
    .unwrap();

    let wrong_evaluation = evaluation + ArkFr::one();

    let mut verifier_transcript = fresh_transcript();
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        wrong_evaluation,
        &point,
        &proof,
        nu,
        sigma,
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

        let mut prover_transcript = fresh_transcript();
        let (commitment, evaluation, proof) =
            prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
                &poly,
                &point,
                None,
                1,
                1,
                &setup,
                &mut prover_transcript,
            )
            .unwrap();

        let mut verifier_transcript = fresh_transcript();
        let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
            commitment,
            evaluation,
            &point,
            &proof,
            1,
            1,
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

        let mut prover_transcript = fresh_transcript();
        let (commitment, evaluation, proof) =
            prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
                &poly,
                &point,
                None,
                3,
                3,
                &setup,
                &mut prover_transcript,
            )
            .unwrap();

        let mut verifier_transcript = fresh_transcript();
        let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
            commitment,
            evaluation,
            &point,
            &proof,
            3,
            3,
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
        let (returned_commitment, evaluation, proof) =
            prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
                &poly,
                &point,
                Some(DoryCommitment::new(tier_2, tier_1.clone())),
                nu,
                sigma,
                &setup,
                &mut prover_transcript,
            )
            .unwrap();

        assert_eq!(tier_2, returned_commitment);

        let mut verifier_transcript = fresh_transcript();
        let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
            tier_2,
            evaluation,
            &point,
            &proof,
            nu,
            sigma,
            verifier_setup.clone(),
            &mut verifier_transcript,
        );
        assert!(result.is_ok());
    }
}
