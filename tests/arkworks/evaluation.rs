//! Evaluation proof tests

use super::*;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, verify, Transparent};

#[test]
fn test_evaluation_proof_small() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    let result = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover,
    );
    assert!(result.is_ok());

    let _y = result.unwrap();
    let evaluation = poly.evaluate(&point);
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier(sigma, &proof_bytes);
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(verify_result.is_ok());
    verifier.check_eof().unwrap();
}

#[test]
fn test_evaluation_proof_with_precomputed_commitment() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    let result = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover,
    );
    assert!(result.is_ok());

    let _y = result.unwrap();
    let evaluation = poly.evaluate(&point);
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier(sigma, &proof_bytes);
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(verify_result.is_ok());
    verifier.check_eof().unwrap();
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

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover,
    )
    .unwrap();

    let evaluation = poly.evaluate(&point);
    assert_eq!(evaluation, ArkFr::from_u64(7));
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier(sigma, &proof_bytes);
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    );

    assert!(verify_result.is_ok());
    verifier.check_eof().unwrap();
}

#[test]
fn test_evaluation_proof_wrong_evaluation_fails() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    let mut prover = test_prover(sigma);
    let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover,
    )
    .unwrap();

    let evaluation = poly.evaluate(&point);
    let wrong_evaluation = evaluation + ArkFr::one();
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = test_verifier(sigma, &proof_bytes);
    let verify_result = verify::<_, BN254, TestG1Routines, TestG2Routines, _, Transparent>(
        tier_2,
        wrong_evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
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
        let nu = 1;
        let sigma = 1;

        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
            .unwrap();

        let mut prover = test_prover(sigma);
        let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            nu,
            sigma,
            &setup,
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

    {
        let setup = test_setup(8);
        let verifier_setup = setup.to_verifier_setup();

        let poly = random_polynomial(64);
        let point = random_point(6);
        let nu = 3;
        let sigma = 3;

        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
            .unwrap();

        let mut prover = test_prover(sigma);
        let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            nu,
            sigma,
            &setup,
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
}

#[test]
fn test_multiple_evaluations_same_commitment() {
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup)
        .unwrap();

    for _ in 0..3 {
        let point = random_point(4);

        let mut prover = test_prover(sigma);
        let _y = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1.clone(),
            commit_blind,
            nu,
            sigma,
            &setup,
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
        assert!(result.is_ok());
        verifier.check_eof().unwrap();
    }
}
