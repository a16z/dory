//! Evaluation proof tests

use super::*;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, verify, Transparent};

#[test]
fn test_evaluation_proof_small() {
    let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup, &mut prover_rng)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let result = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
        &mut prover_rng,
    );
    assert!(result.is_ok());

    let (proof, _) = result.unwrap();
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
    let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup, &mut prover_rng)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let result = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
        &mut prover_rng,
    );
    assert!(result.is_ok());

    let (proof, _) = result.unwrap();
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
    let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = constant_polynomial(7, 4);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let expected_eval = poly.evaluate(&point);
    assert_eq!(expected_eval, ArkFr::from_u64(7));

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup, &mut prover_rng)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
        &mut prover_rng,
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
    let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let point = random_point(4);

    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup, &mut prover_rng)
        .unwrap();

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &setup,
        &mut prover_transcript,
        &mut prover_rng,
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
    let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    {
        let setup = test_setup(4);
        let verifier_setup = setup.to_verifier_setup();

        let poly = random_polynomial(4);
        let point = random_point(2);

        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, TestG1Routines>(1, 1, &setup, &mut prover_rng)
            .unwrap();

        let mut prover_transcript = fresh_transcript();
        let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            1,
            1,
            &setup,
            &mut prover_transcript,
            &mut prover_rng,
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

        let (tier_2, tier_1, commit_blind) = poly
            .commit::<BN254, Transparent, TestG1Routines>(3, 3, &setup, &mut prover_rng)
            .unwrap();

        let mut prover_transcript = fresh_transcript();
        let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1,
            commit_blind,
            3,
            3,
            &setup,
            &mut prover_transcript,
            &mut prover_rng,
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
    let mut prover_rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    let setup = test_setup(4);
    let verifier_setup = setup.to_verifier_setup();

    let poly = random_polynomial(16);
    let nu = 2;
    let sigma = 2;

    let (tier_2, tier_1, commit_blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(nu, sigma, &setup, &mut prover_rng)
        .unwrap();

    for _ in 0..3 {
        let point = random_point(4);

        let mut prover_transcript = fresh_transcript();
        let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
            &poly,
            &point,
            tier_1.clone(),
            commit_blind,
            nu,
            sigma,
            &setup,
            &mut prover_transcript,
            &mut prover_rng,
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

#[test]
fn test_transparent_proving_does_not_consume_rng() {
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    let (prover_setup, verifier_setup) = test_setup_pair(4);
    let poly = constant_polynomial(7, 2);
    let point = vec![ArkFr::from_u64(3); 2];
    let mut rng = StdRng::seed_from_u64(11);
    let mut untouched = rng.clone();
    let (commitment, rows, blind) = poly
        .commit::<BN254, Transparent, TestG1Routines>(1, 1, &prover_setup, &mut rng)
        .unwrap();
    let (proof, evaluation_blind) =
        prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent>(
            &poly,
            &point,
            rows,
            blind,
            1,
            1,
            &prover_setup,
            &mut fresh_transcript(),
            &mut rng,
        )
        .unwrap();
    assert_eq!(blind, ArkFr::zero());
    assert!(evaluation_blind.is_none());
    assert_eq!(rng.next_u64(), untouched.next_u64());
    verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        commitment,
        poly.evaluate(&point),
        &point,
        &proof,
        verifier_setup,
        &mut fresh_transcript(),
    )
    .unwrap();
}
