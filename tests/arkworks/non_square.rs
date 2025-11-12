//! Test to verify behavior with non-square matrices (nu ≤ sigma)

use super::*;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify};

#[test]
fn test_non_square_matrix_nu_eq_sigma_minus_1() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    // nu = 3, sigma = 4 => 2^3 x 2^4 = 8 rows x 16 columns = 128 coefficients
    let nu = 3;
    let sigma = 4;
    let poly_size = 1 << (nu + sigma); // 128
    let num_vars = nu + sigma; // 7

    let poly = random_polynomial(poly_size);
    let point = random_point(num_vars);

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .expect("Commitment should succeed");

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .expect("Proof generation should succeed");

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

    assert!(result.is_ok(), "Verification should succeed for nu < sigma");
}

#[test]
fn test_non_square_matrix_nu_greater_than_sigma_rejected() {
    let mut rng = rand::thread_rng();
    let (prover_setup, _verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    // nu = 4, sigma = 3 => This should be rejected
    let nu = 4;
    let sigma = 3;
    let poly_size = 1 << (nu + sigma);
    let num_vars = nu + sigma;

    let poly = random_polynomial(poly_size);
    let point = random_point(num_vars);

    let (_, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .expect("Commitment should succeed");

    let mut prover_transcript = fresh_transcript();
    let proof_result = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    );

    assert!(
        proof_result.is_err(),
        "Proof generation should be rejected for nu > sigma"
    );
}

#[test]
fn test_non_square_matrix_small() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 6);

    // nu = 2, sigma = 3 => 2^2 x 2^3 = 4 rows x 8 columns = 32 coefficients
    let nu = 2;
    let sigma = 3;
    let poly_size = 1 << (nu + sigma);
    let num_vars = nu + sigma;

    let poly = random_polynomial(poly_size);
    let point = random_point(num_vars);

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .expect("Commitment should succeed");

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .expect("Proof generation should succeed");

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

    assert!(
        result.is_ok(),
        "Verification should succeed for nu < sigma (small)"
    );
}

#[test]
fn test_non_square_matrix_very_rectangular() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 10);

    // nu = 2, sigma = 5 => 2^2 x 2^5 = 4 rows x 32 columns = 128 coefficients
    // This is much "less square" than nu = sigma - 1
    let nu = 2;
    let sigma = 5;
    let poly_size = 1 << (nu + sigma);
    let num_vars = nu + sigma;

    let poly = random_polynomial(poly_size);
    let point = random_point(num_vars);

    let (tier_2, tier_1) = poly
        .commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup)
        .expect("Commitment should succeed");

    let mut prover_transcript = fresh_transcript();
    let proof = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )
    .expect("Proof generation should succeed");

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

    assert!(
        result.is_ok(),
        "Verification should succeed for nu << sigma (very rectangular)"
    );
}
