//! Homomorphic combination tests for Dory commitments

use super::*;
use dory_pcs::backends::arkworks::ArkG1;
use dory_pcs::primitives::arithmetic::{Field, Group};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify, Transparent};

#[test]
fn test_homomorphic_combination_e2e() {
    let mut rng = rand::thread_rng();
    let max_log_n = 10;
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);

    let nu = 4;
    let sigma = 4;
    let poly_size = 256; // 2^(nu + sigma)
    let num_vars = 8;

    let polys: Vec<ArkworksPolynomial> = (0..5).map(|_| random_polynomial(poly_size)).collect();

    let commitments: Vec<_> = polys
        .iter()
        .map(|poly| poly.commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup).unwrap())
        .collect();

    let coeffs: Vec<ArkFr> = (0..5).map(|_| ArkFr::random(&mut rng)).collect();

    // Homomorphically combine commitments
    #[allow(clippy::op_ref)]
    let mut combined_tier2 = coeffs[0] * &commitments[0].0;
    for i in 1..5 {
        #[allow(clippy::op_ref)]
        let scaled = coeffs[i] * &commitments[i].0;
        combined_tier2 = combined_tier2 + scaled;
    }

    // Tier-1 (G1 group): For each row, combine the row commitments
    let num_rows = 1 << nu;
    let mut combined_tier1 = vec![ArkG1::identity(); num_rows];
    for i in 0..5 {
        for (row_idx, row_commitment) in commitments[i].1.iter().enumerate() {
            let scaled = coeffs[i] * row_commitment;
            combined_tier1[row_idx] = combined_tier1[row_idx] + scaled;
        }
    }

    // Compute combined polynomial: P = r1*P1 + r2*P2 + ... + r5*P5
    let mut combined_coeffs = vec![ArkFr::zero(); poly_size];
    for poly_idx in 0..5 {
        #[allow(clippy::needless_range_loop)]
        for coeff_idx in 0..poly_size {
            let point: Vec<ArkFr> = (0..num_vars)
                .map(
                    |bit_idx| {
                        if (coeff_idx >> bit_idx) & 1 == 1 {
                            ArkFr::one()
                        } else {
                            ArkFr::zero()
                        }
                    },
                )
                .collect();

            let eval = polys[poly_idx].evaluate(&point);
            #[allow(clippy::op_ref)]
            let scaled = coeffs[poly_idx] * eval;
            combined_coeffs[coeff_idx] = combined_coeffs[coeff_idx] + scaled;
        }
    }
    let combined_poly = ArkworksPolynomial::new(combined_coeffs);

    let point = random_point(num_vars);
    let evaluation = combined_poly.evaluate(&point);

    // Verify that the combined polynomial evaluation matches the linear combination
    let mut expected_eval = ArkFr::zero();
    for i in 0..5 {
        let poly_eval = polys[i].evaluate(&point);
        expected_eval = expected_eval + coeffs[i].mul(&poly_eval);
    }
    assert_eq!(
        evaluation, expected_eval,
        "Combined polynomial evaluation should match linear combination"
    );

    // Create evaluation proof using combined commitment
    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
        &combined_poly,
        &point,
        combined_tier1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        combined_tier2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_ok(), "Verification should succeed for homomorphically combined commitment");
}

#[test]
fn test_homomorphic_combination_small() {
    let mut rng = rand::thread_rng();
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 6);

    let nu = 2;
    let sigma = 2;
    let poly_size = 16;
    let num_vars = 4;

    let polys: Vec<ArkworksPolynomial> = (0..5).map(|_| random_polynomial(poly_size)).collect();

    let commitments: Vec<_> = polys
        .iter()
        .map(|poly| poly.commit::<BN254, TestG1Routines>(nu, sigma, &prover_setup).unwrap())
        .collect();

    let coeffs: Vec<ArkFr> = (0..5).map(|_| ArkFr::random(&mut rng)).collect();
    #[allow(clippy::op_ref)]
    let mut combined_tier2 = coeffs[0] * &commitments[0].0;
    for i in 1..5 {
        #[allow(clippy::op_ref)]
        let scaled = coeffs[i] * &commitments[i].0;
        combined_tier2 = combined_tier2 + scaled;
    }

    let num_rows = 1 << nu;
    let mut combined_tier1 = vec![ArkG1::identity(); num_rows];
    for i in 0..5 {
        for (row_idx, row_commitment) in commitments[i].1.iter().enumerate() {
            combined_tier1[row_idx] = combined_tier1[row_idx] + (coeffs[i] * row_commitment);
        }
    }

    let mut combined_coeffs = vec![ArkFr::zero(); poly_size];
    for poly_idx in 0..5 {
        #[allow(clippy::needless_range_loop)]
        for coeff_idx in 0..poly_size {
            let point: Vec<ArkFr> = (0..num_vars)
                .map(
                    |bit_idx| {
                        if (coeff_idx >> bit_idx) & 1 == 1 {
                            ArkFr::one()
                        } else {
                            ArkFr::zero()
                        }
                    },
                )
                .collect();

            let eval = polys[poly_idx].evaluate(&point);
            #[allow(clippy::op_ref)]
            let scaled = coeffs[poly_idx] * eval;
            combined_coeffs[coeff_idx] = combined_coeffs[coeff_idx] + scaled;
        }
    }
    let combined_poly = ArkworksPolynomial::new(combined_coeffs);

    let point = random_point(num_vars);
    let evaluation = combined_poly.evaluate(&point);

    let mut prover_transcript = fresh_transcript();
    let (proof, _) = prove::<_, BN254, TestG1Routines, TestG2Routines, _, _, Transparent, _>(
        &combined_poly,
        &point,
        combined_tier1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
    )
    .unwrap();

    let mut verifier_transcript = fresh_transcript();
    let result = verify::<_, BN254, TestG1Routines, TestG2Routines, _>(
        combined_tier2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    );

    assert!(result.is_ok());
}
