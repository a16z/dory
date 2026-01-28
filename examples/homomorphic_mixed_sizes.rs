//! Mixed-size homomorphic combination example for Dory commitments.
//!
//! Demonstrates how to homomorphically combine two polynomials that only use a
//! subset of the coefficient domain (sizes 5 and 20, padded to 32) and then
//! produce and verify an evaluation proof for the combined commitment.

use dory_pcs::backends::arkworks::{
    ArkFr, ArkG1, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines, BN254,
};
use dory_pcs::primitives::arithmetic::{Field, Group};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify, Transparent};
use rand::thread_rng;
use tracing::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Dory PCS - Mixed-size Homomorphic Combination Example");
    let mut rng = thread_rng();

    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, 4);

    info!("Creating two polynomials with logical sizes 16 and 4...");
    let mut coeffs_poly1 = vec![ArkFr::zero(); 16];
    let mut coeffs_poly2 = vec![ArkFr::zero(); 4];
    for coeff in coeffs_poly1.iter_mut() {
        *coeff = ArkFr::random(&mut rng);
    }
    for coeff in coeffs_poly2.iter_mut() {
        *coeff = ArkFr::random(&mut rng);
    }
    let poly1 = ArkworksPolynomial::new(coeffs_poly1.clone());
    let poly2 = ArkworksPolynomial::new(coeffs_poly2.clone());

    info!("Poly1: {:?}", poly1);
    info!("Poly2: {:?}", poly2);

    let commitment1 = poly1.commit::<BN254, G1Routines>(2, 2, &prover_setup).unwrap();
    let commitment2 = poly2.commit::<BN254, G1Routines>(1, 1, &prover_setup).unwrap();
    info!("✓ Commitments ready\n");

    info!("Sampling random combination scalars r1, r2...");
    let coeff_scalars = [ArkFr::random(&mut rng), ArkFr::random(&mut rng)];

    info!("Combining tier-2 commitments (GT)...");
    let combined_tier2 = coeff_scalars[0] * commitment1.0 + coeff_scalars[1] * commitment2.0;

    info!("Combining tier-1 commitments (G1 rows)...");

    let mut combined_tier1 = vec![ArkG1::identity(); 4];
    for (row_idx, row_commit) in commitment1.1.iter().enumerate() {
        combined_tier1[row_idx] = combined_tier1[row_idx] + (coeff_scalars[0] * row_commit);
    }
    for (row_idx, row_commit) in commitment2.1.iter().enumerate() {
        combined_tier1[row_idx] = combined_tier1[row_idx] + (coeff_scalars[1] * row_commit);
    }

    info!("Building combined polynomial coefficients...");
    let mut combined_coeffs = vec![ArkFr::zero(); 16];
    for idx in 0..16 {
        let term1 = coeff_scalars[0].mul(&coeffs_poly1[idx]);
        combined_coeffs[idx] = combined_coeffs[idx] + term1;
        if idx < 2 {
            let term2 = coeff_scalars[1].mul(&coeffs_poly2[idx]);
            combined_coeffs[idx] = combined_coeffs[idx] + term2;
        }
        if idx > 3 && idx < 6 {
            let term3 = coeff_scalars[1].mul(&coeffs_poly2[idx - 2]);
            combined_coeffs[idx] = combined_coeffs[idx] + term3;
        }
    }
    let combined_poly = ArkworksPolynomial::new(combined_coeffs);

    info!("Combined polynomial: {:?}", combined_poly);

    let mut padded_poly2_coefficients = vec![ArkFr::zero(); 16];
    padded_poly2_coefficients[0] = coeffs_poly2[0];
    padded_poly2_coefficients[1] = coeffs_poly2[1];
    padded_poly2_coefficients[4] = coeffs_poly2[2];
    padded_poly2_coefficients[5] = coeffs_poly2[3];
    let padded_poly2 = ArkworksPolynomial::new(padded_poly2_coefficients);

    info!("Evaluating combined polynomial at a random point...");
    let point: Vec<ArkFr> = (0..4).map(|_| ArkFr::random(&mut rng)).collect();
    let evaluation = combined_poly.evaluate(&point);

    info!("Checking that evaluation matches r1·P1(x) + r2·P2(x)...");
    let eval1 = poly1.evaluate(&point);
    let eval2 = padded_poly2.evaluate(&point);
    let eval3 = poly2.evaluate(&[point[0], point[2]])
        * (ArkFr::one() - point[1])
        * (ArkFr::one() - point[3]);
    assert_eq!(eval3, eval2);
    let mut expected = ArkFr::zero();
    expected = expected + coeff_scalars[0].mul(&eval1);
    expected = expected + coeff_scalars[1].mul(&eval2);
    assert_eq!(evaluation, expected);
    info!("✓ Evaluation matches linear combination\n");

    info!("Generating evaluation proof with combined commitment...");
    let mut prover_transcript = Blake2bTranscript::new(b"dory-homomorphic-mixed");
    let (proof, _) = prove::<_, BN254, G1Routines, G2Routines, _, _, Transparent, _>(
        &combined_poly,
        &point,
        combined_tier1,
        2,
        2,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
    )?;
    info!("✓ Proof generated\n");

    info!("Verifying proof against combined tier-2 commitment...");
    let mut verifier_transcript = Blake2bTranscript::new(b"dory-homomorphic-mixed");
    verify::<_, BN254, G1Routines, G2Routines, _>(
        combined_tier2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    )?;
    info!("✓ Proof verified!");

    info!("===========================================");
    let padded_poly_commitment =
        padded_poly2.commit::<BN254, G1Routines>(2, 2, &prover_setup).unwrap();
    assert_eq!(padded_poly_commitment.0, commitment2.0);
    info!("✓ Padded poly commitment matches original poly2 commitment");

    Ok(())
}
