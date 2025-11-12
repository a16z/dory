//! Homomorphic combination example for Dory commitments
//!
//! This example demonstrates the homomorphic properties of Dory commitments:
//! - Commit to multiple polynomials independently
//! - Combine commitments
//! - Prove evaluation on the combined polynomial using the combined commitment
//! - Verify that the homomorphic combination works correctly
//!
//! Homomorphic property: Com(r₁·P₁ + r₂·P₂ + ... + rₙ·Pₙ) = r₁·Com(P₁) + r₂·Com(P₂) + ... + rₙ·Com(Pₙ)

use dory_pcs::backends::arkworks::{
    ArkFr, ArkG1, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines, BN254,
};
use dory_pcs::primitives::arithmetic::{Field, Group};
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify};
use rand::thread_rng;
use tracing::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Dory PCS - Homomorphic Combination Example");
    info!("===========================================\n");

    let mut rng = thread_rng();

    // Step 1: Setup
    let max_log_n = 10;
    info!(
        "1. Generating transparent setup (max_log_n = {})...",
        max_log_n
    );
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);
    info!("   ✓ Setup complete\n");

    // Parameters
    let nu = 4;
    let sigma = 4;
    let poly_size = 1 << (nu + sigma); // 256
    let num_vars = nu + sigma; // 8
    let num_polys = 5;

    info!("2. Creating {} random polynomials...", num_polys);
    info!("   Each polynomial: {} coefficients", poly_size);
    let polys: Vec<ArkworksPolynomial> = (0..num_polys)
        .map(|_| {
            let coeffs: Vec<ArkFr> = (0..poly_size).map(|_| ArkFr::random(&mut rng)).collect();
            ArkworksPolynomial::new(coeffs)
        })
        .collect();
    info!("   ✓ Polynomials created\n");

    // Step 3: Commit to each polynomial
    info!("3. Computing individual commitments...");
    let commitments: Vec<_> = polys
        .iter()
        .map(|poly| {
            poly.commit::<BN254, G1Routines>(nu, sigma, &prover_setup)
                .unwrap()
        })
        .collect();
    info!("   ✓ {} commitments computed\n", num_polys);

    // Step 4: Generate random coefficients for linear combination
    info!("4. Generating random combination coefficients...");
    let coeffs: Vec<ArkFr> = (0..num_polys).map(|_| ArkFr::random(&mut rng)).collect();
    info!("   ✓ Coefficients: r₁, r₂, ..., r{}\n", num_polys);

    // Step 5: Homomorphically combine commitments
    info!("5. Combining commitments homomorphically...");

    // Tier-2 (GT group): combined_tier2 = r₁·C₁ + r₂·C₂ + ... + r₅·C₅
    #[allow(clippy::op_ref)]
    let mut combined_tier2 = coeffs[0] * &commitments[0].0;
    for i in 1..num_polys {
        #[allow(clippy::op_ref)]
        let scaled = coeffs[i] * &commitments[i].0;
        combined_tier2 = combined_tier2 + scaled;
    }

    // Tier-1 (G1 group): For each row, combine the row commitments
    let num_rows = 1 << nu;
    let mut combined_tier1 = vec![ArkG1::identity(); num_rows];
    for i in 0..num_polys {
        for (row_idx, row_commitment) in commitments[i].1.iter().enumerate() {
            let scaled = coeffs[i] * row_commitment;
            combined_tier1[row_idx] = combined_tier1[row_idx] + scaled;
        }
    }
    info!("   ✓ Tier-2 combined (GT)");
    info!("   ✓ Tier-1 combined ({} rows in G1)\n", num_rows);

    // Step 6: Compute combined polynomial
    info!(
        "6. Computing combined polynomial: P = r₁·P₁ + r₂·P₂ + ... + r{}·P{}...",
        num_polys, num_polys
    );
    let mut combined_coeffs = vec![ArkFr::zero(); poly_size];
    for poly_idx in 0..num_polys {
        // Access coefficients through evaluation at hypercube vertices
        #[allow(clippy::needless_range_loop)]
        for coeff_idx in 0..poly_size {
            // Create point that selects the coeff_idx-th vertex of the hypercube
            let point: Vec<ArkFr> = (0..num_vars)
                .map(|bit_idx| {
                    if (coeff_idx >> bit_idx) & 1 == 1 {
                        ArkFr::one()
                    } else {
                        ArkFr::zero()
                    }
                })
                .collect();

            let eval = polys[poly_idx].evaluate(&point);
            #[allow(clippy::op_ref)]
            let scaled = coeffs[poly_idx] * eval;
            combined_coeffs[coeff_idx] = combined_coeffs[coeff_idx] + scaled;
        }
    }
    let combined_poly = ArkworksPolynomial::new(combined_coeffs);
    info!("   ✓ Combined polynomial computed\n");

    // Step 7: Evaluate and verify consistency
    info!("7. Verifying homomorphic property...");
    let point: Vec<ArkFr> = (0..num_vars).map(|_| ArkFr::random(&mut rng)).collect();
    let evaluation = combined_poly.evaluate(&point);

    // Check that combined polynomial evaluation matches linear combination
    let mut expected_eval = ArkFr::zero();
    for i in 0..num_polys {
        let poly_eval = polys[i].evaluate(&point);
        expected_eval = expected_eval + coeffs[i].mul(&poly_eval);
    }
    assert_eq!(
        evaluation, expected_eval,
        "Combined polynomial evaluation must match linear combination"
    );
    info!("   ✓ Evaluation matches: P(x) = Σ rᵢ·Pᵢ(x)\n");

    // Step 8: Generate proof
    info!("8. Generating evaluation proof for combined polynomial...");
    let mut prover_transcript = Blake2bTranscript::new(b"dory-homomorphic-example");
    let proof = prove::<_, BN254, G1Routines, G2Routines, _, _>(
        &combined_poly,
        &point,
        combined_tier1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )?;
    info!("   ✓ Proof generated\n");

    // Step 9: Verify
    info!("9. Verifying proof with combined commitment...");
    let mut verifier_transcript = Blake2bTranscript::new(b"dory-homomorphic-example");
    verify::<_, BN254, G1Routines, G2Routines, _>(
        combined_tier2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    )?;
    info!("   ✓ Proof verified successfully!\n");

    info!("===========================================");
    info!("Homomorphic combination verified!");
    info!(
        "Combined {} polynomials using random coefficients",
        num_polys
    );

    Ok(())
}
