//! Basic end-to-end example of Dory polynomial commitment scheme
//!
//! This example demonstrates the standard workflow with a square matrix layout:
//! - Setup generation
//! - Polynomial commitment
//! - Evaluation proof generation
//! - Verification
//!
//! Matrix dimensions: 16×16 (nu=4, sigma=4, total 256 coefficients)

use dory_pcs::backends::arkworks::{
    ArkFr, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines, BN254,
};
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify};
use rand::thread_rng;
use tracing::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Dory PCS - Basic End-to-End Example");
    info!("====================================\n");

    let mut rng = thread_rng();

    // Step 1: Setup
    let max_log_n = 10;
    info!(
        "1. Generating transparent setup (max_log_n = {})...",
        max_log_n
    );
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);
    info!("   ✓ Setup complete\n");

    // Step 2: Create polynomial
    // Square matrix: nu = sigma = 4 → 16 rows × 16 columns = 256 coefficients
    let nu = 4;
    let sigma = 4;
    let poly_size = 1 << (nu + sigma); // 2^8 = 256
    let num_vars = nu + sigma; // 8

    info!("2. Creating random polynomial...");
    info!("   Matrix layout: {}×{} (square)", 1 << nu, 1 << sigma);
    info!("   Total coefficients: {}", poly_size);
    info!("   Number of variables: {}", num_vars);

    let coefficients: Vec<ArkFr> = (0..poly_size).map(|_| ArkFr::random(&mut rng)).collect();
    let poly = ArkworksPolynomial::new(coefficients);
    info!("   ✓ Polynomial created\n");

    // Step 3: Commit
    info!("3. Computing polynomial commitment...");
    let (tier_2, tier_1) = poly.commit::<BN254, G1Routines>(nu, sigma, &prover_setup)?;
    info!(
        "   ✓ Tier-1 commitment: {} row commitments (G1)",
        tier_1.len()
    );
    info!("   ✓ Tier-2 commitment: final commitment (GT)\n");

    // Step 4: Evaluation
    let point: Vec<ArkFr> = (0..num_vars).map(|_| ArkFr::random(&mut rng)).collect();
    let evaluation = poly.evaluate(&point);
    info!("4. Evaluating polynomial at random point...");
    info!("   ✓ Evaluation result computed\n");

    // Step 5: Prove
    info!("5. Generating evaluation proof...");
    let mut prover_transcript = Blake2bTranscript::new(b"dory-basic-example");
    let proof = prove::<_, BN254, G1Routines, G2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )?;
    info!("   ✓ Proof generated (logarithmic size)\n");

    // Step 6: Verify
    info!("6. Verifying proof...");
    let mut verifier_transcript = Blake2bTranscript::new(b"dory-basic-example");
    verify::<_, BN254, G1Routines, G2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    )?;
    info!("   ✓ Proof verified successfully!\n");

    info!("====================================");
    info!("Example completed successfully!");

    Ok(())
}
