//! Zero-knowledge end-to-end example of Dory polynomial commitment scheme
//!
//! This example demonstrates the ZK workflow where the prover generates a
//! hiding proof. The only API difference from transparent mode is switching
//! the mode type parameter from `Transparent` to `ZK`.
//!
//! In ZK mode:
//! - Protocol messages are blinded with random scalars
//! - The proof contains additional sigma and scalar-product sub-proofs
//! - The evaluation commitment (`y_com`) hides the actual evaluation value
//!
//! Matrix dimensions: 16×16 (nu=4, sigma=4, total 256 coefficients)

use dory_pcs::backends::arkworks::{
    ArkFr, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines, BN254,
};
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify, Transparent, ZK};
use rand::thread_rng;
use tracing::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Dory PCS - Zero-Knowledge End-to-End Example");
    info!("==============================================\n");

    let mut rng = thread_rng();

    // Step 1: Setup (identical to transparent mode)
    let max_log_n = 10;
    info!("1. Generating setup (max_log_n = {})...", max_log_n);
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);
    info!("   Setup complete\n");

    // Step 2: Create polynomial
    let nu = 4;
    let sigma = 4;
    let poly_size = 1 << (nu + sigma); // 256
    let num_vars = nu + sigma; // 8

    info!("2. Creating random polynomial...");
    info!("   Matrix layout: {}x{} (square)", 1 << nu, 1 << sigma);
    info!("   Total coefficients: {}", poly_size);

    let coefficients: Vec<ArkFr> = (0..poly_size).map(|_| ArkFr::random(&mut rng)).collect();
    let poly = ArkworksPolynomial::new(coefficients);
    info!("   Polynomial created\n");

    // Step 3: Commit (identical to transparent mode)
    info!("3. Computing polynomial commitment...");
    let (tier_2, tier_1, _) =
        poly.commit::<BN254, Transparent, G1Routines, _>(nu, sigma, &prover_setup, &mut rng)?;
    info!("   Tier-1: {} row commitments", tier_1.len());
    info!("   Tier-2: final GT commitment\n");

    // Step 4: Evaluate
    let point: Vec<ArkFr> = (0..num_vars).map(|_| ArkFr::random(&mut rng)).collect();
    let evaluation = poly.evaluate(&point);
    info!("4. Evaluated polynomial at random point\n");

    // Step 5: Prove in ZK mode
    // The only API difference: `ZK` replaces `Transparent` as the mode parameter.
    // This causes all protocol messages to be blinded with random scalars and
    // generates additional sigma1, sigma2, and scalar-product sub-proofs.
    info!("5. Generating ZK evaluation proof...");
    let mut prover_transcript = Blake2bTranscript::new(b"dory-zk-example");
    let (proof, _) = prove::<_, BN254, G1Routines, G2Routines, _, _, ZK, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
        &mut rng,
    )?;
    info!("   Proof generated");
    info!(
        "   ZK sub-proofs present: e2={}, y_com={}, sigma1={}, sigma2={}, scalar_product={}",
        proof.e2.is_some(),
        proof.y_com.is_some(),
        proof.sigma1_proof.is_some(),
        proof.sigma2_proof.is_some(),
        proof.scalar_product_proof.is_some(),
    );
    info!(
        "   {} reduce rounds (logarithmic)\n",
        proof.first_messages.len()
    );

    // Step 6: Verify (identical call signature to transparent mode)
    // The verifier detects ZK mode from the proof's e2/y_com fields.
    info!("6. Verifying ZK proof...");
    let mut verifier_transcript = Blake2bTranscript::new(b"dory-zk-example");
    verify::<_, BN254, G1Routines, G2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    )?;
    info!("   Proof verified successfully!\n");

    info!("==============================================");
    info!("ZK example completed successfully!");

    Ok(())
}
