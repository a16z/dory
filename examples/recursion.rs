//! Recursion example: trace generation and hint-based verification
//!
//! This example demonstrates the recursion API workflow:
//! 1. Standard proof generation
//! 2. Witness-generating verification (captures operation traces)
//! 3. Converting witnesses to hints
//! 4. Hint-based verification
//!
//! The hint-based verification enables efficient recursive proof composition.
//!
//! Run with: `cargo run --features recursion --example recursion`

use std::rc::Rc;

use dory_pcs::backends::arkworks::{
    ArkFr, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines, SimpleWitnessBackend,
    SimpleWitnessGenerator, BN254,
};
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::recursion::TraceContext;
use dory_pcs::{prove, setup, verify, verify_recursive};
use rand::thread_rng;
use tracing::info;
use tracing_subscriber::EnvFilter;

type Ctx = TraceContext<SimpleWitnessBackend, BN254, SimpleWitnessGenerator>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("Dory PCS - Recursion API Example");
    info!("=================================\n");

    let mut rng = thread_rng();

    // Step 1: Setup
    let max_log_n = 8;
    info!("1. Generating setup (max_log_n = {})...", max_log_n);
    let (prover_setup, verifier_setup) = setup::<BN254, _>(&mut rng, max_log_n);
    info!("   Setup complete\n");

    // Step 2: Create polynomial
    let nu = 3;
    let sigma = 3;
    let poly_size = 1 << (nu + sigma); // 64 coefficients
    let num_vars = nu + sigma;

    info!("2. Creating random polynomial...");
    info!("   Matrix layout: {}x{}", 1 << nu, 1 << sigma);
    info!("   Total coefficients: {}", poly_size);

    let coefficients: Vec<ArkFr> = (0..poly_size).map(|_| ArkFr::random(&mut rng)).collect();
    let poly = ArkworksPolynomial::new(coefficients);

    // Step 3: Commit
    info!("\n3. Computing commitment...");
    let (tier_2, tier_1) = poly.commit::<BN254, G1Routines>(nu, sigma, &prover_setup)?;

    // Step 4: Create evaluation proof
    let point: Vec<ArkFr> = (0..num_vars).map(|_| ArkFr::random(&mut rng)).collect();
    let evaluation = poly.evaluate(&point);

    info!("4. Generating proof...");
    let mut prover_transcript = Blake2bTranscript::new(b"dory-recursion-example");
    let proof = prove::<_, BN254, G1Routines, G2Routines, _, _>(
        &poly,
        &point,
        tier_1,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )?;

    // Step 5: Standard verification)
    info!("\n5. Standard verification...");
    let mut std_transcript = Blake2bTranscript::new(b"dory-recursion-example");
    verify::<_, BN254, G1Routines, G2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup.clone(),
        &mut std_transcript,
    )?;
    info!("   Standard verification passed\n");

    // Step 6: Witness-generating verification
    info!("6. Witness-generating verification...");
    info!("   This captures traces of all arithmetic operations");

    let ctx = Rc::new(Ctx::for_witness_gen());
    let mut witness_transcript = Blake2bTranscript::new(b"dory-recursion-example");

    verify_recursive::<_, BN254, G1Routines, G2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup.clone(),
        &mut witness_transcript,
        ctx.clone(),
    )?;

    // Finalize and get witness collection
    let collection = Rc::try_unwrap(ctx)
        .ok()
        .expect("should have sole ownership")
        .finalize()
        .expect("should have witnesses");

    info!("   Witness collection stats:");
    info!("     - GT exponentiation: {}", collection.gt_exp.len());
    info!("     - G1 scalar mul: {}", collection.g1_scalar_mul.len());
    info!("     - G2 scalar mul: {}", collection.g2_scalar_mul.len());
    info!("     - GT multiplication: {}", collection.gt_mul.len());
    info!("     - Single pairing: {}", collection.pairing.len());
    info!("     - Multi-pairing: {}", collection.multi_pairing.len());
    info!("     - G1 MSM: {}", collection.msm_g1.len());
    info!("     - G2 MSM: {}", collection.msm_g2.len());
    info!("     - Total operations: {}", collection.total_witnesses());
    info!("     - Reduce-fold rounds: {}\n", collection.num_rounds);

    // Step 7: Convert to hints
    info!("7. Converting witnesses to hints...");
    let hints = collection.to_hints::<BN254>();
    info!("   HintMap entries: {} (one per operation)", hints.len());

    // Step 8: Hint-based verification
    info!("8. Hint-based verification...");

    let ctx = Rc::new(Ctx::for_hints(hints));
    let mut hint_transcript = Blake2bTranscript::new(b"dory-recursion-example");

    verify_recursive::<_, BN254, G1Routines, G2Routines, _, _, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut hint_transcript,
        ctx,
    )?;
    info!("   Hint-based verification passed\n");

    Ok(())
}
