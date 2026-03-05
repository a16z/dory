//! End-to-end Dory proof using Metal GPU-accelerated pairings.
//!
//! Identical to `basic_e2e` but uses `MetalBN254` instead of `BN254`,
//! routing multi-pairings through the Metal GPU when the batch size
//! exceeds the hardware-dependent threshold.
//!
//! Run with: cargo run --example metal_e2e --features backends,metal-gpu,parallel --release

use std::time::Instant;

use dory_pcs::backends::arkworks::{
    ArkFr, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines,
};
use dory_pcs::backends::metal::MetalBN254;
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify, Transparent};
use rayon::prelude::*;
use tracing::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let nu = 12;
    let sigma = 12;
    let poly_size = 1 << (nu + sigma);
    let num_vars = nu + sigma;

    let t = Instant::now();
    let (prover_setup, verifier_setup) = setup::<MetalBN254>(nu + sigma);
    info!(elapsed = ?t.elapsed(), "Setup complete");

    let t = Instant::now();
    let coefficients: Vec<ArkFr> = (0..poly_size)
        .into_par_iter()
        .map(|_| ArkFr::random())
        .collect();
    let poly = ArkworksPolynomial::new(coefficients);
    info!(elapsed = ?t.elapsed(), poly_size, "Polynomial created");

    let t = Instant::now();
    let (tier_2, tier_1, commit_blind) =
        poly.commit::<MetalBN254, Transparent, G1Routines>(nu, sigma, &prover_setup)?;
    info!(elapsed = ?t.elapsed(), "Commit complete");

    let point: Vec<ArkFr> = (0..num_vars).map(|_| ArkFr::random()).collect();

    let t = Instant::now();
    let evaluation = poly.evaluate(&point);
    info!(elapsed = ?t.elapsed(), "Evaluation complete");

    let t = Instant::now();
    let mut prover_transcript = Blake2bTranscript::<MetalBN254>::new(b"dory-metal-example");
    let (proof, _) = prove::<_, MetalBN254, G1Routines, G2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover_transcript,
    )?;
    info!(elapsed = ?t.elapsed(), "Prove complete");

    let t = Instant::now();
    let mut verifier_transcript = Blake2bTranscript::<MetalBN254>::new(b"dory-metal-example");
    verify::<_, MetalBN254, G1Routines, G2Routines, _>(
        tier_2,
        evaluation,
        &point,
        &proof,
        verifier_setup,
        &mut verifier_transcript,
    )?;
    info!(elapsed = ?t.elapsed(), "Verify complete");

    Ok(())
}
