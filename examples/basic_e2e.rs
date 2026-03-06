//! Basic end-to-end example of Dory polynomial commitment scheme
//!
//! Demonstrates the standard workflow with a square matrix layout:
//! setup, commit, evaluate, prove, verify.
//!
//! Matrix dimensions: 16x16 (nu=4, sigma=4, total 256 coefficients)

use dory_pcs::backends::arkworks::{
    dory_prover, dory_verifier, ArkFr, ArkworksPolynomial, G1Routines, G2Routines, BN254,
};
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::primitives::poly::Polynomial;
use dory_pcs::{prove, setup, verify, Transparent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let (prover_setup, verifier_setup) = setup::<BN254>(10);

    let nu = 4;
    let sigma = 4;
    let poly_size = 1 << (nu + sigma);
    let num_vars = nu + sigma;

    let coefficients: Vec<ArkFr> = (0..poly_size).map(|_| ArkFr::random()).collect();
    let poly = ArkworksPolynomial::new(coefficients);

    let (tier_2, tier_1, commit_blind) =
        poly.commit::<BN254, Transparent, G1Routines>(nu, sigma, &prover_setup)?;

    let point: Vec<ArkFr> = (0..num_vars).map(|_| ArkFr::random()).collect();
    let evaluation = poly.evaluate(&point);

    let mut prover = dory_prover(sigma, false);
    prove::<_, BN254, G1Routines, G2Routines, _, _, Transparent>(
        &poly,
        &point,
        tier_1,
        commit_blind,
        nu,
        sigma,
        &prover_setup,
        &mut prover,
    )?;
    let proof_bytes = prover.check_complete().narg_string().to_vec();

    let mut verifier = dory_verifier(sigma, false, &proof_bytes);
    verify::<_, BN254, G1Routines, G2Routines, _, Transparent>(
        tier_2,
        evaluation,
        &point,
        nu,
        sigma,
        verifier_setup,
        &mut verifier,
    )?;
    verifier.check_eof().map_err(|e| format!("{e:?}"))?;

    Ok(())
}
