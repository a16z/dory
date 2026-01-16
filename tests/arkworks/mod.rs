//! Common test utilities for arkworks backend tests

#![allow(unreachable_pub)]

use dory_pcs::backends::arkworks::{
    ArkFr, ArkworksPolynomial, Blake2bTranscript, G1Routines, G2Routines, BN254,
};
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::proof::DoryProof;
use dory_pcs::setup::{ProverSetup, VerifierSetup};
use rand::thread_rng;

pub mod cache;
pub mod commitment;
pub mod evaluation;
pub mod homomorphic;
pub mod integration;
pub mod non_square;
#[cfg(feature = "recursion")]
pub mod recursion;
pub mod setup;
pub mod soundness;
#[cfg(feature = "recursion")]
pub mod witness;

pub fn random_polynomial(size: usize) -> ArkworksPolynomial {
    let mut rng = thread_rng();
    let coefficients: Vec<ArkFr> = (0..size).map(|_| ArkFr::random(&mut rng)).collect();
    ArkworksPolynomial::new(coefficients)
}

pub fn constant_polynomial(value: u64, num_vars: usize) -> ArkworksPolynomial {
    let size = 1 << num_vars;
    let coeff = ArkFr::from_u64(value);
    let coefficients = vec![coeff; size];
    ArkworksPolynomial::new(coefficients)
}

pub fn random_point(num_vars: usize) -> Vec<ArkFr> {
    let mut rng = thread_rng();
    (0..num_vars).map(|_| ArkFr::random(&mut rng)).collect()
}

pub fn test_setup(max_log_n: usize) -> ProverSetup<BN254> {
    let mut rng = thread_rng();
    ProverSetup::new(&mut rng, max_log_n)
}

pub fn test_setup_pair(max_log_n: usize) -> (ProverSetup<BN254>, VerifierSetup<BN254>) {
    let prover_setup = test_setup(max_log_n);
    let verifier_setup = prover_setup.to_verifier_setup();
    (prover_setup, verifier_setup)
}

pub fn fresh_transcript() -> Blake2bTranscript<BN254> {
    Blake2bTranscript::new(b"dory-test")
}

pub type TestG1Routines = G1Routines;
pub type TestG2Routines = G2Routines;
