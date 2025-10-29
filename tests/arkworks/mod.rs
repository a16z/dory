//! Common test utilities for arkworks backend tests

use dory::backends::arkworks::{
    ArkFr, ArkG1, ArkG1Routines, ArkG2, ArkG2Routines, ArkGT, ArkworksPolynomial, BN254,
};
use dory::backends::Blake2bTranscript;
use dory::primitives::arithmetic::Field;
use dory::primitives::poly::DoryCommitment;
use dory::proof::DoryProof;
use dory::setup::{ProverSetup, VerifierSetup};
use rand::thread_rng;

pub mod commitment;
pub mod evaluation;
pub mod integration;
pub mod setup;
pub mod soundness;

/// Helper to create a random polynomial of given size
pub fn random_polynomial(size: usize) -> ArkworksPolynomial {
    let mut rng = thread_rng();
    let coefficients: Vec<ArkFr> = (0..size).map(|_| ArkFr::random(&mut rng)).collect();
    ArkworksPolynomial::new(coefficients)
}

/// Helper to create a constant polynomial
pub fn constant_polynomial(value: u64, num_vars: usize) -> ArkworksPolynomial {
    let size = 1 << num_vars;
    let coeff = ArkFr::from_u64(value);
    let coefficients = vec![coeff; size];
    ArkworksPolynomial::new(coefficients)
}

/// Helper to create a random evaluation point
pub fn random_point(num_vars: usize) -> Vec<ArkFr> {
    let mut rng = thread_rng();
    (0..num_vars).map(|_| ArkFr::random(&mut rng)).collect()
}

/// Helper to create setup for testing
pub fn test_setup(max_log_n: usize) -> ProverSetup<BN254> {
    let mut rng = thread_rng();
    ProverSetup::new(&mut rng, max_log_n)
}

/// Helper to create both prover and verifier setup for testing
pub fn test_setup_pair(max_log_n: usize) -> (ProverSetup<BN254>, VerifierSetup<BN254>) {
    let prover_setup = test_setup(max_log_n);
    let verifier_setup = prover_setup.to_verifier_setup();
    (prover_setup, verifier_setup)
}

/// Helper to create a fresh transcript
pub fn fresh_transcript() -> Blake2bTranscript<BN254> {
    Blake2bTranscript::new(b"dory-test")
}

/// Type aliases for convenience
pub type TestProverSetup = ProverSetup<BN254>;
pub type TestG1Routines = ArkG1Routines;
pub type TestG2Routines = ArkG2Routines;
