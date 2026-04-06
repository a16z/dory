//! Common test utilities for arkworks backend tests

#![allow(unreachable_pub)]

use dory_pcs::backends::arkworks::{
    dory_prover, dory_verifier, ArkFr, ArkworksPolynomial, G1Routines, G2Routines, ProverState,
    VerifierState, BN254,
};
use dory_pcs::primitives::arithmetic::Field;
use dory_pcs::setup::{ProverSetup, VerifierSetup};

pub mod cache;
pub mod commitment;
pub mod evaluation;
pub mod homomorphic;
pub mod integration;
pub mod non_square;
pub mod serialization;
pub mod setup;
pub mod soundness;
#[cfg(feature = "zk")]
pub mod zk;

pub fn random_polynomial(size: usize) -> ArkworksPolynomial {
    let coefficients: Vec<ArkFr> = (0..size).map(|_| ArkFr::random()).collect();
    ArkworksPolynomial::new(coefficients)
}

pub fn constant_polynomial(value: u64, num_vars: usize) -> ArkworksPolynomial {
    let size = 1 << num_vars;
    let coeff = ArkFr::from_u64(value);
    let coefficients = vec![coeff; size];
    ArkworksPolynomial::new(coefficients)
}

pub fn random_point(num_vars: usize) -> Vec<ArkFr> {
    (0..num_vars).map(|_| ArkFr::random()).collect()
}

pub fn test_setup(max_log_n: usize) -> ProverSetup<BN254> {
    ProverSetup::new(max_log_n)
}

pub fn test_setup_pair(max_log_n: usize) -> (ProverSetup<BN254>, VerifierSetup<BN254>) {
    let prover_setup = test_setup(max_log_n);
    let verifier_setup = prover_setup.to_verifier_setup();
    (prover_setup, verifier_setup)
}

/// Create a prover state for transparent mode testing.
pub fn test_prover(nu: usize, sigma: usize) -> ProverState {
    dory_prover(nu, sigma, false)
}

/// Create a verifier state for transparent mode testing.
pub fn test_verifier(nu: usize, sigma: usize, proof_bytes: &[u8]) -> VerifierState<'_> {
    dory_verifier(nu, sigma, false, proof_bytes)
}

/// Create a prover state for ZK mode testing.
#[cfg(feature = "zk")]
pub fn test_prover_zk(nu: usize, sigma: usize) -> ProverState {
    dory_prover(nu, sigma, true)
}

/// Create a verifier state for ZK mode testing.
#[cfg(feature = "zk")]
pub fn test_verifier_zk(nu: usize, sigma: usize, proof_bytes: &[u8]) -> VerifierState<'_> {
    dory_verifier(nu, sigma, true, proof_bytes)
}

pub type TestG1Routines = G1Routines;
pub type TestG2Routines = G2Routines;
