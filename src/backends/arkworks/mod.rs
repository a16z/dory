//! Arkworks backend implementation for BN254 pairing curve

mod ark_field;
mod ark_group;
mod ark_pairing;
mod ark_poly;
mod ark_proof;
mod ark_serde;
mod ark_setup;
mod blake2b_transcript;

#[cfg(feature = "cache")]
pub mod ark_cache;

#[cfg(feature = "recursion")]
mod ark_witness;

pub use ark_field::ArkFr;
pub use ark_group::{ArkG1, ArkG2, ArkGT, G1Routines, G2Routines};
pub use ark_pairing::BN254;
pub use ark_poly::ArkworksPolynomial;
pub use ark_proof::ArkDoryProof;
pub use ark_setup::{ArkworksProverSetup, ArkworksVerifierSetup};
pub use blake2b_transcript::Blake2bTranscript;

#[cfg(feature = "cache")]
pub use ark_cache::{get_prepared_g1, get_prepared_g2, init_cache, is_cached};

#[cfg(feature = "recursion")]
pub use ark_witness::{
    G1ScalarMulWitness, G2ScalarMulWitness, GtExpWitness, GtMulWitness, MillerStep, MsmG1Witness,
    MsmG2Witness, MultiPairingWitness, PairingWitness, SimpleWitnessBackend,
    SimpleWitnessGenerator,
};
