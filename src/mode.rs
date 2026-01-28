//! Mode trait for transparent vs zero-knowledge proofs
//!
//! This module provides a mode abstraction that allows the same protocol implementation
//! to work for both transparent (non-hiding) and zero-knowledge (hiding) proofs.
//!
//! - [`Transparent`]: Default mode with no blinding. `sample` returns zero, `mask` is identity.
//! - [`ZK`]: Zero-knowledge mode (requires `zk` feature). Samples blinds from RNG.

use crate::primitives::arithmetic::{Field, Group};

/// Mode marker trait for transparent vs ZK proofs.
///
/// Determines whether blinds are sampled (ZK) or zero (transparent).
pub trait Mode: 'static {
    /// Sample a blinding factor.
    ///
    /// - Transparent: returns `F::zero()` without using RNG
    /// - ZK: returns a random scalar from the RNG
    ///
    /// Note: Blinds are sampled from RNG (not transcript) because they are
    /// private to the prover. The transcript is only used for public values
    /// and deriving challenges that both prover and verifier compute.
    fn sample<F: Field, R: rand_core::RngCore>(rng: &mut R) -> F;

    /// Mask a group element with a blinding factor.
    ///
    /// - Transparent: returns `value` unchanged
    /// - ZK: returns `value + base * blind`
    fn mask<G: Group>(value: G, base: &G, blind: &G::Scalar) -> G;
}

/// Transparent mode - no blinding.
///
/// All samples return zero, all masks return the value unchanged.
/// This is the default mode and produces non-hiding proofs.
pub struct Transparent;

impl Mode for Transparent {
    fn sample<F: Field, R: rand_core::RngCore>(_rng: &mut R) -> F {
        F::zero()
    }

    fn mask<G: Group>(value: G, _base: &G, _blind: &G::Scalar) -> G {
        value
    }
}

/// Zero-knowledge mode - samples blinds from RNG.
///
/// Produces hiding proofs by masking protocol messages with random blinds.
/// Blinds are sampled from private randomness (RNG), not the transcript,
/// because they must not affect the public challenge derivation.
#[cfg(feature = "zk")]
pub struct ZK;

#[cfg(feature = "zk")]
impl Mode for ZK {
    fn sample<F: Field, R: rand_core::RngCore>(rng: &mut R) -> F {
        F::random(rng)
    }

    fn mask<G: Group>(value: G, base: &G, blind: &G::Scalar) -> G {
        value + base.scale(blind)
    }
}
