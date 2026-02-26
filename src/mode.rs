//! Mode trait for transparent vs zero-knowledge proofs.
use crate::primitives::arithmetic::{Field, Group};

/// Determines whether protocol messages are blinded (ZK) or unblinded (transparent).
pub trait Mode: 'static {
    /// Sample a blinding scalar: zero in Transparent mode, random in ZK mode.
    fn sample<F: Field, R: rand_core::RngCore>(rng: &mut R) -> F;
    /// Mask a group element: identity in Transparent mode, `value + base * blind` in ZK mode.
    fn mask<G: Group>(value: G, base: &G, blind: &G::Scalar) -> G;
}

/// Transparent mode: no blinding, non-hiding proofs.
pub struct Transparent;
impl Mode for Transparent {
    fn sample<F: Field, R: rand_core::RngCore>(_rng: &mut R) -> F {
        F::zero()
    }
    fn mask<G: Group>(value: G, _base: &G, _blind: &G::Scalar) -> G {
        value
    }
}

/// Zero-knowledge mode: samples blinds from RNG for hiding proofs.
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
