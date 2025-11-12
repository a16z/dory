//! Arkworks-specific setup wrappers
//!
//! Provides wrapper types for `ProverSetup` and `VerifierSetup` with transparent access.
//! Serialization implementations via `CanonicalSerialize` and `CanonicalDeserialize`
//! are in the `ark_serde` module.

use crate::setup::{ProverSetup, VerifierSetup};
use rand_core::RngCore;
use std::ops::{Deref, DerefMut};

use super::BN254;

/// Wrapper around `ProverSetup<BN254>` with arkworks canonical serialization
///
/// Provides transparent access to the inner setup while adding support for
/// arkworks' CanonicalSerialize and CanonicalDeserialize traits, allowing
/// easy serialization for users of the arkworks ecosystem.
#[derive(Clone, Debug)]
pub struct ArkworksProverSetup(pub ProverSetup<BN254>);

/// Wrapper around `VerifierSetup<BN254>` with arkworks canonical serialization
///
/// Provides transparent access to the inner setup while adding support for
/// arkworks' CanonicalSerialize and CanonicalDeserialize traits, allowing
/// easy serialization for users of the arkworks ecosystem.
#[derive(Clone, Debug)]
pub struct ArkworksVerifierSetup(pub VerifierSetup<BN254>);

impl ArkworksProverSetup {
    /// Generate new prover setup with transparent randomness
    ///
    /// For square matrices, generates n = 2^((max_log_n+1)/2) generators for both G1 and G2,
    /// supporting polynomials up to 2^max_log_n coefficients arranged as n×n matrices.
    ///
    /// # Parameters
    /// - `rng`: Random number generator
    /// - `max_log_n`: Maximum log₂ of polynomial size (for n×n matrix with n² = 2^max_log_n)
    pub fn new<R: RngCore>(rng: &mut R, max_log_n: usize) -> Self {
        Self(ProverSetup::new(rng, max_log_n))
    }

    /// Load prover setup from disk cache, or generate and cache if not available
    #[cfg(feature = "disk-persistence")]
    pub fn new_from_urs<R: RngCore>(rng: &mut R, max_log_n: usize) -> Self {
        let (prover_setup, _) = crate::setup::<BN254, _>(rng, max_log_n);
        Self(prover_setup)
    }

    /// Derive verifier setup from this prover setup
    pub fn to_verifier_setup(&self) -> ArkworksVerifierSetup {
        ArkworksVerifierSetup(self.0.to_verifier_setup())
    }

    /// Unwrap into inner `ProverSetup<BN254>`
    pub fn into_inner(self) -> ProverSetup<BN254> {
        self.0
    }
}

impl ArkworksVerifierSetup {
    /// Unwrap into inner `VerifierSetup<BN254>`
    pub fn into_inner(self) -> VerifierSetup<BN254> {
        self.0
    }
}

impl From<ProverSetup<BN254>> for ArkworksProverSetup {
    fn from(setup: ProverSetup<BN254>) -> Self {
        Self(setup)
    }
}

impl From<ArkworksProverSetup> for ProverSetup<BN254> {
    fn from(setup: ArkworksProverSetup) -> Self {
        setup.0
    }
}

impl From<VerifierSetup<BN254>> for ArkworksVerifierSetup {
    fn from(setup: VerifierSetup<BN254>) -> Self {
        Self(setup)
    }
}

impl From<ArkworksVerifierSetup> for VerifierSetup<BN254> {
    fn from(setup: ArkworksVerifierSetup) -> Self {
        setup.0
    }
}

impl Deref for ArkworksProverSetup {
    type Target = ProverSetup<BN254>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ArkworksProverSetup {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for ArkworksVerifierSetup {
    type Target = VerifierSetup<BN254>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ArkworksVerifierSetup {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
