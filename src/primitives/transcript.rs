//! Fiat-Shamir transcript traits for Dory's evaluation proof protocol.
//!
//! These traits abstract the prover and verifier sides of the Fiat-Shamir
//! transform. With spongefish, proof data is serialized into a NARG string
//! (`Vec<u8>`) by the prover and deserialized by the verifier.

use crate::error::DoryError;
use crate::primitives::arithmetic::{Group, PairingCurve};

/// Prover-side Fiat-Shamir transcript.
///
/// Absorbs proof elements into the sponge and serializes them into the
/// NARG string. Challenges are squeezed deterministically.
pub trait ProverTranscript<E: PairingCurve> {
    /// Absorb public data (not in NARG string, but bound to the sponge state).
    fn public_u32(&mut self, val: u32);

    /// Absorb a GT element (goes into the NARG string).
    fn absorb_gt(&mut self, val: &E::GT);

    /// Absorb a G1 element (goes into the NARG string).
    fn absorb_g1(&mut self, val: &E::G1);

    /// Absorb a G2 element (goes into the NARG string).
    fn absorb_g2(&mut self, val: &E::G2);

    /// Absorb a scalar field element (goes into the NARG string).
    fn absorb_field(&mut self, val: &<E::G1 as Group>::Scalar);

    /// Squeeze a scalar challenge from the sponge.
    fn squeeze_scalar(&mut self) -> <E::G1 as Group>::Scalar;
}

/// Verifier-side Fiat-Shamir transcript.
///
/// Reads proof elements from the NARG string and absorbs them into
/// the sponge. Challenges are squeezed deterministically.
pub trait VerifierTranscript<E: PairingCurve> {
    /// Absorb public data (must match the prover's `public_u32` calls).
    ///
    /// # Errors
    /// Returns `DoryError` if the sponge state is inconsistent.
    fn public_u32(&mut self, val: u32) -> Result<(), DoryError>;

    /// Read a GT element from the NARG string.
    ///
    /// # Errors
    /// Returns `DoryError` if deserialization or sponge absorption fails.
    fn read_gt(&mut self) -> Result<E::GT, DoryError>;

    /// Read a G1 element from the NARG string.
    ///
    /// # Errors
    /// Returns `DoryError` if deserialization or sponge absorption fails.
    fn read_g1(&mut self) -> Result<E::G1, DoryError>;

    /// Read a G2 element from the NARG string.
    ///
    /// # Errors
    /// Returns `DoryError` if deserialization or sponge absorption fails.
    fn read_g2(&mut self) -> Result<E::G2, DoryError>;

    /// Read a scalar field element from the NARG string.
    ///
    /// # Errors
    /// Returns `DoryError` if deserialization or sponge absorption fails.
    fn read_field(&mut self) -> Result<<E::G1 as Group>::Scalar, DoryError>;

    /// Squeeze a scalar challenge from the sponge.
    ///
    /// # Errors
    /// Returns `DoryError` if the sponge squeeze fails.
    fn squeeze_scalar(&mut self) -> Result<<E::G1 as Group>::Scalar, DoryError>;
}
