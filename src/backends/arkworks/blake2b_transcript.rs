//! Blake2b-based Fiat-Shamir transcript for Dory proofs
//!
//! The transcript is positional: it absorbs each message as its length and
//! its bytes, with no label, and it draws every challenge at full width.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use crate::primitives::arithmetic::PairingCurve;
use crate::primitives::serialization::Compress;
use crate::primitives::transcript::{Challenge, Transcript};
use crate::primitives::DorySerialize;
use ark_ff::PrimeField;
use blake2::Blake2b512;
use digest::{Digest, Output};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Blake2bTranscript<E: PairingCurve> {
    hasher: Blake2b512,
    _phantom: PhantomData<E>,
}

impl<E: PairingCurve> Blake2bTranscript<E> {
    pub fn new(domain_label: &[u8]) -> Self {
        let mut hasher = Blake2b512::default();
        hasher.update(domain_label);
        Self {
            hasher,
            _phantom: PhantomData,
        }
    }

    /// Absorbs `bytes` as its little-endian `u64` length, then the bytes.
    pub fn append_bytes(&mut self, bytes: &[u8]) {
        self.hasher.update((bytes.len() as u64).to_le_bytes());
        self.hasher.update(bytes);
    }

    /// Draws a full-width scalar: the 64-byte digest of the state, reduced
    /// modulo the field order. The digest is then absorbed.
    pub fn challenge_scalar_impl<F: PrimeField>(&mut self) -> F {
        let h = self.hasher.clone();
        let digest: Output<Blake2b512> = h.finalize();

        let repr = digest.to_vec();
        let fe = F::from_le_bytes_mod_order(&repr);

        if fe.is_zero() {
            panic!("Challenge scalar cannot be zero")
        }

        self.hasher.update(&repr);

        fe
    }

    pub fn reset(&mut self, domain_label: &[u8]) {
        *self = Self::new(domain_label);
    }
}

impl Transcript for Blake2bTranscript<crate::backends::arkworks::BN254> {
    type Curve = crate::backends::arkworks::BN254;

    fn append_serde<S: DorySerialize>(&mut self, s: &S) {
        let mut bytes: Vec<u8> = Vec::new();
        s.serialize_with_mode(&mut bytes, Compress::Yes)
            .expect("DorySerialize should not fail");
        self.append_bytes(&bytes);
    }

    /// Draws every challenge at full width, whatever its
    /// [`Challenge::width`].
    fn challenge_scalar(&mut self, _challenge: Challenge) -> crate::backends::arkworks::ArkFr {
        use crate::backends::arkworks::ArkFr;
        ArkFr(self.challenge_scalar_impl())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::arkworks::BN254;

    #[test]
    fn transcript_consistency() {
        let mut t1: Blake2bTranscript<BN254> = Blake2bTranscript::new(b"demo");
        let mut t2: Blake2bTranscript<BN254> = Blake2bTranscript::new(b"demo");

        // Same sequence of messages => same challenge
        t1.append_bytes(b"hello");
        t2.append_bytes(b"hello");

        let c1 = t1.challenge_scalar(Challenge::Beta);
        let c2 = t2.challenge_scalar(Challenge::Beta);

        assert_eq!(c1, c2);
    }

    #[test]
    fn transcript_different_messages() {
        let mut t1: Blake2bTranscript<BN254> = Blake2bTranscript::new(b"demo");
        let mut t2: Blake2bTranscript<BN254> = Blake2bTranscript::new(b"demo");

        t1.append_bytes(b"hello");
        t2.append_bytes(b"world");

        let c1 = t1.challenge_scalar(Challenge::Beta);
        let c2 = t2.challenge_scalar(Challenge::Beta);

        assert_ne!(c1, c2);
    }

    /// The role only names the draw: equal states give equal challenges.
    #[test]
    fn challenge_role_is_not_absorbed() {
        let mut t1: Blake2bTranscript<BN254> = Blake2bTranscript::new(b"demo");
        let mut t2: Blake2bTranscript<BN254> = Blake2bTranscript::new(b"demo");

        t1.append_bytes(b"hello");
        t2.append_bytes(b"hello");

        assert_eq!(
            t1.challenge_scalar(Challenge::Alpha),
            t2.challenge_scalar(Challenge::Gamma)
        );
    }

    /// Two draws with no absorb between them differ, because each draw
    /// absorbs its digest.
    #[test]
    fn back_to_back_draws_differ() {
        let mut t: Blake2bTranscript<BN254> = Blake2bTranscript::new(b"demo");
        t.append_bytes(b"hello");

        let alpha = t.challenge_scalar(Challenge::Alpha);
        let gamma = t.challenge_scalar(Challenge::Gamma);

        assert_ne!(alpha, gamma);
    }
}
