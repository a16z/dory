//! Spongefish codec implementations for Dory's transcript traits.
//!
//! Maps [`ProverTranscript`] and [`VerifierTranscript`] to spongefish's
//! NARG protocol using the unified message API.

use crate::backends::arkworks::{ArkFr, ArkG1, ArkG2, ArkGT, BN254};
use crate::error::DoryError;
use crate::primitives::transcript::{ProverTranscript, VerifierTranscript};

use ark_bn254::{Fq12, Fr, G1Projective, G2Projective};

macro_rules! impl_prover_absorb {
    ($($method:ident, $wrapper:ty);+ $(;)?) => {
        $(fn $method(&mut self, val: &$wrapper) {
            self.prover_message(&val.0);
        })+
    };
}

macro_rules! impl_verifier_read {
    ($($method:ident -> $wrapper:ident($inner:ty));+ $(;)?) => {
        $(fn $method(&mut self) -> Result<$wrapper, DoryError> {
            self.prover_message::<$inner>()
                .map($wrapper)
                .map_err(|e| DoryError::SpongeVerification(e.to_string()))
        })+
    };
}

// ---------------------------------------------------------------------------
// CheckedProverState implements ProverTranscript<BN254>
// ---------------------------------------------------------------------------
impl ProverTranscript<BN254> for spongefish::CheckedProverState {
    fn public_u32(&mut self, val: u32) {
        self.public_message(&val.to_le_bytes());
    }

    impl_prover_absorb! {
        absorb_gt,    ArkGT;
        absorb_g1,    ArkG1;
        absorb_g2,    ArkG2;
        absorb_field, ArkFr;
    }

    fn squeeze_scalar(&mut self) -> ArkFr {
        ArkFr(self.verifier_message::<Fr>())
    }
}

// ---------------------------------------------------------------------------
// CheckedVerifierState implements VerifierTranscript<BN254>
// ---------------------------------------------------------------------------
impl VerifierTranscript<BN254> for spongefish::CheckedVerifierState<'_> {
    fn public_u32(&mut self, val: u32) -> Result<(), DoryError> {
        self.public_message(&val.to_le_bytes());
        Ok(())
    }

    impl_verifier_read! {
        read_gt    -> ArkGT(Fq12);
        read_g1    -> ArkG1(G1Projective);
        read_g2    -> ArkG2(G2Projective);
        read_field -> ArkFr(Fr);
    }

    fn squeeze_scalar(&mut self) -> Result<ArkFr, DoryError> {
        Ok(ArkFr(self.verifier_message::<Fr>()))
    }
}
