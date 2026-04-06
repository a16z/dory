//! Domain separator and instance encoding for the Dory evaluation proof protocol.
//!
//! The domain separator identifies the protocol and binds public parameters
//! (nu, sigma, zk) into the sponge state via the instance.

use spongefish::{ProverState, VerifierState};

/// Encode protocol parameters into an instance byte array for domain binding.
///
/// The instance encodes `nu` (4 bytes LE), `sigma` (4 bytes LE), and `zk` flag
/// (1 byte) so that proofs generated with different parameters are domain-separated.
fn dory_instance(nu: usize, sigma: usize, zk: bool) -> [u8; 9] {
    let mut buf = [0u8; 9];
    buf[..4].copy_from_slice(&(nu as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&(sigma as u32).to_le_bytes());
    buf[8] = zk as u8;
    buf
}

/// Create a Dory prover state with the standard hash.
///
/// Combines domain separator + instance binding. After proving, extract
/// proof bytes via `prover.narg_string().to_vec()`.
pub fn dory_prover(nu: usize, sigma: usize, zk: bool) -> ProverState {
    let instance = dory_instance(nu, sigma, zk);
    spongefish::domain_separator!("dory-pcs-v2")
        .instance(&instance)
        .std_prover()
}

/// Create a Dory verifier state with the standard hash.
///
/// Combines domain separator + instance binding. After verification,
/// call `verifier.check_eof()?` to assert all proof bytes were consumed.
pub fn dory_verifier(nu: usize, sigma: usize, zk: bool, proof_bytes: &[u8]) -> VerifierState<'_> {
    let instance = dory_instance(nu, sigma, zk);
    spongefish::domain_separator!("dory-pcs-v2")
        .instance(&instance)
        .std_verifier(proof_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separator_builds_without_zk() {
        let _prover = dory_prover(4, 4, false);
    }

    #[test]
    fn domain_separator_builds_with_zk() {
        let _prover = dory_prover(4, 4, true);
    }
}
