//! Domain separator and interaction pattern for the Dory evaluation proof protocol.
//!
//! The domain separator identifies the protocol and binds public parameters
//! (sigma, zk) into the sponge state via the instance.
//!
//! The interaction pattern declares the exact sequence of prover/verifier/public
//! messages in the protocol. `CheckedProverState` and `CheckedVerifierState` enforce
//! this pattern at runtime — any deviation (wrong message kind, wrong type, wrong
//! count, extra steps, or incomplete patterns) panics with diagnostics.
//!
//! Sub-protocols (sigma1, sigma2, reduce rounds, scalar product) are declared as
//! reusable pattern builders and composed into the top-level pattern via scoped
//! nesting, giving clear diagnostic paths like `"zk::sigma1::challenge"`.

use ark_bn254::{Fq12, Fr, G1Projective, G2Projective};
use spongefish::{CheckedProverState, CheckedVerifierState, InteractionPattern, PatternBuilder};

/// Encode protocol parameters into an instance byte array for domain binding.
///
/// The instance encodes `sigma` (4 bytes LE) and `zk` flag (1 byte) so that
/// proofs generated with different parameters are domain-separated.
fn dory_instance(sigma: usize, zk: bool) -> [u8; 5] {
    let mut buf = [0u8; 5];
    buf[..4].copy_from_slice(&(sigma as u32).to_le_bytes());
    buf[4] = zk as u8;
    buf
}

// ---------------------------------------------------------------------------
// Reusable sub-protocol patterns
// ---------------------------------------------------------------------------

/// Sigma1 proof pattern: proves knowledge of (y, rE2, ry).
///
/// Messages: a1 (G2), a2 (G1), challenge (Fr), z1 z2 z3 (Fr)
fn sigma1_pattern(b: &mut PatternBuilder) {
    b.prover_message::<G2Projective>("a1");
    b.prover_message::<G1Projective>("a2");
    b.verifier_message::<Fr>("challenge");
    b.prover_message::<Fr>("z1");
    b.prover_message::<Fr>("z2");
    b.prover_message::<Fr>("z3");
}

/// Sigma2 proof pattern: proves e(E1, Γ2,fin) - D2 consistency.
///
/// Messages: a (GT), challenge (Fr), z1 z2 (Fr)
fn sigma2_pattern(b: &mut PatternBuilder) {
    b.prover_message::<Fq12>("a");
    b.verifier_message::<Fr>("challenge");
    b.prover_message::<Fr>("z1");
    b.prover_message::<Fr>("z2");
}

/// Single Dory-Reduce round pattern (first + second reduce messages).
///
/// First reduce: D1L, D1R, D2L, D2R (GT), E1β (G1), E2β (G2), β challenge
/// Second reduce: C+, C- (GT), E1+, E1- (G1), E2+, E2- (G2), α challenge
fn reduce_round_pattern(b: &mut PatternBuilder) {
    // First reduce message
    b.prover_message::<Fq12>("d1-left");
    b.prover_message::<Fq12>("d1-right");
    b.prover_message::<Fq12>("d2-left");
    b.prover_message::<Fq12>("d2-right");
    b.prover_message::<G1Projective>("e1-beta");
    b.prover_message::<G2Projective>("e2-beta");
    b.verifier_message::<Fr>("beta");

    // Second reduce message
    b.prover_message::<Fq12>("c-plus");
    b.prover_message::<Fq12>("c-minus");
    b.prover_message::<G1Projective>("e1-plus");
    b.prover_message::<G1Projective>("e1-minus");
    b.prover_message::<G2Projective>("e2-plus");
    b.prover_message::<G2Projective>("e2-minus");
    b.verifier_message::<Fr>("alpha");
}

/// ZK scalar product proof pattern.
///
/// Messages: p1 p2 q r (GT), challenge (Fr), e1 (G1), e2 (G2), r1 r2 r3 (Fr)
fn scalar_product_proof_pattern(b: &mut PatternBuilder) {
    b.prover_message::<Fq12>("p1");
    b.prover_message::<Fq12>("p2");
    b.prover_message::<Fq12>("q");
    b.prover_message::<Fq12>("r");
    b.verifier_message::<Fr>("challenge");
    b.prover_message::<G1Projective>("e1");
    b.prover_message::<G2Projective>("e2");
    b.prover_message::<Fr>("r1");
    b.prover_message::<Fr>("r2");
    b.prover_message::<Fr>("r3");
}

// ---------------------------------------------------------------------------
// Top-level pattern composition
// ---------------------------------------------------------------------------

/// Declare the interaction pattern for a Dory evaluation proof.
///
/// Composes sub-protocol patterns (sigma proofs, reduce rounds, scalar product)
/// into the full protocol using scoped nesting. Diagnostic paths look like
/// `"zk::sigma1::challenge"` or `"round-0::beta"`.
///
/// # Parameters
/// - `sigma`: Log₂ of number of columns (determines number of reduce rounds)
/// - `zk`: Whether zero-knowledge mode is enabled
fn dory_pattern(sigma: usize, zk: bool) -> InteractionPattern {
    let mut b = PatternBuilder::new();

    // Public inputs
    b.public_message::<[u8; 4]>("nu");
    b.public_message::<[u8; 4]>("sigma");

    // VMV message
    b.scope("vmv", |b| {
        b.prover_message::<Fq12>("c");
        b.prover_message::<Fq12>("d2");
        b.prover_message::<G1Projective>("e1");
    });

    // ZK: commitment blinds + sigma proofs
    if zk {
        b.scope("zk", |b| {
            b.prover_message::<G2Projective>("e2");
            b.prover_message::<G1Projective>("y-com");
            b.scope("sigma1", sigma1_pattern);
            b.scope("sigma2", sigma2_pattern);
        });
    }

    // Reduce rounds
    for round in 0..sigma {
        b.scope(&format!("round-{round}"), reduce_round_pattern);
    }

    // Gamma challenge
    b.verifier_message::<Fr>("gamma");

    // ZK: scalar product proof
    if zk {
        b.scope("scalar-product", scalar_product_proof_pattern);
    }

    // Final scalar product message
    b.scope("final", |b| {
        b.prover_message::<G1Projective>("e1");
        b.prover_message::<G2Projective>("e2");
    });
    b.verifier_message::<Fr>("d");

    b.finalize()
}

/// Create a checked Dory prover state with the standard hash.
///
/// Combines domain separator + instance binding + interaction pattern enforcement.
/// Every `prover_message`/`verifier_message`/`public_message` call on the returned
/// state is validated against the pre-declared pattern — any mismatch panics.
///
/// After proving, call `prover.check_complete()` to assert the full pattern was
/// followed, then extract proof bytes via `.narg_string().to_vec()`.
pub fn dory_prover(sigma: usize, zk: bool) -> CheckedProverState {
    let instance = dory_instance(sigma, zk);
    let pattern = dory_pattern(sigma, zk);
    let inner = spongefish::domain_separator!("dory-pcs-v2")
        .instance(&instance)
        .std_prover();
    CheckedProverState::new(inner, pattern)
}

/// Create a checked Dory verifier state with the standard hash.
///
/// Combines domain separator + instance binding + interaction pattern enforcement.
/// Every message read from the proof is validated against the pre-declared pattern.
///
/// After verification, call `verifier.check_eof()` to assert:
/// 1. The full pattern was followed (panics if incomplete)
/// 2. All proof bytes were consumed (returns `Err` if trailing bytes exist)
pub fn dory_verifier(sigma: usize, zk: bool, proof_bytes: &[u8]) -> CheckedVerifierState<'_> {
    let instance = dory_instance(sigma, zk);
    let pattern = dory_pattern(sigma, zk);
    let inner = spongefish::domain_separator!("dory-pcs-v2")
        .instance(&instance)
        .std_verifier(proof_bytes);
    CheckedVerifierState::new(inner, pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separator_builds_without_zk() {
        let _prover = dory_prover(4, false);
    }

    #[test]
    fn domain_separator_builds_with_zk() {
        let _prover = dory_prover(4, true);
    }

    #[test]
    fn pattern_round_count_increases_with_sigma() {
        let p1 = dory_pattern(2, false);
        let p2 = dory_pattern(3, false);
        assert!(p2.len() > p1.len());
    }

    #[test]
    fn zk_pattern_larger_than_transparent() {
        let transparent = dory_pattern(4, false);
        let zk = dory_pattern(4, true);
        assert!(zk.len() > transparent.len());
    }
}
