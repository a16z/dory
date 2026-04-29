//! Arkworks backend proof type
//!
//! Type alias for Dory proofs using arkworks group types.
//! Serialization implementations are in ark_serde.rs.

use super::{ArkG1, ArkG2, ArkGT};
use crate::proof::DoryProof;

/// Maximum number of reduce-and-fold rounds accepted by default proof deserialization.
///
/// This bounds allocation before a verifier setup is available. It is intentionally
/// conservative for current deployments; callers needing larger proofs should add
/// an explicitly bounded deserialization entry point tied to their setup.
pub const MAX_SERIALIZED_PROOF_ROUNDS: usize = 64;

/// Arkworks-specific Dory proof type
///
/// This is a type alias for `DoryProof` specialized to arkworks group types.
/// Serialization support via `CanonicalSerialize` and `CanonicalDeserialize`
/// is implemented in the `ark_serde` module.
pub type ArkDoryProof = DoryProof<ArkG1, ArkG2, ArkGT>;
