//! Backend implementations for Dory primitives
//!
//! This module provides concrete implementations of the abstract traits
//! defined in the primitives module. Currently supports:
//! - arkworks: BN254 pairing curve implementation using arkworks
//! - blake2b_transcript: Fiat-Shamir transcript using Blake2b hash function + arkworks
//! - serde_bridge: Blanket implementations bridging arkworks serialization to Dory

#[cfg(feature = "arkworks")]
mod serde_bridge;

#[cfg(feature = "arkworks")]
pub mod arkworks;

#[cfg(feature = "arkworks")]
pub mod blake2b_transcript;

#[cfg(feature = "arkworks")]
pub use arkworks::*;

#[cfg(feature = "arkworks")]
pub use blake2b_transcript::Blake2bTranscript;
