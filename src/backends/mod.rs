//! Backend implementations for Dory primitives
//!
//! This module provides concrete implementations of the abstract traits
//! defined in the primitives module. Currently supports:
//! - arkworks: BN254 pairing curve implementation using Arkworks
//! - metal: GPU-accelerated backend for Apple Silicon via Metal

#[cfg(feature = "arkworks")]
pub mod arkworks;

#[cfg(feature = "arkworks")]
pub use arkworks::*;

#[cfg(feature = "metal-gpu")]
pub mod metal;
