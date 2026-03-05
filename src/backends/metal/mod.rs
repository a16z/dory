/// Hardware-dependent GPU dispatch thresholds.
pub mod config;
/// GLV endomorphism scalar decomposition for BN254.
pub mod glv;
/// GPU context and dispatch utilities for Metal compute.
pub mod gpu;
/// Standalone GPU-accelerated pairing functions (drop-in for `BN254::multi_pair`).
#[cfg(feature = "arkworks")]
pub mod pairing;

pub use gpu::MetalGpu;
#[cfg(feature = "arkworks")]
pub use pairing::{multi_pair, multi_pair_g1_setup, multi_pair_g2_setup, MetalBN254};
