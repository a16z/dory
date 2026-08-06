//! Prepared point cache for BN254 pairing optimization
//!
//! This module provides a global cache for prepared G1/G2 points that are reused
//! across multiple pairing operations. Prepared points skip the affine conversion
//! and preprocessing steps, providing ~20-30% speedup for repeated pairings.
//!
//! Cache entries are bound to their setup generators. A cached superset is reused only
//! when the requested generators are matching prefixes; otherwise it is replaced.

use super::ark_group::{ArkG1, ArkG2};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use std::sync::{Arc, RwLock};

/// Global cache for prepared points
#[derive(Debug, Clone)]
pub struct PreparedCache {
    /// Prepared G1 points for efficient pairing operations
    pub g1_prepared: Vec<<Bn254 as Pairing>::G1Prepared>,
    /// Prepared G2 points for efficient pairing operations
    pub g2_prepared: Vec<<Bn254 as Pairing>::G2Prepared>,
    g1_generators: Vec<ArkG1>,
    g2_generators: Vec<ArkG2>,
}

impl PreparedCache {
    fn new(g1_vec: &[ArkG1], g2_vec: &[ArkG2]) -> Self {
        let g1_prepared = g1_vec
            .iter()
            .map(|g| {
                let affine: G1Affine = g.0.into();
                affine.into()
            })
            .collect();
        let g2_prepared = g2_vec
            .iter()
            .map(|g| {
                let affine: G2Affine = g.0.into();
                affine.into()
            })
            .collect();

        Self {
            g1_prepared,
            g2_prepared,
            g1_generators: g1_vec.to_vec(),
            g2_generators: g2_vec.to_vec(),
        }
    }

    /// Returns whether `generators` are a prefix of the cached G1 setup.
    pub fn matches_g1(&self, generators: &[ArkG1]) -> bool {
        self.g1_generators.starts_with(generators)
    }

    /// Returns whether `generators` are a prefix of the cached G2 setup.
    pub fn matches_g2(&self, generators: &[ArkG2]) -> bool {
        self.g2_generators.starts_with(generators)
    }

    fn matches(&self, g1_vec: &[ArkG1], g2_vec: &[ArkG2]) -> bool {
        self.matches_g1(g1_vec) && self.matches_g2(g2_vec)
    }
}

static CACHE: RwLock<Option<Arc<PreparedCache>>> = RwLock::new(None);

/// Initialize the global cache with G1 and G2 vectors.
///
/// A cached superset is reused only when both requested generator vectors are matching
/// prefixes. Any generator mismatch replaces the cache, including equal-length setups.
///
/// Pairing operations independently validate generator identity before using this cache,
/// so proofs from multiple setups can safely run concurrently.
///
/// # Arguments
/// * `g1_vec` - Vector of G1 points to prepare and cache
/// * `g2_vec` - Vector of G2 points to prepare and cache
///
/// # Panics
/// Panics if the internal `RwLock` is poisoned.
///
/// # Example
/// ```ignore
/// use dory_pcs::backends::arkworks::{init_cache, BN254};
/// use dory_pcs::setup::ProverSetup;
///
/// let setup = ProverSetup::<BN254>::new(max_log_n);
/// init_cache(&setup.g1_vec, &setup.g2_vec);
/// ```
pub fn init_cache(g1_vec: &[ArkG1], g2_vec: &[ArkG2]) {
    {
        let read_guard = CACHE.read().unwrap();
        if let Some(ref cache) = *read_guard {
            if cache.matches(g1_vec, g2_vec) {
                return;
            }
        }
    }

    let replacement = Arc::new(PreparedCache::new(g1_vec, g2_vec));
    let mut write_guard = CACHE.write().unwrap();
    if let Some(ref cache) = *write_guard {
        if cache.matches(g1_vec, g2_vec) {
            return;
        }
    }
    *write_guard = Some(replacement);
}

/// Invalidate the global cache, dropping any prepared points.
///
/// # Panics
/// Panics if the internal `RwLock` is poisoned.
pub fn invalidate_cache() {
    *CACHE.write().unwrap() = None;
}

/// Get a shared reference to the prepared cache.
///
/// Returns `None` if cache has not been initialized.
/// The returned `Arc` keeps the cache data alive even if the cache is replaced.
/// Consumers must check [`PreparedCache::matches_g1`] or
/// [`PreparedCache::matches_g2`] before using the corresponding prepared points.
///
/// # Panics
/// Panics if the internal `RwLock` is poisoned.
///
/// # Returns
/// Arc-wrapped cache, or `None` if uninitialized.
pub fn get_prepared_cache() -> Option<Arc<PreparedCache>> {
    CACHE.read().unwrap().clone()
}

/// Check if any cache is initialized.
///
/// This does not indicate that the cache belongs to a particular setup. Call
/// [`init_cache`] for every setup that should receive cached pairing preparation.
///
/// # Panics
/// Panics if the internal `RwLock` is poisoned.
///
/// # Returns
/// `true` if cache has been initialized, `false` otherwise.
pub fn is_cached() -> bool {
    CACHE.read().unwrap().is_some()
}
