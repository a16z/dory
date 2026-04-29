//! Prepared point cache for BN254 pairing optimization
//!
//! This module provides a global cache for prepared G1/G2 points that are reused
//! across multiple pairing operations. Prepared points skip the affine conversion
//! and preprocessing steps, providing ~20-30% speedup for repeated pairings.
//!
//! The cache supports smart re-initialization: if a larger setup is needed,
//! the cache is automatically replaced. Smaller or equal setups reuse the existing cache.

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
}

#[derive(Debug, Clone)]
struct CachedPrepared {
    prepared: Arc<PreparedCache>,
    g1_vec: Vec<ArkG1>,
    g2_vec: Vec<ArkG2>,
}

static CACHE: RwLock<Option<Arc<CachedPrepared>>> = RwLock::new(None);

fn slice_starts_with<T: PartialEq>(cached: &[T], requested: &[T]) -> bool {
    cached.len() >= requested.len() && &cached[..requested.len()] == requested
}

fn cache_covers(cached: &CachedPrepared, g1_vec: &[ArkG1], g2_vec: &[ArkG2]) -> bool {
    slice_starts_with(&cached.g1_vec, g1_vec) && slice_starts_with(&cached.g2_vec, g2_vec)
}

/// Initialize the global cache with G1 and G2 vectors.
///
/// This function implements smart re-initialization:
/// - If the cache doesn't exist, it creates one
/// - If the cache exists but is too small, it replaces it with a larger one
/// - If the cache exists and is large enough, it does nothing (reuses existing)
///
/// This allows multiple proofs with different setup sizes to run in the same process.
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
    // Fast path: check if existing cache is sufficient (read lock only)
    {
        let read_guard = CACHE.read().unwrap();
        if let Some(ref cache) = *read_guard {
            if cache_covers(cache, g1_vec, g2_vec) {
                return; // Existing cache is large enough
            }
        }
    }

    // Slow path: need to initialize or grow the cache
    let mut write_guard = CACHE.write().unwrap();

    // Double-check after acquiring write lock (another thread may have initialized)
    if let Some(ref cache) = *write_guard {
        if cache_covers(cache, g1_vec, g2_vec) {
            return; // Another thread initialized a sufficient cache
        }
    }

    // Prepare the new cache
    let g1_prepared: Vec<<Bn254 as Pairing>::G1Prepared> = g1_vec
        .iter()
        .map(|g| {
            let affine: G1Affine = g.0.into();
            affine.into()
        })
        .collect();

    let g2_prepared: Vec<<Bn254 as Pairing>::G2Prepared> = g2_vec
        .iter()
        .map(|g| {
            let affine: G2Affine = g.0.into();
            affine.into()
        })
        .collect();

    *write_guard = Some(Arc::new(CachedPrepared {
        prepared: Arc::new(PreparedCache {
            g1_prepared,
            g2_prepared,
        }),
        g1_vec: g1_vec.to_vec(),
        g2_vec: g2_vec.to_vec(),
    }));
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
///
/// # Panics
/// Panics if the internal `RwLock` is poisoned.
///
/// # Returns
/// Arc-wrapped cache, or `None` if uninitialized.
pub fn get_prepared_cache() -> Option<Arc<PreparedCache>> {
    CACHE
        .read()
        .unwrap()
        .as_ref()
        .map(|cached| cached.prepared.clone())
}

pub(crate) fn get_prepared_cache_for_g1(g1_vec: &[ArkG1]) -> Option<Arc<PreparedCache>> {
    CACHE.read().unwrap().as_ref().and_then(|cached| {
        slice_starts_with(&cached.g1_vec, g1_vec).then(|| cached.prepared.clone())
    })
}

pub(crate) fn get_prepared_cache_for_g2(g2_vec: &[ArkG2]) -> Option<Arc<PreparedCache>> {
    CACHE.read().unwrap().as_ref().and_then(|cached| {
        slice_starts_with(&cached.g2_vec, g2_vec).then(|| cached.prepared.clone())
    })
}

/// Check if cache is initialized.
///
/// # Panics
/// Panics if the internal `RwLock` is poisoned.
///
/// # Returns
/// `true` if cache has been initialized, `false` otherwise.
pub fn is_cached() -> bool {
    CACHE.read().unwrap().is_some()
}
