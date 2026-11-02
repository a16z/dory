//! Prepared point cache for BN254 pairing optimization
//!
//! This module provides a global cache for prepared G1/G2 points that are reused
//! across multiple pairing operations. Prepared points skip the affine conversion
//! and preprocessing steps, providing ~20-30% speedup for repeated pairings.
//!
//! The cache remembers the points it prepared. A lookup returns prepared
//! points only for a prefix of those points, so a stale cache, or one built
//! from another setup, falls back to preparing the caller's points instead
//! of pairing against the wrong ones.

use super::ark_group::{ArkG1, ArkG2};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use rayon::prelude::*;
use std::sync::{Arc, RwLock};

/// Global cache for prepared points.
///
/// The prepared points are reachable only through
/// [`g1_prepared_for`](Self::g1_prepared_for) and
/// [`g2_prepared_for`](Self::g2_prepared_for), which check that the caller's
/// points are the ones that were prepared.
#[derive(Debug, Clone)]
pub struct PreparedCache {
    g1_prepared: Vec<<Bn254 as Pairing>::G1Prepared>,
    g2_prepared: Vec<<Bn254 as Pairing>::G2Prepared>,
    g1: Vec<ArkG1>,
    g2: Vec<ArkG2>,
}

impl PreparedCache {
    fn covers(&self, g1: &[ArkG1], g2: &[ArkG2]) -> bool {
        is_prefix(&self.g1, g1) && is_prefix(&self.g2, g2)
    }

    /// The number of cached G1 points.
    pub fn g1_len(&self) -> usize {
        self.g1.len()
    }

    /// The number of cached G2 points.
    pub fn g2_len(&self) -> usize {
        self.g2.len()
    }

    /// The prepared form of `g1`, if `g1` is a prefix of the cached G1 points.
    pub fn g1_prepared_for(&self, g1: &[ArkG1]) -> Option<&[<Bn254 as Pairing>::G1Prepared]> {
        is_prefix(&self.g1, g1).then(|| &self.g1_prepared[..g1.len()])
    }

    /// The prepared form of `g2`, if `g2` is a prefix of the cached G2 points.
    pub fn g2_prepared_for(&self, g2: &[ArkG2]) -> Option<&[<Bn254 as Pairing>::G2Prepared]> {
        is_prefix(&self.g2, g2).then(|| &self.g2_prepared[..g2.len()])
    }
}

/// Whether `points` is a prefix of `cached`. Comparing projective points
/// costs a few field multiplications each, far less than preparing them.
fn is_prefix<P: PartialEq + Sync>(cached: &[P], points: &[P]) -> bool {
    cached
        .get(..points.len())
        .is_some_and(|cached| cached.par_iter().zip(points).all(|(a, b)| a == b))
}

static CACHE: RwLock<Option<Arc<PreparedCache>>> = RwLock::new(None);

/// Initialize the global cache with G1 and G2 vectors.
///
/// If `g1_vec` and `g2_vec` are prefixes of the cached points, this does
/// nothing. Otherwise it replaces the cache, whether the cache is smaller or
/// was built from other points.
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
        if read_guard
            .as_ref()
            .is_some_and(|cache| cache.covers(g1_vec, g2_vec))
        {
            return;
        }
    }

    // Prepare outside the write lock: point preparation is expensive and
    // readers can keep using the old cache until the replacement is ready.
    let (g1_prepared, g2_prepared) = rayon::join(
        || {
            g1_vec
                .par_iter()
                .map(|g| {
                    let affine: G1Affine = g.0.into();
                    affine.into()
                })
                .collect()
        },
        || {
            g2_vec
                .par_iter()
                .map(|g| {
                    let affine: G2Affine = g.0.into();
                    affine.into()
                })
                .collect()
        },
    );

    let mut write_guard = CACHE.write().unwrap();

    // Double-check after acquiring the write lock (another thread may have initialized).
    if write_guard
        .as_ref()
        .is_some_and(|cache| cache.covers(g1_vec, g2_vec))
    {
        return;
    }

    *write_guard = Some(Arc::new(PreparedCache {
        g1_prepared,
        g2_prepared,
        g1: g1_vec.to_vec(),
        g2: g2_vec.to_vec(),
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
    CACHE.read().unwrap().clone()
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
