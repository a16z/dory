//! Prepared point cache for BN254 pairing optimization
//!
//! This module provides a global cache for prepared G1/G2 points that are reused
//! across multiple pairing operations. Prepared points skip the affine conversion
//! and preprocessing steps, providing ~20-30% speedup for repeated pairings.

use super::ark_group::{ArkG1, ArkG2};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use once_cell::sync::OnceCell;

/// Global cache for prepared points
#[derive(Debug)]
pub struct PreparedCache {
    pub(crate) g1_prepared: Vec<<Bn254 as Pairing>::G1Prepared>,
    pub(crate) g2_prepared: Vec<<Bn254 as Pairing>::G2Prepared>,
}

static CACHE: OnceCell<PreparedCache> = OnceCell::new();

/// Initialize the global cache with G1 and G2 vectors.
///
/// Both vectors must be provided (typically setup generators).
/// This function can only be called once; subsequent calls will panic.
///
/// # Arguments
/// * `g1_vec` - Vector of G1 points to prepare and cache
/// * `g2_vec` - Vector of G2 points to prepare and cache
///
/// # Panics
/// Panics if the cache has already been initialized.
///
/// # Example
/// ```ignore
/// use dory_pcs::backends::arkworks::{init_cache, BN254};
/// use dory_pcs::setup::ProverSetup;
///
/// let setup = ProverSetup::<BN254>::new(&mut rng, max_log_n);
/// init_cache(&setup.g1_vec, &setup.g2_vec);
/// ```
pub fn init_cache(g1_vec: &[ArkG1], g2_vec: &[ArkG2]) {
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

    CACHE
        .set(PreparedCache {
            g1_prepared,
            g2_prepared,
        })
        .expect("Cache already initialized");
}

/// Get prepared G1 slice from cache.
///
/// Returns `None` if cache has not been initialized.
///
/// # Returns
/// Reference to the cached prepared G1 points, or `None` if uninitialized.
pub fn get_prepared_g1() -> Option<&'static [<Bn254 as Pairing>::G1Prepared]> {
    CACHE.get().map(|cache| cache.g1_prepared.as_slice())
}

/// Get prepared G2 slice from cache.
///
/// Returns `None` if cache has not been initialized.
///
/// # Returns
/// Reference to the cached prepared G2 points, or `None` if uninitialized.
pub fn get_prepared_g2() -> Option<&'static [<Bn254 as Pairing>::G2Prepared]> {
    CACHE.get().map(|cache| cache.g2_prepared.as_slice())
}

/// Check if cache is initialized.
///
/// # Returns
/// `true` if cache has been initialized, `false` otherwise.
pub fn is_cached() -> bool {
    CACHE.get().is_some()
}
