//! Setup structures for Dory PCS
//!
//! The setup consists of:
//! - Prover setup: generators and parameters needed for proving
//! - Verifier setup: precomputed values for efficient verification

use crate::primitives::arithmetic::{Group, PairingCurve};
use crate::primitives::serialization::{DoryDeserialize, DorySerialize};
use rand_core::RngCore;

#[cfg(feature = "disk-persistence")]
use std::fs::{self, File};
#[cfg(feature = "disk-persistence")]
use std::io::{BufReader, BufWriter};
#[cfg(feature = "disk-persistence")]
use std::path::PathBuf;

/// Prover setup parameters
///
/// Contains the generators and parameters needed to create proofs.
/// The setup is transparent (no trusted setup) and can be generated
/// from public randomness.
///
/// For square matrices: |Γ₁| = |Γ₂| = 2^((max_log_n+1)/2)
#[derive(Clone, Debug, DorySerialize, DoryDeserialize)]
pub struct ProverSetup<E: PairingCurve> {
    /// Γ₁ - column generators in G1
    pub g1_vec: Vec<E::G1>,

    /// Γ₂ - row generators in G2
    pub g2_vec: Vec<E::G2>,

    /// h₁ - blinding generator in G1
    pub h1: E::G1,

    /// h₂ - blinding generator in G2
    pub h2: E::G2,

    /// h_t = e(h₁, h₂) - precomputed pairing
    pub ht: E::GT,
}

/// Verifier setup parameters
///
/// Contains precomputed pairing values for efficient verification.
/// Derived from the prover setup.
#[derive(Clone, Debug, DorySerialize, DoryDeserialize)]
pub struct VerifierSetup<E: PairingCurve> {
    /// Δ₁L\[k\] = e(Γ₁\[..2^(k-1)\], Γ₂\[..2^(k-1)\])
    pub delta_1l: Vec<E::GT>,

    /// Δ₁R\[k\] = e(Γ₁\[2^(k-1)..2^k\], Γ₂\[..2^(k-1)\])
    pub delta_1r: Vec<E::GT>,

    /// Δ₂L\[k\] = same as Δ₁L\[k\]
    pub delta_2l: Vec<E::GT>,

    /// Δ₂R\[k\] = e(Γ₁\[..2^(k-1)\], Γ₂\[2^(k-1)..2^k\])
    pub delta_2r: Vec<E::GT>,

    /// χ\[k\] = e(Γ₁\[..2^k\], Γ₂\[..2^k\])
    pub chi: Vec<E::GT>,

    /// First G1 generator
    pub g1_0: E::G1,

    /// First G2 generator
    pub g2_0: E::G2,

    /// Blinding generator in G1
    pub h1: E::G1,

    /// Blinding generator in G2
    pub h2: E::G2,

    /// h_t = e(h₁, h₂)
    pub ht: E::GT,

    /// Maximum log₂ of polynomial size supported
    pub max_log_n: usize,
}

impl<E: PairingCurve> ProverSetup<E> {
    /// Generate new prover setup with transparent randomness
    ///
    /// For square matrices, generates n = 2^((max_log_n+1)/2) generators for both G1 and G2,
    /// supporting polynomials up to 2^max_log_n coefficients arranged as n×n matrices.
    ///
    /// # Parameters
    /// - `rng`: Random number generator
    /// - `max_log_n`: Maximum log₂ of polynomial size (for n×n matrix with n² = 2^max_log_n)
    ///
    /// # Returns
    /// A new `ProverSetup` with randomly generated parameters
    pub fn new<R: RngCore>(rng: &mut R, max_log_n: usize) -> Self {
        // For square matrices: n = 2^((max_log_n+1)/2)
        let n = 1 << max_log_n.div_ceil(2);
        // Generate n random G1 generators (Γ₁)
        let g1_vec: Vec<E::G1> = (0..n).map(|_| E::G1::random(rng)).collect();
        // Generate n random G2 generators (Γ₂)
        let g2_vec: Vec<E::G2> = (0..n).map(|_| E::G2::random(rng)).collect();

        // Generate blinding generators
        let h1 = E::G1::random(rng);
        let h2 = E::G2::random(rng);

        // Precompute e(h₁, h₂)
        let ht = E::pair(&h1, &h2);

        Self {
            g1_vec,
            g2_vec,
            h1,
            h2,
            ht,
        }
    }

    /// Derive verifier setup from prover setup
    ///
    /// Precomputes pairing values for efficient verification by computing
    /// delta and chi values for all rounds of the inner product protocol.
    pub fn to_verifier_setup(&self) -> VerifierSetup<E> {
        let max_num_rounds = self.g1_vec.len().trailing_zeros() as usize;

        let mut delta_1l = Vec::with_capacity(max_num_rounds + 1);
        let mut delta_1r = Vec::with_capacity(max_num_rounds + 1);
        let mut delta_2r = Vec::with_capacity(max_num_rounds + 1);
        let mut chi = Vec::with_capacity(max_num_rounds + 1);

        for k in 0..=max_num_rounds {
            if k == 0 {
                // Base case: identities for deltas, single pairing for chi
                delta_1l.push(E::GT::identity());
                delta_1r.push(E::GT::identity());
                delta_2r.push(E::GT::identity());
                chi.push(E::pair(&self.g1_vec[0], &self.g2_vec[0]));
            } else {
                let half_len = 1 << (k - 1);
                let full_len = 1 << k;

                let g1_first_half = &self.g1_vec[..half_len];
                let g1_second_half = &self.g1_vec[half_len..full_len];
                let g2_first_half = &self.g2_vec[..half_len];
                let g2_second_half = &self.g2_vec[half_len..full_len];

                // Δ₁L[k] = χ[k-1] (reuse previous chi)
                delta_1l.push(chi[k - 1]);

                // Δ₁R[k] = e(Γ₁[2^(k-1)..2^k], Γ₂[..2^(k-1)])
                delta_1r.push(E::multi_pair(g1_second_half, g2_first_half));

                // Δ₂R[k] = e(Γ₁[..2^(k-1)], Γ₂[2^(k-1)..2^k])
                delta_2r.push(E::multi_pair(g1_first_half, g2_second_half));

                // χ[k] = χ[k-1] + e(Γ₁[2^(k-1)..2^k], Γ₂[2^(k-1)..2^k]) (incremental)
                chi.push(chi[k - 1].add(&E::multi_pair(g1_second_half, g2_second_half)));
            }
        }

        VerifierSetup {
            delta_1l: delta_1l.clone(),
            delta_1r,
            delta_2l: delta_1l, // Δ₂L = Δ₁L
            delta_2r,
            chi,
            g1_0: self.g1_vec[0],
            g2_0: self.g2_vec[0],
            h1: self.h1,
            h2: self.h2,
            ht: self.ht,
            max_log_n: max_num_rounds * 2, // Since square matrices: max_log_n = 2 * max_nu
        }
    }

    /// Returns the maximum nu (log column dimension) supported by this setup
    #[inline]
    pub fn max_nu(&self) -> usize {
        self.g1_vec.len().trailing_zeros() as usize
    }

    /// Returns the maximum sigma (log row dimension) supported by this setup
    ///
    /// For square matrices, this always equals max_nu()
    #[inline]
    pub fn max_sigma(&self) -> usize {
        self.max_nu()
    }

    /// Returns the maximum log₂ of polynomial size supported
    ///
    /// For n×n matrices: max_log_n = 2 * max_nu
    #[inline]
    pub fn max_log_n(&self) -> usize {
        self.max_nu() * 2
    }
}

/// Get the storage directory for Dory setup files
///
/// Returns the appropriate storage directory based on the OS:
/// - Linux: `~/.cache/dory/`
/// - macOS: `~/Library/Caches/dory/`
/// - Windows: `{FOLDERID_LocalAppData}\dory\`
///
/// Note: Uses XDG cache directory for persistent storage.
#[cfg(feature = "disk-persistence")]
fn get_storage_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|mut path| {
        path.push("dory");
        path
    })
}

/// Get the full path to the setup file for a given max_log_n
#[cfg(feature = "disk-persistence")]
fn get_storage_path(max_log_n: usize) -> Option<PathBuf> {
    get_storage_dir().map(|mut path| {
        path.push(format!("dory_{}.urs", max_log_n));
        path
    })
}

/// Save prover and verifier setups to disk
///
/// Serializes both setups to a `.urs` file in the storage directory.
/// If the storage directory doesn't exist, it will be created.
///
/// # Panics
/// Panics if:
/// - Storage directory cannot be determined
/// - Directory creation fails
/// - File creation fails
/// - Serialization of prover or verifier setup fails
#[cfg(feature = "disk-persistence")]
pub fn save_setup<E: PairingCurve>(
    prover: &ProverSetup<E>,
    verifier: &VerifierSetup<E>,
    max_log_n: usize,
) where
    ProverSetup<E>: DorySerialize,
    VerifierSetup<E>: DorySerialize,
{
    let storage_path = get_storage_path(max_log_n).expect("Failed to determine storage directory");

    if let Some(parent) = storage_path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("Failed to create storage directory: {}", e));
    }

    tracing::info!("Saving setup to {}", storage_path.display());

    let file = File::create(&storage_path)
        .unwrap_or_else(|e| panic!("Failed to create setup file: {}", e));

    let mut writer = BufWriter::new(file);

    DorySerialize::serialize_compressed(prover, &mut writer)
        .unwrap_or_else(|e| panic!("Failed to serialize prover setup: {}", e));

    DorySerialize::serialize_compressed(verifier, &mut writer)
        .unwrap_or_else(|e| panic!("Failed to serialize verifier setup: {}", e));

    tracing::info!("Successfully saved setup to disk");
}

/// Load prover and verifier setups from disk
///
/// Attempts to deserialize both setups from the saved `.urs` file.
///
/// # Errors
/// Returns `DoryError::InvalidURS` if:
/// - Storage directory cannot be determined
/// - Setup file doesn't exist
/// - File cannot be opened
/// - Deserialization fails
#[cfg(feature = "disk-persistence")]
pub fn load_setup<E: PairingCurve>(
    max_log_n: usize,
) -> Result<(ProverSetup<E>, VerifierSetup<E>), crate::DoryError>
where
    ProverSetup<E>: DoryDeserialize,
    VerifierSetup<E>: DoryDeserialize,
{
    let storage_path = get_storage_path(max_log_n).ok_or_else(|| {
        crate::DoryError::InvalidURS("Failed to determine storage directory".to_string())
    })?;

    if !storage_path.exists() {
        return Err(crate::DoryError::InvalidURS(format!(
            "Setup file not found at {}",
            storage_path.display()
        )));
    }

    tracing::info!("Looking for saved setup at {}", storage_path.display());

    let file = File::open(&storage_path)
        .map_err(|e| crate::DoryError::InvalidURS(format!("Failed to open setup file: {}", e)))?;

    let mut reader = BufReader::new(file);

    let prover = DoryDeserialize::deserialize_compressed(&mut reader).map_err(|e| {
        crate::DoryError::InvalidURS(format!("Failed to deserialize prover setup: {}", e))
    })?;

    let verifier = DoryDeserialize::deserialize_compressed(&mut reader).map_err(|e| {
        crate::DoryError::InvalidURS(format!("Failed to deserialize verifier setup: {}", e))
    })?;

    tracing::info!("Loaded setup for max_log_n={}", max_log_n);

    Ok((prover, verifier))
}
