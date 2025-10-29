//! Setup structures for Dory PCS
//!
//! The setup consists of:
//! - Prover setup: generators and parameters needed for proving
//! - Verifier setup: precomputed values for efficient verification

use crate::primitives::arithmetic::{Group, PairingCurve};
use rand_core::RngCore;

/// Prover setup parameters
///
/// Contains the generators and parameters needed to create proofs.
/// The setup is transparent (no trusted setup) and can be generated
/// from public randomness.
///
/// For square matrices: |Γ₁| = |Γ₂| = 2^((max_log_n+1)/2)
#[derive(Clone)]
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
#[derive(Clone)]
pub struct VerifierSetup<E: PairingCurve> {
    /// Δ₁L[k] = e(Γ₁[..2^(k-1)], Γ₂[..2^(k-1)])
    pub delta_1l: Vec<E::GT>,

    /// Δ₁R[k] = e(Γ₁[2^(k-1)..2^k], Γ₂[..2^(k-1)])
    pub delta_1r: Vec<E::GT>,

    /// Δ₂L[k] = same as Δ₁L[k]
    pub delta_2l: Vec<E::GT>,

    /// Δ₂R[k] = e(Γ₁[..2^(k-1)], Γ₂[2^(k-1)..2^k])
    pub delta_2r: Vec<E::GT>,

    /// χ[k] = e(Γ₁[..2^k], Γ₂[..2^k])
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
        let max_nu = self.g1_vec.len().trailing_zeros() as usize;

        let mut delta_1l = Vec::with_capacity(max_nu + 1);
        let mut delta_1r = Vec::with_capacity(max_nu + 1);
        let mut delta_2r = Vec::with_capacity(max_nu + 1);
        let mut chi = Vec::with_capacity(max_nu + 1);

        for k in 0..=max_nu {
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
            max_log_n: max_nu * 2, // Since square matrices: max_log_n = 2 * max_nu
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
