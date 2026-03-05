//! GLV endomorphism scalar decomposition for BN254.
//!
//! Decomposes a 254-bit scalar `s` into two ~128-bit sub-scalars `(k1, k2)`
//! such that `s ≡ k1 + k2·λ (mod r)`, where λ is a cube root of unity in Fr.
//! This halves the number of EC doublings in scalar multiplication.

use crate::backends::metal::gpu::{FrLimbs, GlvScalar2};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed};

/// BN254 Fr modulus: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const FR_MODULUS_LE: [u8; 32] = {
    let r: [u32; 8] = [
        0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029,
        0x30644e72,
    ];
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 8 {
        let b = r[i].to_le_bytes();
        bytes[4 * i] = b[0];
        bytes[4 * i + 1] = b[1];
        bytes[4 * i + 2] = b[2];
        bytes[4 * i + 3] = b[3];
        i += 1;
    }
    bytes
};

/// GLV lattice coefficients for BN254.
/// The short vectors of the GLV lattice satisfy:
///   n11·1 + n12·λ ≡ 0 (mod r)
///   n21·1 + n22·λ ≡ 0 (mod r)
const N11: u128 = 147946756881789319000765030803803410728;
const N12: u128 = 9931322734385697763;
const N22: u128 = 147946756881789319010696353538189108491;

/// Decompose a raw (non-Montgomery) scalar into GLV-2 form for G1.
///
/// Returns a `GlvScalar2` containing two ~128-bit sub-scalars and their signs,
/// suitable for passing directly to the GPU kernel.
pub fn decompose_scalar_g1(scalar_raw: &FrLimbs) -> GlvScalar2 {
    // Convert FrLimbs to BigInt (LE bytes)
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        bytes[4 * i..4 * i + 4].copy_from_slice(&scalar_raw.limbs[i].to_le_bytes());
    }
    let k = BigInt::from_bytes_le(Sign::Plus, &bytes);
    let r = BigInt::from_bytes_le(Sign::Plus, &FR_MODULUS_LE);

    // Lattice basis: N = [[-n11, n12], [-n21, -n22]]
    // where n21 = n12 (= N12)
    let n11 = BigInt::from(N11);
    let n12 = BigInt::from(N12);
    let n22 = BigInt::from(N22);

    // Babai nearest-plane rounding: β_j = round(k · col_j / r)
    // β₁ = round(k · n22 / r)   (using negative n22 column, but we handle signs)
    // β₂ = round(k · n12 / r)
    let beta_1 = round_div(&(&k * &n22), &r);
    let beta_2 = round_div(&(&k * &n12), &r);

    // k1 = k - β₁·n11 - β₂·n12
    // k2 = β₁·n12 - β₂·n22
    // (derived from the lattice reduction: (k1, k2) = (k, 0) - β₁·v₁ - β₂·v₂)
    let k1 = &k - &beta_1 * &n11 - &beta_2 * &n12;
    let k2 = &beta_1 * &n12 - &beta_2 * &n22;

    let negate1 = k1.sign() == Sign::Minus;
    let negate2 = k2.sign() == Sign::Minus;

    GlvScalar2 {
        k1: bigint_abs_to_fr_limbs(&k1),
        k2: bigint_abs_to_fr_limbs(&k2),
        negate1: u32::from(negate1),
        negate2: u32::from(negate2),
    }
}

fn round_div(a: &BigInt, b: &BigInt) -> BigInt {
    let (mut q, rem) = a.div_rem(b);
    // Round to nearest: if |2·rem| > |b|, adjust quotient
    if (&rem + &rem).abs() > b.abs() {
        if a.sign() == b.sign() {
            q += BigInt::one();
        } else {
            q -= BigInt::one();
        }
    }
    q
}

fn bigint_abs_to_fr_limbs(v: &BigInt) -> FrLimbs {
    let (_, abs_bytes) = v.abs().to_bytes_le();
    let mut limbs = [0u32; 8];
    for (i, chunk) in abs_bytes.chunks(4).enumerate() {
        if i >= 8 {
            break;
        }
        let mut buf = [0u8; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        limbs[i] = u32::from_le_bytes(buf);
    }
    FrLimbs { limbs }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glv_decomposition_small() {
        // scalar = 1: should decompose to k1=1, k2=0
        let one = FrLimbs {
            limbs: [1, 0, 0, 0, 0, 0, 0, 0],
        };
        let glv = decompose_scalar_g1(&one);
        assert_eq!(glv.k1.limbs[0], 1);
        assert_eq!(glv.negate1, 0);
        // k2 should be 0 or very small
        let k2_sum: u32 = glv.k2.limbs.iter().sum();
        assert_eq!(k2_sum, 0);
    }

    #[test]
    fn test_glv_decomposition_sub_scalars_are_small() {
        // Random-ish 256-bit scalar
        let scalar = FrLimbs {
            limbs: [
                0xdeadbeef, 0x12345678, 0xabcdef01, 0x87654321, 0x11111111, 0x22222222, 0x33333333,
                0x04444444,
            ],
        };
        let glv = decompose_scalar_g1(&scalar);

        // Both sub-scalars should fit in ~128 bits (top 4 limbs should be 0)
        assert_eq!(glv.k1.limbs[4], 0, "k1 should be ~128 bits");
        assert_eq!(glv.k1.limbs[5], 0);
        assert_eq!(glv.k1.limbs[6], 0);
        assert_eq!(glv.k1.limbs[7], 0);
        assert_eq!(glv.k2.limbs[4], 0, "k2 should be ~128 bits");
        assert_eq!(glv.k2.limbs[5], 0);
        assert_eq!(glv.k2.limbs[6], 0);
        assert_eq!(glv.k2.limbs[7], 0);
    }
}
