#![allow(missing_docs)]

use super::{DoryDeserialize, DorySerialize};
use rand_core::RngCore;

pub trait Field:
    Sized
    + Clone
    + Copy
    + PartialEq
    + Send
    + Sync
    + DorySerialize
    + DoryDeserialize
    + std::ops::Add<Output = Self>
    + std::ops::Sub<Output = Self>
    + std::ops::Mul<Output = Self>
    + std::ops::Neg<Output = Self>
    + for<'a> std::ops::Add<&'a Self, Output = Self>
    + for<'a> std::ops::Sub<&'a Self, Output = Self>
    + for<'a> std::ops::Mul<&'a Self, Output = Self>
{
    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;

    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;

    fn inv(self) -> Option<Self>;

    fn random<R: RngCore>(rng: &mut R) -> Self;

    fn from_u64(val: u64) -> Self;
    fn from_i64(val: i64) -> Self;
}

pub trait Group:
    Sized
    + Clone
    + Copy
    + PartialEq
    + Send
    + Sync
    + DorySerialize
    + DoryDeserialize
    + std::ops::Add<Output = Self>
    + std::ops::Sub<Output = Self>
    + std::ops::Neg<Output = Self>
    + for<'a> std::ops::Add<&'a Self, Output = Self>
    + for<'a> std::ops::Sub<&'a Self, Output = Self>
{
    type Scalar: Field
        + std::ops::Mul<Self, Output = Self>
        + for<'a> std::ops::Mul<&'a Self, Output = Self>;

    fn identity() -> Self;
    fn add(&self, rhs: &Self) -> Self;
    fn neg(&self) -> Self;
    fn scale(&self, k: &Self::Scalar) -> Self;

    fn random<R: RngCore>(rng: &mut R) -> Self;
}

pub trait PairingCurve: Clone {
    type G1: Group;
    type G2: Group;
    type GT: Group; // multiplicative subgroup F^* of the extension field

    /// e : G1 × G2 → GT
    fn pair(p: &Self::G1, q: &Self::G2) -> Self::GT;

    /// Π e(p_i, q_i)
    fn multi_pair(ps: &[Self::G1], qs: &[Self::G2]) -> Self::GT {
        assert_eq!(
            ps.len(),
            qs.len(),
            "multi_pair requires equal length vectors"
        );

        if ps.is_empty() {
            return Self::GT::identity();
        }

        ps.iter()
            .zip(qs.iter())
            .fold(Self::GT::identity(), |acc, (p, q)| {
                acc.add(&Self::pair(p, q))
            })
    }
}

/// Dory requires MSMs and vector scaling ops, hence we expose a trait for optimized versions of such routines.
pub trait DoryRoutines<G: Group> {
    fn msm(bases: &[G], scalars: &[G::Scalar]) -> G;

    /// Fixed-base vectorized scalar multiplication where the same base is scaled by each scalar individually
    /// Computes: [base * scalars[0], base * scalars[1], ..., base * scalars[n-1]]
    fn fixed_base_vector_scalar_mul(base: &G, scalars: &[G::Scalar]) -> Vec<G>;

    /// vs[i] = vs[i] + scalar * bases[i]
    fn fixed_scalar_mul_bases_then_add(bases: &[G], vs: &mut [G], scalar: &G::Scalar);

    /// vs[i] = scalar * vs[i] + addends[i]
    fn fixed_scalar_mul_vs_then_add(vs: &mut [G], addends: &[G], scalar: &G::Scalar);
}
