//! Group implementations for BN254 curve (G1, G2, GT)

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use super::ark_field::ArkFr;
use crate::primitives::arithmetic::{DoryRoutines, Group};
use ark_bn254::{CompressedFq12, Fq12, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{Field as ArkField, One, PrimeField, UniformRand, Zero as ArkZero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg, Sub};
use rand_core::RngCore;

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkG1(pub G1Projective);

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkG2(pub G2Projective);

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkGT(pub Fq12);

#[derive(Default, Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkGTCompressed(pub CompressedFq12);

impl From<ArkGTCompressed> for ArkGT {
    fn from(gt: ArkGTCompressed) -> Self {
        let decompressed = CompressedFq12::decompress_to_fq12(gt.0);
        Self(decompressed)
    }
}

impl Group for ArkG1 {
    type Scalar = ArkFr;

    fn identity() -> Self {
        ArkG1(ArkZero::zero())
    }

    fn add(&self, rhs: &Self) -> Self {
        ArkG1(self.0 + rhs.0)
    }

    fn neg(&self) -> Self {
        ArkG1(-self.0)
    }

    fn scale(&self, k: &Self::Scalar) -> Self {
        ArkG1(self.0 * k.0)
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        ArkG1(G1Projective::rand(rng))
    }
}

impl Add for ArkG1 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        ArkG1(self.0 + rhs.0)
    }
}

impl Sub for ArkG1 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        ArkG1(self.0 - rhs.0)
    }
}

impl Neg for ArkG1 {
    type Output = Self;
    fn neg(self) -> Self {
        ArkG1(-self.0)
    }
}

impl<'a> Add<&'a ArkG1> for ArkG1 {
    type Output = ArkG1;
    fn add(self, rhs: &'a ArkG1) -> ArkG1 {
        ArkG1(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a ArkG1> for ArkG1 {
    type Output = ArkG1;
    fn sub(self, rhs: &'a ArkG1) -> ArkG1 {
        ArkG1(self.0 - rhs.0)
    }
}

impl Mul<ArkG1> for ArkFr {
    type Output = ArkG1;
    fn mul(self, rhs: ArkG1) -> ArkG1 {
        ArkG1(rhs.0 * self.0)
    }
}

impl<'a> Mul<&'a ArkG1> for ArkFr {
    type Output = ArkG1;
    fn mul(self, rhs: &'a ArkG1) -> ArkG1 {
        ArkG1(rhs.0 * self.0)
    }
}

impl Group for ArkG2 {
    type Scalar = ArkFr;

    fn identity() -> Self {
        ArkG2(ArkZero::zero())
    }

    fn add(&self, rhs: &Self) -> Self {
        ArkG2(self.0 + rhs.0)
    }

    fn neg(&self) -> Self {
        ArkG2(-self.0)
    }

    fn scale(&self, k: &Self::Scalar) -> Self {
        ArkG2(self.0 * k.0)
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        ArkG2(G2Projective::rand(rng))
    }
}

impl Add for ArkG2 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        ArkG2(self.0 + rhs.0)
    }
}

impl Sub for ArkG2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        ArkG2(self.0 - rhs.0)
    }
}

impl Neg for ArkG2 {
    type Output = Self;
    fn neg(self) -> Self {
        ArkG2(-self.0)
    }
}

impl<'a> Add<&'a ArkG2> for ArkG2 {
    type Output = ArkG2;
    fn add(self, rhs: &'a ArkG2) -> ArkG2 {
        ArkG2(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a ArkG2> for ArkG2 {
    type Output = ArkG2;
    fn sub(self, rhs: &'a ArkG2) -> ArkG2 {
        ArkG2(self.0 - rhs.0)
    }
}

impl Mul<ArkG2> for ArkFr {
    type Output = ArkG2;
    fn mul(self, rhs: ArkG2) -> ArkG2 {
        ArkG2(rhs.0 * self.0)
    }
}

impl<'a> Mul<&'a ArkG2> for ArkFr {
    type Output = ArkG2;
    fn mul(self, rhs: &'a ArkG2) -> ArkG2 {
        ArkG2(rhs.0 * self.0)
    }
}

impl Group for ArkGT {
    type Scalar = ArkFr;

    fn identity() -> Self {
        ArkGT(Fq12::one())
    }

    fn add(&self, rhs: &Self) -> Self {
        ArkGT(self.0 * rhs.0)
    }

    fn neg(&self) -> Self {
        ArkGT(ArkField::inverse(&self.0).expect("GT inverse"))
    }

    fn scale(&self, k: &Self::Scalar) -> Self {
        ArkGT(self.0.pow(k.0.into_bigint()))
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        ArkGT(Fq12::rand(rng))
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for ArkGT {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        // GT is a multiplicative group, so group addition is field multiplication
        ArkGT(self.0 * rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for ArkGT {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        // GT is a multiplicative group, so group subtraction is multiplication by inverse
        ArkGT(self.0 * rhs.0.inverse().expect("GT inverse"))
    }
}

impl Neg for ArkGT {
    type Output = Self;
    fn neg(self) -> Self {
        ArkGT(self.0.inverse().expect("GT inverse"))
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a> Add<&'a ArkGT> for ArkGT {
    type Output = ArkGT;
    fn add(self, rhs: &'a ArkGT) -> ArkGT {
        // GT is a multiplicative group, so group addition is field multiplication
        ArkGT(self.0 * rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a> Sub<&'a ArkGT> for ArkGT {
    type Output = ArkGT;
    fn sub(self, rhs: &'a ArkGT) -> ArkGT {
        // GT is a multiplicative group, so group subtraction is multiplication by inverse
        ArkGT(self.0 * rhs.0.inverse().expect("GT inverse"))
    }
}

impl Mul<ArkGT> for ArkFr {
    type Output = ArkGT;
    fn mul(self, rhs: ArkGT) -> ArkGT {
        ArkGT(rhs.0.pow(self.0.into_bigint()))
    }
}

impl<'a> Mul<&'a ArkGT> for ArkFr {
    type Output = ArkGT;
    fn mul(self, rhs: &'a ArkGT) -> ArkGT {
        ArkGT(rhs.0.pow(self.0.into_bigint()))
    }
}

pub struct G1Routines;

impl DoryRoutines<ArkG1> for G1Routines {
    #[tracing::instrument(skip_all, name = "G1::msm", fields(len = bases.len()))]
    fn msm(bases: &[ArkG1], scalars: &[ArkFr]) -> ArkG1 {
        assert_eq!(
            bases.len(),
            scalars.len(),
            "MSM requires equal length vectors"
        );

        if bases.is_empty() {
            return ArkG1::identity();
        }

        let bases_affine: Vec<G1Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let scalars_fr: Vec<ark_bn254::Fr> = scalars.iter().map(|s| s.0).collect();

        ArkG1(G1Projective::msm(&bases_affine, &scalars_fr).expect("MSM failed"))
    }

    fn fixed_base_vector_scalar_mul(base: &ArkG1, scalars: &[ArkFr]) -> Vec<ArkG1> {
        scalars.iter().map(|s| base.scale(s)).collect()
    }

    fn fixed_scalar_mul_bases_then_add(bases: &[ArkG1], vs: &mut [ArkG1], scalar: &ArkFr) {
        assert_eq!(bases.len(), vs.len(), "Lengths must match");

        for (v, base) in vs.iter_mut().zip(bases.iter()) {
            *v = v.add(&base.scale(scalar));
        }
    }

    fn fixed_scalar_mul_vs_then_add(vs: &mut [ArkG1], addends: &[ArkG1], scalar: &ArkFr) {
        assert_eq!(vs.len(), addends.len(), "Lengths must match");

        for (v, addend) in vs.iter_mut().zip(addends.iter()) {
            *v = v.scale(scalar).add(addend);
        }
    }
}

pub struct G2Routines;

impl DoryRoutines<ArkG2> for G2Routines {
    #[tracing::instrument(skip_all, name = "G2::msm", fields(len = bases.len()))]
    fn msm(bases: &[ArkG2], scalars: &[ArkFr]) -> ArkG2 {
        assert_eq!(
            bases.len(),
            scalars.len(),
            "MSM requires equal length vectors"
        );

        if bases.is_empty() {
            return ArkG2::identity();
        }

        let bases_affine: Vec<G2Affine> = bases.iter().map(|b| b.0.into_affine()).collect();
        let scalars_fr: Vec<ark_bn254::Fr> = scalars.iter().map(|s| s.0).collect();

        ArkG2(G2Projective::msm(&bases_affine, &scalars_fr).expect("MSM failed"))
    }

    fn fixed_base_vector_scalar_mul(base: &ArkG2, scalars: &[ArkFr]) -> Vec<ArkG2> {
        scalars.iter().map(|s| base.scale(s)).collect()
    }

    fn fixed_scalar_mul_bases_then_add(bases: &[ArkG2], vs: &mut [ArkG2], scalar: &ArkFr) {
        assert_eq!(bases.len(), vs.len(), "Lengths must match");

        for (v, base) in vs.iter_mut().zip(bases.iter()) {
            *v = v.add(&base.scale(scalar));
        }
    }

    fn fixed_scalar_mul_vs_then_add(vs: &mut [ArkG2], addends: &[ArkG2], scalar: &ArkFr) {
        assert_eq!(vs.len(), addends.len(), "Lengths must match");

        for (v, addend) in vs.iter_mut().zip(addends.iter()) {
            *v = v.scale(scalar).add(addend);
        }
    }
}
