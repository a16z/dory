//! Arkworks backend implementation for BN254 pairing curve

use crate::error::DoryError;
use crate::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::primitives::poly::{MultilinearLagrange, Polynomial};
use crate::setup::ProverSetup;
use ark_bn254::{Bn254, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::{Field as ArkField, One, PrimeField, UniformRand, Zero as ArkZero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg, Sub};
use rand_core::RngCore;

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkFr(pub Fr);

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkG1(pub G1Projective);

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkG2(pub G2Projective);

#[derive(Clone, Copy, PartialEq, Eq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ArkGT(pub Fq12);

#[derive(Clone, Debug)]
pub struct BN254;

impl Field for ArkFr {
    fn zero() -> Self {
        ArkFr(Fr::from(0u64))
    }

    fn one() -> Self {
        ArkFr(Fr::from(1u64))
    }

    fn is_zero(&self) -> bool {
        ArkZero::is_zero(&self.0)
    }

    fn add(&self, rhs: &Self) -> Self {
        ArkFr(self.0 + rhs.0)
    }

    fn sub(&self, rhs: &Self) -> Self {
        ArkFr(self.0 - rhs.0)
    }

    fn mul(&self, rhs: &Self) -> Self {
        ArkFr(self.0 * rhs.0)
    }

    fn inv(self) -> Option<Self> {
        ArkField::inverse(&self.0).map(ArkFr)
    }

    fn random<R: RngCore>(rng: &mut R) -> Self {
        ArkFr(Fr::rand(rng))
    }

    fn from_u64(val: u64) -> Self {
        ArkFr(Fr::from(val))
    }

    fn from_i64(val: i64) -> Self {
        if val >= 0 {
            ArkFr(Fr::from(val as u64))
        } else {
            ArkFr(-Fr::from((-val) as u64))
        }
    }
}

impl Add for ArkFr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        ArkFr(self.0 + rhs.0)
    }
}

impl Sub for ArkFr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        ArkFr(self.0 - rhs.0)
    }
}

impl Mul for ArkFr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        ArkFr(self.0 * rhs.0)
    }
}

impl Neg for ArkFr {
    type Output = Self;
    fn neg(self) -> Self {
        ArkFr(-self.0)
    }
}

impl<'a> Add<&'a ArkFr> for ArkFr {
    type Output = ArkFr;
    fn add(self, rhs: &'a ArkFr) -> ArkFr {
        ArkFr(self.0 + rhs.0)
    }
}

impl<'a> Sub<&'a ArkFr> for ArkFr {
    type Output = ArkFr;
    fn sub(self, rhs: &'a ArkFr) -> ArkFr {
        ArkFr(self.0 - rhs.0)
    }
}

impl<'a> Mul<&'a ArkFr> for ArkFr {
    type Output = ArkFr;
    fn mul(self, rhs: &'a ArkFr) -> ArkFr {
        ArkFr(self.0 * rhs.0)
    }
}

impl Group for ArkG1 {
    type Scalar = ArkFr;

    fn identity() -> Self {
        ArkG1(G1Projective::zero())
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
        ArkG2(G2Projective::zero())
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
        ArkGT(self.0.inverse().expect("GT inverse"))
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

impl PairingCurve for BN254 {
    type G1 = ArkG1;
    type G2 = ArkG2;
    type GT = ArkGT;

    fn pair(p: &Self::G1, q: &Self::G2) -> Self::GT {
        ArkGT(Bn254::pairing(p.0, q.0).0)
    }

    fn multi_pair(ps: &[Self::G1], qs: &[Self::G2]) -> Self::GT {
        assert_eq!(
            ps.len(),
            qs.len(),
            "multi_pair requires equal length vectors"
        );

        if ps.is_empty() {
            return Self::GT::identity();
        }

        let ps_inner: Vec<G1Projective> = ps.iter().map(|p| p.0).collect();
        let qs_inner: Vec<G2Projective> = qs.iter().map(|q| q.0).collect();

        ArkGT(Bn254::multi_pairing(ps_inner, qs_inner).0)
    }
}

pub struct ArkG1Routines;

impl DoryRoutines<ArkG1> for ArkG1Routines {
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
        let scalars_fr: Vec<Fr> = scalars.iter().map(|s| s.0).collect();

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

pub struct ArkG2Routines;

impl DoryRoutines<ArkG2> for ArkG2Routines {
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
        let scalars_fr: Vec<Fr> = scalars.iter().map(|s| s.0).collect();

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

/// Simple polynomial implementation wrapping coefficient vector
#[derive(Clone, Debug)]
pub struct ArkworksPolynomial {
    coefficients: Vec<ArkFr>,
    num_vars: usize,
}

impl ArkworksPolynomial {
    pub fn new(coefficients: Vec<ArkFr>) -> Self {
        let len = coefficients.len();
        let num_vars = (len as f64).log2() as usize;
        assert_eq!(
            1 << num_vars,
            len,
            "Coefficient length must be a power of 2"
        );
        Self {
            coefficients,
            num_vars,
        }
    }
}

impl Polynomial<ArkFr> for ArkworksPolynomial {
    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn evaluate(&self, point: &[ArkFr]) -> ArkFr {
        assert_eq!(point.len(), self.num_vars, "Point dimension mismatch");

        // Compute multilinear Lagrange basis
        let mut basis = vec![ArkFr::zero(); 1 << self.num_vars];
        crate::primitives::poly::multilinear_lagrange_basis(&mut basis, point);

        // Evaluate: sum_i coeff[i] * basis[i]
        let mut result = ArkFr::zero();
        for (coeff, basis_val) in self.coefficients.iter().zip(basis.iter()) {
            result = result + coeff.mul(basis_val);
        }
        result
    }

    fn coefficients(&self) -> &[ArkFr] {
        &self.coefficients
    }

    fn commit<E, M1>(
        &self,
        nu: usize,
        sigma: usize,
        setup: &ProverSetup<E>,
    ) -> Result<(E::GT, Vec<E::G1>), DoryError>
    where
        E: PairingCurve,
        M1: DoryRoutines<E::G1>,
        E::G1: Group<Scalar = ArkFr>,
    {
        let expected_len = 1 << (nu + sigma);
        if self.coefficients.len() != expected_len {
            return Err(DoryError::InvalidSize {
                expected: expected_len,
                actual: self.coefficients.len(),
            });
        }

        let num_rows = 1 << nu;
        let num_cols = 1 << sigma;

        // Tier 1: Compute row commitments
        let mut row_commitments = Vec::with_capacity(num_rows);
        for i in 0..num_rows {
            let row_start = i * num_cols;
            let row_end = row_start + num_cols;
            let row = &self.coefficients[row_start..row_end];

            let g1_bases = &setup.g1_vec[..num_cols];
            let row_commit = M1::msm(g1_bases, row);
            row_commitments.push(row_commit);
        }

        // Tier 2: Compute final commitment via multi-pairing
        let g2_bases = &setup.g2_vec[..num_rows];
        let commitment = E::multi_pair(&row_commitments, g2_bases);

        Ok((commitment, row_commitments))
    }
}

impl MultilinearLagrange<ArkFr> for ArkworksPolynomial {}
