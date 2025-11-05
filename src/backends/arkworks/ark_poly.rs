use super::ark_field::ArkFr;
use crate::error::DoryError;
use crate::primitives::arithmetic::{DoryRoutines, Field, Group, PairingCurve};
use crate::primitives::poly::{MultilinearLagrange, Polynomial};
use crate::setup::ProverSetup;

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
