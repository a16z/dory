//! Simple/testing witness types for recursive proof composition.
//!
//! This module provides basic witness structures that capture inputs and outputs
//! of arithmetic operations without detailed intermediate computation steps.
//!
//! For Jolt or other proof systems, we would provide a more involved witness gen and backend

use super::{ArkFr, ArkG1, ArkG2, ArkGT, BN254};
use crate::primitives::arithmetic::Group;
use crate::recursion::{WitnessBackend, WitnessGenerator, WitnessResult};
use ark_ff::{BigInteger, PrimeField};

/// BN254 scalar field bit length
const SCALAR_BITS: usize = 254;

/// Simplified witness backend for BN254 curve.
///
/// This backend defines witness types that store inputs, outputs, and basic
/// scalar bit decompositions. Intermediate computation steps are mostly empty.
pub struct SimpleWitnessBackend;

impl WitnessBackend for SimpleWitnessBackend {
    type GtExpWitness = GtExpWitness;
    type G1ScalarMulWitness = G1ScalarMulWitness;
    type G2ScalarMulWitness = G2ScalarMulWitness;
    type GtMulWitness = GtMulWitness;
    type PairingWitness = PairingWitness;
    type MultiPairingWitness = MultiPairingWitness;
    type MsmG1Witness = MsmG1Witness;
    type MsmG2Witness = MsmG2Witness;
}

/// Witness for GT exponentiation using square-and-multiply.
///
/// Captures the intermediate values during exponentiation: base^scalar.
/// In GT (multiplicative group), this is computed as repeated squaring and multiplication.
#[derive(Clone, Debug)]
pub struct GtExpWitness {
    /// The base element being exponentiated
    pub base: ArkGT,
    /// Scalar decomposed into bits (LSB first)
    pub scalar_bits: Vec<bool>,
    /// Intermediate squaring results: base, base^2, base^4, ...
    pub squares: Vec<ArkGT>,
    /// Running accumulator after processing each bit
    pub accumulators: Vec<ArkGT>,
    /// Final result: base^scalar
    pub result: ArkGT,
}

impl WitnessResult<ArkGT> for GtExpWitness {
    fn result(&self) -> Option<&ArkGT> {
        Some(&self.result)
    }
}

/// Witness for G1 scalar multiplication using double-and-add.
#[derive(Clone, Debug)]
pub struct G1ScalarMulWitness {
    /// The point being scaled
    pub point: ArkG1,
    /// Scalar decomposed into bits (LSB first)
    pub scalar_bits: Vec<bool>,
    /// Intermediate doubling results: P, 2P, 4P, ...
    pub doubles: Vec<ArkG1>,
    /// Running accumulator after processing each bit
    pub accumulators: Vec<ArkG1>,
    /// Final result: point * scalar
    pub result: ArkG1,
}

impl WitnessResult<ArkG1> for G1ScalarMulWitness {
    fn result(&self) -> Option<&ArkG1> {
        Some(&self.result)
    }
}

/// Witness for G2 scalar multiplication using double-and-add.
#[derive(Clone, Debug)]
pub struct G2ScalarMulWitness {
    /// The point being scaled
    pub point: ArkG2,
    /// Scalar decomposed into bits (LSB first)
    pub scalar_bits: Vec<bool>,
    /// Intermediate doubling results: P, 2P, 4P, ...
    pub doubles: Vec<ArkG2>,
    /// Running accumulator after processing each bit
    pub accumulators: Vec<ArkG2>,
    /// Final result: point * scalar
    pub result: ArkG2,
}

impl WitnessResult<ArkG2> for G2ScalarMulWitness {
    fn result(&self) -> Option<&ArkG2> {
        Some(&self.result)
    }
}

/// Witness for GT multiplication (Fq12 multiplication).
///
/// Since GT is a multiplicative group, "group addition" is field multiplication.
#[derive(Clone, Debug)]
pub struct GtMulWitness {
    /// Left operand
    pub lhs: ArkGT,
    /// Right operand
    pub rhs: ArkGT,
    /// Intermediate values during Fq12 multiplication (Karatsuba steps)
    pub intermediates: Vec<ArkGT>,
    /// Final result: lhs * rhs
    pub result: ArkGT,
}

impl WitnessResult<ArkGT> for GtMulWitness {
    fn result(&self) -> Option<&ArkGT> {
        Some(&self.result)
    }
}

/// Single step in the Miller loop computation.
#[derive(Clone, Debug)]
pub struct MillerStep {
    /// Line evaluation at this step
    pub line_eval: ArkGT,
    /// Accumulated value after this step
    pub accumulator: ArkGT,
}

/// Witness for single pairing e(G1, G2) -> GT.
///
/// Captures the Miller loop iterations and final exponentiation.
#[derive(Clone, Debug)]
pub struct PairingWitness {
    /// G1 input point
    pub g1: ArkG1,
    /// G2 input point
    pub g2: ArkG2,
    /// Miller loop step-by-step trace
    pub miller_steps: Vec<MillerStep>,
    /// Final exponentiation intermediate values
    pub final_exp_steps: Vec<ArkGT>,
    /// Final pairing result
    pub result: ArkGT,
}

impl WitnessResult<ArkGT> for PairingWitness {
    fn result(&self) -> Option<&ArkGT> {
        Some(&self.result)
    }
}

/// Witness for multi-pairing: `∏ e(g1s[i], g2s[i])`.
#[derive(Clone, Debug)]
pub struct MultiPairingWitness {
    /// G1 input points
    pub g1s: Vec<ArkG1>,
    /// G2 input points
    pub g2s: Vec<ArkG2>,
    /// Miller loop traces for each pair
    pub individual_millers: Vec<Vec<MillerStep>>,
    /// Combined Miller loop result before final exponentiation
    pub combined_miller: ArkGT,
    /// Final exponentiation steps
    pub final_exp_steps: Vec<ArkGT>,
    /// Final multi-pairing result
    pub result: ArkGT,
}

impl WitnessResult<ArkGT> for MultiPairingWitness {
    fn result(&self) -> Option<&ArkGT> {
        Some(&self.result)
    }
}

/// Witness for G1 multi-scalar multiplication.
///
/// For detailed Pippenger algorithm traces, stores bucket states.
#[derive(Clone, Debug)]
pub struct MsmG1Witness {
    /// Base points
    pub bases: Vec<ArkG1>,
    /// Scalar values
    pub scalars: Vec<ArkFr>,
    /// Bucket sums (simplified - actual Pippenger has more structure)
    pub bucket_sums: Vec<ArkG1>,
    /// Running sum intermediates
    pub running_sums: Vec<ArkG1>,
    /// Final MSM result
    pub result: ArkG1,
}

impl WitnessResult<ArkG1> for MsmG1Witness {
    fn result(&self) -> Option<&ArkG1> {
        Some(&self.result)
    }
}

/// Witness for G2 multi-scalar multiplication.
#[derive(Clone, Debug)]
pub struct MsmG2Witness {
    /// Base points
    pub bases: Vec<ArkG2>,
    /// Scalar values
    pub scalars: Vec<ArkFr>,
    /// Bucket sums
    pub bucket_sums: Vec<ArkG2>,
    /// Running sum intermediates
    pub running_sums: Vec<ArkG2>,
    /// Final MSM result
    pub result: ArkG2,
}

impl WitnessResult<ArkG2> for MsmG2Witness {
    fn result(&self) -> Option<&ArkG2> {
        Some(&self.result)
    }
}

/// Simplified witness generator for the Arkworks backend.
///
/// This generator creates basic witnesses with inputs, outputs, and scalar
/// bit decompositions. Most intermediate traces are empty.
pub struct SimpleWitnessGenerator;

impl WitnessGenerator<SimpleWitnessBackend, BN254> for SimpleWitnessGenerator {
    fn generate_gt_exp(base: &ArkGT, scalar: &ArkFr, result: &ArkGT) -> GtExpWitness {
        // Get scalar bits (LSB first)
        let bigint = scalar.0.into_bigint();
        let scalar_bits: Vec<bool> = (0..SCALAR_BITS).map(|i| bigint.get_bit(i)).collect();

        // Doesn't record intermediate results
        let squares = vec![*base];
        let accumulators = vec![*result];

        GtExpWitness {
            base: *base,
            scalar_bits,
            squares,
            accumulators,
            result: *result,
        }
    }

    fn generate_g1_scalar_mul(point: &ArkG1, scalar: &ArkFr, result: &ArkG1) -> G1ScalarMulWitness {
        let bigint = scalar.0.into_bigint();
        let scalar_bits: Vec<bool> = (0..SCALAR_BITS).map(|i| bigint.get_bit(i)).collect();

        // Doesn't record intermediate results
        let doubles = vec![*point];
        let accumulators = vec![*result];

        G1ScalarMulWitness {
            point: *point,
            scalar_bits,
            doubles,
            accumulators,
            result: *result,
        }
    }

    fn generate_g2_scalar_mul(point: &ArkG2, scalar: &ArkFr, result: &ArkG2) -> G2ScalarMulWitness {
        let bigint = scalar.0.into_bigint();
        let scalar_bits: Vec<bool> = (0..SCALAR_BITS).map(|i| bigint.get_bit(i)).collect();

        let doubles = vec![*point];
        let accumulators = vec![*result];

        G2ScalarMulWitness {
            point: *point,
            scalar_bits,
            doubles,
            accumulators,
            result: *result,
        }
    }

    fn generate_gt_mul(lhs: &ArkGT, rhs: &ArkGT, result: &ArkGT) -> GtMulWitness {
        GtMulWitness {
            lhs: *lhs,
            rhs: *rhs,
            intermediates: vec![],
            result: *result,
        }
    }

    fn generate_pairing(g1: &ArkG1, g2: &ArkG2, result: &ArkGT) -> PairingWitness {
        PairingWitness {
            g1: *g1,
            g2: *g2,
            miller_steps: vec![],
            final_exp_steps: vec![],
            result: *result,
        }
    }

    fn generate_multi_pairing(g1s: &[ArkG1], g2s: &[ArkG2], result: &ArkGT) -> MultiPairingWitness {
        MultiPairingWitness {
            g1s: g1s.to_vec(),
            g2s: g2s.to_vec(),
            individual_millers: vec![],
            combined_miller: ArkGT::identity(),
            final_exp_steps: vec![],
            result: *result,
        }
    }

    fn generate_msm_g1(bases: &[ArkG1], scalars: &[ArkFr], result: &ArkG1) -> MsmG1Witness {
        MsmG1Witness {
            bases: bases.to_vec(),
            scalars: scalars.to_vec(),
            bucket_sums: vec![],
            running_sums: vec![],
            result: *result,
        }
    }

    fn generate_msm_g2(bases: &[ArkG2], scalars: &[ArkFr], result: &ArkG2) -> MsmG2Witness {
        MsmG2Witness {
            bases: bases.to_vec(),
            scalars: scalars.to_vec(),
            bucket_sums: vec![],
            running_sums: vec![],
            result: *result,
        }
    }
}
