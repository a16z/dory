//! Default witness types for recursive proof composition (arkworks, pairing-friendly curves).
//!
//! This module provides a baseline witness backend/generator that captures inputs and outputs
//! of arithmetic operations (and basic scalar bit decompositions) without detailed intermediate
//! computation steps.
//!
//! Upstream proof systems are expected to implement [`WitnessBackend`] / [`WitnessGenerator`]
//! to capture the exact witness trace their circuit needs.

use super::{ArkFr, ArkG1, ArkG2, ArkGT, BN254};
use crate::primitives::arithmetic::{Group, PairingCurve};
use crate::recursion::{WitnessBackend, WitnessGenerator, WitnessResult};
use ark_ff::{BigInteger, PrimeField};

/// Helper for extracting little-endian bit decomposition from a scalar type.
///
/// This is intentionally kept minimal, so other arkworks-backed curves can implement it
/// for their scalar wrapper types.
pub trait ScalarBits: Copy + Send + Sync + 'static {
    /// Scalar bit length used for witness bit-decomposition.
    const BIT_LEN: usize;

    /// Return little-endian bits (LSB first), of length `BIT_LEN`.
    fn bits_le(&self) -> Vec<bool>;
}

impl ScalarBits for ArkFr {
    const BIT_LEN: usize = <ark_bn254::Fr as PrimeField>::MODULUS_BIT_SIZE as usize;

    fn bits_le(&self) -> Vec<bool> {
        let bigint = self.0.into_bigint();
        (0..Self::BIT_LEN).map(|i| bigint.get_bit(i)).collect()
    }
}

/// Simplified witness backend for arkworks pairing curves.
///
/// This backend defines witness types that store inputs, outputs, and basic
/// scalar bit decompositions. Intermediate computation steps are mostly empty.
///
/// By default, this is instantiated with the crate's BN254 arkworks backend curve type.
/// For other curves, specify a different `E` that implements [`PairingCurve`] and uses
/// scalar types implementing [`ScalarBits`].
pub struct SimpleWitnessBackend<E: PairingCurve = BN254>(std::marker::PhantomData<E>);

impl<E: PairingCurve> Default for SimpleWitnessBackend<E> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<E> WitnessBackend for SimpleWitnessBackend<E>
where
    E: PairingCurve + Send + Sync + 'static,
{
    // G1 operations
    type G1AddWitness = G1AddWitness<E::G1>;
    type G1ScalarMulWitness = G1ScalarMulWitness<E::G1>;
    type MsmG1Witness = MsmG1Witness<E::G1, <E::G1 as Group>::Scalar>;
    // G2 operations
    type G2AddWitness = G2AddWitness<E::G2>;
    type G2ScalarMulWitness = G2ScalarMulWitness<E::G2>;
    type MsmG2Witness = MsmG2Witness<E::G2, <E::G1 as Group>::Scalar>;
    // GT operations
    type GtMulWitness = GtMulWitness<E::GT>;
    type GtExpWitness = GtExpWitness<E::GT>;
    // Pairing operations
    type PairingWitness = PairingWitness<E::G1, E::G2, E::GT>;
    type MultiPairingWitness = MultiPairingWitness<E::G1, E::G2, E::GT>;
}

/// Witness for GT exponentiation using square-and-multiply.
///
/// Captures the intermediate values during exponentiation: base^scalar.
/// In GT (multiplicative group), this is computed as repeated squaring and multiplication.
#[derive(Clone, Debug)]
pub struct GtExpWitness<GT = ArkGT> {
    /// The base element being exponentiated
    pub base: GT,
    /// Scalar decomposed into bits (LSB first)
    pub scalar_bits: Vec<bool>,
    /// Intermediate squaring results: base, base^2, base^4, ...
    pub squares: Vec<GT>,
    /// Running accumulator after processing each bit
    pub accumulators: Vec<GT>,
    /// Final result: base^scalar
    pub result: GT,
}

impl<GT> WitnessResult<GT> for GtExpWitness<GT> {
    fn result(&self) -> Option<&GT> {
        Some(&self.result)
    }
}

/// Witness for G1 scalar multiplication using double-and-add.
#[derive(Clone, Debug)]
pub struct G1ScalarMulWitness<G1 = ArkG1> {
    /// The point being scaled
    pub point: G1,
    /// Scalar decomposed into bits (LSB first)
    pub scalar_bits: Vec<bool>,
    /// Intermediate doubling results: P, 2P, 4P, ...
    pub doubles: Vec<G1>,
    /// Running accumulator after processing each bit
    pub accumulators: Vec<G1>,
    /// Final result: point * scalar
    pub result: G1,
}

impl<G1> WitnessResult<G1> for G1ScalarMulWitness<G1> {
    fn result(&self) -> Option<&G1> {
        Some(&self.result)
    }
}

/// Witness for G2 scalar multiplication using double-and-add.
#[derive(Clone, Debug)]
pub struct G2ScalarMulWitness<G2 = ArkG2> {
    /// The point being scaled
    pub point: G2,
    /// Scalar decomposed into bits (LSB first)
    pub scalar_bits: Vec<bool>,
    /// Intermediate doubling results: P, 2P, 4P, ...
    pub doubles: Vec<G2>,
    /// Running accumulator after processing each bit
    pub accumulators: Vec<G2>,
    /// Final result: point * scalar
    pub result: G2,
}

impl<G2> WitnessResult<G2> for G2ScalarMulWitness<G2> {
    fn result(&self) -> Option<&G2> {
        Some(&self.result)
    }
}

/// Witness for GT multiplication (Fq12 multiplication).
///
/// Since GT is a multiplicative group, "group addition" is field multiplication.
#[derive(Clone, Debug)]
pub struct GtMulWitness<GT = ArkGT> {
    /// Left operand
    pub lhs: GT,
    /// Right operand
    pub rhs: GT,
    /// Intermediate values during Fq12 multiplication (Karatsuba steps)
    pub intermediates: Vec<GT>,
    /// Final result: lhs * rhs
    pub result: GT,
}

impl<GT> WitnessResult<GT> for GtMulWitness<GT> {
    fn result(&self) -> Option<&GT> {
        Some(&self.result)
    }
}

/// Single step in the Miller loop computation.
#[derive(Clone, Debug)]
pub struct MillerStep<GT = ArkGT> {
    /// Line evaluation at this step
    pub line_eval: GT,
    /// Accumulated value after this step
    pub accumulator: GT,
}

/// Witness for single pairing e(G1, G2) -> GT.
///
/// Captures the Miller loop iterations and final exponentiation.
#[derive(Clone, Debug)]
pub struct PairingWitness<G1 = ArkG1, G2 = ArkG2, GT = ArkGT> {
    /// G1 input point
    pub g1: G1,
    /// G2 input point
    pub g2: G2,
    /// Miller loop step-by-step trace
    pub miller_steps: Vec<MillerStep<GT>>,
    /// Final exponentiation intermediate values
    pub final_exp_steps: Vec<GT>,
    /// Final pairing result
    pub result: GT,
}

impl<G1, G2, GT> WitnessResult<GT> for PairingWitness<G1, G2, GT> {
    fn result(&self) -> Option<&GT> {
        Some(&self.result)
    }
}

/// Witness for multi-pairing: `∏ e(g1s[i], g2s[i])`.
#[derive(Clone, Debug)]
pub struct MultiPairingWitness<G1 = ArkG1, G2 = ArkG2, GT = ArkGT> {
    /// G1 input points
    pub g1s: Vec<G1>,
    /// G2 input points
    pub g2s: Vec<G2>,
    /// Miller loop traces for each pair
    pub individual_millers: Vec<Vec<MillerStep<GT>>>,
    /// Combined Miller loop result before final exponentiation
    pub combined_miller: GT,
    /// Final exponentiation steps
    pub final_exp_steps: Vec<GT>,
    /// Final multi-pairing result
    pub result: GT,
}

impl<G1, G2, GT> WitnessResult<GT> for MultiPairingWitness<G1, G2, GT> {
    fn result(&self) -> Option<&GT> {
        Some(&self.result)
    }
}

/// Witness for G1 multi-scalar multiplication.
///
/// For detailed Pippenger algorithm traces, stores bucket states.
#[derive(Clone, Debug)]
pub struct MsmG1Witness<G1 = ArkG1, Scalar = ArkFr> {
    /// Base points
    pub bases: Vec<G1>,
    /// Scalar values
    pub scalars: Vec<Scalar>,
    /// Bucket sums (simplified - actual Pippenger has more structure)
    pub bucket_sums: Vec<G1>,
    /// Running sum intermediates
    pub running_sums: Vec<G1>,
    /// Final MSM result
    pub result: G1,
}

impl<G1, Scalar> WitnessResult<G1> for MsmG1Witness<G1, Scalar> {
    fn result(&self) -> Option<&G1> {
        Some(&self.result)
    }
}

/// Witness for G2 multi-scalar multiplication.
#[derive(Clone, Debug)]
pub struct MsmG2Witness<G2 = ArkG2, Scalar = ArkFr> {
    /// Base points
    pub bases: Vec<G2>,
    /// Scalar values
    pub scalars: Vec<Scalar>,
    /// Bucket sums
    pub bucket_sums: Vec<G2>,
    /// Running sum intermediates
    pub running_sums: Vec<G2>,
    /// Final MSM result
    pub result: G2,
}

impl<G2, Scalar> WitnessResult<G2> for MsmG2Witness<G2, Scalar> {
    fn result(&self) -> Option<&G2> {
        Some(&self.result)
    }
}

/// Witness for G1 addition.
#[derive(Clone, Debug)]
pub struct G1AddWitness<G1 = ArkG1> {
    /// First operand
    pub a: G1,
    /// Second operand
    pub b: G1,
    /// Result: a + b
    pub result: G1,
}

impl<G1> WitnessResult<G1> for G1AddWitness<G1> {
    fn result(&self) -> Option<&G1> {
        Some(&self.result)
    }
}

/// Witness for G2 addition.
#[derive(Clone, Debug)]
pub struct G2AddWitness<G2 = ArkG2> {
    /// First operand
    pub a: G2,
    /// Second operand
    pub b: G2,
    /// Result: a + b
    pub result: G2,
}

impl<G2> WitnessResult<G2> for G2AddWitness<G2> {
    fn result(&self) -> Option<&G2> {
        Some(&self.result)
    }
}

/// Simplified witness generator for the Arkworks backend.
///
/// This generator creates basic witnesses with inputs, outputs, and scalar
/// bit decompositions. Most intermediate traces are empty.
///
/// By default, this is instantiated for BN254. For other curves, specify a different `E`.
pub struct SimpleWitnessGenerator<E: PairingCurve = BN254>(std::marker::PhantomData<E>);

impl<E: PairingCurve> Default for SimpleWitnessGenerator<E> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<E> WitnessGenerator<SimpleWitnessBackend<E>, E> for SimpleWitnessGenerator<E>
where
    E: PairingCurve + Send + Sync + 'static,
    <E::G1 as Group>::Scalar: ScalarBits,
{
    fn generate_gt_exp(
        base: &E::GT,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::GT,
    ) -> GtExpWitness<E::GT> {
        let scalar_bits = scalar.bits_le();

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

    fn generate_g1_scalar_mul(
        point: &E::G1,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::G1,
    ) -> G1ScalarMulWitness<E::G1> {
        let scalar_bits = scalar.bits_le();

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

    fn generate_g2_scalar_mul(
        point: &E::G2,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::G2,
    ) -> G2ScalarMulWitness<E::G2> {
        let scalar_bits = scalar.bits_le();

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

    fn generate_gt_mul(lhs: &E::GT, rhs: &E::GT, result: &E::GT) -> GtMulWitness<E::GT> {
        GtMulWitness {
            lhs: *lhs,
            rhs: *rhs,
            intermediates: vec![],
            result: *result,
        }
    }

    fn generate_pairing(
        g1: &E::G1,
        g2: &E::G2,
        result: &E::GT,
    ) -> PairingWitness<E::G1, E::G2, E::GT> {
        PairingWitness {
            g1: *g1,
            g2: *g2,
            miller_steps: vec![],
            final_exp_steps: vec![],
            result: *result,
        }
    }

    fn generate_multi_pairing(
        g1s: &[E::G1],
        g2s: &[E::G2],
        result: &E::GT,
    ) -> MultiPairingWitness<E::G1, E::G2, E::GT> {
        MultiPairingWitness {
            g1s: g1s.to_vec(),
            g2s: g2s.to_vec(),
            individual_millers: vec![],
            combined_miller: E::GT::identity(),
            final_exp_steps: vec![],
            result: *result,
        }
    }

    fn generate_msm_g1(
        bases: &[E::G1],
        scalars: &[<E::G1 as Group>::Scalar],
        result: &E::G1,
    ) -> MsmG1Witness<E::G1, <E::G1 as Group>::Scalar> {
        MsmG1Witness {
            bases: bases.to_vec(),
            scalars: scalars.to_vec(),
            bucket_sums: vec![],
            running_sums: vec![],
            result: *result,
        }
    }

    fn generate_msm_g2(
        bases: &[E::G2],
        scalars: &[<E::G1 as Group>::Scalar],
        result: &E::G2,
    ) -> MsmG2Witness<E::G2, <E::G1 as Group>::Scalar> {
        MsmG2Witness {
            bases: bases.to_vec(),
            scalars: scalars.to_vec(),
            bucket_sums: vec![],
            running_sums: vec![],
            result: *result,
        }
    }

    fn generate_g1_add(a: &E::G1, b: &E::G1, result: &E::G1) -> G1AddWitness<E::G1> {
        G1AddWitness {
            a: *a,
            b: *b,
            result: *result,
        }
    }

    fn generate_g2_add(a: &E::G2, b: &E::G2, result: &E::G2) -> G2AddWitness<E::G2> {
        G2AddWitness {
            a: *a,
            b: *b,
            result: *result,
        }
    }
}
