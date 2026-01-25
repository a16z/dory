//! Verifier backend abstraction for polymorphic verification.
//!
//! This module defines the `VerifierBackend` trait which abstracts group operations,
//! allowing the same verification logic to work with both native group elements
//! (for fast verification) and traced wrappers (for recursive verification).

use std::marker::PhantomData;

use super::arithmetic::{Field, Group, PairingCurve};
use crate::error::DoryError;

/// Backend trait for polymorphic verification.
///
/// Implementations of this trait define how group operations are executed.
/// The same verification code can work with different backends:
/// - `NativeBackend`: Direct computation on group elements
/// - `TracingBackend` (in recursion module): Records operations for witness generation
pub trait VerifierBackend {
    /// The underlying pairing curve
    type Curve: PairingCurve;
    /// Scalar field type
    type Scalar: Field;
    /// G1 group element type
    type G1: Clone;
    /// G2 group element type
    type G2: Clone;
    /// GT group element type
    type GT: Clone;

    // ========== Element Wrapping ==========
    // These methods convert raw curve elements into backend-specific types.
    // For NativeBackend, these are identity functions.
    // For TracingBackend, these create traced wrappers with metadata.

    /// Wrap a G1 element from setup
    fn wrap_g1_setup(
        &mut self,
        value: <Self::Curve as PairingCurve>::G1,
        name: &'static str,
        index: Option<usize>,
    ) -> Self::G1;

    /// Wrap a G2 element from setup
    fn wrap_g2_setup(
        &mut self,
        value: <Self::Curve as PairingCurve>::G2,
        name: &'static str,
        index: Option<usize>,
    ) -> Self::G2;

    /// Wrap a GT element from setup
    fn wrap_gt_setup(
        &mut self,
        value: <Self::Curve as PairingCurve>::GT,
        name: &'static str,
        index: Option<usize>,
    ) -> Self::GT;

    /// Wrap a G1 element from proof
    fn wrap_g1_proof(
        &mut self,
        value: <Self::Curve as PairingCurve>::G1,
        name: &'static str,
    ) -> Self::G1;

    /// Wrap a G2 element from proof
    fn wrap_g2_proof(
        &mut self,
        value: <Self::Curve as PairingCurve>::G2,
        name: &'static str,
    ) -> Self::G2;

    /// Wrap a GT element from proof
    fn wrap_gt_proof(
        &mut self,
        value: <Self::Curve as PairingCurve>::GT,
        name: &'static str,
    ) -> Self::GT;

    /// Wrap a G1 element from a proof round message
    fn wrap_g1_proof_round(
        &mut self,
        value: <Self::Curve as PairingCurve>::G1,
        round: usize,
        is_first_msg: bool,
        name: &'static str,
    ) -> Self::G1;

    /// Wrap a G2 element from a proof round message
    fn wrap_g2_proof_round(
        &mut self,
        value: <Self::Curve as PairingCurve>::G2,
        round: usize,
        is_first_msg: bool,
        name: &'static str,
    ) -> Self::G2;

    /// Wrap a GT element from a proof round message
    fn wrap_gt_proof_round(
        &mut self,
        value: <Self::Curve as PairingCurve>::GT,
        round: usize,
        is_first_msg: bool,
        name: &'static str,
    ) -> Self::GT;

    // ========== G1 Operations ==========

    /// Scalar multiplication in G1: g * s
    fn g1_scale(&mut self, g: &Self::G1, s: &Self::Scalar) -> Self::G1;

    /// Addition in G1: a + b
    fn g1_add(&mut self, a: &Self::G1, b: &Self::G1) -> Self::G1;

    // ========== G2 Operations ==========

    /// Scalar multiplication in G2: g * s
    fn g2_scale(&mut self, g: &Self::G2, s: &Self::Scalar) -> Self::G2;

    /// Addition in G2: a + b
    fn g2_add(&mut self, a: &Self::G2, b: &Self::G2) -> Self::G2;

    // ========== GT Operations ==========

    /// Exponentiation in GT: g^s (scalar multiplication in additive notation)
    fn gt_scale(&mut self, g: &Self::GT, s: &Self::Scalar) -> Self::GT;

    /// Multiplication in GT: a * b (addition in additive notation)
    fn gt_mul(&mut self, a: &Self::GT, b: &Self::GT) -> Self::GT;

    // ========== Pairing ==========

    /// Multi-pairing: ∏ e(g1s[i], g2s[i])
    fn multi_pair(&mut self, g1s: &[Self::G1], g2s: &[Self::G2]) -> Self::GT;

    // ========== Equality Check ==========

    /// Check GT equality: lhs == rhs
    ///
    /// For native backend, this just compares values.
    /// For tracing backend, this also records the constraint.
    ///
    /// # Errors
    ///
    /// Returns `DoryError::InvalidProof` if `lhs != rhs`.
    fn gt_eq(&mut self, lhs: &Self::GT, rhs: &Self::GT) -> Result<(), DoryError>;

    // ========== Lifecycle Hooks ==========
    // These are used by TracingBackend to track round structure.
    // NativeBackend ignores them.

    /// Set the total number of rounds (no-op for native)
    fn set_num_rounds(&mut self, _rounds: usize) {}

    /// Advance to the next round (no-op for native)
    fn advance_round(&mut self) {}

    /// Enter the final verification phase (no-op for native)
    fn enter_final(&mut self) {}
}

/// Native backend for direct computation on group elements.
///
/// This is the default backend for `verify_evaluation_proof`.
/// All operations are direct computations with zero overhead.
pub struct NativeBackend<E: PairingCurve> {
    _marker: PhantomData<E>,
}

impl<E: PairingCurve> NativeBackend<E> {
    /// Create a new native backend.
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<E: PairingCurve> Default for NativeBackend<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> VerifierBackend for NativeBackend<E>
where
    E: PairingCurve,
    E::G1: Group,
    E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
    <E::G1 as Group>::Scalar: Field,
{
    type Curve = E;
    type Scalar = <E::G1 as Group>::Scalar;
    type G1 = E::G1;
    type G2 = E::G2;
    type GT = E::GT;

    // Wrapping methods are identity functions for native backend
    #[inline(always)]
    fn wrap_g1_setup(&mut self, value: E::G1, _name: &'static str, _index: Option<usize>) -> E::G1 {
        value
    }

    #[inline(always)]
    fn wrap_g2_setup(&mut self, value: E::G2, _name: &'static str, _index: Option<usize>) -> E::G2 {
        value
    }

    #[inline(always)]
    fn wrap_gt_setup(&mut self, value: E::GT, _name: &'static str, _index: Option<usize>) -> E::GT {
        value
    }

    #[inline(always)]
    fn wrap_g1_proof(&mut self, value: E::G1, _name: &'static str) -> E::G1 {
        value
    }

    #[inline(always)]
    fn wrap_g2_proof(&mut self, value: E::G2, _name: &'static str) -> E::G2 {
        value
    }

    #[inline(always)]
    fn wrap_gt_proof(&mut self, value: E::GT, _name: &'static str) -> E::GT {
        value
    }

    #[inline(always)]
    fn wrap_g1_proof_round(
        &mut self,
        value: E::G1,
        _round: usize,
        _is_first_msg: bool,
        _name: &'static str,
    ) -> E::G1 {
        value
    }

    #[inline(always)]
    fn wrap_g2_proof_round(
        &mut self,
        value: E::G2,
        _round: usize,
        _is_first_msg: bool,
        _name: &'static str,
    ) -> E::G2 {
        value
    }

    #[inline(always)]
    fn wrap_gt_proof_round(
        &mut self,
        value: E::GT,
        _round: usize,
        _is_first_msg: bool,
        _name: &'static str,
    ) -> E::GT {
        value
    }

    #[inline(always)]
    fn g1_scale(&mut self, g: &Self::G1, s: &Self::Scalar) -> Self::G1 {
        g.scale(s)
    }

    #[inline(always)]
    fn g1_add(&mut self, a: &Self::G1, b: &Self::G1) -> Self::G1 {
        *a + *b
    }

    #[inline(always)]
    fn g2_scale(&mut self, g: &Self::G2, s: &Self::Scalar) -> Self::G2 {
        g.scale(s)
    }

    #[inline(always)]
    fn g2_add(&mut self, a: &Self::G2, b: &Self::G2) -> Self::G2 {
        *a + *b
    }

    #[inline(always)]
    fn gt_scale(&mut self, g: &Self::GT, s: &Self::Scalar) -> Self::GT {
        g.scale(s)
    }

    #[inline(always)]
    fn gt_mul(&mut self, a: &Self::GT, b: &Self::GT) -> Self::GT {
        *a + *b // GT uses additive notation internally
    }

    #[inline(always)]
    fn multi_pair(&mut self, g1s: &[Self::G1], g2s: &[Self::G2]) -> Self::GT {
        E::multi_pair(g1s, g2s)
    }

    #[inline(always)]
    fn gt_eq(&mut self, lhs: &Self::GT, rhs: &Self::GT) -> Result<(), DoryError> {
        if lhs == rhs {
            Ok(())
        } else {
            Err(DoryError::InvalidProof)
        }
    }
}
