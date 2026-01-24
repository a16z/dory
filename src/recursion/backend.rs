//! Tracing backend for recursive verification.
//!
//! This module provides `TracingBackend`, which implements `VerifierBackend`
//! using traced wrapper types (`TraceG1`, `TraceG2`, `TraceGT`). Operations
//! are recorded for witness generation or use hints for fast verification.

use std::rc::Rc;

use crate::error::DoryError;
use crate::primitives::arithmetic::{Field, Group, PairingCurve};
use crate::primitives::backend::VerifierBackend;

use super::ast::RoundMsg;
use super::trace::{TraceG1, TraceG2, TraceGT, TracePairing};
use super::{CtxHandle, WitnessBackend, WitnessGenerator};

/// Tracing backend for recursive verification.
///
/// This backend wraps group operations using `TraceG1`, `TraceG2`, `TraceGT`
/// which automatically record operations (in witness generation mode) or
/// use precomputed hints (in hint-based mode).
pub struct TracingBackend<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    ctx: CtxHandle<W, E, Gen>,
}

impl<W, E, Gen> TracingBackend<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    /// Create a new tracing backend with the given context.
    #[inline(always)]
    pub fn new(ctx: CtxHandle<W, E, Gen>) -> Self {
        Self { ctx }
    }

    /// Get a clone of the context handle.
    #[inline(always)]
    pub fn ctx(&self) -> CtxHandle<W, E, Gen> {
        Rc::clone(&self.ctx)
    }
}

impl<W, E, Gen> VerifierBackend for TracingBackend<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
    <E::G1 as Group>::Scalar: Field,
    Gen: WitnessGenerator<W, E>,
{
    type Curve = E;
    type Scalar = <E::G1 as Group>::Scalar;
    type G1 = TraceG1<W, E, Gen>;
    type G2 = TraceG2<W, E, Gen>;
    type GT = TraceGT<W, E, Gen>;

    #[inline(always)]
    fn wrap_g1_setup(
        &mut self,
        value: E::G1,
        name: &'static str,
        index: Option<usize>,
    ) -> Self::G1 {
        TraceG1::from_setup(value, Rc::clone(&self.ctx), name, index)
    }

    #[inline(always)]
    fn wrap_g2_setup(
        &mut self,
        value: E::G2,
        name: &'static str,
        index: Option<usize>,
    ) -> Self::G2 {
        TraceG2::from_setup(value, Rc::clone(&self.ctx), name, index)
    }

    #[inline(always)]
    fn wrap_gt_setup(
        &mut self,
        value: E::GT,
        name: &'static str,
        index: Option<usize>,
    ) -> Self::GT {
        TraceGT::from_setup(value, Rc::clone(&self.ctx), name, index)
    }

    #[inline(always)]
    fn wrap_g1_proof(&mut self, value: E::G1, name: &'static str) -> Self::G1 {
        TraceG1::from_proof(value, Rc::clone(&self.ctx), name)
    }

    #[inline(always)]
    fn wrap_g2_proof(&mut self, value: E::G2, name: &'static str) -> Self::G2 {
        TraceG2::from_proof(value, Rc::clone(&self.ctx), name)
    }

    #[inline(always)]
    fn wrap_gt_proof(&mut self, value: E::GT, name: &'static str) -> Self::GT {
        TraceGT::from_proof(value, Rc::clone(&self.ctx), name)
    }

    #[inline(always)]
    fn wrap_g1_proof_round(
        &mut self,
        value: E::G1,
        round: usize,
        is_first_msg: bool,
        name: &'static str,
    ) -> Self::G1 {
        let msg = if is_first_msg {
            RoundMsg::First
        } else {
            RoundMsg::Second
        };
        TraceG1::from_proof_round(value, Rc::clone(&self.ctx), round, msg, name)
    }

    #[inline(always)]
    fn wrap_g2_proof_round(
        &mut self,
        value: E::G2,
        round: usize,
        is_first_msg: bool,
        name: &'static str,
    ) -> Self::G2 {
        let msg = if is_first_msg {
            RoundMsg::First
        } else {
            RoundMsg::Second
        };
        TraceG2::from_proof_round(value, Rc::clone(&self.ctx), round, msg, name)
    }

    #[inline(always)]
    fn wrap_gt_proof_round(
        &mut self,
        value: E::GT,
        round: usize,
        is_first_msg: bool,
        name: &'static str,
    ) -> Self::GT {
        let msg = if is_first_msg {
            RoundMsg::First
        } else {
            RoundMsg::Second
        };
        TraceGT::from_proof_round(value, Rc::clone(&self.ctx), round, msg, name)
    }

    #[inline(always)]
    fn g1_scale(&mut self, g: &Self::G1, s: &Self::Scalar) -> Self::G1 {
        g.scale(s)
    }

    #[inline(always)]
    fn g1_add(&mut self, a: &Self::G1, b: &Self::G1) -> Self::G1 {
        a.clone() + b.clone()
    }

    #[inline(always)]
    fn g2_scale(&mut self, g: &Self::G2, s: &Self::Scalar) -> Self::G2 {
        g.scale(s)
    }

    #[inline(always)]
    fn g2_add(&mut self, a: &Self::G2, b: &Self::G2) -> Self::G2 {
        a.clone() + b.clone()
    }

    #[inline(always)]
    fn gt_scale(&mut self, g: &Self::GT, s: &Self::Scalar) -> Self::GT {
        g.scale(s)
    }

    #[inline(always)]
    fn gt_mul(&mut self, a: &Self::GT, b: &Self::GT) -> Self::GT {
        a.clone() + b.clone() // TraceGT uses Add for GT multiplication
    }

    #[inline(always)]
    fn multi_pair(&mut self, g1s: &[Self::G1], g2s: &[Self::G2]) -> Self::GT {
        TracePairing::new(Rc::clone(&self.ctx)).multi_pair(g1s, g2s)
    }

    #[inline(always)]
    fn gt_eq(&mut self, lhs: &Self::GT, rhs: &Self::GT) -> Result<(), DoryError> {
        // Record AST equality constraint if AST tracing is enabled
        if let Some(mut ast) = self.ctx.ast_mut() {
            if let (Some(lhs_id), Some(rhs_id)) = (lhs.value_id(), rhs.value_id()) {
                ast.push_eq(lhs_id, rhs_id, "gt equality");
            }
        }

        // Also verify for soundness
        if lhs.inner() == rhs.inner() {
            Ok(())
        } else {
            Err(DoryError::InvalidProof)
        }
    }

    #[inline(always)]
    fn set_num_rounds(&mut self, rounds: usize) {
        self.ctx.set_num_rounds(rounds);
    }

    #[inline(always)]
    fn advance_round(&mut self) {
        self.ctx.advance_round();
    }

    #[inline(always)]
    fn enter_final(&mut self) {
        self.ctx.enter_final();
    }
}
