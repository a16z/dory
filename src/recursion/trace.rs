//! Trace wrapper types for automatic operation tracing.
//!
//! This module provides wrapper types (`TraceG1`, `TraceG2`, `TraceGT`) that
//! automatically trace arithmetic operations during verification. Operations
//! are recorded (in witness generation mode) or use hints (in hint-based mode).
//!
//! When AST tracing is enabled on the context, these wrappers also carry a
//! `ValueId` that tracks the value through the operation DAG.

// Some methods/types are kept for API completeness but not currently used
#![allow(dead_code)]

use std::ops::{Add, Neg, Sub};
use std::rc::Rc;

use super::ast::{AstOp, ScalarValue, ValueId, ValueType};
use super::witness::{OpType, WitnessBackend};
use crate::primitives::arithmetic::{Group, PairingCurve};

use super::{CtxHandle, ExecutionMode, WitnessGenerator};

/// G1 element with automatic operation tracing.
#[derive(Clone)]
pub(crate) struct TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    inner: E::G1,
    ctx: CtxHandle<W, E, Gen>,
    /// ValueId for AST wiring (None if AST tracing is disabled).
    value_id: Option<ValueId>,
}

impl<W, E, Gen> TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    /// Wrap a G1 element with a trace context (no AST tracking).
    #[inline]
    pub(crate) fn new(inner: E::G1, ctx: CtxHandle<W, E, Gen>) -> Self {
        Self {
            inner,
            ctx,
            value_id: None,
        }
    }

    /// Wrap a G1 element with a trace context and ValueId for AST tracking.
    #[inline]
    pub(crate) fn new_with_id(
        inner: E::G1,
        ctx: CtxHandle<W, E, Gen>,
        value_id: ValueId,
    ) -> Self {
        Self {
            inner,
            ctx,
            value_id: Some(value_id),
        }
    }

    /// Get a reference to the underlying G1 element.
    #[inline]
    pub(crate) fn inner(&self) -> &E::G1 {
        &self.inner
    }

    /// Unwrap to get the raw G1 value.
    #[inline]
    pub(crate) fn into_inner(self) -> E::G1 {
        self.inner
    }

    /// Get the ValueId for this element (if AST tracking is enabled).
    #[inline]
    pub(crate) fn value_id(&self) -> Option<ValueId> {
        self.value_id
    }

    /// Get a clone of the context handle.
    #[inline]
    pub(crate) fn ctx(&self) -> CtxHandle<W, E, Gen> {
        Rc::clone(&self.ctx)
    }

    /// Create a traced G1 from a setup element, interning it for AST if enabled.
    pub(crate) fn from_setup(
        inner: E::G1,
        ctx: CtxHandle<W, E, Gen>,
        name: &'static str,
        index: Option<usize>,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_g1_setup(inner, name, index))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Create a traced G1 from a proof element, interning it for AST if enabled.
    pub(crate) fn from_proof(
        inner: E::G1,
        ctx: CtxHandle<W, E, Gen>,
        name: &'static str,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_g1_proof(inner, name))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Create a traced G1 from a per-round proof message element.
    pub(crate) fn from_proof_round(
        inner: E::G1,
        ctx: CtxHandle<W, E, Gen>,
        round: usize,
        msg: super::ast::RoundMsg,
        name: &'static str,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_g1_proof_round(inner, round, msg, name))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Traced scalar multiplication.
    pub(crate) fn scale(&self, scalar: &<E::G1 as Group>::Scalar) -> Self {
        self.scale_named(scalar, None)
    }

    /// Traced scalar multiplication with an optional debug name for the scalar.
    pub(crate) fn scale_named(
        &self,
        scalar: &<E::G1 as Group>::Scalar,
        scalar_name: Option<&'static str>,
    ) -> Self {
        let id = self.ctx.next_id(OpType::G1ScalarMul);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner.scale(scalar);
                self.ctx
                    .record_g1_scalar_mul(id, &self.inner, scalar, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "G1ScalarMul",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    self.inner.scale(scalar)
                }
            }
        };

        // AST tracking: record the scalar mul operation
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let scalar_value = match scalar_name {
                Some(name) => ScalarValue::named(scalar.clone(), name),
                None => ScalarValue::new(scalar.clone()),
            };
            Some(ast.push(
                ValueType::G1,
                AstOp::G1ScalarMul {
                    op_id: Some(id),
                    point: self.value_id.expect("G1ScalarMul input must have ValueId when AST enabled"),
                    scalar: scalar_value,
                },
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: Rc::clone(&self.ctx),
            value_id: out_value_id,
        }
    }

    /// Get the identity element for G1.
    pub(crate) fn identity(ctx: CtxHandle<W, E, Gen>) -> Self {
        Self::new(E::G1::identity(), ctx)
    }
}

// G1 + G1
impl<W, E, Gen> Add for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let id = self.ctx.next_id(OpType::G1Add);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner + rhs.inner;
                self.ctx.record_g1_add(id, &self.inner, &rhs.inner, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "G1Add",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    self.inner + rhs.inner
                }
            }
        };

        // AST tracking: record G1Add with OpId for witness linkage
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let a = self.value_id.expect("G1Add lhs must have ValueId when AST enabled");
            let b = rhs.value_id.expect("G1Add rhs must have ValueId when AST enabled");
            Some(ast.push_with_opid(
                ValueType::G1,
                AstOp::G1Add { op_id: Some(id), a, b },
                id,
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: self.ctx,
            value_id: out_value_id,
        }
    }
}

impl<W, E, Gen> Add<&Self> for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        let id = self.ctx.next_id(OpType::G1Add);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner + rhs.inner;
                self.ctx.record_g1_add(id, &self.inner, &rhs.inner, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "G1Add",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    self.inner + rhs.inner
                }
            }
        };

        // AST tracking: record G1Add with OpId for witness linkage
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let a = self.value_id.expect("G1Add lhs must have ValueId when AST enabled");
            let b = rhs.value_id.expect("G1Add rhs must have ValueId when AST enabled");
            Some(ast.push_with_opid(
                ValueType::G1,
                AstOp::G1Add { op_id: Some(id), a, b },
                id,
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: self.ctx,
            value_id: out_value_id,
        }
    }
}

// G1 - G1 is implemented as G1 + (-G1)
impl<W, E, Gen> Sub for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl<W, E, Gen> Sub<&Self> for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        // Compute negation directly (cheap, no witness tracking)
        let neg_result = -rhs.inner;

        // Record addition with witness/hint tracking
        let add_id = self.ctx.next_id(OpType::G1Add);
        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner + neg_result;
                self.ctx.record_g1_add(add_id, &self.inner, &neg_result, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(add_id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?add_id,
                        op_type = "G1Add",
                        round = add_id.round,
                        index = add_id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(add_id);
                    self.inner + neg_result
                }
            }
        };

        // AST tracking: record G1Add (subtraction is add with negated operand, but AST only tracks add)
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let a = self.value_id.expect("G1Sub lhs must have ValueId when AST enabled");
            let b = rhs.value_id.expect("G1Sub rhs must have ValueId when AST enabled");
            Some(ast.push_with_opid(
                ValueType::G1,
                AstOp::G1Add { op_id: Some(add_id), a, b },
                add_id,
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: self.ctx,
            value_id: out_value_id,
        }
    }
}

// -G1
impl<W, E, Gen> Neg for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn neg(self) -> Self {
        // Negation is cheap - no witness/hint tracking needed, just compute directly
        let result = -self.inner;

        // No AST tracking for negation - it's a cheap inline operation
        Self {
            inner: result,
            ctx: self.ctx,
            value_id: None,
        }
    }
}

/// G2 element with automatic operation tracing.
#[derive(Clone)]
pub(crate) struct TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    inner: E::G2,
    ctx: CtxHandle<W, E, Gen>,
    /// ValueId for AST wiring (None if AST tracing is disabled).
    value_id: Option<ValueId>,
}

impl<W, E, Gen> TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    /// Wrap a G2 element with a trace context (no AST tracking).
    #[inline]
    pub(crate) fn new(inner: E::G2, ctx: CtxHandle<W, E, Gen>) -> Self {
        Self {
            inner,
            ctx,
            value_id: None,
        }
    }

    /// Wrap a G2 element with a trace context and ValueId for AST tracking.
    #[inline]
    pub(crate) fn new_with_id(
        inner: E::G2,
        ctx: CtxHandle<W, E, Gen>,
        value_id: ValueId,
    ) -> Self {
        Self {
            inner,
            ctx,
            value_id: Some(value_id),
        }
    }

    /// Get a reference to the underlying G2 element.
    #[inline]
    pub(crate) fn inner(&self) -> &E::G2 {
        &self.inner
    }

    /// Unwrap to get the raw G2 value.
    #[inline]
    pub(crate) fn into_inner(self) -> E::G2 {
        self.inner
    }

    /// Get the ValueId for this element (if AST tracking is enabled).
    #[inline]
    pub(crate) fn value_id(&self) -> Option<ValueId> {
        self.value_id
    }

    /// Get a clone of the context handle.
    #[inline]
    pub(crate) fn ctx(&self) -> CtxHandle<W, E, Gen> {
        Rc::clone(&self.ctx)
    }

    /// Create a traced G2 from a setup element, interning it for AST if enabled.
    pub(crate) fn from_setup(
        inner: E::G2,
        ctx: CtxHandle<W, E, Gen>,
        name: &'static str,
        index: Option<usize>,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_g2_setup(inner, name, index))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Create a traced G2 from a proof element, interning it for AST if enabled.
    pub(crate) fn from_proof(
        inner: E::G2,
        ctx: CtxHandle<W, E, Gen>,
        name: &'static str,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_g2_proof(inner, name))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Create a traced G2 from a per-round proof message element.
    pub(crate) fn from_proof_round(
        inner: E::G2,
        ctx: CtxHandle<W, E, Gen>,
        round: usize,
        msg: super::ast::RoundMsg,
        name: &'static str,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_g2_proof_round(inner, round, msg, name))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Traced scalar multiplication.
    pub(crate) fn scale(&self, scalar: &<E::G1 as Group>::Scalar) -> Self
    where
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        self.scale_named(scalar, None)
    }

    /// Traced scalar multiplication with an optional debug name for the scalar.
    pub(crate) fn scale_named(
        &self,
        scalar: &<E::G1 as Group>::Scalar,
        scalar_name: Option<&'static str>,
    ) -> Self
    where
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        let id = self.ctx.next_id(OpType::G2ScalarMul);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner.scale(scalar);
                self.ctx
                    .record_g2_scalar_mul(id, &self.inner, scalar, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "G2ScalarMul",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    self.inner.scale(scalar)
                }
            }
        };

        // AST tracking: record the scalar mul operation
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let scalar_value = match scalar_name {
                Some(name) => ScalarValue::named(scalar.clone(), name),
                None => ScalarValue::new(scalar.clone()),
            };
            Some(ast.push(
                ValueType::G2,
                AstOp::G2ScalarMul {
                    op_id: Some(id),
                    point: self.value_id.expect("G2ScalarMul input must have ValueId when AST enabled"),
                    scalar: scalar_value,
                },
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: Rc::clone(&self.ctx),
            value_id: out_value_id,
        }
    }

    /// Get the identity element for G2.
    pub(crate) fn identity(ctx: CtxHandle<W, E, Gen>) -> Self {
        Self::new(E::G2::identity(), ctx)
    }
}

// G2 + G2
impl<W, E, Gen> Add for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let id = self.ctx.next_id(OpType::G2Add);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner + rhs.inner;
                self.ctx.record_g2_add(id, &self.inner, &rhs.inner, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "G2Add",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    self.inner + rhs.inner
                }
            }
        };

        // AST tracking: record G2Add with OpId for witness linkage
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let a = self.value_id.expect("G2Add lhs must have ValueId when AST enabled");
            let b = rhs.value_id.expect("G2Add rhs must have ValueId when AST enabled");
            Some(ast.push_with_opid(
                ValueType::G2,
                AstOp::G2Add { op_id: Some(id), a, b },
                id,
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: self.ctx,
            value_id: out_value_id,
        }
    }
}

impl<W, E, Gen> Add<&Self> for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        let id = self.ctx.next_id(OpType::G2Add);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner + rhs.inner;
                self.ctx.record_g2_add(id, &self.inner, &rhs.inner, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "G2Add",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    self.inner + rhs.inner
                }
            }
        };

        // AST tracking: record G2Add with OpId for witness linkage
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let a = self.value_id.expect("G2Add lhs must have ValueId when AST enabled");
            let b = rhs.value_id.expect("G2Add rhs must have ValueId when AST enabled");
            Some(ast.push_with_opid(
                ValueType::G2,
                AstOp::G2Add { op_id: Some(id), a, b },
                id,
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: self.ctx,
            value_id: out_value_id,
        }
    }
}

// G2 - G2 is implemented as G2 + (-G2)
impl<W, E, Gen> Sub for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl<W, E, Gen> Sub<&Self> for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        // Compute negation directly (cheap, no witness tracking)
        let neg_result = -rhs.inner;

        // Record addition with witness/hint tracking
        let add_id = self.ctx.next_id(OpType::G2Add);
        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner + neg_result;
                self.ctx.record_g2_add(add_id, &self.inner, &neg_result, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(add_id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?add_id,
                        op_type = "G2Add",
                        round = add_id.round,
                        index = add_id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(add_id);
                    self.inner + neg_result
                }
            }
        };

        // AST tracking: record G2Add (subtraction is add with negated operand, but AST only tracks add)
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let a = self.value_id.expect("G2Sub lhs must have ValueId when AST enabled");
            let b = rhs.value_id.expect("G2Sub rhs must have ValueId when AST enabled");
            Some(ast.push_with_opid(
                ValueType::G2,
                AstOp::G2Add { op_id: Some(add_id), a, b },
                add_id,
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: self.ctx,
            value_id: out_value_id,
        }
    }
}

// -G2
impl<W, E, Gen> Neg for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn neg(self) -> Self {
        // Negation is cheap - no witness/hint tracking needed, just compute directly
        let result = -self.inner;

        // No AST tracking for negation - it's a cheap inline operation
        Self {
            inner: result,
            ctx: self.ctx,
            value_id: None,
        }
    }
}

/// GT element with automatic operation tracing.
///
/// Note: GT is a multiplicative group, so "addition" in the Group trait
/// corresponds to field multiplication in Fq12
#[derive(Clone)]
pub(crate) struct TraceGT<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    inner: E::GT,
    ctx: CtxHandle<W, E, Gen>,
    /// ValueId for AST wiring (None if AST tracing is disabled).
    value_id: Option<ValueId>,
}

impl<W, E, Gen> TraceGT<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    /// Wrap a GT element with a trace context (no AST tracking).
    #[inline]
    pub(crate) fn new(inner: E::GT, ctx: CtxHandle<W, E, Gen>) -> Self {
        Self {
            inner,
            ctx,
            value_id: None,
        }
    }

    /// Wrap a GT element with a trace context and ValueId for AST tracking.
    #[inline]
    pub(crate) fn new_with_id(
        inner: E::GT,
        ctx: CtxHandle<W, E, Gen>,
        value_id: ValueId,
    ) -> Self {
        Self {
            inner,
            ctx,
            value_id: Some(value_id),
        }
    }

    /// Get a reference to the underlying GT element.
    #[inline]
    pub(crate) fn inner(&self) -> &E::GT {
        &self.inner
    }

    /// Unwrap to get the raw GT value.
    #[inline]
    pub(crate) fn into_inner(self) -> E::GT {
        self.inner
    }

    /// Get the ValueId for this element (if AST tracking is enabled).
    #[inline]
    pub(crate) fn value_id(&self) -> Option<ValueId> {
        self.value_id
    }

    /// Get a clone of the context handle.
    #[inline]
    pub(crate) fn ctx(&self) -> CtxHandle<W, E, Gen> {
        Rc::clone(&self.ctx)
    }

    /// Create a traced GT from a setup element, interning it for AST if enabled.
    pub(crate) fn from_setup(
        inner: E::GT,
        ctx: CtxHandle<W, E, Gen>,
        name: &'static str,
        index: Option<usize>,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_gt_setup(inner, name, index))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Create a traced GT from a proof element, interning it for AST if enabled.
    pub(crate) fn from_proof(
        inner: E::GT,
        ctx: CtxHandle<W, E, Gen>,
        name: &'static str,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_gt_proof(inner, name))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Create a traced GT from a per-round proof message element.
    pub(crate) fn from_proof_round(
        inner: E::GT,
        ctx: CtxHandle<W, E, Gen>,
        round: usize,
        msg: super::ast::RoundMsg,
        name: &'static str,
    ) -> Self {
        let value_id = if let Some(mut ast) = ctx.ast_mut() {
            Some(ast.intern_gt_proof_round(inner, round, msg, name))
        } else {
            None
        };
        Self { inner, ctx, value_id }
    }

    /// Traced GT exponentiation (scalar multiplication in multiplicative group).
    pub(crate) fn scale(&self, scalar: &<E::G1 as Group>::Scalar) -> Self
    where
        E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        self.scale_named(scalar, None)
    }

    /// Traced GT exponentiation with an optional debug name for the scalar.
    pub(crate) fn scale_named(
        &self,
        scalar: &<E::G1 as Group>::Scalar,
        scalar_name: Option<&'static str>,
    ) -> Self
    where
        E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        let id = self.ctx.next_id(OpType::GtExp);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner.scale(scalar);
                self.ctx.record_gt_exp(id, &self.inner, scalar, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "GtExp",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    self.inner.scale(scalar)
                }
            }
        };

        // AST tracking: record the exponentiation operation
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let scalar_value = match scalar_name {
                Some(name) => ScalarValue::named(scalar.clone(), name),
                None => ScalarValue::new(scalar.clone()),
            };
            Some(ast.push(
                ValueType::GT,
                AstOp::GTExp {
                    op_id: Some(id),
                    base: self.value_id.expect("GTExp input must have ValueId when AST enabled"),
                    scalar: scalar_value,
                },
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: Rc::clone(&self.ctx),
            value_id: out_value_id,
        }
    }

    /// Traced GT multiplication.
    pub(crate) fn mul_traced(&self, rhs: &Self) -> Self {
        let id = self.ctx.next_id(OpType::GtMul);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner + rhs.inner;
                self.ctx.record_gt_mul(id, &self.inner, &rhs.inner, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "GtMul",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    self.inner + rhs.inner
                }
            }
        };

        // AST tracking: record the multiplication operation
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let lhs_id = self.value_id.expect("GTMul lhs must have ValueId when AST enabled");
            let rhs_id = rhs.value_id.expect("GTMul rhs must have ValueId when AST enabled");
            Some(ast.push(
                ValueType::GT,
                AstOp::GTMul {
                    op_id: Some(id),
                    lhs: lhs_id,
                    rhs: rhs_id,
                },
            ))
        } else {
            None
        };

        Self {
            inner: result,
            ctx: Rc::clone(&self.ctx),
            value_id: out_value_id,
        }
    }

    /// Get the identity element for GT (the multiplicative identity).
    pub(crate) fn identity(ctx: CtxHandle<W, E, Gen>) -> Self {
        Self::new(E::GT::identity(), ctx)
    }
}

// GT * GT
impl<W, E, Gen> Add for TraceGT<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        self.mul_traced(&rhs)
    }
}

impl<W, E, Gen> Add<&Self> for TraceGT<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        self.mul_traced(rhs)
    }
}

// GT^(-1) (inversion in multiplicative group)
impl<W, E, Gen> Neg for TraceGT<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn neg(self) -> Self {
        // GT negation (inversion) - compute directly, no AST tracking
        // (GT negation is not used in Dory verification)
        let result = -self.inner;

        Self {
            inner: result,
            ctx: self.ctx,
            value_id: None, // No AST node for GT negation
        }
    }
}

/// Traced pairing operations.
///
/// Provides `pair` and `multi_pair` methods that automatically trace
/// the pairing computation.
pub(crate) struct TracePairing<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    ctx: CtxHandle<W, E, Gen>,
}

impl<W, E, Gen> TracePairing<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    /// Create a new traced pairing operator with the given context.
    pub(crate) fn new(ctx: CtxHandle<W, E, Gen>) -> Self {
        Self { ctx }
    }

    /// Traced single pairing e(G1, G2) -> GT.
    pub(crate) fn pair(
        &self,
        g1: &TraceG1<W, E, Gen>,
        g2: &TraceG2<W, E, Gen>,
    ) -> TraceGT<W, E, Gen> {
        let id = self.ctx.next_id(OpType::Pairing);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = E::pair(&g1.inner, &g2.inner);
                self.ctx.record_pairing(id, &g1.inner, &g2.inner, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "Pairing",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    E::pair(&g1.inner, &g2.inner)
                }
            }
        };

        // AST tracking: record the pairing operation
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let g1_id = g1.value_id.expect("Pairing G1 input must have ValueId when AST enabled");
            let g2_id = g2.value_id.expect("Pairing G2 input must have ValueId when AST enabled");
            Some(ast.push(
                ValueType::GT,
                AstOp::Pairing {
                    op_id: Some(id),
                    g1: g1_id,
                    g2: g2_id,
                },
            ))
        } else {
            None
        };

        TraceGT {
            inner: result,
            ctx: Rc::clone(&self.ctx),
            value_id: out_value_id,
        }
    }

    /// Traced single pairing from raw G1/G2 elements.
    ///
    /// Note: This method does NOT record AST nodes because the raw inputs
    /// don't have ValueIds. Use `pair()` with traced inputs for AST tracking.
    pub(crate) fn pair_raw(&self, g1: &E::G1, g2: &E::G2) -> TraceGT<W, E, Gen> {
        let id = self.ctx.next_id(OpType::Pairing);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = E::pair(g1, g2);
                self.ctx.record_pairing(id, g1, g2, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "Pairing",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    E::pair(g1, g2)
                }
            }
        };

        // Raw pairings don't have ValueIds for inputs, so no AST tracking
        TraceGT::new(result, Rc::clone(&self.ctx))
    }

    /// Traced multi-pairing: product of e(g1s[i], g2s[i]).
    pub(crate) fn multi_pair(
        &self,
        g1s: &[TraceG1<W, E, Gen>],
        g2s: &[TraceG2<W, E, Gen>],
    ) -> TraceGT<W, E, Gen> {
        let id = self.ctx.next_id(OpType::MultiPairing);

        let g1_inners: Vec<E::G1> = g1s.iter().map(|g| g.inner).collect();
        let g2_inners: Vec<E::G2> = g2s.iter().map(|g| g.inner).collect();

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = E::multi_pair(&g1_inners, &g2_inners);
                self.ctx
                    .record_multi_pairing(id, &g1_inners, &g2_inners, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "MultiPairing",
                        round = id.round,
                        index = id.index,
                        num_pairs = g1s.len(),
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    E::multi_pair(&g1_inners, &g2_inners)
                }
            }
        };

        // AST tracking: record the multi-pairing operation
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let g1_ids: Vec<ValueId> = g1s
                .iter()
                .map(|g| g.value_id.expect("MultiPairing G1 inputs must have ValueId when AST enabled"))
                .collect();
            let g2_ids: Vec<ValueId> = g2s
                .iter()
                .map(|g| g.value_id.expect("MultiPairing G2 inputs must have ValueId when AST enabled"))
                .collect();
            Some(ast.push(
                ValueType::GT,
                AstOp::MultiPairing {
                    op_id: Some(id),
                    g1s: g1_ids,
                    g2s: g2_ids,
                },
            ))
        } else {
            None
        };

        TraceGT {
            inner: result,
            ctx: Rc::clone(&self.ctx),
            value_id: out_value_id,
        }
    }

    /// Traced multi-pairing from raw slices.
    ///
    /// Note: This method does NOT record AST nodes because the raw inputs
    /// don't have ValueIds. Use `multi_pair()` with traced inputs for AST tracking.
    pub(crate) fn multi_pair_raw(&self, g1s: &[E::G1], g2s: &[E::G2]) -> TraceGT<W, E, Gen> {
        let id = self.ctx.next_id(OpType::MultiPairing);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = E::multi_pair(g1s, g2s);
                self.ctx.record_multi_pairing(id, g1s, g2s, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "MultiPairing",
                        round = id.round,
                        index = id.index,
                        num_pairs = g1s.len(),
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    E::multi_pair(g1s, g2s)
                }
            }
        };

        // Raw pairings don't have ValueIds for inputs, so no AST tracking
        TraceGT::new(result, Rc::clone(&self.ctx))
    }
}

/// Traced MSM operations.
pub(crate) struct TraceMsm<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    ctx: CtxHandle<W, E, Gen>,
}

impl<W, E, Gen> TraceMsm<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    /// Create a new traced MSM operator with the given context.
    pub(crate) fn new(ctx: CtxHandle<W, E, Gen>) -> Self {
        Self { ctx }
    }

    /// Traced G1 MSM using the provided MSM implementation.
    pub(crate) fn msm_g1<F>(
        &self,
        bases: &[TraceG1<W, E, Gen>],
        scalars: &[<E::G1 as Group>::Scalar],
        msm_fn: F,
    ) -> TraceG1<W, E, Gen>
    where
        F: FnOnce(&[E::G1], &[<E::G1 as Group>::Scalar]) -> E::G1,
    {
        self.msm_g1_named(bases, scalars, None, msm_fn)
    }

    /// Traced G1 MSM with optional scalar names for debugging.
    pub(crate) fn msm_g1_named<F>(
        &self,
        bases: &[TraceG1<W, E, Gen>],
        scalars: &[<E::G1 as Group>::Scalar],
        scalar_names: Option<&[&'static str]>,
        msm_fn: F,
    ) -> TraceG1<W, E, Gen>
    where
        F: FnOnce(&[E::G1], &[<E::G1 as Group>::Scalar]) -> E::G1,
    {
        let id = self.ctx.next_id(OpType::MsmG1);
        let base_inners: Vec<E::G1> = bases.iter().map(|b| b.inner).collect();

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = msm_fn(&base_inners, scalars);
                self.ctx.record_msm_g1(id, &base_inners, scalars, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "MsmG1",
                        round = id.round,
                        index = id.index,
                        size = bases.len(),
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    msm_fn(&base_inners, scalars)
                }
            }
        };

        // AST tracking: record the MSM operation
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let point_ids: Vec<ValueId> = bases
                .iter()
                .map(|b| b.value_id.expect("MsmG1 base points must have ValueId when AST enabled"))
                .collect();
            let scalar_values: Vec<ScalarValue<<E::G1 as Group>::Scalar>> = scalars
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    if let Some(names) = scalar_names {
                        ScalarValue::named(s.clone(), names[i])
                    } else {
                        ScalarValue::new(s.clone())
                    }
                })
                .collect();
            Some(ast.push(
                ValueType::G1,
                AstOp::MsmG1 {
                    op_id: Some(id),
                    points: point_ids,
                    scalars: scalar_values,
                },
            ))
        } else {
            None
        };

        TraceG1 {
            inner: result,
            ctx: Rc::clone(&self.ctx),
            value_id: out_value_id,
        }
    }

    /// Traced G1 MSM from raw bases.
    ///
    /// Note: This method does NOT record AST nodes because the raw inputs
    /// don't have ValueIds. Use `msm_g1()` with traced inputs for AST tracking.
    pub(crate) fn msm_g1_raw<F>(
        &self,
        bases: &[E::G1],
        scalars: &[<E::G1 as Group>::Scalar],
        msm_fn: F,
    ) -> TraceG1<W, E, Gen>
    where
        F: FnOnce(&[E::G1], &[<E::G1 as Group>::Scalar]) -> E::G1,
    {
        let id = self.ctx.next_id(OpType::MsmG1);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = msm_fn(bases, scalars);
                self.ctx.record_msm_g1(id, bases, scalars, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "MsmG1",
                        round = id.round,
                        index = id.index,
                        size = bases.len(),
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    msm_fn(bases, scalars)
                }
            }
        };

        // Raw MSM doesn't have ValueIds for inputs, so no AST tracking
        TraceG1::new(result, Rc::clone(&self.ctx))
    }

    /// Traced G2 MSM using the provided MSM implementation.
    pub(crate) fn msm_g2<F>(
        &self,
        bases: &[TraceG2<W, E, Gen>],
        scalars: &[<E::G1 as Group>::Scalar],
        msm_fn: F,
    ) -> TraceG2<W, E, Gen>
    where
        F: FnOnce(&[E::G2], &[<E::G1 as Group>::Scalar]) -> E::G2,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        self.msm_g2_named(bases, scalars, None, msm_fn)
    }

    /// Traced G2 MSM with optional scalar names for debugging.
    pub(crate) fn msm_g2_named<F>(
        &self,
        bases: &[TraceG2<W, E, Gen>],
        scalars: &[<E::G1 as Group>::Scalar],
        scalar_names: Option<&[&'static str]>,
        msm_fn: F,
    ) -> TraceG2<W, E, Gen>
    where
        F: FnOnce(&[E::G2], &[<E::G1 as Group>::Scalar]) -> E::G2,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        let id = self.ctx.next_id(OpType::MsmG2);
        let base_inners: Vec<E::G2> = bases.iter().map(|b| b.inner).collect();

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = msm_fn(&base_inners, scalars);
                self.ctx.record_msm_g2(id, &base_inners, scalars, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "MsmG2",
                        round = id.round,
                        index = id.index,
                        size = bases.len(),
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    msm_fn(&base_inners, scalars)
                }
            }
        };

        // AST tracking: record the MSM operation
        let out_value_id = if let Some(mut ast) = self.ctx.ast_mut() {
            let point_ids: Vec<ValueId> = bases
                .iter()
                .map(|b| b.value_id.expect("MsmG2 base points must have ValueId when AST enabled"))
                .collect();
            let scalar_values: Vec<ScalarValue<<E::G1 as Group>::Scalar>> = scalars
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    if let Some(names) = scalar_names {
                        ScalarValue::named(s.clone(), names[i])
                    } else {
                        ScalarValue::new(s.clone())
                    }
                })
                .collect();
            Some(ast.push(
                ValueType::G2,
                AstOp::MsmG2 {
                    op_id: Some(id),
                    points: point_ids,
                    scalars: scalar_values,
                },
            ))
        } else {
            None
        };

        TraceG2 {
            inner: result,
            ctx: Rc::clone(&self.ctx),
            value_id: out_value_id,
        }
    }

    /// Traced G2 MSM from raw bases.
    ///
    /// Note: This method does NOT record AST nodes because the raw inputs
    /// don't have ValueIds. Use `msm_g2()` with traced inputs for AST tracking.
    pub(crate) fn msm_g2_raw<F>(
        &self,
        bases: &[E::G2],
        scalars: &[<E::G1 as Group>::Scalar],
        msm_fn: F,
    ) -> TraceG2<W, E, Gen>
    where
        F: FnOnce(&[E::G2], &[<E::G1 as Group>::Scalar]) -> E::G2,
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        let id = self.ctx.next_id(OpType::MsmG2);

        let result = match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = msm_fn(bases, scalars);
                self.ctx.record_msm_g2(id, bases, scalars, &result);
                result
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(id) {
                    result
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "MsmG2",
                        round = id.round,
                        index = id.index,
                        size = bases.len(),
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    msm_fn(bases, scalars)
                }
            }
        };

        // Raw MSM doesn't have ValueIds for inputs, so no AST tracking
        TraceG2::new(result, Rc::clone(&self.ctx))
    }
}
