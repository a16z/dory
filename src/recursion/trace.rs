//! Trace wrapper types for automatic operation tracing.
//!
//! This module provides wrapper types (`TraceG1`, `TraceG2`, `TraceGT`) that
//! automatically trace arithmetic operations during verification. Operations
//! are recorded (in witness generation mode) or use hints (in hint-based mode)

// Some methods/types are kept for API completeness but not currently used
#![allow(dead_code)]

use std::ops::{Add, Neg, Sub};
use std::rc::Rc;

use super::witness::{OpType, WitnessBackend};
use crate::primitives::arithmetic::{Group, PairingCurve};

use super::{CtxHandle, ExecutionMode, WitnessGenerator};

/// G1 element with automatic operation tracing.
#[derive(Clone)]
pub(crate) struct TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    inner: E::G1,
    ctx: CtxHandle<W, E, Gen>,
}

impl<W, E, Gen> TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    /// Wrap a G1 element with a trace context.
    #[inline]
    pub(crate) fn new(inner: E::G1, ctx: CtxHandle<W, E, Gen>) -> Self {
        Self { inner, ctx }
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

    /// Get a clone of the context handle.
    #[inline]
    pub(crate) fn ctx(&self) -> CtxHandle<W, E, Gen> {
        Rc::clone(&self.ctx)
    }

    /// Traced scalar multiplication.
    pub(crate) fn scale(&self, scalar: &<E::G1 as Group>::Scalar) -> Self {
        let id = self.ctx.next_id(OpType::G1ScalarMul);

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner.scale(scalar);
                self.ctx
                    .record_g1_scalar_mul(id, &self.inner, scalar, &result);
                Self::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(id) {
                    Self::new(result, Rc::clone(&self.ctx))
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "G1ScalarMul",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    let result = self.inner.scale(scalar);
                    Self::new(result, Rc::clone(&self.ctx))
                }
            }
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
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::new(self.inner + rhs.inner, self.ctx)
    }
}

impl<W, E, Gen> Add<&Self> for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self::new(self.inner + rhs.inner, self.ctx)
    }
}

// G1 - G1
impl<W, E, Gen> Sub for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::new(self.inner - rhs.inner, self.ctx)
    }
}

impl<W, E, Gen> Sub<&Self> for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        Self::new(self.inner - rhs.inner, self.ctx)
    }
}

// -G1
impl<W, E, Gen> Neg for TraceG1<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(-self.inner, self.ctx)
    }
}

/// G2 element with automatic operation tracing.
#[derive(Clone)]
pub(crate) struct TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    inner: E::G2,
    ctx: CtxHandle<W, E, Gen>,
}

impl<W, E, Gen> TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    /// Wrap a G2 element with a trace context.
    #[inline]
    pub(crate) fn new(inner: E::G2, ctx: CtxHandle<W, E, Gen>) -> Self {
        Self { inner, ctx }
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

    /// Get a clone of the context handle.
    #[inline]
    pub(crate) fn ctx(&self) -> CtxHandle<W, E, Gen> {
        Rc::clone(&self.ctx)
    }

    /// Traced scalar multiplication.
    pub(crate) fn scale(&self, scalar: &<E::G1 as Group>::Scalar) -> Self
    where
        E::G2: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        let id = self.ctx.next_id(OpType::G2ScalarMul);

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner.scale(scalar);
                self.ctx
                    .record_g2_scalar_mul(id, &self.inner, scalar, &result);
                Self::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(id) {
                    Self::new(result, Rc::clone(&self.ctx))
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "G2ScalarMul",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    let result = self.inner.scale(scalar);
                    Self::new(result, Rc::clone(&self.ctx))
                }
            }
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
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self::new(self.inner + rhs.inner, self.ctx)
    }
}

impl<W, E, Gen> Add<&Self> for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self::new(self.inner + rhs.inner, self.ctx)
    }
}

// G2 - G2
impl<W, E, Gen> Sub for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self::new(self.inner - rhs.inner, self.ctx)
    }
}

impl<W, E, Gen> Sub<&Self> for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        Self::new(self.inner - rhs.inner, self.ctx)
    }
}

// -G2
impl<W, E, Gen> Neg for TraceG2<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(-self.inner, self.ctx)
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
    Gen: WitnessGenerator<W, E>,
{
    inner: E::GT,
    ctx: CtxHandle<W, E, Gen>,
}

impl<W, E, Gen> TraceGT<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    /// Wrap a GT element with a trace context.
    #[inline]
    pub(crate) fn new(inner: E::GT, ctx: CtxHandle<W, E, Gen>) -> Self {
        Self { inner, ctx }
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

    /// Get a clone of the context handle.
    #[inline]
    pub(crate) fn ctx(&self) -> CtxHandle<W, E, Gen> {
        Rc::clone(&self.ctx)
    }

    /// Traced GT exponentiation (scalar multiplication in multiplicative group).
    pub(crate) fn scale(&self, scalar: &<E::G1 as Group>::Scalar) -> Self
    where
        E::GT: Group<Scalar = <E::G1 as Group>::Scalar>,
    {
        let id = self.ctx.next_id(OpType::GtExp);

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner.scale(scalar);
                self.ctx.record_gt_exp(id, &self.inner, scalar, &result);
                Self::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    Self::new(result, Rc::clone(&self.ctx))
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "GtExp",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    let result = self.inner.scale(scalar);
                    Self::new(result, Rc::clone(&self.ctx))
                }
            }
        }
    }

    /// Traced GT multiplication.
    pub(crate) fn mul_traced(&self, rhs: &Self) -> Self {
        let id = self.ctx.next_id(OpType::GtMul);

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = self.inner + rhs.inner;
                self.ctx.record_gt_mul(id, &self.inner, &rhs.inner, &result);
                Self::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    Self::new(result, Rc::clone(&self.ctx))
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "GtMul",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    let result = self.inner + rhs.inner;
                    Self::new(result, Rc::clone(&self.ctx))
                }
            }
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
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        self.mul_traced(rhs)
    }
}

// GT^(-1) (NOT traced)
impl<W, E, Gen> Neg for TraceGT<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(-self.inner, self.ctx)
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
    Gen: WitnessGenerator<W, E>,
{
    ctx: CtxHandle<W, E, Gen>,
}

impl<W, E, Gen> TracePairing<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
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

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = E::pair(&g1.inner, &g2.inner);
                self.ctx.record_pairing(id, &g1.inner, &g2.inner, &result);
                TraceGT::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    TraceGT::new(result, Rc::clone(&self.ctx))
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "Pairing",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    let result = E::pair(&g1.inner, &g2.inner);
                    TraceGT::new(result, Rc::clone(&self.ctx))
                }
            }
        }
    }

    /// Traced single pairing from raw G1/G2 elements.
    pub(crate) fn pair_raw(&self, g1: &E::G1, g2: &E::G2) -> TraceGT<W, E, Gen> {
        let id = self.ctx.next_id(OpType::Pairing);

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = E::pair(g1, g2);
                self.ctx.record_pairing(id, g1, g2, &result);
                TraceGT::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    TraceGT::new(result, Rc::clone(&self.ctx))
                } else {
                    tracing::warn!(
                        op_id = ?id,
                        op_type = "Pairing",
                        round = id.round,
                        index = id.index,
                        "Missing hint, computing fallback"
                    );
                    self.ctx.record_missing_hint(id);
                    let result = E::pair(g1, g2);
                    TraceGT::new(result, Rc::clone(&self.ctx))
                }
            }
        }
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

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = E::multi_pair(&g1_inners, &g2_inners);
                self.ctx
                    .record_multi_pairing(id, &g1_inners, &g2_inners, &result);
                TraceGT::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    TraceGT::new(result, Rc::clone(&self.ctx))
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
                    let result = E::multi_pair(&g1_inners, &g2_inners);
                    TraceGT::new(result, Rc::clone(&self.ctx))
                }
            }
        }
    }

    /// Traced multi-pairing from raw slices.
    pub(crate) fn multi_pair_raw(&self, g1s: &[E::G1], g2s: &[E::G2]) -> TraceGT<W, E, Gen> {
        let id = self.ctx.next_id(OpType::MultiPairing);

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = E::multi_pair(g1s, g2s);
                self.ctx.record_multi_pairing(id, g1s, g2s, &result);
                TraceGT::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_gt(id) {
                    TraceGT::new(result, Rc::clone(&self.ctx))
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
                    let result = E::multi_pair(g1s, g2s);
                    TraceGT::new(result, Rc::clone(&self.ctx))
                }
            }
        }
    }
}

/// Traced MSM operations.
pub(crate) struct TraceMsm<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    ctx: CtxHandle<W, E, Gen>,
}

impl<W, E, Gen> TraceMsm<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
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
        let id = self.ctx.next_id(OpType::MsmG1);
        let base_inners: Vec<E::G1> = bases.iter().map(|b| b.inner).collect();

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = msm_fn(&base_inners, scalars);
                self.ctx.record_msm_g1(id, &base_inners, scalars, &result);
                TraceG1::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(id) {
                    TraceG1::new(result, Rc::clone(&self.ctx))
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
                    let result = msm_fn(&base_inners, scalars);
                    TraceG1::new(result, Rc::clone(&self.ctx))
                }
            }
        }
    }

    /// Traced G1 MSM from raw bases.
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

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = msm_fn(bases, scalars);
                self.ctx.record_msm_g1(id, bases, scalars, &result);
                TraceG1::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g1(id) {
                    TraceG1::new(result, Rc::clone(&self.ctx))
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
                    let result = msm_fn(bases, scalars);
                    TraceG1::new(result, Rc::clone(&self.ctx))
                }
            }
        }
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
        let id = self.ctx.next_id(OpType::MsmG2);
        let base_inners: Vec<E::G2> = bases.iter().map(|b| b.inner).collect();

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = msm_fn(&base_inners, scalars);
                self.ctx.record_msm_g2(id, &base_inners, scalars, &result);
                TraceG2::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(id) {
                    TraceG2::new(result, Rc::clone(&self.ctx))
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
                    let result = msm_fn(&base_inners, scalars);
                    TraceG2::new(result, Rc::clone(&self.ctx))
                }
            }
        }
    }

    /// Traced G2 MSM from raw bases.
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

        match self.ctx.mode() {
            ExecutionMode::WitnessGeneration => {
                let result = msm_fn(bases, scalars);
                self.ctx.record_msm_g2(id, bases, scalars, &result);
                TraceG2::new(result, Rc::clone(&self.ctx))
            }
            ExecutionMode::HintBased => {
                if let Some(result) = self.ctx.get_hint_g2(id) {
                    TraceG2::new(result, Rc::clone(&self.ctx))
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
                    let result = msm_fn(bases, scalars);
                    TraceG2::new(result, Rc::clone(&self.ctx))
                }
            }
        }
    }
}
