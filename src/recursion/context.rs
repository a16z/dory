//! Trace context for automatic operation tracing during verification.
//!
//! This module provides [`TraceContext`], a unified context that manages both
//! witness generation and hint-based verification modes. Operations executed
//! through trace types automatically record witnesses or use hints based on
//! the context's mode.

use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use super::witness::{OpId, OpType, WitnessBackend};
use crate::primitives::arithmetic::{Group, PairingCurve};

use super::{HintMap, OpIdBuilder, WitnessCollection, WitnessCollector, WitnessGenerator};

/// Execution mode for traced verification operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutionMode {
    /// Always compute operations and record witnesses.
    /// Used during initial witness generation phase.
    #[default]
    WitnessGeneration,

    /// Try hints first, fall back to compute with warning.
    /// Used during recursive verification when hints should be available.
    HintBased,
}

/// Handle to a trace context
pub type CtxHandle<W, E, Gen> = Rc<TraceContext<W, E, Gen>>;

/// Context for executing arithmetic operations with automatic tracing.
///
/// In **witness generation** mode, all traced operations are computed and
/// their witnesses are recorded.
///
/// In **hint-based** mode, traced operations first check for pre-computed hints.
/// If a hint is missing, the operation is computed with a warning logged via
/// `tracing::warn!`.
///
/// # Interior Mutability
///
/// This context uses [`RefCell`] for interior mutability because arithmetic
/// operators (`Add`, `Sub`, `Mul`) take `&self`, not `&mut self`. Since
/// verification is single-threaded, `RefCell` provides the necessary mutability.
pub struct TraceContext<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    mode: ExecutionMode,
    id_builder: RefCell<OpIdBuilder>,
    collector: RefCell<Option<WitnessCollector<W, E, Gen>>>,
    hints: Option<HintMap<E>>,
    missing_hints: RefCell<Vec<OpId>>,
    _phantom: PhantomData<(W, E, Gen)>,
}

impl<W, E, Gen> TraceContext<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    /// Create a context for witness generation mode.
    ///
    /// All traced operations will be computed and their witnesses recorded.
    pub fn for_witness_gen() -> Self {
        Self {
            mode: ExecutionMode::WitnessGeneration,
            id_builder: RefCell::new(OpIdBuilder::new()),
            collector: RefCell::new(Some(WitnessCollector::new())),
            hints: None,
            missing_hints: RefCell::new(Vec::new()),
            _phantom: PhantomData,
        }
    }

    /// Create a context for hint-based verification.
    ///
    /// Traced operations will use pre-computed hints when available,
    /// falling back to computation with a warning when hints are missing.
    pub fn for_hints(hints: HintMap<E>) -> Self {
        Self {
            mode: ExecutionMode::HintBased,
            id_builder: RefCell::new(OpIdBuilder::new()),
            collector: RefCell::new(None),
            hints: Some(hints),
            missing_hints: RefCell::new(Vec::new()),
            _phantom: PhantomData,
        }
    }

    /// Get the current execution mode.
    #[inline]
    pub fn mode(&self) -> ExecutionMode {
        self.mode
    }

    /// Advance to the next round.
    pub fn advance_round(&self) {
        self.id_builder.borrow_mut().advance_round();
    }

    /// Enter the final verification phase.
    pub fn enter_final(&self) {
        self.id_builder.borrow_mut().enter_final();
    }

    /// Get the current round number.
    pub fn round(&self) -> u16 {
        self.id_builder.borrow().round()
    }

    /// Set the number of rounds for witness collection.
    pub fn set_num_rounds(&self, num_rounds: usize) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.set_num_rounds(num_rounds);
        }
    }

    /// Generate the next operation ID for the given type.
    pub fn next_id(&self, op_type: OpType) -> OpId {
        self.id_builder.borrow_mut().next(op_type)
    }

    /// Get all missing hints encountered during hint-based verification.
    pub fn missing_hints(&self) -> Vec<OpId> {
        self.missing_hints.borrow().clone()
    }

    /// Check if any hints were missing during verification.
    pub fn had_missing_hints(&self) -> bool {
        !self.missing_hints.borrow().is_empty()
    }

    /// Record that a hint was missing for the given operation.
    pub fn record_missing_hint(&self, id: OpId) {
        self.missing_hints.borrow_mut().push(id);
    }

    /// Finalize and return the collected witnesses (if in witness generation mode).
    ///
    /// Returns `None` if no collector was active (pure hint mode without recording).
    pub fn finalize(self) -> Option<WitnessCollection<W>> {
        self.collector.into_inner().map(|c| c.finalize())
    }

    /// Get a G1 hint for the given operation.
    #[inline]
    pub fn get_hint_g1(&self, id: OpId) -> Option<E::G1> {
        self.hints.as_ref().and_then(|h| h.get_g1(&id).copied())
    }

    /// Get a G2 hint for the given operation.
    #[inline]
    pub fn get_hint_g2(&self, id: OpId) -> Option<E::G2> {
        self.hints.as_ref().and_then(|h| h.get_g2(&id).copied())
    }

    /// Get a GT hint for the given operation.
    #[inline]
    pub fn get_hint_gt(&self, id: OpId) -> Option<E::GT> {
        self.hints.as_ref().and_then(|h| h.get_gt(&id).copied())
    }

    /// Record a GT exponentiation witness.
    pub fn record_gt_exp(
        &self,
        id: OpId,
        base: &E::GT,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::GT,
    ) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_gt_exp(id, base, scalar, result);
        }
    }

    /// Record a G1 scalar multiplication witness.
    pub fn record_g1_scalar_mul(
        &self,
        id: OpId,
        point: &E::G1,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::G1,
    ) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_g1_scalar_mul(id, point, scalar, result);
        }
    }

    /// Record a G2 scalar multiplication witness.
    pub fn record_g2_scalar_mul(
        &self,
        id: OpId,
        point: &E::G2,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::G2,
    ) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_g2_scalar_mul(id, point, scalar, result);
        }
    }

    /// Record a GT multiplication witness.
    pub fn record_gt_mul(&self, id: OpId, lhs: &E::GT, rhs: &E::GT, result: &E::GT) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_gt_mul(id, lhs, rhs, result);
        }
    }

    /// Record a pairing witness.
    pub fn record_pairing(&self, id: OpId, g1: &E::G1, g2: &E::G2, result: &E::GT) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_pairing(id, g1, g2, result);
        }
    }

    /// Record a multi-pairing witness.
    pub fn record_multi_pairing(&self, id: OpId, g1s: &[E::G1], g2s: &[E::G2], result: &E::GT) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_multi_pairing(id, g1s, g2s, result);
        }
    }

    /// Record a G1 MSM witness.
    pub fn record_msm_g1(
        &self,
        id: OpId,
        bases: &[E::G1],
        scalars: &[<E::G1 as Group>::Scalar],
        result: &E::G1,
    ) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_msm_g1(id, bases, scalars, result);
        }
    }

    /// Record a G2 MSM witness.
    pub fn record_msm_g2(
        &self,
        id: OpId,
        bases: &[E::G2],
        scalars: &[<E::G1 as Group>::Scalar],
        result: &E::G2,
    ) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_msm_g2(id, bases, scalars, result);
        }
    }
}
