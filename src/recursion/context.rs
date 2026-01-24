//! Trace context for automatic operation tracing during verification.
//!
//! This module provides [`TraceContext`], a unified context that manages both
//! witness generation and hint-based verification modes. Operations executed
//! through trace types automatically record witnesses or use hints based on
//! the context's mode.

use std::cell::{RefCell, RefMut};
use std::marker::PhantomData;
use std::rc::Rc;

use super::ast::{AstBuilder, AstGraph};
use super::witness::{OpId, OpType, WitnessBackend};
use crate::primitives::arithmetic::{Group, PairingCurve};

use super::hint_map::HintResult;
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

    /// Record AST + hints only, skip detailed witness expansion.
    /// Used for two-phase parallel witness generation where:
    /// - Phase 1: Record lightweight op log (AST) + results (hints)
    /// - Phase 2: Expand witnesses in parallel (done by upstream crate)
    Deferred,
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
    E::G1: Group,
    Gen: WitnessGenerator<W, E>,
{
    mode: ExecutionMode,
    id_builder: RefCell<OpIdBuilder>,
    collector: RefCell<Option<WitnessCollector<W, E, Gen>>>,
    /// Hints for hint-based mode (read-only).
    hints: Option<HintMap<E>>,
    /// Hints being recorded in deferred mode (write).
    deferred_hints: RefCell<Option<HintMap<E>>>,
    missing_hints: RefCell<Vec<OpId>>,
    /// Optional AST builder for recording operation wiring.
    ast: RefCell<Option<AstBuilder<E>>>,
    _phantom: PhantomData<(W, E, Gen)>,
}

impl<W, E, Gen> TraceContext<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    E::G1: Group,
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
            deferred_hints: RefCell::new(None),
            missing_hints: RefCell::new(Vec::new()),
            ast: RefCell::new(None),
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
            deferred_hints: RefCell::new(None),
            missing_hints: RefCell::new(Vec::new()),
            ast: RefCell::new(None),
            _phantom: PhantomData,
        }
    }

    /// Create a context for deferred witness expansion.
    ///
    /// In deferred mode:
    /// - Operations are computed and results are recorded to a `HintMap`
    /// - AST is recorded for operation wiring
    /// - Detailed witnesses are NOT expanded (no `WitnessCollector`)
    ///
    /// After verification, call `take_deferred_hints()` and `take_ast()` to get
    /// the recorded data for parallel witness expansion by upstream crates.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Phase 1: Record ops in deferred mode
    /// let ctx = Rc::new(TraceContext::for_deferred());
    /// verify_recursive(..., ctx.clone())?;
    /// let ast = ctx.take_ast().unwrap();
    /// let hints = ctx.take_deferred_hints().unwrap();
    ///
    /// // Phase 2: Expand witnesses in parallel (upstream crate)
    /// let witnesses = parallel_expand_witnesses(&ast, &hints);
    /// ```
    pub fn for_deferred() -> Self {
        Self {
            mode: ExecutionMode::Deferred,
            id_builder: RefCell::new(OpIdBuilder::new()),
            collector: RefCell::new(None), // No witness expansion
            hints: None,
            deferred_hints: RefCell::new(Some(HintMap::new(0))), // Will set rounds later
            missing_hints: RefCell::new(Vec::new()),
            ast: RefCell::new(Some(AstBuilder::new())), // Always enable AST
            _phantom: PhantomData,
        }
    }

    /// Create a context for witness generation with AST tracing enabled.
    ///
    /// This combines `for_witness_gen()` with `with_ast()`.
    pub fn for_witness_gen_with_ast() -> Self {
        Self::for_witness_gen().with_ast()
    }

    /// Create a context for deferred mode (alias for `for_deferred`).
    ///
    /// Provided for API symmetry with `for_witness_gen_with_ast()`.
    pub fn for_deferred_with_ast() -> Self {
        Self::for_deferred()
    }

    /// Enable AST tracing for this context.
    ///
    /// When enabled, all operations will record AST nodes for circuit wiring.
    /// The AST is independent of execution mode (witness gen or hint-based).
    pub fn with_ast(self) -> Self {
        *self.ast.borrow_mut() = Some(AstBuilder::new());
        self
    }

    /// Check if AST tracing is enabled.
    #[inline]
    pub fn has_ast(&self) -> bool {
        self.ast.borrow().is_some()
    }

    /// Get mutable access to the AST builder, if enabled.
    ///
    /// Returns `None` if AST tracing is not enabled.
    pub fn ast_mut(&self) -> Option<RefMut<'_, AstBuilder<E>>> {
        let borrow = self.ast.borrow_mut();
        if borrow.is_some() {
            Some(RefMut::map(borrow, |opt| opt.as_mut().unwrap()))
        } else {
            None
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
        // Also set rounds on deferred hints
        if let Some(ref mut hints) = *self.deferred_hints.borrow_mut() {
            hints.num_rounds = num_rounds;
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
    /// Note: This consumes the context. Use `finalize_with_ast()` if you also need the AST.
    pub fn finalize(self) -> Option<WitnessCollection<W>> {
        self.collector.into_inner().map(|c| c.finalize())
    }

    /// Finalize and return both witnesses and AST graph.
    ///
    /// Returns a tuple of:
    /// - `Option<WitnessCollection<W>>`: Collected witnesses (if in witness generation mode)
    /// - `Option<AstGraph<E>>`: The AST graph (if AST tracing was enabled)
    pub fn finalize_with_ast(self) -> (Option<WitnessCollection<W>>, Option<AstGraph<E>>) {
        let witnesses = self.collector.into_inner().map(|c| c.finalize());
        let ast = self.ast.into_inner().map(|b| b.finalize());
        (witnesses, ast)
    }

    /// Finalize and return just the AST graph (without consuming witnesses).
    ///
    /// Useful when you only care about the AST for circuit generation.
    pub fn take_ast(&self) -> Option<AstGraph<E>> {
        self.ast.borrow_mut().take().map(|b| b.finalize())
    }

    /// Take the deferred hints recorded during deferred mode execution.
    ///
    /// Returns `None` if not in deferred mode or if already taken.
    pub fn take_deferred_hints(&self) -> Option<HintMap<E>> {
        self.deferred_hints.borrow_mut().take()
    }

    /// Check if running in deferred mode.
    #[inline]
    pub fn is_deferred(&self) -> bool {
        self.mode == ExecutionMode::Deferred
    }

    /// Record a hint result in deferred mode.
    ///
    /// This is called internally by trace wrappers to record operation results
    /// without expanding full witnesses.
    pub(crate) fn record_deferred_hint(&self, id: OpId, result: HintResult<E>) {
        if let Some(ref mut hints) = *self.deferred_hints.borrow_mut() {
            hints.insert(id, result);
        }
    }

    /// Get a G1 hint for the given operation.
    #[inline]
    pub fn get_hint_g1(&self, id: OpId) -> Option<E::G1> {
        self.hints.as_ref().and_then(|h| h.get_g1(id).copied())
    }

    /// Get a G2 hint for the given operation.
    #[inline]
    pub fn get_hint_g2(&self, id: OpId) -> Option<E::G2> {
        self.hints.as_ref().and_then(|h| h.get_g2(id).copied())
    }

    /// Get a GT hint for the given operation.
    #[inline]
    pub fn get_hint_gt(&self, id: OpId) -> Option<E::GT> {
        self.hints.as_ref().and_then(|h| h.get_gt(id).copied())
    }

    // ===== G1 operations =====

    /// Record a G1 addition witness.
    pub fn record_g1_add(&self, id: OpId, a: &E::G1, b: &E::G1, result: &E::G1) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_g1_add(id, a, b, result);
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

    // ===== G2 operations =====

    /// Record a G2 addition witness.
    pub fn record_g2_add(&self, id: OpId, a: &E::G2, b: &E::G2, result: &E::G2) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_g2_add(id, a, b, result);
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

    // ===== GT operations =====

    /// Record a GT multiplication witness.
    pub fn record_gt_mul(&self, id: OpId, lhs: &E::GT, rhs: &E::GT, result: &E::GT) {
        if let Some(ref mut collector) = *self.collector.borrow_mut() {
            collector.collect_gt_mul(id, lhs, rhs, result);
        }
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

    // ===== Pairing operations =====

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
}
