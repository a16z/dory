//! Trace context for automatic operation tracing during verification.
//!
//! This module provides [`TraceContext`], a unified context that manages both
//! witness generation and symbolic verification modes. Operations executed
//! through trace types automatically record witnesses or build AST based on
//! the context's mode.

use std::cell::{RefCell, RefMut};
use std::marker::PhantomData;
use std::rc::Rc;

use super::ast::{AstBuilder, AstGraph};
use super::witness::{OpId, OpType, WitnessBackend};
use crate::primitives::arithmetic::{Group, PairingCurve};

use super::{OpIdBuilder, WitnessCollection, WitnessCollector, WitnessGenerator};

/// Execution mode for traced verification operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecutionMode {
    /// Compute operations and record witnesses.
    /// Used during prover witness generation phase.
    #[default]
    WitnessGeneration,

    /// Build AST only, no computation.
    /// Used for verifier recursion where we just need proof obligations.
    Symbolic,
}

/// Handle to a trace context
pub type CtxHandle<W, E, Gen> = Rc<TraceContext<W, E, Gen>>;

/// Context for executing arithmetic operations with automatic tracing.
///
/// In **witness generation** mode, all traced operations are computed and
/// their witnesses are recorded. Used by the prover.
///
/// In **symbolic** mode, operations build an AST without computation.
/// Used by the verifier for recursion (proof obligations).
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
    /// Witness collector (only active in WitnessGeneration mode).
    collector: RefCell<Option<WitnessCollector<W, E, Gen>>>,
    /// AST builder for recording operation wiring.
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
    /// Create a context for witness generation mode (prover).
    ///
    /// All traced operations will be computed and their witnesses recorded.
    pub fn for_witness_gen() -> Self {
        Self {
            mode: ExecutionMode::WitnessGeneration,
            id_builder: RefCell::new(OpIdBuilder::new()),
            collector: RefCell::new(Some(WitnessCollector::new())),
            ast: RefCell::new(None),
            _phantom: PhantomData,
        }
    }

    /// Create a context for symbolic mode (verifier recursion).
    ///
    /// In symbolic mode:
    /// - No group operations are computed
    /// - AST is built with operation wiring
    /// - No witnesses are recorded
    ///
    /// After verification, call `take_ast()` to get the proof obligations.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ctx = Rc::new(TraceContext::for_symbolic());
    /// verify_recursive(..., ctx.clone())?;
    /// let ast = ctx.take_ast().unwrap();
    /// // ast contains proof obligations for circuit generation
    /// ```
    pub fn for_symbolic() -> Self {
        Self {
            mode: ExecutionMode::Symbolic,
            id_builder: RefCell::new(OpIdBuilder::new()),
            collector: RefCell::new(None),
            ast: RefCell::new(Some(AstBuilder::new())),
            _phantom: PhantomData,
        }
    }

    /// Create a context for witness generation with AST tracing enabled.
    ///
    /// This combines `for_witness_gen()` with `with_ast()`.
    pub fn for_witness_gen_with_ast() -> Self {
        Self::for_witness_gen().with_ast()
    }

    /// Enable AST tracing for this context.
    ///
    /// When enabled, all operations will record AST nodes for circuit wiring.
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
        RefMut::filter_map(self.ast.borrow_mut(), Option::as_mut).ok()
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

    /// Finalize and return the collected witnesses (if in witness generation mode).
    ///
    /// Returns `None` if in symbolic mode (no witnesses collected).
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

    /// Check if running in symbolic mode.
    #[inline]
    pub fn is_symbolic(&self) -> bool {
        self.mode == ExecutionMode::Symbolic
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
