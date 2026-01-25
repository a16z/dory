//! Parallel AST evaluation using task-based work-stealing.
//!
//! This module provides infrastructure for evaluating AST operations in parallel
//! using rayon's work-stealing scheduler. Each AST node becomes a task that is
//! executed when all its dependencies are satisfied.
//!
//! # Strategy
//!
//! Instead of synchronizing at level boundaries (wavefront), tasks are spawned
//! dynamically as their dependencies complete. This allows cross-level parallelism
//! and maximum thread utilization.
//!
//! ```text
//! Thread 1: [L0 op] [L1 op] [L2 op] [L1 op] ...
//! Thread 2: [L0 op] [L1 op] [L1 op] [L3 op] ...
//! Thread 3: [L0 op] [L2 op] [L1 op] [L2 op] ...
//! ```
//!
//! No barriers - threads work continuously on any ready task.
//!
//! # Usage
//!
//! ```ignore
//! use dory_pcs::recursion::parallel::TaskExecutor;
//!
//! let executor = TaskExecutor::new(&graph, &inputs, &ops);
//! let results = executor.execute();
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

use super::ast::{AstGraph, AstNode, AstOp, ValueId, ValueType};
use crate::primitives::arithmetic::{Group, PairingCurve};

/// Result of evaluating an AST node.
///
/// This enum mirrors the `ValueType` variants but holds actual computed values.
#[derive(Clone)]
pub enum EvalResult<E: PairingCurve> {
    /// G1 point result.
    G1(E::G1),
    /// G2 point result.
    G2(E::G2),
    /// GT element result.
    GT(E::GT),
}

impl<E: PairingCurve> EvalResult<E> {
    /// Get as G1, panics if wrong type.
    pub fn as_g1(&self) -> &E::G1 {
        match self {
            EvalResult::G1(g1) => g1,
            _ => panic!("Expected G1 result"),
        }
    }

    /// Get as G2, panics if wrong type.
    pub fn as_g2(&self) -> &E::G2 {
        match self {
            EvalResult::G2(g2) => g2,
            _ => panic!("Expected G2 result"),
        }
    }

    /// Get as GT, panics if wrong type.
    pub fn as_gt(&self) -> &E::GT {
        match self {
            EvalResult::GT(gt) => gt,
            _ => panic!("Expected GT result"),
        }
    }

    /// Get the value type of this result.
    pub fn value_type(&self) -> ValueType {
        match self {
            EvalResult::G1(_) => ValueType::G1,
            EvalResult::G2(_) => ValueType::G2,
            EvalResult::GT(_) => ValueType::GT,
        }
    }
}

/// Trait for providing input values to the parallel evaluator.
///
/// Implement this trait to supply the actual values for input nodes
/// (setup elements, proof elements, etc.).
pub trait InputProvider<E: PairingCurve>: Sync {
    /// Get the value for an input node.
    ///
    /// Returns `None` if the input is not available.
    fn get_input(&self, node: &AstNode<E>) -> Option<EvalResult<E>>;
}

/// Trait for evaluating group operations.
///
/// Implement this trait to define how to compute operations.
/// This allows different backends (arkworks, halo2, etc.) to provide
/// their own implementations.
pub trait OperationEvaluator<E: PairingCurve>: Sync
where
    E::G1: Group,
{
    /// Evaluate a G1 addition.
    fn g1_add(&self, a: &E::G1, b: &E::G1) -> E::G1;

    /// Evaluate a G1 scalar multiplication.
    fn g1_scalar_mul(&self, point: &E::G1, scalar: &<E::G1 as Group>::Scalar) -> E::G1;

    /// Evaluate a G1 MSM.
    fn g1_msm(&self, points: &[E::G1], scalars: &[<E::G1 as Group>::Scalar]) -> E::G1;

    /// Evaluate a G2 addition.
    fn g2_add(&self, a: &E::G2, b: &E::G2) -> E::G2;

    /// Evaluate a G2 scalar multiplication.
    fn g2_scalar_mul(&self, point: &E::G2, scalar: &<E::G1 as Group>::Scalar) -> E::G2;

    /// Evaluate a G2 MSM.
    fn g2_msm(&self, points: &[E::G2], scalars: &[<E::G1 as Group>::Scalar]) -> E::G2;

    /// Evaluate a GT multiplication.
    fn gt_mul(&self, lhs: &E::GT, rhs: &E::GT) -> E::GT;

    /// Evaluate a GT exponentiation.
    fn gt_exp(&self, base: &E::GT, scalar: &<E::G1 as Group>::Scalar) -> E::GT;

    /// Evaluate a single pairing.
    fn pairing(&self, g1: &E::G1, g2: &E::G2) -> E::GT;

    /// Evaluate a multi-pairing.
    fn multi_pairing(&self, g1s: &[E::G1], g2s: &[E::G2]) -> E::GT;
}

/// Shared state for task-based execution.
///
/// This structure is shared across all rayon tasks and provides:
/// - Thread-safe storage for computed results
/// - Atomic dependency counters for each node
/// - Consumer map for propagating completion
struct ExecutionState<E: PairingCurve> {
    /// Computed results (thread-safe).
    results: RwLock<HashMap<ValueId, EvalResult<E>>>,
    /// Pending dependency count for each node.
    pending_deps: Vec<AtomicUsize>,
    /// Reverse map: producer -> list of consumers.
    consumers: HashMap<ValueId, Vec<ValueId>>,
}

impl<E: PairingCurve> ExecutionState<E> {
    /// Create new execution state from an AST graph.
    fn new(graph: &AstGraph<E>) -> Self {
        let n = graph.len();

        // Build consumer map
        let consumers = graph.consumers();

        // Initialize pending dependency counts
        let pending_deps: Vec<AtomicUsize> = graph
            .nodes
            .iter()
            .map(|node| AtomicUsize::new(node.op.input_ids().len()))
            .collect();

        Self {
            results: RwLock::new(HashMap::with_capacity(n)),
            pending_deps,
            consumers,
        }
    }

    /// Get a computed result by ID.
    fn get(&self, id: ValueId) -> EvalResult<E> {
        self.results
            .read()
            .unwrap()
            .get(&id)
            .cloned()
            .expect("Dependency must be computed before access")
    }

    /// Store a computed result.
    fn insert(&self, id: ValueId, value: EvalResult<E>) {
        self.results.write().unwrap().insert(id, value);
    }

    /// Decrement dependency count for a consumer, returns true if now ready.
    fn decrement_and_check_ready(&self, consumer_id: ValueId) -> bool {
        let prev = self.pending_deps[consumer_id.0 as usize].fetch_sub(1, Ordering::AcqRel);
        prev == 1 // Was 1, now 0 -> ready
    }

    /// Get consumers of a node.
    fn get_consumers(&self, id: ValueId) -> Option<&Vec<ValueId>> {
        self.consumers.get(&id)
    }

    /// Check if a node is ready (0 pending dependencies).
    fn is_ready(&self, id: ValueId) -> bool {
        self.pending_deps[id.0 as usize].load(Ordering::Acquire) == 0
    }

    /// Extract final results.
    fn into_results(self) -> HashMap<ValueId, EvalResult<E>> {
        self.results.into_inner().unwrap()
    }
}

/// Task-based executor using rayon's work-stealing scheduler.
///
/// This executor spawns tasks dynamically as their dependencies complete,
/// allowing maximum parallelism without level barriers.
///
/// # Algorithm
///
/// 1. All input nodes (0 dependencies) are spawned immediately
/// 2. When a task completes, it checks each consumer:
///    - Decrement consumer's pending_deps atomically
///    - If pending_deps hits 0, spawn the consumer task
/// 3. Rayon's work-stealing ensures efficient load balancing
///
/// # Example
///
/// ```ignore
/// let executor = TaskExecutor::new(&graph, &inputs, &ops);
/// let results = executor.execute();
/// ```
#[cfg(feature = "parallel")]
pub struct TaskExecutor<'a, E, I, Op>
where
    E: PairingCurve,
    E::G1: Group,
    I: InputProvider<E>,
    Op: OperationEvaluator<E>,
{
    graph: &'a AstGraph<E>,
    inputs: &'a I,
    ops: &'a Op,
}

#[cfg(feature = "parallel")]
impl<'a, E, I, Op> TaskExecutor<'a, E, I, Op>
where
    E: PairingCurve,
    E::G1: Group,
    I: InputProvider<E>,
    Op: OperationEvaluator<E>,
{
    /// Create a new task-based executor.
    pub fn new(graph: &'a AstGraph<E>, inputs: &'a I, ops: &'a Op) -> Self {
        Self { graph, inputs, ops }
    }

    /// Execute all nodes using rayon's work-stealing parallelism.
    ///
    /// Tasks are spawned dynamically as dependencies complete, allowing
    /// cross-level parallelism without barrier synchronization.
    pub fn execute(&self) -> HashMap<ValueId, EvalResult<E>> {
        if self.graph.is_empty() {
            return HashMap::new();
        }

        let state = ExecutionState::new(self.graph);

        // Collect initially ready nodes (inputs with 0 dependencies)
        let initial_ready: Vec<ValueId> = (0..self.graph.len())
            .filter(|&idx| state.is_ready(ValueId(idx as u32)))
            .map(|idx| ValueId(idx as u32))
            .collect();

        // Use rayon::scope for dynamic task spawning
        rayon::scope(|s| {
            for id in initial_ready {
                self.spawn_task(s, id, &state);
            }
        });

        state.into_results()
    }

    /// Spawn a task for a node within a rayon scope.
    ///
    /// When the task completes, it spawns any consumers that become ready.
    fn spawn_task<'s>(&'s self, scope: &rayon::Scope<'s>, id: ValueId, state: &'s ExecutionState<E>)
    where
        'a: 's,
    {
        scope.spawn(move |s| {
            // Execute the node
            let node = self.graph.get(id).expect("Node must exist");
            let result = self.evaluate_node(node, state);
            state.insert(id, result);

            // Notify consumers and spawn newly ready ones
            if let Some(consumer_ids) = state.get_consumers(id) {
                for &consumer_id in consumer_ids {
                    if state.decrement_and_check_ready(consumer_id) {
                        // Consumer is now ready - spawn it
                        self.spawn_task(s, consumer_id, state);
                    }
                }
            }
        });
    }

    /// Evaluate a single node, reading dependencies from state.
    fn evaluate_node(&self, node: &AstNode<E>, state: &ExecutionState<E>) -> EvalResult<E> {
        match &node.op {
            AstOp::Input { .. } => self
                .inputs
                .get_input(node)
                .expect("Input provider must supply all inputs"),

            AstOp::G1Add { a, b, .. } => {
                let a_val = state.get(*a);
                let b_val = state.get(*b);
                EvalResult::G1(self.ops.g1_add(a_val.as_g1(), b_val.as_g1()))
            }

            AstOp::G1ScalarMul { point, scalar, .. } => {
                let p = state.get(*point);
                EvalResult::G1(self.ops.g1_scalar_mul(p.as_g1(), &scalar.value))
            }

            AstOp::MsmG1 {
                points, scalars, ..
            } => {
                let pts: Vec<E::G1> = points
                    .iter()
                    .map(|id| state.get(*id).as_g1().clone())
                    .collect();
                let scs: Vec<_> = scalars.iter().map(|s| s.value.clone()).collect();
                EvalResult::G1(self.ops.g1_msm(&pts, &scs))
            }

            AstOp::G2Add { a, b, .. } => {
                let a_val = state.get(*a);
                let b_val = state.get(*b);
                EvalResult::G2(self.ops.g2_add(a_val.as_g2(), b_val.as_g2()))
            }

            AstOp::G2ScalarMul { point, scalar, .. } => {
                let p = state.get(*point);
                EvalResult::G2(self.ops.g2_scalar_mul(p.as_g2(), &scalar.value))
            }

            AstOp::MsmG2 {
                points, scalars, ..
            } => {
                let pts: Vec<E::G2> = points
                    .iter()
                    .map(|id| state.get(*id).as_g2().clone())
                    .collect();
                let scs: Vec<_> = scalars.iter().map(|s| s.value.clone()).collect();
                EvalResult::G2(self.ops.g2_msm(&pts, &scs))
            }

            AstOp::GTMul { lhs, rhs, .. } => {
                let l = state.get(*lhs);
                let r = state.get(*rhs);
                EvalResult::GT(self.ops.gt_mul(l.as_gt(), r.as_gt()))
            }

            AstOp::GTExp { base, scalar, .. } => {
                let b = state.get(*base);
                EvalResult::GT(self.ops.gt_exp(b.as_gt(), &scalar.value))
            }

            AstOp::Pairing { g1, g2, .. } => {
                let g1_val = state.get(*g1);
                let g2_val = state.get(*g2);
                EvalResult::GT(self.ops.pairing(g1_val.as_g1(), g2_val.as_g2()))
            }

            AstOp::MultiPairing { g1s, g2s, .. } => {
                let g1_vals: Vec<E::G1> = g1s
                    .iter()
                    .map(|id| state.get(*id).as_g1().clone())
                    .collect();
                let g2_vals: Vec<E::G2> = g2s
                    .iter()
                    .map(|id| state.get(*id).as_g2().clone())
                    .collect();
                EvalResult::GT(self.ops.multi_pairing(&g1_vals, &g2_vals))
            }
        }
    }

    /// Execute with timing statistics.
    pub fn execute_timed(&self) -> (HashMap<ValueId, EvalResult<E>>, std::time::Duration) {
        let start = std::time::Instant::now();
        let results = self.execute();
        (results, start.elapsed())
    }
}

/// Sequential evaluator (fallback when parallel feature is disabled).
///
/// Evaluates nodes in topological order (by ValueId).
#[cfg(not(feature = "parallel"))]
pub struct TaskExecutor<'a, E, I, Op>
where
    E: PairingCurve,
    E::G1: Group,
    I: InputProvider<E>,
    Op: OperationEvaluator<E>,
{
    graph: &'a AstGraph<E>,
    inputs: &'a I,
    ops: &'a Op,
}

#[cfg(not(feature = "parallel"))]
impl<'a, E, I, Op> TaskExecutor<'a, E, I, Op>
where
    E: PairingCurve,
    E::G1: Group,
    I: InputProvider<E>,
    Op: OperationEvaluator<E>,
{
    /// Create a new sequential executor.
    pub fn new(graph: &'a AstGraph<E>, inputs: &'a I, ops: &'a Op) -> Self {
        Self { graph, inputs, ops }
    }

    /// Execute all nodes sequentially in topological order.
    pub fn execute(&self) -> HashMap<ValueId, EvalResult<E>> {
        let mut results = HashMap::with_capacity(self.graph.len());

        for (idx, node) in self.graph.nodes.iter().enumerate() {
            let id = ValueId(idx as u32);
            let result = self.evaluate_node(node, &results);
            results.insert(id, result);
        }

        results
    }

    /// Evaluate a single node.
    fn evaluate_node(
        &self,
        node: &AstNode<E>,
        results: &HashMap<ValueId, EvalResult<E>>,
    ) -> EvalResult<E> {
        let get = |id: ValueId| -> &EvalResult<E> {
            results.get(&id).expect("Dependency must be computed")
        };

        match &node.op {
            AstOp::Input { .. } => self
                .inputs
                .get_input(node)
                .expect("Input provider must supply all inputs"),

            AstOp::G1Add { a, b, .. } => {
                EvalResult::G1(self.ops.g1_add(get(*a).as_g1(), get(*b).as_g1()))
            }

            AstOp::G1ScalarMul { point, scalar, .. } => {
                EvalResult::G1(self.ops.g1_scalar_mul(get(*point).as_g1(), &scalar.value))
            }

            AstOp::MsmG1 {
                points, scalars, ..
            } => {
                let pts: Vec<E::G1> = points.iter().map(|id| get(*id).as_g1().clone()).collect();
                let scs: Vec<_> = scalars.iter().map(|s| s.value.clone()).collect();
                EvalResult::G1(self.ops.g1_msm(&pts, &scs))
            }

            AstOp::G2Add { a, b, .. } => {
                EvalResult::G2(self.ops.g2_add(get(*a).as_g2(), get(*b).as_g2()))
            }

            AstOp::G2ScalarMul { point, scalar, .. } => {
                EvalResult::G2(self.ops.g2_scalar_mul(get(*point).as_g2(), &scalar.value))
            }

            AstOp::MsmG2 {
                points, scalars, ..
            } => {
                let pts: Vec<E::G2> = points.iter().map(|id| get(*id).as_g2().clone()).collect();
                let scs: Vec<_> = scalars.iter().map(|s| s.value.clone()).collect();
                EvalResult::G2(self.ops.g2_msm(&pts, &scs))
            }

            AstOp::GTMul { lhs, rhs, .. } => {
                EvalResult::GT(self.ops.gt_mul(get(*lhs).as_gt(), get(*rhs).as_gt()))
            }

            AstOp::GTExp { base, scalar, .. } => {
                EvalResult::GT(self.ops.gt_exp(get(*base).as_gt(), &scalar.value))
            }

            AstOp::Pairing { g1, g2, .. } => {
                EvalResult::GT(self.ops.pairing(get(*g1).as_g1(), get(*g2).as_g2()))
            }

            AstOp::MultiPairing { g1s, g2s, .. } => {
                let g1_vals: Vec<E::G1> = g1s.iter().map(|id| get(*id).as_g1().clone()).collect();
                let g2_vals: Vec<E::G2> = g2s.iter().map(|id| get(*id).as_g2().clone()).collect();
                EvalResult::GT(self.ops.multi_pairing(&g1_vals, &g2_vals))
            }
        }
    }

    /// Execute with timing.
    pub fn execute_timed(&self) -> (HashMap<ValueId, EvalResult<E>>, std::time::Duration) {
        let start = std::time::Instant::now();
        let results = self.execute();
        (results, start.elapsed())
    }
}

#[cfg(all(test, feature = "arkworks"))]
mod tests {
    use super::*;

    #[test]
    fn test_eval_result_types() {
        use crate::backends::arkworks::BN254;
        use crate::primitives::arithmetic::PairingCurve;

        // Just test that the types compile correctly
        fn _check_types<E: PairingCurve>(_: EvalResult<E>) {}
        let _ = std::any::type_name::<EvalResult<BN254>>();
    }
}
