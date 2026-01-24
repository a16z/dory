//! AST/DAG representation of verification computations for recursive proof composition.
//!
//! This module provides an explicit graph representation of group/pairing operations
//! performed during Dory verification. The AST enables:
//!
//! - **Wiring constraints**: track that "output of op A is input of op B"
//! - **Circuit generation**: upstream crates can consume the AST to generate constraints
//! - **Debugging**: operation names and scalar labels aid in understanding the computation
//!
//! # Design
//!
//! - **Group elements** (`G1`, `G2`, `GT`) are tracked as `ValueId`s with explicit wiring.
//! - **Scalars** are embedded directly in operations (not tracked as `ValueId`s).
//! - The AST is a strict superset of the existing `OpId`-based witness/hint system.
//!
//! # Example
//!
//! ```ignore
//! use dory_pcs::recursion::ast::{AstBuilder, ValueType, InputSource, AstOp, ScalarValue};
//!
//! let mut builder = AstBuilder::<E>::new();
//!
//! // Intern setup elements
//! let g1_0 = builder.intern_input(ValueType::G1, InputSource::Setup { name: "g1_0", index: None });
//! let chi_0 = builder.intern_input(ValueType::GT, InputSource::Setup { name: "chi", index: Some(0) });
//!
//! // Record a scalar multiplication
//! let scaled = builder.push(ValueType::G1, AstOp::G1ScalarMul {
//!     op_id: Some(op_id),
//!     point: g1_0,
//!     scalar: ScalarValue::named(beta, "beta"),
//! });
//!
//! let graph = builder.finalize();
//! graph.validate().expect("valid DAG");
//! ```

use std::collections::HashMap;
use std::fmt;

use crate::primitives::arithmetic::{Group, PairingCurve};
use crate::recursion::witness::OpId;

/// Unique identifier for a group value in the AST.
///
/// `ValueId`s are assigned in creation order, which is also topological order.
/// This means `ValueId(n)` can only depend on `ValueId(m)` where `m < n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueId(pub u32);

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Type of a group value in the AST.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueType {
    /// Element of G1 (first source group of the pairing).
    G1,
    /// Element of G2 (second source group of the pairing).
    G2,
    /// Element of GT (target group of the pairing, multiplicative).
    GT,
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueType::G1 => write!(f, "G1"),
            ValueType::G2 => write!(f, "G2"),
            ValueType::GT => write!(f, "GT"),
        }
    }
}

/// A scalar value embedded in an AST operation, with optional debug name.
///
/// Scalars are derived by the verifier during Fiat-Shamir transcript operations
/// and field arithmetic (inversions, products, etc.). They are embedded directly
/// in the AST nodes rather than being tracked as `ValueId`s.
#[derive(Clone, Debug)]
pub struct ScalarValue<F> {
    /// The actual scalar value.
    pub value: F,
    /// Optional debug name (e.g., "beta", "alpha_inv", "gamma").
    pub name: Option<&'static str>,
}

impl<F> ScalarValue<F> {
    /// Create a scalar value without a debug name.
    pub fn new(value: F) -> Self {
        Self { value, name: None }
    }

    /// Create a scalar value with a debug name.
    pub fn named(value: F, name: &'static str) -> Self {
        Self {
            value,
            name: Some(name),
        }
    }
}

impl<F: fmt::Debug> fmt::Display for ScalarValue<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name {
            write!(f, "{}", name)
        } else {
            write!(f, "{:?}", self.value)
        }
    }
}

/// Stable semantic identity for input group elements (setup/proof).
///
/// Used to intern input nodes so the same setup/proof element maps to the same `ValueId`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum InputSource {
    /// Setup element, e.g., `("chi", Some(i))`, `("h2", None)`, `("g1_0", None)`.
    Setup {
        /// Element name (e.g., "chi", "h2", "g1_0").
        name: &'static str,
        /// Optional array index for indexed elements.
        index: Option<usize>,
    },
    /// Top-level proof element, e.g., `"vmv.c"`.
    Proof {
        /// Element name.
        name: &'static str,
    },
    /// Per-round proof message element.
    ProofRound {
        /// Round index (0-based).
        round: usize,
        /// Which message in the round (First or Second).
        msg: RoundMsg,
        /// Element name within the message.
        name: &'static str,
    },
}

impl fmt::Display for InputSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputSource::Setup { name, index: None } => write!(f, "setup.{}", name),
            InputSource::Setup {
                name,
                index: Some(i),
            } => write!(f, "setup.{}[{}]", name, i),
            InputSource::Proof { name } => write!(f, "proof.{}", name),
            InputSource::ProofRound { round, msg, name } => {
                write!(f, "proof.round[{}].{:?}.{}", round, msg, name)
            }
        }
    }
}

/// Which message within a reduce-and-fold round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoundMsg {
    /// First message of the round.
    First,
    /// Second message of the round.
    Second,
}

/// AST operation kind.
///
/// Each variant represents a group/pairing operation. Operations that are traced
/// (have witnesses/hints) carry an optional `OpId` for joining with the witness system.
#[derive(Clone)]
pub enum AstOp<E: PairingCurve>
where
    E::G1: Group,
{
    /// Input group element from setup or proof.
    Input {
        /// The semantic source of this input.
        source: InputSource,
    },

    // ===== G1 operations =====
    /// G1 addition: a + b
    G1Add {
        /// OpId for witness/hint linkage.
        op_id: Option<OpId>,
        /// Left operand.
        a: ValueId,
        /// Right operand.
        b: ValueId,
    },
    /// G1 scalar multiplication: scalar * point
    G1ScalarMul {
        /// OpId for witness/hint linkage (traced operations only).
        op_id: Option<OpId>,
        /// The G1 point to scale.
        point: ValueId,
        /// The scalar multiplier with optional debug name.
        scalar: ScalarValue<<E::G1 as Group>::Scalar>,
    },

    // ===== G2 operations =====
    /// G2 addition: a + b
    G2Add {
        /// OpId for witness/hint linkage.
        op_id: Option<OpId>,
        /// Left operand.
        a: ValueId,
        /// Right operand.
        b: ValueId,
    },
    /// G2 scalar multiplication: scalar * point
    G2ScalarMul {
        /// OpId for witness/hint linkage (traced operations only).
        op_id: Option<OpId>,
        /// The G2 point to scale.
        point: ValueId,
        /// The scalar multiplier with optional debug name.
        scalar: ScalarValue<<E::G1 as Group>::Scalar>,
    },

    // ===== GT operations (multiplicative group) =====
    /// GT multiplication: lhs * rhs (this is "add" in Group trait for GT)
    GTMul {
        /// OpId for witness/hint linkage (traced operations only).
        op_id: Option<OpId>,
        /// Left operand.
        lhs: ValueId,
        /// Right operand.
        rhs: ValueId,
    },
    /// GT exponentiation: base^scalar (this is "scale" in Group trait for GT)
    GTExp {
        /// OpId for witness/hint linkage (traced operations only).
        op_id: Option<OpId>,
        /// The GT element to exponentiate.
        base: ValueId,
        /// The scalar exponent with optional debug name.
        scalar: ScalarValue<<E::G1 as Group>::Scalar>,
    },

    // ===== Pairing operations =====
    /// Single pairing: e(g1, g2) -> GT
    Pairing {
        /// OpId for witness/hint linkage (traced operations only).
        op_id: Option<OpId>,
        /// The G1 element.
        g1: ValueId,
        /// The G2 element.
        g2: ValueId,
    },
    /// Multi-pairing: ∏ e(g1s[i], g2s[i]) -> GT
    MultiPairing {
        /// OpId for witness/hint linkage (traced operations only).
        op_id: Option<OpId>,
        /// The G1 elements.
        g1s: Vec<ValueId>,
        /// The G2 elements.
        g2s: Vec<ValueId>,
    },

    // ===== MSM operations =====
    /// G1 multi-scalar multiplication: Σ scalars[i] * points[i]
    MsmG1 {
        /// OpId for witness/hint linkage (traced operations only).
        op_id: Option<OpId>,
        /// The G1 base points.
        points: Vec<ValueId>,
        /// The scalars with optional debug names.
        scalars: Vec<ScalarValue<<E::G1 as Group>::Scalar>>,
    },
    /// G2 multi-scalar multiplication: Σ scalars[i] * points[i]
    MsmG2 {
        /// OpId for witness/hint linkage (traced operations only).
        op_id: Option<OpId>,
        /// The G2 base points.
        points: Vec<ValueId>,
        /// The scalars with optional debug names.
        scalars: Vec<ScalarValue<<E::G1 as Group>::Scalar>>,
    },
}

impl<E: PairingCurve> AstOp<E>
where
    E::G1: Group,
{
    /// Returns the expected output type for this operation.
    pub fn output_type(&self) -> ValueType {
        match self {
            AstOp::Input { source } => {
                // Infer from source name convention (caller should use correct type)
                // This is a fallback; prefer explicit type from intern_input
                match source {
                    InputSource::Setup { name, .. } => {
                        if name.starts_with("g1") || name.starts_with("h1") {
                            ValueType::G1
                        } else if name.starts_with("g2") || name.starts_with("h2") {
                            ValueType::G2
                        } else {
                            ValueType::GT
                        }
                    }
                    _ => ValueType::G1, // Default, should be overridden
                }
            }
            AstOp::G1Add { .. } | AstOp::G1ScalarMul { .. } => ValueType::G1,
            AstOp::MsmG1 { .. } => ValueType::G1,
            AstOp::G2Add { .. } | AstOp::G2ScalarMul { .. } => ValueType::G2,
            AstOp::MsmG2 { .. } => ValueType::G2,
            AstOp::GTMul { .. } | AstOp::GTExp { .. } => ValueType::GT,
            AstOp::Pairing { .. } | AstOp::MultiPairing { .. } => ValueType::GT,
        }
    }

    /// Returns all input ValueIds referenced by this operation.
    pub fn input_ids(&self) -> Vec<ValueId> {
        match self {
            AstOp::Input { .. } => vec![],
            AstOp::G1Add { a, b, .. } | AstOp::G2Add { a, b, .. } => vec![*a, *b],
            AstOp::GTMul { lhs, rhs, .. } => vec![*lhs, *rhs],
            AstOp::G1ScalarMul { point, .. }
            | AstOp::G2ScalarMul { point, .. }
            | AstOp::GTExp { base: point, .. } => vec![*point],
            AstOp::Pairing { g1, g2, .. } => vec![*g1, *g2],
            AstOp::MultiPairing { g1s, g2s, .. } => {
                let mut ids = g1s.clone();
                ids.extend(g2s.iter().copied());
                ids
            }
            AstOp::MsmG1 { points, .. } | AstOp::MsmG2 { points, .. } => points.clone(),
        }
    }

    /// Returns input ValueIds with their precise input slots.
    ///
    /// Each entry is `(ValueId, InputSlot)` indicating which input slot
    /// of this operation receives the given ValueId.
    pub fn input_slots(&self) -> Vec<(ValueId, InputSlot)> {
        match self {
            AstOp::Input { .. } => vec![],
            AstOp::G1Add { a, b, .. } | AstOp::G2Add { a, b, .. } => {
                vec![(*a, InputSlot::A), (*b, InputSlot::B)]
            }
            AstOp::GTMul { lhs, rhs, .. } => {
                vec![(*lhs, InputSlot::Lhs), (*rhs, InputSlot::Rhs)]
            }
            AstOp::G1ScalarMul { point, .. } | AstOp::G2ScalarMul { point, .. } => {
                vec![(*point, InputSlot::Point)]
            }
            AstOp::GTExp { base, .. } => {
                vec![(*base, InputSlot::Base)]
            }
            AstOp::Pairing { g1, g2, .. } => {
                vec![(*g1, InputSlot::G1), (*g2, InputSlot::G2)]
            }
            AstOp::MultiPairing { g1s, g2s, .. } => {
                let mut slots = Vec::with_capacity(g1s.len() + g2s.len());
                for (i, &id) in g1s.iter().enumerate() {
                    slots.push((id, InputSlot::G1At(i)));
                }
                for (i, &id) in g2s.iter().enumerate() {
                    slots.push((id, InputSlot::G2At(i)));
                }
                slots
            }
            AstOp::MsmG1 { points, .. } | AstOp::MsmG2 { points, .. } => {
                points
                    .iter()
                    .enumerate()
                    .map(|(i, &id)| (id, InputSlot::PointAt(i)))
                    .collect()
            }
        }
    }

    /// Returns a short name for this operation kind.
    pub fn op_name(&self) -> &'static str {
        match self {
            AstOp::Input { .. } => "Input",
            AstOp::G1Add { .. } => "G1Add",
            AstOp::G1ScalarMul { .. } => "G1ScalarMul",
            AstOp::G2Add { .. } => "G2Add",
            AstOp::G2ScalarMul { .. } => "G2ScalarMul",
            AstOp::GTMul { .. } => "GTMul",
            AstOp::GTExp { .. } => "GTExp",
            AstOp::Pairing { .. } => "Pairing",
            AstOp::MultiPairing { .. } => "MultiPairing",
            AstOp::MsmG1 { .. } => "MsmG1",
            AstOp::MsmG2 { .. } => "MsmG2",
        }
    }

    /// Returns the OpId if this operation is traced (has witness/hint).
    pub fn op_id(&self) -> Option<OpId> {
        match self {
            AstOp::G1ScalarMul { op_id, .. }
            | AstOp::G2ScalarMul { op_id, .. }
            | AstOp::GTMul { op_id, .. }
            | AstOp::GTExp { op_id, .. }
            | AstOp::Pairing { op_id, .. }
            | AstOp::MultiPairing { op_id, .. }
            | AstOp::MsmG1 { op_id, .. }
            | AstOp::MsmG2 { op_id, .. } => *op_id,
            _ => None,
        }
    }
}

/// A single node in the AST, representing a produced group value.
#[derive(Clone)]
pub struct AstNode<E: PairingCurve>
where
    E::G1: Group,
{
    /// The output ValueId produced by this node.
    pub out: ValueId,
    /// The type of the output value.
    pub out_ty: ValueType,
    /// The operation that produces this value.
    pub op: AstOp<E>,
}

// Manual Debug implementations to avoid requiring Debug on scalar types

impl<E: PairingCurve> fmt::Debug for AstOp<E>
where
    E::G1: Group,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AstOp::Input { source } => f.debug_struct("Input").field("source", source).finish(),
            AstOp::G1Add { op_id, a, b } => f
                .debug_struct("G1Add")
                .field("op_id", op_id)
                .field("a", a)
                .field("b", b)
                .finish(),
            AstOp::G1ScalarMul { op_id, point, scalar } => f
                .debug_struct("G1ScalarMul")
                .field("op_id", op_id)
                .field("point", point)
                .field("scalar_name", &scalar.name)
                .finish(),
            AstOp::G2Add { op_id, a, b } => f
                .debug_struct("G2Add")
                .field("op_id", op_id)
                .field("a", a)
                .field("b", b)
                .finish(),
            AstOp::G2ScalarMul { op_id, point, scalar } => f
                .debug_struct("G2ScalarMul")
                .field("op_id", op_id)
                .field("point", point)
                .field("scalar_name", &scalar.name)
                .finish(),
            AstOp::GTMul { op_id, lhs, rhs } => f
                .debug_struct("GTMul")
                .field("op_id", op_id)
                .field("lhs", lhs)
                .field("rhs", rhs)
                .finish(),
            AstOp::GTExp { op_id, base, scalar } => f
                .debug_struct("GTExp")
                .field("op_id", op_id)
                .field("base", base)
                .field("scalar_name", &scalar.name)
                .finish(),
            AstOp::Pairing { op_id, g1, g2 } => f
                .debug_struct("Pairing")
                .field("op_id", op_id)
                .field("g1", g1)
                .field("g2", g2)
                .finish(),
            AstOp::MultiPairing { op_id, g1s, g2s } => f
                .debug_struct("MultiPairing")
                .field("op_id", op_id)
                .field("g1s", g1s)
                .field("g2s", g2s)
                .finish(),
            AstOp::MsmG1 { op_id, points, scalars } => f
                .debug_struct("MsmG1")
                .field("op_id", op_id)
                .field("points", points)
                .field("num_scalars", &scalars.len())
                .finish(),
            AstOp::MsmG2 { op_id, points, scalars } => f
                .debug_struct("MsmG2")
                .field("op_id", op_id)
                .field("points", points)
                .field("num_scalars", &scalars.len())
                .finish(),
        }
    }
}

impl<E: PairingCurve> fmt::Debug for AstNode<E>
where
    E::G1: Group,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AstNode")
            .field("out", &self.out)
            .field("out_ty", &self.out_ty)
            .field("op", &self.op)
            .finish()
    }
}

/// Verification constraint (e.g., final equality check).
#[derive(Clone, Debug)]
pub enum AstConstraint {
    /// Assert that two values are equal.
    AssertEq {
        /// Left-hand side of the equality.
        lhs: ValueId,
        /// Right-hand side of the equality.
        rhs: ValueId,
        /// Human-readable description of what's being asserted.
        what: &'static str,
    },
}

/// Validation error for AST graphs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AstValidationError {
    /// A node references a ValueId that hasn't been defined yet (violates topo order).
    UndefinedInput {
        /// The node containing the undefined reference.
        node: ValueId,
        /// The undefined input that was referenced.
        undefined_input: ValueId,
    },
    /// A node's output ValueId doesn't match its position in the node list.
    MismatchedOutputId {
        /// Expected ValueId based on position.
        expected: ValueId,
        /// Actual ValueId in the node.
        actual: ValueId,
    },
    /// Type mismatch: an operation received an input of the wrong type.
    TypeMismatch {
        /// The node with the type mismatch.
        node: ValueId,
        /// The input that has the wrong type.
        input: ValueId,
        /// The expected type.
        expected: ValueType,
        /// The actual type found.
        actual: ValueType,
    },
    /// Multi-pairing has mismatched G1/G2 counts.
    MultiPairingLengthMismatch {
        /// The multi-pairing node.
        node: ValueId,
        /// Number of G1 elements.
        g1_count: usize,
        /// Number of G2 elements.
        g2_count: usize,
    },
    /// MSM has mismatched points/scalars counts.
    MsmLengthMismatch {
        /// The MSM node.
        node: ValueId,
        /// Number of points.
        points_count: usize,
        /// Number of scalars.
        scalars_count: usize,
    },
    /// Constraint references an undefined ValueId.
    ConstraintUndefinedValue {
        /// Index of the constraint with the error.
        constraint_idx: usize,
        /// The undefined value referenced.
        value: ValueId,
    },
    /// OpId mapping references an undefined ValueId.
    OpIdMappingUndefinedValue {
        /// The OpId with the invalid mapping.
        op_id: OpId,
        /// The undefined ValueId it maps to.
        value: ValueId,
    },
}

impl fmt::Display for AstValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AstValidationError::UndefinedInput {
                node,
                undefined_input,
            } => {
                write!(f, "node {} references undefined input {}", node, undefined_input)
            }
            AstValidationError::MismatchedOutputId { expected, actual } => {
                write!(
                    f,
                    "node has output id {} but expected {} based on position",
                    actual, expected
                )
            }
            AstValidationError::TypeMismatch {
                node,
                input,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "node {} input {} has type {} but expected {}",
                    node, input, actual, expected
                )
            }
            AstValidationError::MultiPairingLengthMismatch {
                node,
                g1_count,
                g2_count,
            } => {
                write!(
                    f,
                    "multi-pairing node {} has {} G1 elements but {} G2 elements",
                    node, g1_count, g2_count
                )
            }
            AstValidationError::MsmLengthMismatch {
                node,
                points_count,
                scalars_count,
            } => {
                write!(
                    f,
                    "MSM node {} has {} points but {} scalars",
                    node, points_count, scalars_count
                )
            }
            AstValidationError::ConstraintUndefinedValue {
                constraint_idx,
                value,
            } => {
                write!(
                    f,
                    "constraint {} references undefined value {}",
                    constraint_idx, value
                )
            }
            AstValidationError::OpIdMappingUndefinedValue { op_id, value } => {
                write!(
                    f,
                    "opid_to_value maps {:?} to undefined value {}",
                    op_id, value
                )
            }
        }
    }
}

impl std::error::Error for AstValidationError {}

/// The complete AST/DAG of verification computations.
///
/// Nodes are stored in creation order, which is also topological order.
/// This invariant is checked by [`AstGraph::validate`].
#[derive(Clone, Debug)]
pub struct AstGraph<E: PairingCurve>
where
    E::G1: Group,
{
    /// Nodes in topological (creation) order.
    pub nodes: Vec<AstNode<E>>,
    /// Verification constraints (e.g., final equality checks).
    pub constraints: Vec<AstConstraint>,
    /// Mapping from OpId to ValueId for joining with WitnessCollection/HintMap.
    pub opid_to_value: HashMap<OpId, ValueId>,
}

impl<E: PairingCurve> AstGraph<E>
where
    E::G1: Group,
{
    /// Validate the AST graph for structural correctness.
    ///
    /// Checks:
    /// - All input ValueIds refer to earlier nodes (DAG / topo order)
    /// - Node output IDs match their position
    /// - Type correctness for each operation
    /// - Multi-pairing and MSM have matching input counts
    /// - Constraints reference valid ValueIds
    /// - OpId mappings reference valid ValueIds
    pub fn validate(&self) -> Result<(), AstValidationError> {
        // Build a map of ValueId -> (index, type) for defined nodes
        let mut defined: HashMap<ValueId, (usize, ValueType)> = HashMap::new();

        for (idx, node) in self.nodes.iter().enumerate() {
            let expected_id = ValueId(idx as u32);

            // Check output ID matches position
            if node.out != expected_id {
                return Err(AstValidationError::MismatchedOutputId {
                    expected: expected_id,
                    actual: node.out,
                });
            }

            // Check all inputs are defined (topo order) and have correct types
            self.validate_op_inputs(node.out, &node.op, &defined)?;

            // Mark this node as defined
            defined.insert(node.out, (idx, node.out_ty));
        }

        // Validate constraints
        for (idx, constraint) in self.constraints.iter().enumerate() {
            match constraint {
                AstConstraint::AssertEq { lhs, rhs, .. } => {
                    if !defined.contains_key(lhs) {
                        return Err(AstValidationError::ConstraintUndefinedValue {
                            constraint_idx: idx,
                            value: *lhs,
                        });
                    }
                    if !defined.contains_key(rhs) {
                        return Err(AstValidationError::ConstraintUndefinedValue {
                            constraint_idx: idx,
                            value: *rhs,
                        });
                    }
                }
            }
        }

        // Validate opid_to_value mappings
        for (&op_id, &value_id) in &self.opid_to_value {
            if !defined.contains_key(&value_id) {
                return Err(AstValidationError::OpIdMappingUndefinedValue {
                    op_id,
                    value: value_id,
                });
            }
        }

        Ok(())
    }

    /// Validate inputs for a single operation.
    fn validate_op_inputs(
        &self,
        node_id: ValueId,
        op: &AstOp<E>,
        defined: &HashMap<ValueId, (usize, ValueType)>,
    ) -> Result<(), AstValidationError> {
        // Helper to check that an input is defined and has the expected type
        let check_input = |input: ValueId, expected_ty: ValueType| -> Result<(), AstValidationError> {
            match defined.get(&input) {
                None => Err(AstValidationError::UndefinedInput {
                    node: node_id,
                    undefined_input: input,
                }),
                Some((_, actual_ty)) if *actual_ty != expected_ty => {
                    Err(AstValidationError::TypeMismatch {
                        node: node_id,
                        input,
                        expected: expected_ty,
                        actual: *actual_ty,
                    })
                }
                Some(_) => Ok(()),
            }
        };

        match op {
            AstOp::Input { .. } => {
                // Inputs have no dependencies
                Ok(())
            }
            AstOp::G1Add { a, b, .. } => {
                check_input(*a, ValueType::G1)?;
                check_input(*b, ValueType::G1)
            }
            AstOp::G1ScalarMul { point, .. } => check_input(*point, ValueType::G1),
            AstOp::G2Add { a, b, .. } => {
                check_input(*a, ValueType::G2)?;
                check_input(*b, ValueType::G2)
            }
            AstOp::G2ScalarMul { point, .. } => check_input(*point, ValueType::G2),
            AstOp::GTMul { lhs, rhs, .. } => {
                check_input(*lhs, ValueType::GT)?;
                check_input(*rhs, ValueType::GT)
            }
            AstOp::GTExp { base, .. } => check_input(*base, ValueType::GT),
            AstOp::Pairing { g1, g2, .. } => {
                check_input(*g1, ValueType::G1)?;
                check_input(*g2, ValueType::G2)
            }
            AstOp::MultiPairing { g1s, g2s, .. } => {
                if g1s.len() != g2s.len() {
                    return Err(AstValidationError::MultiPairingLengthMismatch {
                        node: node_id,
                        g1_count: g1s.len(),
                        g2_count: g2s.len(),
                    });
                }
                for g1 in g1s {
                    check_input(*g1, ValueType::G1)?;
                }
                for g2 in g2s {
                    check_input(*g2, ValueType::G2)?;
                }
                Ok(())
            }
            AstOp::MsmG1 { points, scalars, .. } => {
                if points.len() != scalars.len() {
                    return Err(AstValidationError::MsmLengthMismatch {
                        node: node_id,
                        points_count: points.len(),
                        scalars_count: scalars.len(),
                    });
                }
                for point in points {
                    check_input(*point, ValueType::G1)?;
                }
                Ok(())
            }
            AstOp::MsmG2 { points, scalars, .. } => {
                if points.len() != scalars.len() {
                    return Err(AstValidationError::MsmLengthMismatch {
                        node: node_id,
                        points_count: points.len(),
                        scalars_count: scalars.len(),
                    });
                }
                for point in points {
                    check_input(*point, ValueType::G2)?;
                }
                Ok(())
            }
        }
    }

    /// Returns the number of nodes in the graph.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the graph has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get a node by its ValueId.
    pub fn get(&self, id: ValueId) -> Option<&AstNode<E>> {
        self.nodes.get(id.0 as usize)
    }

    /// Get the type of a value by its ValueId.
    pub fn get_type(&self, id: ValueId) -> Option<ValueType> {
        self.get(id).map(|n| n.out_ty)
    }

    /// Extract all wiring pairs: (producer, consumer) representing
    /// "output of producer is used as input to consumer".
    ///
    /// Each pair `(producer, consumer)` means that the value computed at `producer`
    /// is used as an input to the operation at `consumer`.
    ///
    /// # Returns
    /// A vector of `(producer: ValueId, consumer: ValueId)` pairs.
    ///
    /// # Example
    /// ```ignore
    /// let graph = builder.finalize();
    /// for (producer, consumer) in graph.wiring_pairs() {
    ///     println!("v{} -> v{}", producer.0, consumer.0);
    /// }
    /// ```
    pub fn wiring_pairs(&self) -> Vec<(ValueId, ValueId)> {
        let mut pairs = Vec::new();
        for node in &self.nodes {
            let consumer = node.out;
            for producer in node.op.input_ids() {
                pairs.push((producer, consumer));
            }
        }
        pairs
    }

    /// Extract wiring pairs with detailed information including types and operation kinds.
    ///
    /// Returns tuples of `(producer_id, producer_type, consumer_id, consumer_type)`.
    ///
    /// # Example
    /// ```ignore
    /// for (prod_id, prod_ty, cons_id, cons_ty) in graph.wiring_pairs_with_types() {
    ///     println!("{} ({:?}) -> {} ({:?})", prod_id, prod_ty, cons_id, cons_ty);
    /// }
    /// ```
    pub fn wiring_pairs_with_types(&self) -> Vec<(ValueId, ValueType, ValueId, ValueType)> {
        let mut pairs = Vec::new();
        for node in &self.nodes {
            let consumer = node.out;
            let consumer_ty = node.out_ty;
            for producer in node.op.input_ids() {
                if let Some(prod_ty) = self.get_type(producer) {
                    pairs.push((producer, prod_ty, consumer, consumer_ty));
                }
            }
        }
        pairs
    }

    /// Build a reverse index: for each ValueId, who consumes it?
    ///
    /// Returns a map from `ValueId` -> `Vec<ValueId>` of consumers.
    /// This is useful for traversing the graph from outputs to inputs.
    pub fn consumers(&self) -> HashMap<ValueId, Vec<ValueId>> {
        let mut map: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
        for node in &self.nodes {
            let consumer = node.out;
            for producer in node.op.input_ids() {
                map.entry(producer).or_default().push(consumer);
            }
        }
        map
    }

    /// Compute the depth level for each node in the graph.
    ///
    /// - Level 0: Input nodes (no dependencies)
    /// - Level N: Nodes whose maximum input level is N-1
    ///
    /// Nodes at the same level have no dependencies on each other and can be
    /// processed in parallel during witness generation or hint computation.
    ///
    /// # Returns
    /// A vector where `result[i]` is the level of node `ValueId(i)`.
    ///
    /// # Complexity
    /// O(V + E) where V is the number of nodes and E is the total input count.
    pub fn compute_levels(&self) -> Vec<usize> {
        let mut levels = vec![0usize; self.nodes.len()];

        for (idx, node) in self.nodes.iter().enumerate() {
            let max_input_level = node
                .op
                .input_ids()
                .iter()
                .map(|id| levels[id.0 as usize])
                .max()
                .unwrap_or(0);

            levels[idx] = if matches!(node.op, AstOp::Input { .. }) {
                0
            } else {
                max_input_level + 1
            };
        }

        levels
    }

    /// Group nodes by level for wavefront parallel processing.
    ///
    /// Returns a vector of vectors, where `result[level]` contains all `ValueId`s
    /// at that level. Nodes within the same level are independent and can be
    /// processed in parallel.
    ///
    /// # Example
    /// ```ignore
    /// let levels = graph.levels();
    /// for (level, node_ids) in levels.iter().enumerate() {
    ///     println!("Level {}: {} nodes", level, node_ids.len());
    ///     // Process node_ids in parallel with rayon
    /// }
    /// ```
    pub fn levels(&self) -> Vec<Vec<ValueId>> {
        let node_levels = self.compute_levels();
        let max_level = node_levels.iter().copied().max().unwrap_or(0);

        let mut levels: Vec<Vec<ValueId>> = vec![Vec::new(); max_level + 1];
        for (idx, &level) in node_levels.iter().enumerate() {
            levels[level].push(ValueId(idx as u32));
        }

        levels
    }

    /// Group nodes by level and value type for fine-grained parallelism.
    ///
    /// Returns a vector where each entry is a map from `ValueType` to nodes
    /// of that type at that level. This enables type-aware parallel processing
    /// where G1, G2, and GT operations can be batched separately.
    ///
    /// # Example
    /// ```ignore
    /// let levels_by_type = graph.levels_by_type();
    /// for (level, type_map) in levels_by_type.iter().enumerate() {
    ///     // Process G1 ops, G2 ops, GT ops independently
    ///     if let Some(g1_nodes) = type_map.get(&ValueType::G1) {
    ///         // Parallel process all G1 nodes at this level
    ///     }
    /// }
    /// ```
    pub fn levels_by_type(&self) -> Vec<HashMap<ValueType, Vec<ValueId>>> {
        let node_levels = self.compute_levels();
        let max_level = node_levels.iter().copied().max().unwrap_or(0);

        let mut levels: Vec<HashMap<ValueType, Vec<ValueId>>> =
            vec![HashMap::new(); max_level + 1];

        for (idx, node) in self.nodes.iter().enumerate() {
            let level = node_levels[idx];
            levels[level]
                .entry(node.out_ty)
                .or_default()
                .push(ValueId(idx as u32));
        }

        levels
    }

    /// Returns statistics about parallelism opportunities at each level.
    ///
    /// Useful for understanding the graph structure and potential speedup
    /// from parallel processing.
    ///
    /// # Returns
    /// A vector of `(total_nodes, g1_count, g2_count, gt_count)` for each level.
    pub fn level_stats(&self) -> Vec<(usize, usize, usize, usize)> {
        let levels_by_type = self.levels_by_type();
        levels_by_type
            .iter()
            .map(|type_map| {
                let g1 = type_map.get(&ValueType::G1).map_or(0, |v| v.len());
                let g2 = type_map.get(&ValueType::G2).map_or(0, |v| v.len());
                let gt = type_map.get(&ValueType::GT).map_or(0, |v| v.len());
                (g1 + g2 + gt, g1, g2, gt)
            })
            .collect()
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Wiring information
    // ────────────────────────────────────────────────────────────────────────────────

    /// Extract wiring pairs with precise operation type and input slot information.
    ///
    /// Returns a vector of [`Wire`] structs containing:
    /// - Producer: operation kind, its index among that kind, and ValueId
    /// - Consumer: operation kind, its index among that kind, ValueId, and the precise input slot
    ///
    /// The input slot uses [`InputSlot`] to precisely identify which field of the
    /// consumer operation receives this wire (e.g., `GTMul.lhs` vs `GTMul.rhs`).
    ///
    /// # Example
    /// ```ignore
    /// for wire in graph.wires() {
    ///     println!("{}", wire);
    ///     // Output: "GTExp #2 -> GTMul #3 .lhs"
    /// }
    /// ```
    pub fn wires(&self) -> Vec<Wire> {
        // First pass: count occurrences of each op kind to assign indices
        let mut op_indices: HashMap<ValueId, (OpKind, usize)> = HashMap::new();
        let mut op_counts: HashMap<OpKind, usize> = HashMap::new();

        for node in &self.nodes {
            let kind = OpKind::from(&node.op);
            let idx = *op_counts.get(&kind).unwrap_or(&0);
            op_indices.insert(node.out, (kind.clone(), idx));
            *op_counts.entry(kind).or_insert(0) += 1;
        }

        // Second pass: build wires with precise input slots
        let mut wires = Vec::new();
        for node in &self.nodes {
            let consumer_id = node.out;
            let (consumer_kind, consumer_idx) = op_indices.get(&consumer_id).unwrap().clone();
            
            for (producer_id, slot) in node.op.input_slots() {
                if let Some((producer_kind, producer_idx)) = op_indices.get(&producer_id) {
                    wires.push(Wire {
                        producer_id,
                        producer_kind: producer_kind.clone(),
                        producer_idx: *producer_idx,
                        consumer_id,
                        consumer_kind: consumer_kind.clone(),
                        consumer_idx,
                        input_slot: slot,
                    });
                }
            }
        }
        wires
    }
}

/// Classification of AST operations by kind.
///
/// This provides a structured way to identify operation types without
/// carrying the full payload (scalars, etc.).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OpKind {
    /// Input from setup or proof.
    Input(InputSource),
    /// G1 point addition.
    G1Add,
    /// G1 scalar multiplication.
    G1ScalarMul,
    /// G2 point addition.
    G2Add,
    /// G2 scalar multiplication.
    G2ScalarMul,
    /// GT group multiplication.
    GTMul,
    /// GT exponentiation.
    GTExp,
    /// Single pairing.
    Pairing,
    /// Multi-pairing.
    MultiPairing,
    /// G1 multi-scalar multiplication.
    MsmG1,
    /// G2 multi-scalar multiplication.
    MsmG2,
}

impl<E: PairingCurve> From<&AstOp<E>> for OpKind
where
    E::G1: Group,
{
    fn from(op: &AstOp<E>) -> Self {
        match op {
            AstOp::Input { source } => OpKind::Input(source.clone()),
            AstOp::G1Add { .. } => OpKind::G1Add,
            AstOp::G1ScalarMul { .. } => OpKind::G1ScalarMul,
            AstOp::G2Add { .. } => OpKind::G2Add,
            AstOp::G2ScalarMul { .. } => OpKind::G2ScalarMul,
            AstOp::GTMul { .. } => OpKind::GTMul,
            AstOp::GTExp { .. } => OpKind::GTExp,
            AstOp::Pairing { .. } => OpKind::Pairing,
            AstOp::MultiPairing { .. } => OpKind::MultiPairing,
            AstOp::MsmG1 { .. } => OpKind::MsmG1,
            AstOp::MsmG2 { .. } => OpKind::MsmG2,
        }
    }
}

impl fmt::Display for OpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpKind::Input(source) => write!(f, "Input({})", source),
            OpKind::G1Add => write!(f, "G1Add"),
            OpKind::G1ScalarMul => write!(f, "G1ScalarMul"),
            OpKind::G2Add => write!(f, "G2Add"),
            OpKind::G2ScalarMul => write!(f, "G2ScalarMul"),
            OpKind::GTMul => write!(f, "GTMul"),
            OpKind::GTExp => write!(f, "GTExp"),
            OpKind::Pairing => write!(f, "Pairing"),
            OpKind::MultiPairing => write!(f, "MultiPairing"),
            OpKind::MsmG1 => write!(f, "MsmG1"),
            OpKind::MsmG2 => write!(f, "MsmG2"),
        }
    }
}

/// Precise identification of which input slot of an operation receives a wire.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum InputSlot {
    // === Binary operations (G1Add, G2Add) ===
    /// First operand `a` in G1Add/G2Add.
    A,
    /// Second operand `b` in G1Add/G2Add.
    B,

    // === GT operations ===
    /// Left operand in GTMul.
    Lhs,
    /// Right operand in GTMul.
    Rhs,
    /// Base in GTExp.
    Base,

    // === Scalar mul operations ===
    /// Point operand in G1ScalarMul/G2ScalarMul.
    Point,

    // === Pairing operations ===
    /// G1 element in single Pairing.
    G1,
    /// G2 element in single Pairing.
    G2,
    /// G1 element at index i in MultiPairing.
    G1At(usize),
    /// G2 element at index i in MultiPairing.
    G2At(usize),

    // === MSM operations ===
    /// Point at index i in MsmG1/MsmG2.
    PointAt(usize),
}

impl fmt::Display for InputSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputSlot::A => write!(f, ".a"),
            InputSlot::B => write!(f, ".b"),
            InputSlot::Lhs => write!(f, ".lhs"),
            InputSlot::Rhs => write!(f, ".rhs"),
            InputSlot::Base => write!(f, ".base"),
            InputSlot::Point => write!(f, ".point"),
            InputSlot::G1 => write!(f, ".g1"),
            InputSlot::G2 => write!(f, ".g2"),
            InputSlot::G1At(i) => write!(f, ".g1s[{}]", i),
            InputSlot::G2At(i) => write!(f, ".g2s[{}]", i),
            InputSlot::PointAt(i) => write!(f, ".points[{}]", i),
        }
    }
}

/// A wire connecting producer output to consumer input in the AST.
#[derive(Clone, Debug)]
pub struct Wire {
    /// The ValueId of the producer node.
    pub producer_id: ValueId,
    /// The operation kind of the producer.
    pub producer_kind: OpKind,
    /// The index of the producer among operations of its kind (0-indexed).
    pub producer_idx: usize,
    /// The ValueId of the consumer node.
    pub consumer_id: ValueId,
    /// The operation kind of the consumer.
    pub consumer_kind: OpKind,
    /// The index of the consumer among operations of its kind.
    pub consumer_idx: usize,
    /// Which input slot of the consumer this wire connects to.
    pub input_slot: InputSlot,
}

impl fmt::Display for Wire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} #{} -> {} #{}{}",
            self.producer_kind,
            self.producer_idx,
            self.consumer_kind,
            self.consumer_idx,
            self.input_slot
        )
    }
}

impl<E: PairingCurve> Default for AstGraph<E>
where
    E::G1: Group,
{
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            constraints: Vec::new(),
            opid_to_value: HashMap::new(),
        }
    }
}

/// Builder for constructing an AstGraph incrementally.
///
/// Nodes are added in topological order (each new node can only reference
/// previously added nodes).
pub struct AstBuilder<E: PairingCurve>
where
    E::G1: Group,
{
    next: u32,
    interned: HashMap<InputSource, ValueId>,
    graph: AstGraph<E>,
}

impl<E: PairingCurve> AstBuilder<E>
where
    E::G1: Group,
{
    /// Create a new empty AST builder.
    pub fn new() -> Self {
        Self {
            next: 0,
            interned: HashMap::new(),
            graph: AstGraph::default(),
        }
    }

    /// Allocate a fresh ValueId.
    fn fresh(&mut self) -> ValueId {
        let id = ValueId(self.next);
        self.next += 1;
        id
    }

    /// Intern an input node (setup/proof element).
    ///
    /// Returns the existing ValueId if the source was already interned,
    /// otherwise creates a new Input node.
    pub fn intern_input(&mut self, out_ty: ValueType, source: InputSource) -> ValueId {
        if let Some(&id) = self.interned.get(&source) {
            return id;
        }
        let out = self.fresh();
        self.graph.nodes.push(AstNode {
            out,
            out_ty,
            op: AstOp::Input { source: source.clone() },
        });
        self.interned.insert(source, out);
        out
    }

    // ===== Convenience intern methods for G1 =====

    /// Intern a G1 setup element.
    pub fn intern_g1_setup(&mut self, _value: E::G1, name: &'static str, index: Option<usize>) -> ValueId {
        self.intern_input(ValueType::G1, InputSource::Setup { name, index })
    }

    /// Intern a G1 proof element.
    pub fn intern_g1_proof(&mut self, _value: E::G1, name: &'static str) -> ValueId {
        self.intern_input(ValueType::G1, InputSource::Proof { name })
    }

    /// Intern a G1 per-round proof message element.
    pub fn intern_g1_proof_round(&mut self, _value: E::G1, round: usize, msg: RoundMsg, name: &'static str) -> ValueId {
        self.intern_input(ValueType::G1, InputSource::ProofRound { round, msg, name })
    }

    // ===== Convenience intern methods for G2 =====

    /// Intern a G2 setup element.
    pub fn intern_g2_setup(&mut self, _value: E::G2, name: &'static str, index: Option<usize>) -> ValueId {
        self.intern_input(ValueType::G2, InputSource::Setup { name, index })
    }

    /// Intern a G2 proof element.
    pub fn intern_g2_proof(&mut self, _value: E::G2, name: &'static str) -> ValueId {
        self.intern_input(ValueType::G2, InputSource::Proof { name })
    }

    /// Intern a G2 per-round proof message element.
    pub fn intern_g2_proof_round(&mut self, _value: E::G2, round: usize, msg: RoundMsg, name: &'static str) -> ValueId {
        self.intern_input(ValueType::G2, InputSource::ProofRound { round, msg, name })
    }

    // ===== Convenience intern methods for GT =====

    /// Intern a GT setup element.
    pub fn intern_gt_setup(&mut self, _value: E::GT, name: &'static str, index: Option<usize>) -> ValueId {
        self.intern_input(ValueType::GT, InputSource::Setup { name, index })
    }

    /// Intern a GT proof element.
    pub fn intern_gt_proof(&mut self, _value: E::GT, name: &'static str) -> ValueId {
        self.intern_input(ValueType::GT, InputSource::Proof { name })
    }

    /// Intern a GT per-round proof message element.
    pub fn intern_gt_proof_round(&mut self, _value: E::GT, round: usize, msg: RoundMsg, name: &'static str) -> ValueId {
        self.intern_input(ValueType::GT, InputSource::ProofRound { round, msg, name })
    }

    /// Push a new operation node and return its output ValueId.
    pub fn push(&mut self, out_ty: ValueType, op: AstOp<E>) -> ValueId {
        let out = self.fresh();
        self.graph.nodes.push(AstNode { out, out_ty, op });
        out
    }

    /// Push a node and record the OpId -> ValueId mapping.
    pub fn push_with_opid(&mut self, out_ty: ValueType, op: AstOp<E>, op_id: OpId) -> ValueId {
        let out = self.push(out_ty, op);
        self.graph.opid_to_value.insert(op_id, out);
        out
    }

    /// Record an equality constraint for final verification.
    pub fn push_eq(&mut self, lhs: ValueId, rhs: ValueId, what: &'static str) {
        self.graph
            .constraints
            .push(AstConstraint::AssertEq { lhs, rhs, what });
    }

    /// Returns a reference to the graph being built.
    pub fn graph(&self) -> &AstGraph<E> {
        &self.graph
    }

    /// Returns the next ValueId that would be allocated.
    pub fn next_id(&self) -> ValueId {
        ValueId(self.next)
    }

    /// Returns the number of nodes added so far.
    pub fn len(&self) -> usize {
        self.graph.nodes.len()
    }

    /// Returns true if no nodes have been added.
    pub fn is_empty(&self) -> bool {
        self.graph.nodes.is_empty()
    }

    /// Finalize and return the constructed graph.
    pub fn finalize(self) -> AstGraph<E> {
        self.graph
    }
}

impl<E: PairingCurve> Default for AstBuilder<E>
where
    E::G1: Group,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::arkworks::BN254;
    use crate::primitives::arithmetic::Field;

    // Type alias for convenience - use the public re-export
    type Fr = <BN254 as crate::primitives::arithmetic::PairingCurve>::G1;
    type Scalar = <Fr as Group>::Scalar;

    #[test]
    fn test_empty_graph_is_valid() {
        let graph: AstGraph<BN254> = AstGraph::default();
        assert!(graph.validate().is_ok());
        assert!(graph.is_empty());
    }

    #[test]
    fn test_single_input_node() {
        let mut builder = AstBuilder::<BN254>::new();
        let g1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        assert_eq!(g1, ValueId(0));

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
        assert_eq!(graph.len(), 1);
    }

    #[test]
    fn test_intern_deduplicates() {
        let mut builder = AstBuilder::<BN254>::new();
        let source = InputSource::Setup {
            name: "g1_0",
            index: None,
        };

        let id1 = builder.intern_input(ValueType::G1, source.clone());
        let id2 = builder.intern_input(ValueType::G1, source);

        assert_eq!(id1, id2);
        assert_eq!(builder.len(), 1);
    }

    #[test]
    fn test_simple_add_chain() {
        let mut builder = AstBuilder::<BN254>::new();

        let a = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        let b = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_1",
                index: Some(1),
            },
        );
        let c = builder.push(ValueType::G1, AstOp::G1Add { op_id: None, a, b });

        assert_eq!(c, ValueId(2));

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
        assert_eq!(graph.len(), 3);
    }

    #[test]
    fn test_scalar_mul_with_opid() {
        use crate::recursion::witness::{OpId, OpType};

        let mut builder = AstBuilder::<BN254>::new();

        let point = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );

        let op_id = OpId::new(1, OpType::G1ScalarMul, 0);
        let scalar_value: Scalar = Scalar::from_u64(42);
        let scaled = builder.push_with_opid(
            ValueType::G1,
            AstOp::G1ScalarMul {
                op_id: Some(op_id),
                point,
                scalar: ScalarValue::named(scalar_value, "beta"),
            },
            op_id,
        );

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
        assert_eq!(graph.opid_to_value.get(&op_id), Some(&scaled));
    }

    #[test]
    fn test_pairing_type_check() {
        let mut builder = AstBuilder::<BN254>::new();

        let g1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        let g2 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "g2_0",
                index: None,
            },
        );
        let _gt = builder.push(
            ValueType::GT,
            AstOp::Pairing {
                op_id: None,
                g1,
                g2,
            },
        );

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn test_type_mismatch_detected() {
        let mut builder = AstBuilder::<BN254>::new();

        let g1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        // Try to add G1 + G1 but claim it's a G2Add (wrong types)
        let _bad = builder.push(ValueType::G2, AstOp::G2Add { op_id: None, a: g1, b: g1 });

        let graph = builder.finalize();
        let result = graph.validate();
        assert!(matches!(
            result,
            Err(AstValidationError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn test_undefined_input_detected() {
        let mut builder = AstBuilder::<BN254>::new();

        // Reference a ValueId that doesn't exist
        let _bad = builder.push(
            ValueType::G1,
            AstOp::G1Add {
                op_id: None,
                a: ValueId(99),
                b: ValueId(100),
            },
        );

        let graph = builder.finalize();
        let result = graph.validate();
        assert!(matches!(
            result,
            Err(AstValidationError::UndefinedInput { .. })
        ));
    }

    #[test]
    fn test_multi_pairing_length_mismatch() {
        let mut builder = AstBuilder::<BN254>::new();

        let g1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        let g2 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "g2_0",
                index: None,
            },
        );

        let _bad = builder.push(
            ValueType::GT,
            AstOp::MultiPairing {
                op_id: None,
                g1s: vec![g1, g1], // 2 elements
                g2s: vec![g2],     // 1 element
            },
        );

        let graph = builder.finalize();
        let result = graph.validate();
        assert!(matches!(
            result,
            Err(AstValidationError::MultiPairingLengthMismatch { .. })
        ));
    }

    #[test]
    fn test_constraint_validation() {
        let mut builder = AstBuilder::<BN254>::new();

        let a = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(0),
            },
        );
        let b = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(1),
            },
        );

        builder.push_eq(a, b, "final check");

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
    }

    #[test]
    fn test_constraint_undefined_value() {
        let mut builder = AstBuilder::<BN254>::new();

        let a = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(0),
            },
        );

        builder.push_eq(a, ValueId(99), "bad check");

        let graph = builder.finalize();
        let result = graph.validate();
        assert!(matches!(
            result,
            Err(AstValidationError::ConstraintUndefinedValue { .. })
        ));
    }

    #[test]
    fn test_complex_graph() {
        // Build a graph similar to what verification would produce
        let mut builder = AstBuilder::<BN254>::new();

        // Setup inputs
        let g1_0 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_0",
                index: None,
            },
        );
        let _g2_0 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "g2_0",
                index: None,
            },
        );
        let h1 = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "h1",
                index: None,
            },
        );
        let h2 = builder.intern_input(
            ValueType::G2,
            InputSource::Setup {
                name: "h2",
                index: None,
            },
        );
        let chi_0 = builder.intern_input(
            ValueType::GT,
            InputSource::Setup {
                name: "chi",
                index: Some(0),
            },
        );

        // Proof inputs
        let e1 = builder.intern_input(ValueType::G1, InputSource::Proof { name: "final.e1" });
        let e2 = builder.intern_input(ValueType::G2, InputSource::Proof { name: "final.e2" });

        // Some operations
        let d_scalar: Scalar = Scalar::from_u64(5);
        let g1_scaled = builder.push(
            ValueType::G1,
            AstOp::G1ScalarMul {
                op_id: None,
                point: g1_0,
                scalar: ScalarValue::named(d_scalar, "d"),
            },
        );
        let e1_mod = builder.push(ValueType::G1, AstOp::G1Add { op_id: None, a: e1, b: g1_scaled });

        let pair1 = builder.push(
            ValueType::GT,
            AstOp::Pairing {
                op_id: None,
                g1: e1_mod,
                g2: e2,
            },
        );
        let pair2 = builder.push(
            ValueType::GT,
            AstOp::Pairing {
                op_id: None,
                g1: h1,
                g2: h2,
            },
        );

        let lhs = builder.push(
            ValueType::GT,
            AstOp::GTMul {
                op_id: None,
                lhs: pair1,
                rhs: pair2,
            },
        );

        let gamma_scalar: Scalar = Scalar::from_u64(2);
        let rhs = builder.push(
            ValueType::GT,
            AstOp::GTExp {
                op_id: None,
                base: chi_0,
                scalar: ScalarValue::named(gamma_scalar, "gamma"),
            },
        );

        builder.push_eq(lhs, rhs, "final pairing check");

        let graph = builder.finalize();
        assert!(graph.validate().is_ok());
        // 7 inputs + 6 operations = 13 nodes
        assert_eq!(graph.len(), 13);
        assert_eq!(graph.constraints.len(), 1);
    }

    #[test]
    fn test_wiring_pairs() {
        let mut builder = AstBuilder::<BN254>::new();

        // Create a simple graph: g1 -> scale -> add
        let g1_a = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_a",
                index: None,
            },
        );
        let g1_b = builder.intern_input(
            ValueType::G1,
            InputSource::Setup {
                name: "g1_b",
                index: None,
            },
        );

        let scalar: Scalar = Scalar::from_u64(5);
        let scaled = builder.push(
            ValueType::G1,
            AstOp::G1ScalarMul {
                op_id: None,
                point: g1_a,
                scalar: ScalarValue::new(scalar),
            },
        );

        let _sum = builder.push(
            ValueType::G1,
            AstOp::G1Add {
                op_id: None,
                a: scaled,
                b: g1_b,
            },
        );

        let graph = builder.finalize();
        let pairs = graph.wiring_pairs();

        // Expected wiring:
        // - g1_a (0) -> scaled (2)
        // - scaled (2) -> sum (3)
        // - g1_b (1) -> sum (3)
        assert_eq!(pairs.len(), 3);
        assert!(pairs.contains(&(ValueId(0), ValueId(2)))); // g1_a -> scaled
        assert!(pairs.contains(&(ValueId(2), ValueId(3)))); // scaled -> sum
        assert!(pairs.contains(&(ValueId(1), ValueId(3)))); // g1_b -> sum

        // Test consumers map
        let consumers = graph.consumers();
        assert_eq!(consumers.get(&ValueId(0)), Some(&vec![ValueId(2)])); // g1_a consumed by scaled
        assert_eq!(consumers.get(&ValueId(1)), Some(&vec![ValueId(3)])); // g1_b consumed by sum
        assert_eq!(consumers.get(&ValueId(2)), Some(&vec![ValueId(3)])); // scaled consumed by sum
        assert_eq!(consumers.get(&ValueId(3)), None); // sum not consumed by anyone
    }
}
