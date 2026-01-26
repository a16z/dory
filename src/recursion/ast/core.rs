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
            AstOp::G1ScalarMul {
                op_id,
                point,
                scalar,
            } => f
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
            AstOp::G2ScalarMul {
                op_id,
                point,
                scalar,
            } => f
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
            AstOp::GTExp {
                op_id,
                base,
                scalar,
            } => f
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
            AstOp::MsmG1 {
                op_id,
                points,
                scalars,
            } => f
                .debug_struct("MsmG1")
                .field("op_id", op_id)
                .field("points", points)
                .field("num_scalars", &scalars.len())
                .finish(),
            AstOp::MsmG2 {
                op_id,
                points,
                scalars,
            } => f
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
                write!(
                    f,
                    "node {} references undefined input {}",
                    node, undefined_input
                )
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
    ///
    /// # Errors
    /// Returns [`AstValidationError`] if any of the invariants above are violated.
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
        let check_input =
            |input: ValueId, expected_ty: ValueType| -> Result<(), AstValidationError> {
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
            AstOp::MsmG1 {
                points, scalars, ..
            } => {
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
            AstOp::MsmG2 {
                points, scalars, ..
            } => {
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
            op: AstOp::Input {
                source: source.clone(),
            },
        });
        self.interned.insert(source, out);
        out
    }

    // ===== Convenience intern methods for G1 =====

    /// Intern a G1 setup element.
    pub fn intern_g1_setup(
        &mut self,
        _value: E::G1,
        name: &'static str,
        index: Option<usize>,
    ) -> ValueId {
        self.intern_input(ValueType::G1, InputSource::Setup { name, index })
    }

    /// Intern a G1 proof element.
    pub fn intern_g1_proof(&mut self, _value: E::G1, name: &'static str) -> ValueId {
        self.intern_input(ValueType::G1, InputSource::Proof { name })
    }

    /// Intern a G1 per-round proof message element.
    pub fn intern_g1_proof_round(
        &mut self,
        _value: E::G1,
        round: usize,
        msg: RoundMsg,
        name: &'static str,
    ) -> ValueId {
        self.intern_input(ValueType::G1, InputSource::ProofRound { round, msg, name })
    }

    // ===== Convenience intern methods for G2 =====

    /// Intern a G2 setup element.
    pub fn intern_g2_setup(
        &mut self,
        _value: E::G2,
        name: &'static str,
        index: Option<usize>,
    ) -> ValueId {
        self.intern_input(ValueType::G2, InputSource::Setup { name, index })
    }

    /// Intern a G2 proof element.
    pub fn intern_g2_proof(&mut self, _value: E::G2, name: &'static str) -> ValueId {
        self.intern_input(ValueType::G2, InputSource::Proof { name })
    }

    /// Intern a G2 per-round proof message element.
    pub fn intern_g2_proof_round(
        &mut self,
        _value: E::G2,
        round: usize,
        msg: RoundMsg,
        name: &'static str,
    ) -> ValueId {
        self.intern_input(ValueType::G2, InputSource::ProofRound { round, msg, name })
    }

    // ===== Convenience intern methods for GT =====

    /// Intern a GT setup element.
    pub fn intern_gt_setup(
        &mut self,
        _value: E::GT,
        name: &'static str,
        index: Option<usize>,
    ) -> ValueId {
        self.intern_input(ValueType::GT, InputSource::Setup { name, index })
    }

    /// Intern a GT proof element.
    pub fn intern_gt_proof(&mut self, _value: E::GT, name: &'static str) -> ValueId {
        self.intern_input(ValueType::GT, InputSource::Proof { name })
    }

    /// Intern a GT per-round proof message element.
    pub fn intern_gt_proof_round(
        &mut self,
        _value: E::GT,
        round: usize,
        msg: RoundMsg,
        name: &'static str,
    ) -> ValueId {
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
