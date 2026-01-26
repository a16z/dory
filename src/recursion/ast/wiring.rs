use std::collections::HashMap;
use std::fmt;

use crate::primitives::arithmetic::{Group, PairingCurve};

use super::core::{AstGraph, AstOp, InputSource, ValueId, ValueType};

/// Precise identification of which input slot of an operation receives a wire.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum InputSlot {
    /// Left operand `a` in G1Add.
    G1AddLhs,
    /// Right operand `b` in G1Add.
    G1AddRhs,

    /// Left operand `a` in G2Add.
    G2AddLhs,
    /// Right operand `b` in G2Add.
    G2AddRhs,

    /// Left operand in GTMul.
    GTMulLhs,
    /// Right operand in GTMul.
    GTMulRhs,

    /// Base in GTExp.
    GTExpBase,

    /// Base point operand in G1ScalarMul.
    G1ScalarMulBase,
    /// Base point operand in G2ScalarMul.
    G2ScalarMulBase,

    /// G1 element in single Pairing.
    PairingG1,
    /// G2 element in single Pairing.
    PairingG2,

    /// G1 element at index i in MultiPairing.
    MultiPairingG1(usize),
    /// G2 element at index i in MultiPairing.
    MultiPairingG2(usize),

    /// Point at index i in MsmG1.
    MsmG1(usize),
    /// Point at index i in MsmG2.
    MsmG2(usize),
}

impl fmt::Display for InputSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputSlot::G1AddLhs | InputSlot::G2AddLhs => write!(f, ".a"),
            InputSlot::G1AddRhs | InputSlot::G2AddRhs => write!(f, ".b"),
            InputSlot::GTMulLhs => write!(f, ".lhs"),
            InputSlot::GTMulRhs => write!(f, ".rhs"),
            InputSlot::GTExpBase => write!(f, ".base"),
            InputSlot::G1ScalarMulBase | InputSlot::G2ScalarMulBase => write!(f, ".point"),
            InputSlot::PairingG1 => write!(f, ".g1"),
            InputSlot::PairingG2 => write!(f, ".g2"),
            InputSlot::MultiPairingG1(i) => write!(f, ".g1s[{}]", i),
            InputSlot::MultiPairingG2(i) => write!(f, ".g2s[{}]", i),
            InputSlot::MsmG1(i) | InputSlot::MsmG2(i) => write!(f, ".points[{}]", i),
        }
    }
}

impl<E: PairingCurve> AstOp<E>
where
    E::G1: Group,
{
    /// Returns input ValueIds with their precise input slots.
    ///
    /// Each entry is `(ValueId, InputSlot)` indicating which input slot
    /// of this operation receives the given ValueId.
    pub fn input_slots(&self) -> Vec<(ValueId, InputSlot)> {
        match self {
            AstOp::Input { .. } => vec![],
            AstOp::G1Add { a, b, .. } => vec![(*a, InputSlot::G1AddLhs), (*b, InputSlot::G1AddRhs)],
            AstOp::G2Add { a, b, .. } => vec![(*a, InputSlot::G2AddLhs), (*b, InputSlot::G2AddRhs)],
            AstOp::GTMul { lhs, rhs, .. } => {
                vec![(*lhs, InputSlot::GTMulLhs), (*rhs, InputSlot::GTMulRhs)]
            }
            AstOp::G1ScalarMul { point, .. } => vec![(*point, InputSlot::G1ScalarMulBase)],
            AstOp::G2ScalarMul { point, .. } => vec![(*point, InputSlot::G2ScalarMulBase)],
            AstOp::GTExp { base, .. } => vec![(*base, InputSlot::GTExpBase)],
            AstOp::Pairing { g1, g2, .. } => {
                vec![(*g1, InputSlot::PairingG1), (*g2, InputSlot::PairingG2)]
            }
            AstOp::MultiPairing { g1s, g2s, .. } => {
                let mut slots = Vec::with_capacity(g1s.len() + g2s.len());
                for (i, &id) in g1s.iter().enumerate() {
                    slots.push((id, InputSlot::MultiPairingG1(i)));
                }
                for (i, &id) in g2s.iter().enumerate() {
                    slots.push((id, InputSlot::MultiPairingG2(i)));
                }
                slots
            }
            AstOp::MsmG1 { points, .. } => points
                .iter()
                .enumerate()
                .map(|(i, &id)| (id, InputSlot::MsmG1(i)))
                .collect(),
            AstOp::MsmG2 { points, .. } => points
                .iter()
                .enumerate()
                .map(|(i, &id)| (id, InputSlot::MsmG2(i)))
                .collect(),
        }
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

impl<E: PairingCurve> AstGraph<E>
where
    E::G1: Group,
{
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
    ///
    /// # Panics
    /// Panics if internal indexing invariants are violated (this should be impossible for a
    /// well-formed graph).
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
