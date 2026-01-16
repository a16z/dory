//! Witness generation types and traits for recursive proof composition.

/// Operation type identifier for witness indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum OpType {
    /// GT exponentiation: base^scalar in the target group
    GtExp = 0,
    /// G1 scalar multiplication: scalar * point
    G1ScalarMul = 1,
    /// G2 scalar multiplication: scalar * point
    G2ScalarMul = 2,
    /// GT multiplication: lhs * rhs in the target group
    GtMul = 3,
    /// Single pairing: e(G1, G2) -> GT
    Pairing = 4,
    /// Multi-pairing: product of pairings
    MultiPairing = 5,
    /// Multi-scalar multiplication in G1
    MsmG1 = 6,
    /// Multi-scalar multiplication in G2
    MsmG2 = 7,
}

/// Unique identifier for an arithmetic operation in the verification protocol.
///
/// Operations are indexed by (round, op_type, index) to enable deterministic
/// mapping between witness generation and hint consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpId {
    /// Protocol round number (0 for initial checks, 1..=num_rounds for reduce rounds)
    pub round: u16,
    /// Type of arithmetic operation
    pub op_type: OpType,
    /// Index within the round for operations of the same type
    pub index: u16,
}

impl OpId {
    /// Create a new operation identifier.
    #[inline]
    pub const fn new(round: u16, op_type: OpType, index: u16) -> Self {
        Self {
            round,
            op_type,
            index,
        }
    }

    /// Create an operation ID for the initial VMV check phase (round 0).
    #[inline]
    pub const fn vmv(op_type: OpType, index: u16) -> Self {
        Self::new(0, op_type, index)
    }

    /// Create an operation ID for a reduce-and-fold round.
    #[inline]
    pub const fn reduce(round: u16, op_type: OpType, index: u16) -> Self {
        Self::new(round, op_type, index)
    }

    /// Create an operation ID for the final verification phase.
    /// Uses round = u16::MAX to distinguish from reduce rounds.
    #[inline]
    pub const fn final_verify(op_type: OpType, index: u16) -> Self {
        Self::new(u16::MAX, op_type, index)
    }
}

/// Backend-defined witness types for arithmetic operations.
///
/// Each proof system backend implements this trait to define
/// the structure of witness data for each operation type. This allows different
/// proof systems to capture the level of detail they need.
pub trait WitnessBackend: Sized + Send + Sync + 'static {
    /// Witness type for GT exponentiation (base^scalar).
    type GtExpWitness: Clone + Send + Sync;

    /// Witness type for G1 scalar multiplication.
    type G1ScalarMulWitness: Clone + Send + Sync;

    /// Witness type for G2 scalar multiplication.
    type G2ScalarMulWitness: Clone + Send + Sync;

    /// Witness type for GT multiplication (Fq12 multiplication).
    type GtMulWitness: Clone + Send + Sync;

    /// Witness type for single pairing e(G1, G2) -> GT.
    type PairingWitness: Clone + Send + Sync;

    /// Witness type for multi-pairing (product of pairings).
    type MultiPairingWitness: Clone + Send + Sync;

    /// Witness type for G1 multi-scalar multiplication.
    type MsmG1Witness: Clone + Send + Sync;

    /// Witness type for G2 multi-scalar multiplication.
    type MsmG2Witness: Clone + Send + Sync;
}

/// Trait for extracting the result from a witness.
pub trait WitnessResult<T> {
    /// Get the result of the operation if implemented.
    /// Returns None for unimplemented operations.
    fn result(&self) -> Option<&T>;
}
