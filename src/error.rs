/// Errors that can occur in Dory PCS operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DoryError {
    /// The proof verification failed
    #[error("Invalid proof")]
    InvalidProof,

    /// Polynomial size is invalid for the given parameters
    #[error("Invalid polynomial size: expected {expected}, got {actual}")]
    InvalidSize { expected: usize, actual: usize },

    /// Evaluation point has wrong dimension
    #[error("Invalid evaluation point dimension: expected {expected}, got {actual}")]
    InvalidPointDimension { expected: usize, actual: usize },

    /// Invalid input parameters
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
