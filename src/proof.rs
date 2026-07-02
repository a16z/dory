//! Dory proof structure
//!
//! A Dory proof consists of:
//! - VMV message (PCS transform)
//! - Multiple rounds of reduce messages (log n rounds)
//! - Final scalar product message

use crate::messages::*;
use crate::primitives::arithmetic::Group;

/// A complete Dory evaluation proof
///
/// The proof demonstrates that a committed polynomial evaluates to a specific value
/// at a given point. It consists of messages from the interactive protocol made
/// non-interactive via Fiat-Shamir.
///
/// The proof includes the matrix dimensions (nu, sigma) used during proof generation,
/// which the verifier uses to ensure consistency with the evaluation point.
#[derive(Clone, Debug, PartialEq)]
#[allow(missing_docs)]
pub struct DoryProof<G1: Group, G2, GT> {
    /// Vector-Matrix-Vector message for PCS transformation
    pub vmv_message: VMVMessage<G1, GT>,

    /// First reduce messages for each round (nu rounds total)
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,

    /// Second reduce messages for each round (nu rounds total)
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,

    /// Final scalar product message revealing the folded witness.
    ///
    /// `Some` in transparent mode. `None` in ZK mode, where revealing the
    /// folded witness would break hiding: the scalar-product Σ-proof
    /// (`scalar_product_proof`) replaces it.
    pub final_message: Option<ScalarProductMessage<G1, G2>>,

    /// Log₂ of number of rows in the coefficient matrix
    pub nu: usize,

    /// Log₂ of number of columns in the coefficient matrix
    pub sigma: usize,

    /// Blinded E₂ element for zero-knowledge proofs
    #[cfg(feature = "zk")]
    pub e2: Option<G2>,
    /// Pedersen commitment to the blinding vector y
    #[cfg(feature = "zk")]
    pub y_com: Option<G1>,
    /// Σ₁ proof: E₂ and y_com commit to the same y
    #[cfg(feature = "zk")]
    pub sigma1_proof: Option<Sigma1Proof<G1, G2, G1::Scalar>>,
    /// Σ₂ proof: consistency of E₁ with D₂
    #[cfg(feature = "zk")]
    pub sigma2_proof: Option<Sigma2Proof<G1::Scalar, GT>>,
    /// ZK scalar product proof: (C, D₁, D₂) consistency with blinded vectors
    #[cfg(feature = "zk")]
    pub scalar_product_proof: Option<ScalarProductProof<G1, G2, G1::Scalar, GT>>,
}
