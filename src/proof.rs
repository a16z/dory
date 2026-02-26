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
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub struct DoryProof<G1: Group, G2, GT> {
    /// Vector-Matrix-Vector message for PCS transformation
    pub vmv_message: VMVMessage<G1, GT>,

    /// First reduce messages for each round (nu rounds total)
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,

    /// Second reduce messages for each round (nu rounds total)
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,

    /// Final scalar product message
    pub final_message: ScalarProductMessage<G1, G2>,

    /// Log₂ of number of rows in the coefficient matrix
    pub nu: usize,

    /// Log₂ of number of columns in the coefficient matrix
    pub sigma: usize,

    #[cfg(feature = "zk")]
    pub e2: Option<G2>,
    #[cfg(feature = "zk")]
    pub y_com: Option<G1>,
    #[cfg(feature = "zk")]
    pub sigma1_proof: Option<Sigma1Proof<G1, G2, G1::Scalar>>,
    #[cfg(feature = "zk")]
    pub sigma2_proof: Option<Sigma2Proof<G1::Scalar, GT>>,
    #[cfg(feature = "zk")]
    pub scalar_product_proof: Option<ScalarProductProof<G1, G2, G1::Scalar, GT>>,
}
