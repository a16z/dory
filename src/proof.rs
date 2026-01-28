//! Dory proof structure
//!
//! A Dory proof consists of:
//! - VMV message (PCS transform)
//! - Multiple rounds of reduce messages (log n rounds)
//! - Final scalar product message
//!
//! For ZK mode, the proof additionally contains:
//! - E2 and y_com (blinded VMV extension)
//! - Sigma proofs for ZK verification

use crate::messages::*;
use crate::primitives::arithmetic::Group;

/// A complete Dory evaluation proof
///
/// The proof demonstrates that a committed polynomial evaluates to a specific value
/// at a given point. It consists of messages from the interactive protocol made
/// non-interactive via Fiat-Shamir.
///
/// In ZK mode (when `zk` feature is enabled), additional fields contain the
/// sigma proofs and blinded values needed for zero-knowledge verification.
#[derive(Clone, Debug)]
pub struct DoryProof<G1: Group, G2, GT> {
    /// Vector-Matrix-Vector message for PCS transformation
    pub vmv_message: VMVMessage<G1, GT>,

    /// First reduce messages for each round
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,

    /// Second reduce messages for each round
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,

    /// Final scalar product message
    pub final_message: ScalarProductMessage<G1, G2>,

    /// Log₂ of number of rows in the coefficient matrix
    pub nu: usize,

    /// Log₂ of number of columns in the coefficient matrix
    pub sigma: usize,

    // ZK-specific fields (present when zk feature is enabled)
    /// E2 = y·Γ2,fin + r_e2·H2 (blinded VMV extension)
    #[cfg(feature = "zk")]
    pub e2: Option<G2>,

    /// y_com = y·Γ1,fin + r_y·H1 (commitment to evaluation)
    #[cfg(feature = "zk")]
    pub y_com: Option<G1>,

    /// Sigma1 proof: proves y_com and e2 commit to same y
    #[cfg(feature = "zk")]
    pub sigma1_proof: Option<Sigma1Proof<G1, G2, G1::Scalar>>,

    /// Sigma2 proof: proves VMV relation holds with blinds
    #[cfg(feature = "zk")]
    pub sigma2_proof: Option<Sigma2Proof<G1::Scalar, GT>>,

    /// ZK scalar product proof (Σ-protocol)
    #[cfg(feature = "zk")]
    pub scalar_product_proof: Option<ScalarProductProof<G1, G2, G1::Scalar, GT>>,
}
