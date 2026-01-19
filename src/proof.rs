//! Dory proof structure
//!
//! A Dory proof consists of:
//! - VMV message (PCS transform)
//! - Multiple rounds of reduce messages (log n rounds)
//! - Final scalar product message
//!
//! For ZK mode, the proof additionally contains:
//! - ScalarProductProof (Σ-protocol) for zero-knowledge verification

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
///
/// In ZK mode (when `zk` feature is enabled and `scalar_product_proof` is `Some`),
/// verification uses the Σ-protocol to verify the final inner product relation
/// without revealing intermediate values.
#[derive(Clone, Debug)]
pub struct DoryProof<G1: Group, G2, GT> {
    /// Vector-Matrix-Vector message for PCS transformation
    pub vmv_message: VMVMessage<G1, GT>,

    /// First reduce messages for each round (nu rounds total)
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,

    /// Second reduce messages for each round (nu rounds total)
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,

    /// Final scalar product message
    pub final_message: ScalarProductMessage<G1, G2>,

    /// ZK scalar product proof (Σ-protocol)
    ///
    /// Present only in ZK mode. When `Some`, verification uses `verify_final_zk`
    /// which incorporates the Σ-protocol to handle blinded values.
    #[cfg(feature = "zk")]
    pub scalar_product_proof: Option<ScalarProductProof<G1, G2, G1::Scalar, GT>>,

    /// Log₂ of number of rows in the coefficient matrix
    pub nu: usize,

    /// Log₂ of number of columns in the coefficient matrix
    pub sigma: usize,
}

/// A complete Dory ZK evaluation proof
///
/// In ZK mode, the evaluation `y` is not revealed. Instead:
/// - `y_com = y·Γ1,fin + r_y·H1` commits to the evaluation
/// - `e2 = y·Γ2,fin + r_e2·H2` is the blinded E2 for the reduce protocol
/// - Sigma1 proves y_com and e2 commit to the same y
/// - Sigma2 proves the VMV relation holds with blinds
/// - ScalarProductProof proves the final inner product relation
#[cfg(feature = "zk")]
#[derive(Clone, Debug)]
pub struct ZkDoryProof<G1, G2, F, GT> {
    /// ZK VMV message with committed evaluation
    pub vmv_message: ZkVMVMessage<G1, G2, GT>,

    /// First reduce messages for each round
    pub first_messages: Vec<FirstReduceMessage<G1, G2, GT>>,

    /// Second reduce messages for each round
    pub second_messages: Vec<SecondReduceMessage<G1, G2, GT>>,

    /// Final scalar product message
    pub final_message: ScalarProductMessage<G1, G2>,

    /// Sigma1 proof: proves y_com and e2 commit to same y
    pub sigma1_proof: Sigma1Proof<G1, G2, F>,

    /// Sigma2 proof: proves VMV relation holds with blinds
    pub sigma2_proof: Sigma2Proof<F, GT>,

    /// ZK scalar product proof
    pub scalar_product_proof: ScalarProductProof<G1, G2, F, GT>,

    /// Log₂ of number of rows in the coefficient matrix
    pub nu: usize,

    /// Log₂ of number of columns in the coefficient matrix
    pub sigma: usize,
}
