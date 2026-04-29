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

    /// Final scalar product message
    pub final_message: ScalarProductMessage<G1, G2>,

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

impl<G1: Group, G2, GT> DoryProof<G1, G2, GT> {
    /// Returns `true` when no zero-knowledge-only proof fields are present.
    pub fn is_transparent(&self) -> bool {
        #[cfg(feature = "zk")]
        {
            self.zk_fields_absent()
        }
        #[cfg(not(feature = "zk"))]
        {
            true
        }
    }

    /// Returns `true` when all zero-knowledge-required proof fields are present.
    #[cfg(feature = "zk")]
    pub fn is_zk(&self) -> bool {
        self.zk_fields_present()
    }

    /// Returns the proof-owned hiding commitment to the claimed evaluation.
    ///
    /// Higher-level protocols that bind an evaluation hiding commitment should
    /// bind this value from the proof instead of carrying an independent copy.
    #[cfg(feature = "zk")]
    pub fn y_com(&self) -> Option<&G1> {
        self.y_com.as_ref()
    }

    /// Returns `true` when every zero-knowledge-required field is present.
    #[cfg(feature = "zk")]
    pub fn zk_fields_present(&self) -> bool {
        self.e2.is_some()
            && self.y_com.is_some()
            && self.sigma1_proof.is_some()
            && self.sigma2_proof.is_some()
            && self.scalar_product_proof.is_some()
    }

    /// Returns `true` when every zero-knowledge-only field is absent.
    #[cfg(feature = "zk")]
    pub fn zk_fields_absent(&self) -> bool {
        self.e2.is_none()
            && self.y_com.is_none()
            && self.sigma1_proof.is_none()
            && self.sigma2_proof.is_none()
            && self.scalar_product_proof.is_none()
    }
}
