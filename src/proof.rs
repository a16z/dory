//! Dory proof structure
//!
//! A Dory proof consists of:
//! - VMV message (PCS transform)
//! - Multiple rounds of reduce messages (log n rounds)
//! - Final scalar product message

use crate::messages::*;

/// A complete Dory evaluation proof
///
/// The proof demonstrates that a committed polynomial evaluates to a specific value
/// at a given point. It consists of messages from the interactive protocol made
/// non-interactive via Fiat-Shamir.
///
/// The proof includes the matrix dimensions (nu, sigma) used during proof generation,
/// which the verifier uses to ensure consistency with the evaluation point.
#[derive(Clone, Debug)]
pub struct DoryProof<G1, G2, GT> {
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
}

impl<G1, G2, GT> DoryProof<G1, G2, GT> {
    /// Return all GT elements in the proof (for testing)
    #[cfg(test)]
    pub fn gt_elements(&self) -> Vec<GT>
    where
        GT: Clone,
    {
        // Return all GT elements in the proof
        let mut elements = Vec::new();
        elements.push(self.vmv_message.c.clone());
        elements.push(self.vmv_message.d2.clone());
        for msg in &self.first_messages {
            elements.push(msg.d1_left.clone());
            elements.push(msg.d1_right.clone());
            elements.push(msg.d2_left.clone());
            elements.push(msg.d2_right.clone());
        }
        for msg in &self.second_messages {
            elements.push(msg.c_plus.clone());
            elements.push(msg.c_minus.clone());
        }
        elements
    }

    /// Convert the proof's GT type to another type
    pub fn convert_gt<GT2>(self) -> DoryProof<G1, G2, GT2>
    where
        GT: Into<GT2>,
    {
        DoryProof {
            vmv_message: VMVMessage {
                c: self.vmv_message.c.into(),
                d2: self.vmv_message.d2.into(),
                e1: self.vmv_message.e1,
            },
            first_messages: self
                .first_messages
                .into_iter()
                .map(|msg| FirstReduceMessage {
                    d1_left: msg.d1_left.into(),
                    d1_right: msg.d1_right.into(),
                    d2_left: msg.d2_left.into(),
                    d2_right: msg.d2_right.into(),
                    e1_beta: msg.e1_beta,
                    e2_beta: msg.e2_beta,
                })
                .collect(),
            second_messages: self
                .second_messages
                .into_iter()
                .map(|msg| SecondReduceMessage {
                    c_plus: msg.c_plus.into(),
                    c_minus: msg.c_minus.into(),
                    e1_plus: msg.e1_plus,
                    e1_minus: msg.e1_minus,
                    e2_plus: msg.e2_plus,
                    e2_minus: msg.e2_minus,
                })
                .collect(),
            final_message: self.final_message,
            nu: self.nu,
            sigma: self.sigma,
        }
    }
}
