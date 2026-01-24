//! Input provider for parallel AST evaluation.
//!
//! This module provides `DoryInputProvider`, which implements the `InputProvider`
//! trait to supply setup and proof elements to the parallel AST executor.

use crate::primitives::arithmetic::{Group, PairingCurve};
use crate::proof::DoryProof;
use crate::setup::VerifierSetup;

use super::ast::{AstNode, AstOp, InputSource, RoundMsg};
use super::parallel::{EvalResult, InputProvider};

/// Provides input values for parallel AST evaluation.
///
/// Maps `InputSource` (setup elements, proof elements) to actual values
/// from the `VerifierSetup` and `DoryProof`.
///
/// # Example
///
/// ```ignore
/// use dory_pcs::recursion::input_provider::DoryInputProvider;
/// use dory_pcs::recursion::parallel::TaskExecutor;
///
/// let input_provider = DoryInputProvider::new(&setup, &proof);
/// let executor = TaskExecutor::new(&ast, &input_provider, &ops);
/// let results = executor.execute();
/// ```
pub struct DoryInputProvider<'a, E: PairingCurve> {
    setup: &'a VerifierSetup<E>,
    proof: &'a DoryProof<E::G1, E::G2, E::GT>,
}

impl<'a, E: PairingCurve> DoryInputProvider<'a, E> {
    /// Create a new input provider from setup and proof.
    pub fn new(setup: &'a VerifierSetup<E>, proof: &'a DoryProof<E::G1, E::G2, E::GT>) -> Self {
        Self { setup, proof }
    }
}

impl<E> InputProvider<E> for DoryInputProvider<'_, E>
where
    E: PairingCurve,
    E::G1: Group,
{
    fn get_input(&self, node: &AstNode<E>) -> Option<EvalResult<E>> {
        match &node.op {
            AstOp::Input { source } => {
                match source {
                    InputSource::Setup { name, index } => {
                        match (*name, index) {
                            // G1 setup elements
                            ("h1", None) => Some(EvalResult::G1(self.setup.h1)),
                            ("g1_0", None) => Some(EvalResult::G1(self.setup.g1_0)),

                            // G2 setup elements
                            ("h2", None) => Some(EvalResult::G2(self.setup.h2)),
                            ("g2_0", None) => Some(EvalResult::G2(self.setup.g2_0)),

                            // GT setup elements (indexed arrays)
                            ("chi", Some(i)) => self.setup.chi.get(*i).map(|v| EvalResult::GT(*v)),
                            ("delta_1l", Some(i)) => {
                                self.setup.delta_1l.get(*i).map(|v| EvalResult::GT(*v))
                            }
                            ("delta_1r", Some(i)) => {
                                self.setup.delta_1r.get(*i).map(|v| EvalResult::GT(*v))
                            }
                            ("delta_2l", Some(i)) => {
                                self.setup.delta_2l.get(*i).map(|v| EvalResult::GT(*v))
                            }
                            ("delta_2r", Some(i)) => {
                                self.setup.delta_2r.get(*i).map(|v| EvalResult::GT(*v))
                            }
                            ("ht", None) => Some(EvalResult::GT(self.setup.ht)),

                            _ => {
                                tracing::warn!(
                                    name = name,
                                    index = ?index,
                                    "Unknown setup element"
                                );
                                None
                            }
                        }
                    }
                    InputSource::Proof { name } => {
                        match *name {
                            // VMV message elements
                            "vmv.c" => Some(EvalResult::GT(self.proof.vmv_message.c)),
                            "vmv.d2" => Some(EvalResult::GT(self.proof.vmv_message.d2)),
                            "vmv.e1" => Some(EvalResult::G1(self.proof.vmv_message.e1)),
                            // VMV init elements (for deferred VMV check in final multi-pairing)
                            "vmv.e1_init" => Some(EvalResult::G1(self.proof.vmv_message.e1)),
                            "vmv.d2_init" => Some(EvalResult::GT(self.proof.vmv_message.d2)),
                            "commitment" => {
                                // The commitment is passed to verify_recursive, not stored in proof.
                                // Return None - caller should provide this separately.
                                tracing::debug!("Commitment requested - should be provided externally");
                                None
                            }
                            // Final message elements
                            "final.e1" => Some(EvalResult::G1(self.proof.final_message.e1)),
                            "final.e2" => Some(EvalResult::G2(self.proof.final_message.e2)),

                            _ => {
                                tracing::warn!(name = name, "Unknown proof element");
                                None
                            }
                        }
                    }
                    InputSource::ProofRound { round, msg, name } => {
                        let round = *round;
                        if round >= self.proof.first_messages.len() {
                            tracing::warn!(round = round, name = name, "Round out of bounds");
                            return None;
                        }

                        match msg {
                            RoundMsg::First => {
                                let first_msg = &self.proof.first_messages[round];
                                match *name {
                                    "d1_left" => Some(EvalResult::GT(first_msg.d1_left)),
                                    "d1_right" => Some(EvalResult::GT(first_msg.d1_right)),
                                    "d2_left" => Some(EvalResult::GT(first_msg.d2_left)),
                                    "d2_right" => Some(EvalResult::GT(first_msg.d2_right)),
                                    "e1_beta" => Some(EvalResult::G1(first_msg.e1_beta)),
                                    "e2_beta" => Some(EvalResult::G2(first_msg.e2_beta)),
                                    _ => {
                                        tracing::warn!(
                                            round = round,
                                            name = name,
                                            "Unknown first message element"
                                        );
                                        None
                                    }
                                }
                            }
                            RoundMsg::Second => {
                                let second_msg = &self.proof.second_messages[round];
                                match *name {
                                    "c_plus" => Some(EvalResult::GT(second_msg.c_plus)),
                                    "c_minus" => Some(EvalResult::GT(second_msg.c_minus)),
                                    "e1_plus" => Some(EvalResult::G1(second_msg.e1_plus)),
                                    "e1_minus" => Some(EvalResult::G1(second_msg.e1_minus)),
                                    "e2_plus" => Some(EvalResult::G2(second_msg.e2_plus)),
                                    "e2_minus" => Some(EvalResult::G2(second_msg.e2_minus)),
                                    _ => {
                                        tracing::warn!(
                                            round = round,
                                            name = name,
                                            "Unknown second message element"
                                        );
                                        None
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // Not an input node
                None
            }
        }
    }
}

/// Extended input provider that also includes the commitment.
///
/// Since the commitment is passed as a parameter to `verify_recursive`
/// (not stored in the proof), this provider includes it explicitly.
pub struct DoryInputProviderWithCommitment<'a, E: PairingCurve> {
    base: DoryInputProvider<'a, E>,
    commitment: E::GT,
}

impl<'a, E: PairingCurve> DoryInputProviderWithCommitment<'a, E> {
    /// Create a new input provider with the commitment.
    pub fn new(
        setup: &'a VerifierSetup<E>,
        proof: &'a DoryProof<E::G1, E::G2, E::GT>,
        commitment: E::GT,
    ) -> Self {
        Self {
            base: DoryInputProvider::new(setup, proof),
            commitment,
        }
    }
}

impl<E> InputProvider<E> for DoryInputProviderWithCommitment<'_, E>
where
    E: PairingCurve,
    E::G1: Group,
{
    fn get_input(&self, node: &AstNode<E>) -> Option<EvalResult<E>> {
        // Check for commitment first
        if let AstOp::Input {
            source: InputSource::Proof { name },
            ..
        } = &node.op
        {
            if *name == "commitment" {
                return Some(EvalResult::GT(self.commitment));
            }
        }
        // Delegate to base provider
        self.base.get_input(node)
    }
}
