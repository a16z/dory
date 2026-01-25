//! Witness collection storage for recursive proof composition.

use std::collections::HashMap;

use super::witness::{OpId, WitnessBackend};

/// Storage for all witnesses collected during a verification run.
///
/// This struct holds witnesses for each type of arithmetic operation, indexed
/// by their [`OpId`]. Used by the prover for witness generation.
///
/// # Type Parameters
///
/// - `W`: The witness backend defining concrete witness types
pub struct WitnessCollection<W: WitnessBackend> {
    /// Number of reduce-and-fold rounds in the verification
    pub num_rounds: usize,

    /// G1 addition witnesses
    pub g1_add: HashMap<OpId, W::G1AddWitness>,
    /// G1 scalar multiplication witnesses
    pub g1_scalar_mul: HashMap<OpId, W::G1ScalarMulWitness>,
    /// G1 MSM witnesses
    pub msm_g1: HashMap<OpId, W::MsmG1Witness>,

    /// G2 addition witnesses
    pub g2_add: HashMap<OpId, W::G2AddWitness>,
    /// G2 scalar multiplication witnesses
    pub g2_scalar_mul: HashMap<OpId, W::G2ScalarMulWitness>,
    /// G2 MSM witnesses
    pub msm_g2: HashMap<OpId, W::MsmG2Witness>,

    /// GT multiplication witnesses
    pub gt_mul: HashMap<OpId, W::GtMulWitness>,
    /// GT exponentiation witnesses (base^scalar)
    pub gt_exp: HashMap<OpId, W::GtExpWitness>,

    /// Single pairing witnesses
    pub pairing: HashMap<OpId, W::PairingWitness>,
    /// Multi-pairing witnesses
    pub multi_pairing: HashMap<OpId, W::MultiPairingWitness>,
}

impl<W: WitnessBackend> WitnessCollection<W> {
    /// Create an empty witness collection.
    pub fn new() -> Self {
        Self {
            num_rounds: 0,

            g1_add: HashMap::new(),
            g1_scalar_mul: HashMap::new(),
            msm_g1: HashMap::new(),

            g2_add: HashMap::new(),
            g2_scalar_mul: HashMap::new(),
            msm_g2: HashMap::new(),

            gt_mul: HashMap::new(),
            gt_exp: HashMap::new(),

            pairing: HashMap::new(),
            multi_pairing: HashMap::new(),
        }
    }

    /// Total number of witnesses across all operation types.
    pub fn total_witnesses(&self) -> usize {
        self.g1_add.len()
            + self.g1_scalar_mul.len()
            + self.msm_g1.len()
            + self.g2_add.len()
            + self.g2_scalar_mul.len()
            + self.msm_g2.len()
            + self.gt_mul.len()
            + self.gt_exp.len()
            + self.pairing.len()
            + self.multi_pairing.len()
    }

    /// Check if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.total_witnesses() == 0
    }
}

impl<W: WitnessBackend> Default for WitnessCollection<W> {
    fn default() -> Self {
        Self::new()
    }
}
