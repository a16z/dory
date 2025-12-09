//! Witness collection storage for recursive proof composition.

use std::collections::HashMap;

use super::hint_map::HintMap;
use super::witness::{OpId, WitnessBackend, WitnessResult};
use crate::primitives::arithmetic::PairingCurve;

/// Storage for all witnesses collected during a verification run.
///
/// This struct holds witnesses for each type of arithmetic operation, indexed
/// by their [`OpId`]. It is produced internally during witness generation and can
/// be converted to a [`HintMap`](crate::recursion::HintMap) for hint-based verification.
///
/// # Type Parameters
///
/// - `W`: The witness backend defining concrete witness types
pub struct WitnessCollection<W: WitnessBackend> {
    /// Number of reduce-and-fold rounds in the verification
    pub num_rounds: usize,

    /// GT exponentiation witnesses (base^scalar)
    pub gt_exp: HashMap<OpId, W::GtExpWitness>,

    /// G1 scalar multiplication witnesses
    pub g1_scalar_mul: HashMap<OpId, W::G1ScalarMulWitness>,

    /// G2 scalar multiplication witnesses
    pub g2_scalar_mul: HashMap<OpId, W::G2ScalarMulWitness>,

    /// GT multiplication witnesses
    pub gt_mul: HashMap<OpId, W::GtMulWitness>,

    /// Single pairing witnesses
    pub pairing: HashMap<OpId, W::PairingWitness>,

    /// Multi-pairing witnesses
    pub multi_pairing: HashMap<OpId, W::MultiPairingWitness>,

    /// G1 MSM witnesses
    pub msm_g1: HashMap<OpId, W::MsmG1Witness>,

    /// G2 MSM witnesses
    pub msm_g2: HashMap<OpId, W::MsmG2Witness>,
}

impl<W: WitnessBackend> WitnessCollection<W> {
    /// Create an empty witness collection.
    pub fn new() -> Self {
        Self {
            num_rounds: 0,
            gt_exp: HashMap::new(),
            g1_scalar_mul: HashMap::new(),
            g2_scalar_mul: HashMap::new(),
            gt_mul: HashMap::new(),
            pairing: HashMap::new(),
            multi_pairing: HashMap::new(),
            msm_g1: HashMap::new(),
            msm_g2: HashMap::new(),
        }
    }

    /// Total number of witnesses across all operation types.
    pub fn total_witnesses(&self) -> usize {
        self.gt_exp.len()
            + self.g1_scalar_mul.len()
            + self.g2_scalar_mul.len()
            + self.gt_mul.len()
            + self.pairing.len()
            + self.multi_pairing.len()
            + self.msm_g1.len()
            + self.msm_g2.len()
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

impl<W: WitnessBackend> WitnessCollection<W> {
    /// Convert full witness collection to hints (outputs only).
    ///
    /// # Type Parameters
    ///
    /// - `E`: The pairing curve whose group elements are stored in the witnesses
    pub fn to_hints<E>(&self) -> HintMap<E>
    where
        E: PairingCurve,
        W::GtExpWitness: WitnessResult<E::GT>,
        W::G1ScalarMulWitness: WitnessResult<E::G1>,
        W::G2ScalarMulWitness: WitnessResult<E::G2>,
        W::GtMulWitness: WitnessResult<E::GT>,
        W::PairingWitness: WitnessResult<E::GT>,
        W::MultiPairingWitness: WitnessResult<E::GT>,
        W::MsmG1Witness: WitnessResult<E::G1>,
        W::MsmG2Witness: WitnessResult<E::G2>,
    {
        let mut hints = HintMap::new(self.num_rounds);

        // Extract GT results
        for (id, w) in &self.gt_exp {
            if let Some(result) = w.result() {
                hints.insert_gt(*id, *result);
            }
        }
        for (id, w) in &self.gt_mul {
            if let Some(result) = w.result() {
                hints.insert_gt(*id, *result);
            }
        }
        for (id, w) in &self.pairing {
            if let Some(result) = w.result() {
                hints.insert_gt(*id, *result);
            }
        }
        for (id, w) in &self.multi_pairing {
            if let Some(result) = w.result() {
                hints.insert_gt(*id, *result);
            }
        }

        // Extract G1 results
        for (id, w) in &self.g1_scalar_mul {
            if let Some(result) = w.result() {
                hints.insert_g1(*id, *result);
            }
        }
        for (id, w) in &self.msm_g1 {
            if let Some(result) = w.result() {
                hints.insert_g1(*id, *result);
            }
        }

        // Extract G2 results
        for (id, w) in &self.g2_scalar_mul {
            if let Some(result) = w.result() {
                hints.insert_g2(*id, *result);
            }
        }
        for (id, w) in &self.msm_g2 {
            if let Some(result) = w.result() {
                hints.insert_g2(*id, *result);
            }
        }

        hints
    }
}
