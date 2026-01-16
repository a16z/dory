//! Witness collection for recursive proof composition.

use std::collections::HashMap;
use std::marker::PhantomData;

use super::witness::{OpId, OpType, WitnessBackend};
use crate::primitives::arithmetic::{Group, PairingCurve};

use super::WitnessCollection;

/// Builder for tracking operation IDs during witness collection.
///
/// Maintains counters for each operation type within a round,
/// providing deterministic operation IDs.
#[derive(Debug, Clone)]
pub(crate) struct OpIdBuilder {
    current_round: u16,
    counters: HashMap<OpType, u16>,
}

impl OpIdBuilder {
    /// Create a new builder starting at round 0 (VMV phase).
    pub(crate) fn new() -> Self {
        Self {
            current_round: 0,
            counters: HashMap::new(),
        }
    }

    /// Advance to the next round.
    pub(crate) fn advance_round(&mut self) {
        self.current_round += 1;
        self.counters.clear();
    }

    /// Enter the final verification phase (base case of Dory reduce)
    pub(crate) fn enter_final(&mut self) {
        self.current_round = u16::MAX;
        self.counters.clear();
    }

    /// Get the current round number.
    pub(crate) fn round(&self) -> u16 {
        self.current_round
    }

    /// Generate the next operation ID for the given type.
    pub(crate) fn next(&mut self, op_type: OpType) -> OpId {
        let index = self.counters.entry(op_type).or_insert(0);
        let id = OpId::new(self.current_round, op_type, *index);
        *index += 1;
        id
    }
}

impl Default for OpIdBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for generating detailed witness traces from operation inputs/outputs.
///
/// Backend implementations provide this to create witnesses with intermediate
/// computation steps (e.g., Miller loop iterations, square-and-multiply steps).
pub trait WitnessGenerator<W: WitnessBackend, E: PairingCurve> {
    /// Generate a GT exponentiation witness with intermediate steps.
    fn generate_gt_exp(
        base: &E::GT,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::GT,
    ) -> W::GtExpWitness;

    /// Generate a G1 scalar multiplication witness with intermediate steps.
    fn generate_g1_scalar_mul(
        point: &E::G1,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::G1,
    ) -> W::G1ScalarMulWitness;

    /// Generate a G2 scalar multiplication witness with intermediate steps.
    fn generate_g2_scalar_mul(
        point: &E::G2,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::G2,
    ) -> W::G2ScalarMulWitness;

    /// Generate a GT multiplication witness with intermediate steps.
    fn generate_gt_mul(lhs: &E::GT, rhs: &E::GT, result: &E::GT) -> W::GtMulWitness;

    /// Generate a single pairing witness with Miller loop steps.
    fn generate_pairing(g1: &E::G1, g2: &E::G2, result: &E::GT) -> W::PairingWitness;

    /// Generate a multi-pairing witness with all Miller loop steps.
    fn generate_multi_pairing(
        g1s: &[E::G1],
        g2s: &[E::G2],
        result: &E::GT,
    ) -> W::MultiPairingWitness;

    /// Generate a G1 MSM witness with bucket and accumulator states.
    fn generate_msm_g1(
        bases: &[E::G1],
        scalars: &[<E::G1 as Group>::Scalar],
        result: &E::G1,
    ) -> W::MsmG1Witness;

    /// Generate a G2 MSM witness with bucket and accumulator states.
    fn generate_msm_g2(
        bases: &[E::G2],
        scalars: &[<E::G1 as Group>::Scalar],
        result: &E::G2,
    ) -> W::MsmG2Witness;
}

/// Witness collector that generates and stores witnesses during verification.
///
/// # Type Parameters
///
/// - `W`: The witness backend defining witness types
/// - `E`: The pairing curve providing group element types
/// - `Gen`: A witness generator that creates detailed traces
pub(crate) struct WitnessCollector<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    collection: WitnessCollection<W>,
    _phantom: PhantomData<(E, Gen)>,
}

impl<W, E, Gen> WitnessCollector<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    /// Create a new witness collector.
    pub(crate) fn new() -> Self {
        Self {
            collection: WitnessCollection::new(),
            _phantom: PhantomData,
        }
    }

    /// Set the number of rounds for the verification.
    pub(crate) fn set_num_rounds(&mut self, num_rounds: usize) {
        self.collection.num_rounds = num_rounds;
    }

    /// Finalize collection and return all accumulated witnesses.
    pub(crate) fn finalize(self) -> WitnessCollection<W> {
        self.collection
    }

    /// Collect a GT exponentiation witness.
    pub(crate) fn collect_gt_exp(
        &mut self,
        id: OpId,
        base: &E::GT,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::GT,
    ) -> W::GtExpWitness {
        let witness = Gen::generate_gt_exp(base, scalar, result);
        self.collection.gt_exp.insert(id, witness.clone());
        witness
    }

    /// Collect a G1 scalar multiplication witness.
    pub(crate) fn collect_g1_scalar_mul(
        &mut self,
        id: OpId,
        point: &E::G1,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::G1,
    ) -> W::G1ScalarMulWitness {
        let witness = Gen::generate_g1_scalar_mul(point, scalar, result);
        self.collection.g1_scalar_mul.insert(id, witness.clone());
        witness
    }

    /// Collect a G2 scalar multiplication witness.
    pub(crate) fn collect_g2_scalar_mul(
        &mut self,
        id: OpId,
        point: &E::G2,
        scalar: &<E::G1 as Group>::Scalar,
        result: &E::G2,
    ) -> W::G2ScalarMulWitness {
        let witness = Gen::generate_g2_scalar_mul(point, scalar, result);
        self.collection.g2_scalar_mul.insert(id, witness.clone());
        witness
    }

    /// Collect a GT multiplication witness.
    pub(crate) fn collect_gt_mul(
        &mut self,
        id: OpId,
        lhs: &E::GT,
        rhs: &E::GT,
        result: &E::GT,
    ) -> W::GtMulWitness {
        let witness = Gen::generate_gt_mul(lhs, rhs, result);
        self.collection.gt_mul.insert(id, witness.clone());
        witness
    }

    /// Collect a single pairing witness.
    pub(crate) fn collect_pairing(
        &mut self,
        id: OpId,
        g1: &E::G1,
        g2: &E::G2,
        result: &E::GT,
    ) -> W::PairingWitness {
        let witness = Gen::generate_pairing(g1, g2, result);
        self.collection.pairing.insert(id, witness.clone());
        witness
    }

    /// Collect a multi-pairing witness.
    pub(crate) fn collect_multi_pairing(
        &mut self,
        id: OpId,
        g1s: &[E::G1],
        g2s: &[E::G2],
        result: &E::GT,
    ) -> W::MultiPairingWitness {
        let witness = Gen::generate_multi_pairing(g1s, g2s, result);
        self.collection.multi_pairing.insert(id, witness.clone());
        witness
    }

    /// Collect a G1 MSM witness.
    pub(crate) fn collect_msm_g1(
        &mut self,
        id: OpId,
        bases: &[E::G1],
        scalars: &[<E::G1 as Group>::Scalar],
        result: &E::G1,
    ) -> W::MsmG1Witness {
        let witness = Gen::generate_msm_g1(bases, scalars, result);
        self.collection.msm_g1.insert(id, witness.clone());
        witness
    }

    /// Collect a G2 MSM witness.
    pub(crate) fn collect_msm_g2(
        &mut self,
        id: OpId,
        bases: &[E::G2],
        scalars: &[<E::G1 as Group>::Scalar],
        result: &E::G2,
    ) -> W::MsmG2Witness {
        let witness = Gen::generate_msm_g2(bases, scalars, result);
        self.collection.msm_g2.insert(id, witness.clone());
        witness
    }
}

impl<W, E, Gen> Default for WitnessCollector<W, E, Gen>
where
    W: WitnessBackend,
    E: PairingCurve,
    Gen: WitnessGenerator<W, E>,
{
    fn default() -> Self {
        Self::new()
    }
}
