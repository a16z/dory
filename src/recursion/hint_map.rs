//! Lightweight hint storage for recursive verification.
//!
//! This module provides [`HintMap`], a simplified storage structure that holds
//! only operation results (not full witnesses with intermediate computation steps).
//! This results in ~30-50x smaller storage compared to full witness collections.

use std::collections::HashMap;
use std::io::{Read, Write};

use super::witness::{OpId, OpType};
use crate::primitives::arithmetic::PairingCurve;
use crate::primitives::serialization::{
    Compress, DoryDeserialize, DorySerialize, SerializationError, Valid, Validate,
};

/// Tag bytes for HintResult discriminant during serialization.
const TAG_G1: u8 = 0;
const TAG_G2: u8 = 1;
const TAG_GT: u8 = 2;

/// Result value storing only the computed output of an operation.
///
/// Unlike full witness types which store intermediate computation steps,
/// this stores only the final result, suitable for hint-based verification.
#[derive(Clone)]
pub enum HintResult<E: PairingCurve> {
    /// G1 point result (from G1ScalarMul, MsmG1)
    G1(E::G1),
    /// G2 point result (from G2ScalarMul, MsmG2)
    G2(E::G2),
    /// GT element result (from GtExp, GtMul, Pairing, MultiPairing)
    GT(E::GT),
}

impl<E: PairingCurve> HintResult<E> {
    /// Returns true if this is a G1 result.
    #[inline]
    pub fn is_g1(&self) -> bool {
        matches!(self, HintResult::G1(_))
    }

    /// Returns true if this is a G2 result.
    #[inline]
    pub fn is_g2(&self) -> bool {
        matches!(self, HintResult::G2(_))
    }

    /// Returns true if this is a GT result.
    #[inline]
    pub fn is_gt(&self) -> bool {
        matches!(self, HintResult::GT(_))
    }

    /// Try to get as G1, returns None if wrong variant.
    #[inline]
    pub fn as_g1(&self) -> Option<&E::G1> {
        match self {
            HintResult::G1(g1) => Some(g1),
            _ => None,
        }
    }

    /// Try to get as G2, returns None if wrong variant.
    #[inline]
    pub fn as_g2(&self) -> Option<&E::G2> {
        match self {
            HintResult::G2(g2) => Some(g2),
            _ => None,
        }
    }

    /// Try to get as GT, returns None if wrong variant.
    #[inline]
    pub fn as_gt(&self) -> Option<&E::GT> {
        match self {
            HintResult::GT(gt) => Some(gt),
            _ => None,
        }
    }
}

impl<E: PairingCurve> Valid for HintResult<E> {
    fn check(&self) -> Result<(), SerializationError> {
        // Curve points are validated during deserialization
        Ok(())
    }
}

impl<E: PairingCurve> DorySerialize for HintResult<E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            HintResult::G1(g1) => {
                TAG_G1.serialize_with_mode(&mut writer, compress)?;
                g1.serialize_with_mode(writer, compress)
            }
            HintResult::G2(g2) => {
                TAG_G2.serialize_with_mode(&mut writer, compress)?;
                g2.serialize_with_mode(writer, compress)
            }
            HintResult::GT(gt) => {
                TAG_GT.serialize_with_mode(&mut writer, compress)?;
                gt.serialize_with_mode(writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        1 + match self {
            HintResult::G1(g1) => g1.serialized_size(compress),
            HintResult::G2(g2) => g2.serialized_size(compress),
            HintResult::GT(gt) => gt.serialized_size(compress),
        }
    }
}

impl<E: PairingCurve> DoryDeserialize for HintResult<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            TAG_G1 => Ok(HintResult::G1(E::G1::deserialize_with_mode(
                reader, compress, validate,
            )?)),
            TAG_G2 => Ok(HintResult::G2(E::G2::deserialize_with_mode(
                reader, compress, validate,
            )?)),
            TAG_GT => Ok(HintResult::GT(E::GT::deserialize_with_mode(
                reader, compress, validate,
            )?)),
            _ => Err(SerializationError::InvalidData(format!(
                "Invalid HintResult tag: {tag}"
            ))),
        }
    }
}

/// Hint storage
///
/// Unlike [`WitnessCollection`](crate::recursion::WitnessCollection) which stores
/// full computation traces, this stores only the final results for each operation,
/// indexed by [`OpId`].
#[derive(Clone)]
pub struct HintMap<E: PairingCurve> {
    /// Number of reduce-and-fold rounds in the verification
    pub num_rounds: usize,
    /// All operation results indexed by OpId
    results: HashMap<OpId, HintResult<E>>,
}

impl<E: PairingCurve> HintMap<E> {
    /// Create a new empty hint map.
    pub fn new(num_rounds: usize) -> Self {
        Self {
            num_rounds,
            results: HashMap::new(),
        }
    }

    /// Get G1 result for an operation.
    ///
    /// Returns None if the operation is not found or is not a G1 result.
    #[inline]
    pub fn get_g1(&self, id: OpId) -> Option<&E::G1> {
        self.results.get(&id).and_then(|r| r.as_g1())
    }

    /// Get G2 result for an operation.
    ///
    /// Returns None if the operation is not found or is not a G2 result.
    #[inline]
    pub fn get_g2(&self, id: OpId) -> Option<&E::G2> {
        self.results.get(&id).and_then(|r| r.as_g2())
    }

    /// Get GT result for an operation.
    ///
    /// Returns None if the operation is not found or is not a GT result.
    #[inline]
    pub fn get_gt(&self, id: OpId) -> Option<&E::GT> {
        self.results.get(&id).and_then(|r| r.as_gt())
    }

    /// Get raw result enum for an operation.
    #[inline]
    pub fn get(&self, id: OpId) -> Option<&HintResult<E>> {
        self.results.get(&id)
    }

    /// Insert a G1 result.
    #[inline]
    pub fn insert_g1(&mut self, id: OpId, value: E::G1) {
        self.results.insert(id, HintResult::G1(value));
    }

    /// Insert a G2 result.
    #[inline]
    pub fn insert_g2(&mut self, id: OpId, value: E::G2) {
        self.results.insert(id, HintResult::G2(value));
    }

    /// Insert a GT result.
    #[inline]
    pub fn insert_gt(&mut self, id: OpId, value: E::GT) {
        self.results.insert(id, HintResult::GT(value));
    }

    /// Total number of hints stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Check if the hint map is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Iterate over all (OpId, HintResult) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&OpId, &HintResult<E>)> {
        self.results.iter()
    }

    /// Check if a hint exists for the given operation.
    #[inline]
    pub fn contains(&self, id: OpId) -> bool {
        self.results.contains_key(&id)
    }
}

impl<E: PairingCurve> Default for HintMap<E> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<E: PairingCurve> Valid for HintMap<E> {
    fn check(&self) -> Result<(), SerializationError> {
        for result in self.results.values() {
            result.check()?;
        }
        Ok(())
    }
}

impl<E: PairingCurve> DorySerialize for HintMap<E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        (self.num_rounds as u64).serialize_with_mode(&mut writer, compress)?;
        (self.results.len() as u64).serialize_with_mode(&mut writer, compress)?;

        for (id, result) in &self.results {
            // Serialize OpId as (round: u16, op_type: u8, index: u16)
            id.round.serialize_with_mode(&mut writer, compress)?;
            (id.op_type as u8).serialize_with_mode(&mut writer, compress)?;
            id.index.serialize_with_mode(&mut writer, compress)?;
            result.serialize_with_mode(&mut writer, compress)?;
        }
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let header = 8 + 8; // num_rounds + len
        let entries: usize = self
            .results
            .values()
            .map(|r| 2 + 1 + 2 + r.serialized_size(compress))
            .sum();
        header + entries
    }
}

impl<E: PairingCurve> DoryDeserialize for HintMap<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let num_rounds = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;
        let len = u64::deserialize_with_mode(&mut reader, compress, validate)? as usize;

        let mut results = HashMap::with_capacity(len);
        for _ in 0..len {
            let round = u16::deserialize_with_mode(&mut reader, compress, validate)?;
            let op_type_byte = u8::deserialize_with_mode(&mut reader, compress, validate)?;
            let index = u16::deserialize_with_mode(&mut reader, compress, validate)?;

            let op_type = match op_type_byte {
                0 => OpType::GtExp,
                1 => OpType::G1ScalarMul,
                2 => OpType::G2ScalarMul,
                3 => OpType::GtMul,
                4 => OpType::Pairing,
                5 => OpType::MultiPairing,
                6 => OpType::MsmG1,
                7 => OpType::MsmG2,
                _ => {
                    return Err(SerializationError::InvalidData(format!(
                        "Invalid OpType: {op_type_byte}"
                    )))
                }
            };

            let id = OpId::new(round, op_type, index);
            let result = HintResult::deserialize_with_mode(&mut reader, compress, validate)?;
            results.insert(id, result);
        }

        Ok(Self {
            num_rounds,
            results,
        })
    }
}
