use std::collections::BTreeMap;
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

    /// Extract a G1 result, returning None if this is not a G1 variant.
    #[inline]
    pub fn as_g1(&self) -> Option<&E::G1> {
        if let HintResult::G1(g1) = self {
            Some(g1)
        } else {
            None
        }
    }

    /// Extract a G2 result, returning None if this is not a G2 variant.
    #[inline]
    pub fn as_g2(&self) -> Option<&E::G2> {
        if let HintResult::G2(g2) = self {
            Some(g2)
        } else {
            None
        }
    }

    /// Extract a GT result, returning None if this is not a GT variant.
    #[inline]
    pub fn as_gt(&self) -> Option<&E::GT> {
        if let HintResult::GT(gt) = self {
            Some(gt)
        } else {
            None
        }
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
                DorySerialize::serialize_with_mode(&TAG_G1, &mut writer, compress)?;
                DorySerialize::serialize_with_mode(g1, &mut writer, compress)?;
            }
            HintResult::G2(g2) => {
                DorySerialize::serialize_with_mode(&TAG_G2, &mut writer, compress)?;
                DorySerialize::serialize_with_mode(g2, &mut writer, compress)?;
            }
            HintResult::GT(gt) => {
                DorySerialize::serialize_with_mode(&TAG_GT, &mut writer, compress)?;
                DorySerialize::serialize_with_mode(gt, &mut writer, compress)?;
            }
        }
        Ok(())
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
        let tag = <u8 as DoryDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            TAG_G1 => {
                let g1 = E::G1::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(HintResult::G1(g1))
            }
            TAG_G2 => {
                let g2 = E::G2::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(HintResult::G2(g2))
            }
            TAG_GT => {
                let gt = E::GT::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(HintResult::GT(gt))
            }
            _ => Err(SerializationError::InvalidData(
                "Invalid HintResult tag".to_string(),
            )),
        }
    }
}

impl<E: PairingCurve> Valid for HintResult<E> {
    fn check(&self) -> Result<(), SerializationError> {
        // Curve elements are already validated upon creation
        Ok(())
    }
}

/// A lightweight hint storage for recursive verification.
///
/// Unlike [`WitnessCollection`](crate::recursion::WitnessCollection) which stores
/// full computation traces, this stores only the final results for each operation,
/// indexed by [`OpId`].
#[derive(Clone)]
pub struct HintMap<E: PairingCurve> {
    /// Number of reduce-and-fold rounds in the verification
    pub num_rounds: usize,
    /// All operation results indexed by OpId
    results: BTreeMap<OpId, HintResult<E>>,
}

impl<E: PairingCurve> HintMap<E> {
    /// Create a new empty hint map.
    pub fn new(num_rounds: usize) -> Self {
        Self {
            num_rounds,
            results: BTreeMap::new(),
        }
    }

    /// Get G1 result for an operation.
    pub fn get_g1(&self, op_id: &OpId) -> Option<&E::G1> {
        self.results.get(op_id)?.as_g1()
    }

    /// Get G2 result for an operation.
    pub fn get_g2(&self, op_id: &OpId) -> Option<&E::G2> {
        self.results.get(op_id)?.as_g2()
    }

    /// Get GT result for an operation.
    pub fn get_gt(&self, op_id: &OpId) -> Option<&E::GT> {
        self.results.get(op_id)?.as_gt()
    }

    /// Get any result for an operation.
    pub fn get(&self, op_id: &OpId) -> Option<&HintResult<E>> {
        self.results.get(op_id)
    }

    /// Insert a result for an operation.
    pub fn insert(&mut self, op_id: OpId, result: HintResult<E>) -> Option<HintResult<E>> {
        self.results.insert(op_id, result)
    }

    /// Insert a G1 result for an operation.
    pub fn insert_g1(&mut self, op_id: OpId, result: E::G1) -> Option<HintResult<E>> {
        self.results.insert(op_id, HintResult::G1(result))
    }

    /// Insert a G2 result for an operation.
    pub fn insert_g2(&mut self, op_id: OpId, result: E::G2) -> Option<HintResult<E>> {
        self.results.insert(op_id, HintResult::G2(result))
    }

    /// Insert a GT result for an operation.
    pub fn insert_gt(&mut self, op_id: OpId, result: E::GT) -> Option<HintResult<E>> {
        self.results.insert(op_id, HintResult::GT(result))
    }

    /// Number of operations stored.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Iterator over all operations and results.
    pub fn iter(&self) -> impl Iterator<Item = (&OpId, &HintResult<E>)> {
        self.results.iter()
    }

    /// Count operations by type.
    pub fn count_by_type(&self) -> (usize, usize, usize) {
        let mut g1_count = 0;
        let mut g2_count = 0;
        let mut gt_count = 0;

        for result in self.results.values() {
            match result {
                HintResult::G1(_) => g1_count += 1,
                HintResult::G2(_) => g2_count += 1,
                HintResult::GT(_) => gt_count += 1,
            }
        }

        (g1_count, g2_count, gt_count)
    }

    /// Count operations by round and type.
    pub fn stats(&self) -> Vec<(u16, OpType, usize)> {
        use std::collections::HashMap;

        let mut stats: HashMap<(u16, OpType), usize> = HashMap::new();

        for op_id in self.results.keys() {
            *stats.entry((op_id.round, op_id.op_type)).or_insert(0) += 1;
        }

        let mut result: Vec<_> = stats
            .into_iter()
            .map(|((round, op_type), count)| (round, op_type, count))
            .collect();
        result.sort();
        result
    }
}

impl<E: PairingCurve> DorySerialize for HintMap<E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        DorySerialize::serialize_with_mode(&(self.num_rounds as u64), &mut writer, compress)?;
        DorySerialize::serialize_with_mode(&(self.results.len() as u64), &mut writer, compress)?;

        for (id, result) in &self.results {
            // Serialize OpId as (round: u16, op_type: u8, index: u16)
            DorySerialize::serialize_with_mode(&id.round, &mut writer, compress)?;
            DorySerialize::serialize_with_mode(&(id.op_type as u8), &mut writer, compress)?;
            DorySerialize::serialize_with_mode(&id.index, &mut writer, compress)?;

            // Serialize the result
            DorySerialize::serialize_with_mode(result, &mut writer, compress)?;
        }

        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut size = 8 + 8; // num_rounds + len

        for result in self.results.values() {
            size += 2 + 1 + 2; // OpId: round + op_type + index
            size += result.serialized_size(compress);
        }

        size
    }
}

impl<E: PairingCurve> DoryDeserialize for HintMap<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let num_rounds =
            <u64 as DoryDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?
                as usize;
        let len = <u64 as DoryDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?
            as usize;

        let mut results = BTreeMap::new();
        for _ in 0..len {
            let round =
                <u16 as DoryDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?;
            let op_type_byte =
                <u8 as DoryDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?;
            let index =
                <u16 as DoryDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?;

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
                    return Err(SerializationError::InvalidData(
                        "Invalid OpType byte".to_string(),
                    ))
                }
            };

            let op_id = OpId {
                round,
                op_type,
                index,
            };

            let result = HintResult::deserialize_with_mode(&mut reader, compress, validate)?;
            results.insert(op_id, result);
        }

        Ok(Self {
            num_rounds,
            results,
        })
    }
}

// Implement ark-serialize traits by delegating to DorySerialize/DoryDeserialize
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress as ArkCompress, Read as ArkRead,
    SerializationError as ArkSerializationError, Valid as ArkValid, Validate as ArkValidate,
    Write as ArkWrite,
};

// NOTE: These implementations preserve the original error information from Dory's
// serialization for better debugging. The error messages include the underlying
// cause to help diagnose serialization/deserialization failures.
impl<E: PairingCurve> CanonicalSerialize for HintMap<E> {
    fn serialize_with_mode<W: ArkWrite>(
        &self,
        writer: W,
        compress: ArkCompress,
    ) -> Result<(), ArkSerializationError> {
        let compress = if matches!(compress, ArkCompress::Yes) {
            Compress::Yes
        } else {
            Compress::No
        };
        DorySerialize::serialize_with_mode(self, writer, compress).map_err(|e| {
            ArkSerializationError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HintMap serialization failed: {:?}", e),
            ))
        })
    }

    fn serialized_size(&self, compress: ArkCompress) -> usize {
        let compress = if matches!(compress, ArkCompress::Yes) {
            Compress::Yes
        } else {
            Compress::No
        };
        DorySerialize::serialized_size(self, compress)
    }
}

impl<E: PairingCurve> CanonicalDeserialize for HintMap<E> {
    fn deserialize_with_mode<R: ArkRead>(
        reader: R,
        compress: ArkCompress,
        validate: ArkValidate,
    ) -> Result<Self, ArkSerializationError> {
        let compress = if matches!(compress, ArkCompress::Yes) {
            Compress::Yes
        } else {
            Compress::No
        };
        let validate = if matches!(validate, ArkValidate::Yes) {
            Validate::Yes
        } else {
            Validate::No
        };
        DoryDeserialize::deserialize_with_mode(reader, compress, validate).map_err(|e| {
            ArkSerializationError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HintMap deserialization failed: {:?}", e),
            ))
        })
    }
}

impl<E: PairingCurve> ArkValid for HintMap<E> {
    fn check(&self) -> Result<(), ArkSerializationError> {
        Ok(())
    }
}
