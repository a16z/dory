//! Bridge between arkworks CanonicalSerialize and Dory serialization traits
use crate::primitives::serialization::{Compress, SerializationError, Valid, Validate};
use crate::primitives::{DoryDeserialize, DorySerialize};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid as ArkValid};
use std::io::{Read, Write};

// Blanket implementation: any arkworks Valid type implements our Valid trait
impl<T: ArkValid> Valid for T {
    fn check(&self) -> Result<(), SerializationError> {
        self.check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

// Blanket implementation: any CanonicalSerialize type implements DorySerialize
impl<T: CanonicalSerialize> DorySerialize for T {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.compressed_size(),
            Compress::No => self.uncompressed_size(),
        }
    }
}

// Blanket implementation: any CanonicalDeserialize + Valid type implements DoryDeserialize
impl<T: CanonicalDeserialize + ArkValid> DoryDeserialize for T {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        let result = match compress {
            Compress::Yes => T::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => T::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            result
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(result)
    }
}
