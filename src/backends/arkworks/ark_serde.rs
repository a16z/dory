//! Manual implementations of Dory serialization traits for arkworks wrapper types
use crate::backends::arkworks::{ArkFr, ArkG1, ArkG2, ArkGT};
use crate::primitives::serialization::{Compress, SerializationError, Valid, Validate};
use crate::primitives::{DoryDeserialize, DorySerialize};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid as ArkValid};
use std::io::{Read, Write};

// Manual implementations for ArkFr
impl Valid for ArkFr {
    fn check(&self) -> Result<(), SerializationError> {
        self.0
            .check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

impl DorySerialize for ArkFr {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .0
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .0
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.0.compressed_size(),
            Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl DoryDeserialize for ArkFr {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bn254::Fr::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => ark_bn254::Fr::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            inner
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(ArkFr(inner))
    }
}

// Manual implementations for ArkG1
impl Valid for ArkG1 {
    fn check(&self) -> Result<(), SerializationError> {
        self.0
            .check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

impl DorySerialize for ArkG1 {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .0
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .0
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.0.compressed_size(),
            Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl DoryDeserialize for ArkG1 {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bn254::G1Projective::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => ark_bn254::G1Projective::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            inner
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(ArkG1(inner))
    }
}

// Manual implementations for ArkG2
impl Valid for ArkG2 {
    fn check(&self) -> Result<(), SerializationError> {
        self.0
            .check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

impl DorySerialize for ArkG2 {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .0
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .0
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.0.compressed_size(),
            Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl DoryDeserialize for ArkG2 {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bn254::G2Projective::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => ark_bn254::G2Projective::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            inner
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(ArkG2(inner))
    }
}

// Manual implementations for ArkGT
impl Valid for ArkGT {
    fn check(&self) -> Result<(), SerializationError> {
        self.0
            .check()
            .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))
    }
}

impl DorySerialize for ArkGT {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match compress {
            Compress::Yes => self
                .0
                .serialize_compressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
            Compress::No => self
                .0
                .serialize_uncompressed(writer)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e))),
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match compress {
            Compress::Yes => self.0.compressed_size(),
            Compress::No => self.0.uncompressed_size(),
        }
    }
}

impl DoryDeserialize for ArkGT {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let inner = match compress {
            Compress::Yes => ark_bn254::Fq12::deserialize_compressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
            Compress::No => ark_bn254::Fq12::deserialize_uncompressed(reader)
                .map_err(|e| SerializationError::InvalidData(format!("{}", e)))?,
        };

        if matches!(validate, Validate::Yes) {
            inner
                .check()
                .map_err(|e| SerializationError::InvalidData(format!("{:?}", e)))?;
        }

        Ok(ArkGT(inner))
    }
}
