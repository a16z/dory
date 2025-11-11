//! Manual implementations of Dory serialization traits for arkworks wrapper types
use crate::backends::arkworks::{ArkFr, ArkG1, ArkG2, ArkGT};
use crate::primitives::serialization::{Compress, SerializationError, Valid, Validate};
use crate::primitives::{DoryDeserialize, DorySerialize};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress as ArkCompress,
    SerializationError as ArkSerializationError, Valid as ArkValid, Validate as ArkValidate,
};
use std::io::{Read, Write};

use super::BN254;
use crate::messages::{FirstReduceMessage, ScalarProductMessage, SecondReduceMessage, VMVMessage};
use crate::setup::{ProverSetup, VerifierSetup};

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

// Arkworks-specific Dory proof type
use super::ArkDoryProof;

impl ArkValid for ArkDoryProof {
    fn check(&self) -> Result<(), ArkSerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for ArkDoryProof {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ArkCompress,
    ) -> Result<(), ArkSerializationError> {
        // Serialize VMV message
        CanonicalSerialize::serialize_with_mode(&self.vmv_message.c, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.vmv_message.d2, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.vmv_message.e1, &mut writer, compress)?;

        // Serialize number of rounds
        let num_rounds = self.first_messages.len() as u32;
        CanonicalSerialize::serialize_with_mode(&num_rounds, &mut writer, compress)?;

        // Serialize first messages
        for msg in &self.first_messages {
            CanonicalSerialize::serialize_with_mode(&msg.d1_left, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.d1_right, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.d2_left, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.d2_right, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.e1_beta, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.e2_beta, &mut writer, compress)?;
        }

        // Serialize second messages
        for msg in &self.second_messages {
            CanonicalSerialize::serialize_with_mode(&msg.c_plus, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.c_minus, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.e1_plus, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.e1_minus, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.e2_plus, &mut writer, compress)?;
            CanonicalSerialize::serialize_with_mode(&msg.e2_minus, &mut writer, compress)?;
        }

        // Serialize final message
        CanonicalSerialize::serialize_with_mode(&self.final_message.e1, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.final_message.e2, &mut writer, compress)?;

        // Serialize nu and sigma
        CanonicalSerialize::serialize_with_mode(&(self.nu as u32), &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&(self.sigma as u32), &mut writer, compress)?;

        Ok(())
    }

    fn serialized_size(&self, compress: ArkCompress) -> usize {
        let mut size = 0;

        // VMV message
        size += CanonicalSerialize::serialized_size(&self.vmv_message.c, compress);
        size += CanonicalSerialize::serialized_size(&self.vmv_message.d2, compress);
        size += CanonicalSerialize::serialized_size(&self.vmv_message.e1, compress);

        // Number of rounds
        size += 4; // u32

        // First messages
        for msg in &self.first_messages {
            size += CanonicalSerialize::serialized_size(&msg.d1_left, compress);
            size += CanonicalSerialize::serialized_size(&msg.d1_right, compress);
            size += CanonicalSerialize::serialized_size(&msg.d2_left, compress);
            size += CanonicalSerialize::serialized_size(&msg.d2_right, compress);
            size += CanonicalSerialize::serialized_size(&msg.e1_beta, compress);
            size += CanonicalSerialize::serialized_size(&msg.e2_beta, compress);
        }

        // Second messages
        for msg in &self.second_messages {
            size += CanonicalSerialize::serialized_size(&msg.c_plus, compress);
            size += CanonicalSerialize::serialized_size(&msg.c_minus, compress);
            size += CanonicalSerialize::serialized_size(&msg.e1_plus, compress);
            size += CanonicalSerialize::serialized_size(&msg.e1_minus, compress);
            size += CanonicalSerialize::serialized_size(&msg.e2_plus, compress);
            size += CanonicalSerialize::serialized_size(&msg.e2_minus, compress);
        }

        // Final message
        size += CanonicalSerialize::serialized_size(&self.final_message.e1, compress);
        size += CanonicalSerialize::serialized_size(&self.final_message.e2, compress);

        // nu and sigma
        size += 8; // 2 * u32

        size
    }
}

impl CanonicalDeserialize for ArkDoryProof {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ArkCompress,
        validate: ArkValidate,
    ) -> Result<Self, ArkSerializationError> {
        // Deserialize VMV message
        let c = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let d2 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let e1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let vmv_message = VMVMessage { c, d2, e1 };

        // Deserialize number of rounds
        let num_rounds =
            <u32 as CanonicalDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?
                as usize;

        // Deserialize first messages
        let mut first_messages = Vec::with_capacity(num_rounds);
        for _ in 0..num_rounds {
            let d1_left =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let d1_right =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let d2_left =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let d2_right =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let e1_beta =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let e2_beta =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            first_messages.push(FirstReduceMessage {
                d1_left,
                d1_right,
                d2_left,
                d2_right,
                e1_beta,
                e2_beta,
            });
        }

        // Deserialize second messages
        let mut second_messages = Vec::with_capacity(num_rounds);
        for _ in 0..num_rounds {
            let c_plus =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let c_minus =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let e1_plus =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let e1_minus =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let e2_plus =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            let e2_minus =
                CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
            second_messages.push(SecondReduceMessage {
                c_plus,
                c_minus,
                e1_plus,
                e1_minus,
                e2_plus,
                e2_minus,
            });
        }

        // Deserialize final message
        let e1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let e2 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let final_message = ScalarProductMessage { e1, e2 };

        // Deserialize nu and sigma
        let nu =
            <u32 as CanonicalDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?
                as usize;
        let sigma =
            <u32 as CanonicalDeserialize>::deserialize_with_mode(&mut reader, compress, validate)?
                as usize;

        Ok(ArkDoryProof {
            vmv_message,
            first_messages,
            second_messages,
            final_message,
            nu,
            sigma,
        })
    }
}

// Setup wrapper types (declared in ark_setup.rs, serialization impls here)
use super::{ArkworksProverSetup, ArkworksVerifierSetup};

impl ArkValid for ArkworksProverSetup {
    fn check(&self) -> Result<(), ArkSerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for ArkworksProverSetup {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ArkCompress,
    ) -> Result<(), ArkSerializationError> {
        let dory_compress = match compress {
            ArkCompress::Yes => Compress::Yes,
            ArkCompress::No => Compress::No,
        };

        DorySerialize::serialize_with_mode(&self.0, &mut writer, dory_compress)
            .map_err(|_| ArkSerializationError::InvalidData)
    }

    fn serialized_size(&self, compress: ArkCompress) -> usize {
        let dory_compress = match compress {
            ArkCompress::Yes => Compress::Yes,
            ArkCompress::No => Compress::No,
        };
        DorySerialize::serialized_size(&self.0, dory_compress)
    }
}

impl CanonicalDeserialize for ArkworksProverSetup {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ArkCompress,
        validate: ArkValidate,
    ) -> Result<Self, ArkSerializationError> {
        let dory_compress = match compress {
            ArkCompress::Yes => Compress::Yes,
            ArkCompress::No => Compress::No,
        };

        let dory_validate = match validate {
            ArkValidate::Yes => Validate::Yes,
            ArkValidate::No => Validate::No,
        };

        let setup =
            ProverSetup::<BN254>::deserialize_with_mode(&mut reader, dory_compress, dory_validate)
                .map_err(|_| ArkSerializationError::InvalidData)?;

        Ok(Self(setup))
    }
}

impl ArkValid for ArkworksVerifierSetup {
    fn check(&self) -> Result<(), ArkSerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for ArkworksVerifierSetup {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ArkCompress,
    ) -> Result<(), ArkSerializationError> {
        let dory_compress = match compress {
            ArkCompress::Yes => Compress::Yes,
            ArkCompress::No => Compress::No,
        };

        DorySerialize::serialize_with_mode(&self.0, &mut writer, dory_compress)
            .map_err(|_| ArkSerializationError::InvalidData)
    }

    fn serialized_size(&self, compress: ArkCompress) -> usize {
        let dory_compress = match compress {
            ArkCompress::Yes => Compress::Yes,
            ArkCompress::No => Compress::No,
        };
        DorySerialize::serialized_size(&self.0, dory_compress)
    }
}

impl CanonicalDeserialize for ArkworksVerifierSetup {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ArkCompress,
        validate: ArkValidate,
    ) -> Result<Self, ArkSerializationError> {
        let dory_compress = match compress {
            ArkCompress::Yes => Compress::Yes,
            ArkCompress::No => Compress::No,
        };

        let dory_validate = match validate {
            ArkValidate::Yes => Validate::Yes,
            ArkValidate::No => Validate::No,
        };

        let setup = VerifierSetup::<BN254>::deserialize_with_mode(
            &mut reader,
            dory_compress,
            dory_validate,
        )
        .map_err(|_| ArkSerializationError::InvalidData)?;

        Ok(Self(setup))
    }
}
