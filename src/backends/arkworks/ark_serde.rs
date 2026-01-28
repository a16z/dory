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
#[cfg(feature = "zk")]
use crate::messages::{ScalarProductProof, Sigma1Proof, Sigma2Proof};
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

        #[cfg(feature = "zk")]
        {
            let is_zk = self.e2.is_some()
                || self.y_com.is_some()
                || self.sigma1_proof.is_some()
                || self.sigma2_proof.is_some()
                || self.scalar_product_proof.is_some();
            CanonicalSerialize::serialize_with_mode(&(is_zk as u8), &mut writer, compress)?;
            if is_zk {
                CanonicalSerialize::serialize_with_mode(
                    self.e2.as_ref().expect("zk proof missing e2"),
                    &mut writer,
                    compress,
                )?;
                CanonicalSerialize::serialize_with_mode(
                    self.y_com.as_ref().expect("zk proof missing y_com"),
                    &mut writer,
                    compress,
                )?;
                CanonicalSerialize::serialize_with_mode(
                    self.y_blinding
                        .as_ref()
                        .expect("zk proof missing y blinding"),
                    &mut writer,
                    compress,
                )?;
                CanonicalSerialize::serialize_with_mode(
                    self.sigma1_proof.as_ref().expect("zk proof missing sigma1"),
                    &mut writer,
                    compress,
                )?;
                CanonicalSerialize::serialize_with_mode(
                    self.sigma2_proof.as_ref().expect("zk proof missing sigma2"),
                    &mut writer,
                    compress,
                )?;
                CanonicalSerialize::serialize_with_mode(
                    self.scalar_product_proof
                        .as_ref()
                        .expect("zk proof missing scalar product proof"),
                    &mut writer,
                    compress,
                )?;
            }
        }

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

        #[cfg(feature = "zk")]
        {
            size += 1; // is_zk flag
            if self.e2.is_some()
                || self.y_com.is_some()
                || self.y_blinding.is_some()
                || self.sigma1_proof.is_some()
                || self.sigma2_proof.is_some()
                || self.scalar_product_proof.is_some()
            {
                size += CanonicalSerialize::serialized_size(
                    self.e2.as_ref().expect("zk proof missing e2"),
                    compress,
                );
                size += CanonicalSerialize::serialized_size(
                    self.y_com.as_ref().expect("zk proof missing y_com"),
                    compress,
                );
                size += CanonicalSerialize::serialized_size(
                    self.y_blinding
                        .as_ref()
                        .expect("zk proof missing y blinding"),
                    compress,
                );
                size += CanonicalSerialize::serialized_size(
                    self.sigma1_proof.as_ref().expect("zk proof missing sigma1"),
                    compress,
                );
                size += CanonicalSerialize::serialized_size(
                    self.sigma2_proof.as_ref().expect("zk proof missing sigma2"),
                    compress,
                );
                size += CanonicalSerialize::serialized_size(
                    self.scalar_product_proof
                        .as_ref()
                        .expect("zk proof missing scalar product proof"),
                    compress,
                );
            }
        }

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

        #[cfg(feature = "zk")]
        let (e2, y_com, y_blinding, sigma1_proof, sigma2_proof, scalar_product_proof) = {
            let is_zk = <u8 as CanonicalDeserialize>::deserialize_with_mode(
                &mut reader,
                compress,
                validate,
            )? != 0;
            if is_zk {
                let e2 =
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
                let y_com =
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
                let y_blinding =
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
                let sigma1_proof =
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
                let sigma2_proof =
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
                let scalar_product_proof =
                    CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
                (
                    Some(e2),
                    Some(y_com),
                    Some(y_blinding),
                    Some(sigma1_proof),
                    Some(sigma2_proof),
                    Some(scalar_product_proof),
                )
            } else {
                (None, None, None, None, None, None)
            }
        };

        Ok(ArkDoryProof {
            vmv_message,
            first_messages,
            second_messages,
            final_message,
            nu,
            sigma,
            #[cfg(feature = "zk")]
            e2,
            #[cfg(feature = "zk")]
            y_com,
            #[cfg(feature = "zk")]
            y_blinding,
            #[cfg(feature = "zk")]
            sigma1_proof,
            #[cfg(feature = "zk")]
            sigma2_proof,
            #[cfg(feature = "zk")]
            scalar_product_proof,
        })
    }
}

#[cfg(feature = "zk")]
impl CanonicalSerialize for Sigma1Proof<ArkG1, ArkG2, ArkFr> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ArkCompress,
    ) -> Result<(), ArkSerializationError> {
        CanonicalSerialize::serialize_with_mode(&self.a1, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.a2, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.z1, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.z2, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.z3, &mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ArkCompress) -> usize {
        CanonicalSerialize::serialized_size(&self.a1, compress)
            + CanonicalSerialize::serialized_size(&self.a2, compress)
            + CanonicalSerialize::serialized_size(&self.z1, compress)
            + CanonicalSerialize::serialized_size(&self.z2, compress)
            + CanonicalSerialize::serialized_size(&self.z3, compress)
    }
}

#[cfg(feature = "zk")]
impl ArkValid for Sigma1Proof<ArkG1, ArkG2, ArkFr> {
    fn check(&self) -> Result<(), ArkSerializationError> {
        Ok(())
    }
}

#[cfg(feature = "zk")]
impl CanonicalDeserialize for Sigma1Proof<ArkG1, ArkG2, ArkFr> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ArkCompress,
        validate: ArkValidate,
    ) -> Result<Self, ArkSerializationError> {
        let a1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let a2 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let z1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let z2 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let z3 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Sigma1Proof { a1, a2, z1, z2, z3 })
    }
}

#[cfg(feature = "zk")]
impl CanonicalSerialize for Sigma2Proof<ArkFr, ArkGT> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ArkCompress,
    ) -> Result<(), ArkSerializationError> {
        CanonicalSerialize::serialize_with_mode(&self.a, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.z1, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.z2, &mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ArkCompress) -> usize {
        CanonicalSerialize::serialized_size(&self.a, compress)
            + CanonicalSerialize::serialized_size(&self.z1, compress)
            + CanonicalSerialize::serialized_size(&self.z2, compress)
    }
}

#[cfg(feature = "zk")]
impl ArkValid for Sigma2Proof<ArkFr, ArkGT> {
    fn check(&self) -> Result<(), ArkSerializationError> {
        Ok(())
    }
}

#[cfg(feature = "zk")]
impl CanonicalDeserialize for Sigma2Proof<ArkFr, ArkGT> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ArkCompress,
        validate: ArkValidate,
    ) -> Result<Self, ArkSerializationError> {
        let a = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let z1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let z2 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Sigma2Proof { a, z1, z2 })
    }
}

#[cfg(feature = "zk")]
impl CanonicalSerialize for ScalarProductProof<ArkG1, ArkG2, ArkFr, ArkGT> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: ArkCompress,
    ) -> Result<(), ArkSerializationError> {
        CanonicalSerialize::serialize_with_mode(&self.p1, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.p2, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.q, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.r, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.e1, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.e2, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.r1, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.r2, &mut writer, compress)?;
        CanonicalSerialize::serialize_with_mode(&self.r3, &mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ArkCompress) -> usize {
        CanonicalSerialize::serialized_size(&self.p1, compress)
            + CanonicalSerialize::serialized_size(&self.p2, compress)
            + CanonicalSerialize::serialized_size(&self.q, compress)
            + CanonicalSerialize::serialized_size(&self.r, compress)
            + CanonicalSerialize::serialized_size(&self.e1, compress)
            + CanonicalSerialize::serialized_size(&self.e2, compress)
            + CanonicalSerialize::serialized_size(&self.r1, compress)
            + CanonicalSerialize::serialized_size(&self.r2, compress)
            + CanonicalSerialize::serialized_size(&self.r3, compress)
    }
}

#[cfg(feature = "zk")]
impl ArkValid for ScalarProductProof<ArkG1, ArkG2, ArkFr, ArkGT> {
    fn check(&self) -> Result<(), ArkSerializationError> {
        Ok(())
    }
}

#[cfg(feature = "zk")]
impl CanonicalDeserialize for ScalarProductProof<ArkG1, ArkG2, ArkFr, ArkGT> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: ArkCompress,
        validate: ArkValidate,
    ) -> Result<Self, ArkSerializationError> {
        let p1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let p2 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let q = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let r = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let e1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let e2 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let r1 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let r2 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let r3 = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(ScalarProductProof {
            p1,
            p2,
            q,
            r,
            e1,
            e2,
            r1,
            r2,
            r3,
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
