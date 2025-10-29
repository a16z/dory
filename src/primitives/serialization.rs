use std::io::{Read, Write};

// Re-export derive macros
pub use dory_derive::{DoryDeserialize, DorySerialize, Valid};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compress {
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validate {
    Yes,
    No,
}

#[derive(Debug, thiserror::Error)]
pub enum SerializationError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Not in canonical form")]
    NotCanonical,

    #[error("Unexpected data")]
    UnexpectedData,
}

/// Trait for validating deserialized data.
/// This is checked after deserialization when `Validate::Yes` is used.
pub trait Valid {
    /// Check that the current value is valid (e.g., in the correct subgroup).
    fn check(&self) -> Result<(), SerializationError>;

    /// Batch check for efficiency when validating multiple elements.
    fn batch_check<'a>(batch: impl Iterator<Item = &'a Self>) -> Result<(), SerializationError>
    where
        Self: 'a,
    {
        for item in batch {
            item.check()?;
        }
        Ok(())
    }
}

/// Serializer in little endian format.
pub trait DorySerialize {
    /// Serialize with customization flags.
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError>;

    /// Returns the serialized size in bytes for the given compression mode.
    fn serialized_size(&self, compress: Compress) -> usize;

    /// Serialize in compressed form.
    fn serialize_compressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.serialize_with_mode(writer, Compress::Yes)
    }

    /// Returns the compressed size in bytes.
    fn compressed_size(&self) -> usize {
        self.serialized_size(Compress::Yes)
    }

    /// Serialize in uncompressed form.
    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.serialize_with_mode(writer, Compress::No)
    }

    /// Returns the uncompressed size in bytes.
    fn uncompressed_size(&self) -> usize {
        self.serialized_size(Compress::No)
    }
}

/// Deserializer in little endian format.
pub trait DoryDeserialize: Valid {
    /// Deserialize with customization flags.
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError>
    where
        Self: Sized;

    /// Deserialize from compressed form with validation.
    fn deserialize_compressed<R: Read>(reader: R) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        Self::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
    }

    /// Deserialize from compressed form without validation.
    ///
    /// # Safety
    /// This skips validation checks. Use only when you trust the input source.
    fn deserialize_compressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        Self::deserialize_with_mode(reader, Compress::Yes, Validate::No)
    }

    /// Deserialize from uncompressed form with validation.
    fn deserialize_uncompressed<R: Read>(reader: R) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        Self::deserialize_with_mode(reader, Compress::No, Validate::Yes)
    }

    /// Deserialize from uncompressed form without validation.
    ///
    /// # Safety
    /// This skips validation checks. Use only when you trust the input source.
    fn deserialize_uncompressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        Self::deserialize_with_mode(reader, Compress::No, Validate::No)
    }
}
