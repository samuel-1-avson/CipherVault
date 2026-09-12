use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::FormatError;

pub const MAX_RECORD_SIZE: usize = 16 * 1024 * 1024; // 16 MiB maximum decoded manifest/record

/// Serializes any serializable data structure to canonical CBOR.
pub fn to_canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, FormatError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| FormatError::SerializationError(e.to_string()))?;

    if buf.len() > MAX_RECORD_SIZE {
        return Err(FormatError::SizeLimitExceeded {
            limit: MAX_RECORD_SIZE,
            actual: buf.len(),
        });
    }

    Ok(buf)
}

/// Deserializes a canonical CBOR byte slice into a typed record with size limits.
pub fn from_canonical_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, FormatError> {
    if bytes.len() > MAX_RECORD_SIZE {
        return Err(FormatError::SizeLimitExceeded {
            limit: MAX_RECORD_SIZE,
            actual: bytes.len(),
        });
    }

    ciborium::from_reader(bytes).map_err(|e| FormatError::DeserializationError(e.to_string()))
}

/// Computes SHA-256 digest of wire bytes.
pub fn compute_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct DummyRecord {
        id: u64,
        tag: String,
    }

    #[test]
    fn test_cbor_roundtrip() {
        let record = DummyRecord {
            id: 42,
            tag: "vault_genesis".to_string(),
        };

        let bytes = to_canonical_cbor(&record).unwrap();
        let decoded: DummyRecord = from_canonical_cbor(&bytes).unwrap();
        assert_eq!(record, decoded);
    }
}
