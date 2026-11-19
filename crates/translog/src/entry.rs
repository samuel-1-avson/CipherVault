//! The CipherVault log entry (ADR-014, *Entries*).
//!
//! A leaf is `0x01 || commitment (32 B) || monitor_tag (32 B)`:
//!
//! * `commitment` is the anchor commitment
//!   `SHA-256("CIPHERVAULT-ANCHOR-V1" || salt || head_cid)`. Its preimage
//!   never leaves the vault.
//! * `monitor_tag` stays all zeros until vault monitor tags ship
//!   (ADR-014 Phase 5). It is reserved now so that adding it later is not
//!   a format change.
//!
//! The entry carries no device key and no signature, so entries from one
//! vault cannot be linked to each other.

use crate::hash::{leaf_hash, Hash};

/// Version byte of the v1 entry format.
pub const ENTRY_V1: u8 = 0x01;

/// Length in bytes of an encoded v1 entry.
pub const ENTRY_V1_LEN: usize = 1 + 32 + 32;

/// Why bytes are not a valid entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EntryError {
    /// The entry is empty or starts with a version byte this crate does
    /// not know.
    #[error("unknown entry version {0:?}")]
    UnknownVersion(Option<u8>),
    /// A v1 entry of the wrong length.
    #[error("a v1 entry is {ENTRY_V1_LEN} bytes, got {0}")]
    WrongLength(usize),
}

/// One log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogEntry {
    /// The anchor commitment.
    pub commitment: [u8; 32],
    /// The vault monitor tag; all zeros until Phase 5.
    pub monitor_tag: [u8; 32],
}

impl LogEntry {
    /// An entry with an explicit monitor tag.
    pub const fn new(commitment: [u8; 32], monitor_tag: [u8; 32]) -> Self {
        Self {
            commitment,
            monitor_tag,
        }
    }

    /// An entry whose monitor tag is the reserved all-zero value.
    pub const fn untagged(commitment: [u8; 32]) -> Self {
        Self::new(commitment, [0; 32])
    }

    /// The encoded entry, as stored in entry bundles and hashed as a leaf.
    pub fn to_bytes(&self) -> [u8; ENTRY_V1_LEN] {
        let mut out = [0u8; ENTRY_V1_LEN];
        out[0] = ENTRY_V1;
        out[1..33].copy_from_slice(&self.commitment);
        out[33..].copy_from_slice(&self.monitor_tag);
        out
    }

    /// Decodes an entry. Only the exact v1 encoding is accepted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EntryError> {
        match bytes.first() {
            Some(&ENTRY_V1) => {}
            other => return Err(EntryError::UnknownVersion(other.copied())),
        }
        let bytes: &[u8; ENTRY_V1_LEN] = bytes
            .try_into()
            .map_err(|_| EntryError::WrongLength(bytes.len()))?;
        let mut commitment = [0u8; 32];
        let mut monitor_tag = [0u8; 32];
        commitment.copy_from_slice(&bytes[1..33]);
        monitor_tag.copy_from_slice(&bytes[33..]);
        Ok(Self {
            commitment,
            monitor_tag,
        })
    }

    /// The RFC 9162 leaf hash of the encoded entry.
    pub fn leaf_hash(&self) -> Hash {
        leaf_hash(&self.to_bytes())
    }
}
