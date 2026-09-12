//! # CipherVault Canonical Formats and Validation
//!
//! Provides deterministic canonical CBOR serialization and deserialization,
//! object schemas (Genesis, DeviceCert, EpochEnvelope, Chunk, Manifest, SnapshotRecord, Head),
//! and cryptographic bindings.

pub mod canonical;
pub mod error;
pub mod schema;

pub use canonical::{compute_digest, from_canonical_cbor, to_canonical_cbor, MAX_RECORD_SIZE};
pub use error::FormatError;
pub use schema::{
    CheckpointEvidence, ChunkWireObject, DeviceCertificate, EpochEnvelope, GenesisRecord,
    HeadRecord, ManifestFileEntry, PlacementUpdate, RecoveryClosure, RecoverySet, SnapshotManifest,
    SnapshotRecord, PROTOCOL_VERSION,
};
