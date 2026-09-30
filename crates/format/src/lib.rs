//! # CipherVault Canonical Formats and Validation
//!
//! Provides deterministic canonical CBOR serialization and deserialization,
//! object schemas (Genesis, DeviceCert, EpochEnvelope, Chunk, Manifest, SnapshotRecord, Head),
//! cryptographic bindings, and scoped-secret domain types (identifiers, scopes, records).

pub mod canonical;
pub mod error;
pub mod schema;
pub mod scope;
pub mod secret_value;

pub use canonical::{compute_digest, from_canonical_cbor, to_canonical_cbor, MAX_RECORD_SIZE};
pub use error::FormatError;
pub use schema::{
    CheckpointEvidence, ChunkWireObject, DeviceCertificate, EpochEnvelope, GenesisRecord,
    HeadRecord, ManifestFileEntry, PlacementUpdate, RecoveryClosure, RecoverySet, SnapshotManifest,
    SnapshotRecord, CHUNK_WIRE_VERSION_V2, PROTOCOL_VERSION,
};
pub use scope::{
    validate_description, validate_external_repo_id, validate_secret_name, validate_slug,
    validate_tag, BindingStatus, EnvironmentId, EnvironmentRecord, KeyId, MigrationEntryId,
    MigrationId, PolicyId, ProjectId, ProjectRecord, ProjectStatus, RepositoryBindingId,
    RepositoryBindingRecord, RepositoryProvider, Scope, SecretId, SecretMetadata, SecretStatus,
    SecretVersionId, SecretVersionRecord, ServiceId, ServiceRecord, TenantId, WorkspaceId,
    MAX_DESCRIPTION_LEN, MAX_EXTERNAL_ID_LEN, MAX_SECRET_NAME_LEN, MAX_SLUG_LEN, MAX_TAGS,
    MAX_TAG_LEN,
};
pub use secret_value::SecretValue;
