//! Log core for CipherVault's witnessed transparency log (ADR-014, Phase 1).
//!
//! This crate holds the parts of the log that need no storage, network or
//! clock, so that the operator log, the witness and the CLI verifier all
//! share one implementation:
//!
//! * [`hash`]: the RFC 9162 §2.1.1 Merkle Tree Hash over SHA-256, with the
//!   `0x00`/`0x01` leaf/node prefixes and the largest-power-of-two split.
//!   An odd node is promoted, never duplicated.
//! * [`proof`]: RFC 9162 inclusion proofs (§2.1.3) and consistency proofs
//!   (§2.1.4), both generated and verified.
//! * [`compact`]: compact ranges, for O(log n) appends and the tree root
//!   without rebuilding the tree.
//! * [`note`]: C2SP signed notes with Ed25519 signatures, key IDs and
//!   verifier keys (`c2sp.org/signed-note@v1.1.0`).
//! * [`checkpoint`]: C2SP checkpoints (`c2sp.org/tlog-checkpoint@v1.1.0`)
//!   and opening a checkpoint signed by a pinned log key.
//! * [`cosignature`]: Ed25519 `cosignature/v1` witness cosignatures, with
//!   their signed timestamp (`c2sp.org/tlog-cosignature@v1.1.0`).
//! * [`tiles`]: tile and entry-bundle paths (`c2sp.org/tlog-tiles@v1.0.0`).
//! * [`entry`]: the CipherVault leaf entry,
//!   `0x01 || commitment (32 B) || monitor_tag (32 B)`.
//!
//! The spec versions above are the ones this crate was written and tested
//! against. All byte formats are canonical: every parser rejects input
//! that its encoder would not produce, so a parsed value re-encodes to the
//! same bytes.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod checkpoint;
pub mod compact;
pub mod cosignature;
mod encoding;
pub mod entry;
pub mod hash;
pub mod note;
pub mod proof;
pub mod tiles;

pub use checkpoint::{
    open_checkpoint, Checkpoint, CheckpointError, Cosignature, VerifiedCheckpoint,
};
pub use compact::{CompactRange, CompactRangeError, NodeId};
pub use cosignature::{
    cosignature_timestamp, CosignatureV1Signer, CosignatureV1Verifier, SIG_TYPE_COSIGNATURE_V1,
};
pub use entry::{EntryError, LogEntry};
pub use hash::{empty_root, leaf_hash, node_hash, root_from_leaf_hashes, Hash, HASH_SIZE};
pub use note::{
    key_id, Ed25519NoteSigner, Ed25519NoteVerifier, KeyError, Note, NoteError, NoteSignature,
    NoteSigner, NoteVerifier, VerifiedNote, VerifierKey, SIG_TYPE_ED25519,
};
pub use proof::{
    consistency_proof, inclusion_proof, root_from_inclusion_proof, verify_consistency,
    verify_inclusion, ProofError,
};
pub use tiles::{Tile, TileError, TileKind};
