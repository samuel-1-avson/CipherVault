//! C2SP checkpoints (`c2sp.org/tlog-checkpoint@v1.1.0`).
//!
//! A checkpoint is a signed note whose text is
//!
//! ```text
//! <origin>
//! <tree size>
//! <base64 root hash>
//! [<extension line>...]
//! ```
//!
//! with every line non-empty and ending in a newline. The log signs it with
//! a plain Ed25519 note signature (type `0x01`); witnesses add Ed25519
//! `cosignature/v1` (type `0x04`) or ML-DSA-44 (type `0x06`) cosignatures.

use crate::cosignature::{cosignature_timestamp, WitnessVerifier};
use crate::encoding::{
    b64_decode, b64_encode, is_forbidden_control, is_valid_cosigner_name, parse_decimal_u64,
};
use crate::hash::Hash;
use crate::note::{Ed25519NoteSigner, Ed25519NoteVerifier, Note, NoteError, NoteVerifier};

/// Why a checkpoint could not be built, parsed or opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    /// The text does not follow the checkpoint syntax.
    #[error("malformed checkpoint: {0}")]
    Malformed(&'static str),
    /// The origin is not a valid log origin.
    #[error("invalid log origin")]
    InvalidOrigin,
    /// An extension line is empty or contains a control character.
    #[error("invalid extension line")]
    InvalidExtension,
    /// The checkpoint names a different log.
    #[error("checkpoint origin is {got:?}, expected {expected:?}")]
    WrongOrigin {
        /// The origin the caller pinned.
        expected: String,
        /// The origin in the checkpoint.
        got: String,
    },
    /// Two signature lines share a key name and key ID, which checkpoints
    /// must not have.
    #[error("two signatures from key {name}+{key_id:08x}")]
    DuplicateSignature {
        /// The repeated key name.
        name: String,
        /// The repeated key ID.
        key_id: u32,
    },
    /// The log's own key did not sign the checkpoint.
    #[error("checkpoint is not signed by the log key")]
    MissingLogSignature,
    /// The note layer rejected the checkpoint.
    #[error(transparent)]
    Note(#[from] NoteError),
}

/// The body of a checkpoint: a log's tree head at one size.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    origin: String,
    size: u64,
    root: Hash,
    extensions: Vec<String>,
}

impl Checkpoint {
    /// A checkpoint without extension lines.
    pub fn new(origin: impl Into<String>, size: u64, root: Hash) -> Result<Self, CheckpointError> {
        let origin = origin.into();
        if !is_valid_cosigner_name(&origin) {
            return Err(CheckpointError::InvalidOrigin);
        }
        Ok(Self {
            origin,
            size,
            root,
            extensions: Vec::new(),
        })
    }

    /// Replaces the extension lines. Each must be non-empty, without a
    /// newline or other control character. The spec does not recommend
    /// extension lines.
    pub fn with_extensions(mut self, extensions: Vec<String>) -> Result<Self, CheckpointError> {
        if extensions.iter().any(|line| {
            line.is_empty() || line.contains('\n') || line.chars().any(is_forbidden_control)
        }) {
            return Err(CheckpointError::InvalidExtension);
        }
        self.extensions = extensions;
        Ok(self)
    }

    /// The log origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The tree size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The root hash of the tree at [`Checkpoint::size`].
    pub fn root(&self) -> &Hash {
        &self.root
    }

    /// The extension lines.
    pub fn extensions(&self) -> &[String] {
        &self.extensions
    }

    /// The note text of the checkpoint.
    pub fn to_text(&self) -> String {
        let mut text = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            b64_encode(&self.root)
        );
        for line in &self.extensions {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    /// Parses checkpoint note text. Only the canonical encoding is
    /// accepted, so the result re-encodes to the same text.
    pub fn parse_text(text: &str) -> Result<Self, CheckpointError> {
        let body = text
            .strip_suffix('\n')
            .ok_or(CheckpointError::Malformed("text must end in a newline"))?;
        let mut lines = body.split('\n');
        let (Some(origin), Some(size), Some(root)) = (lines.next(), lines.next(), lines.next())
        else {
            return Err(CheckpointError::Malformed(
                "a checkpoint has at least three lines",
            ));
        };
        if !is_valid_cosigner_name(origin) {
            return Err(CheckpointError::InvalidOrigin);
        }
        let size = parse_decimal_u64(size).ok_or(CheckpointError::Malformed(
            "tree size must be a canonical decimal",
        ))?;
        let root: Hash = b64_decode(root)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(CheckpointError::Malformed(
                "root hash must be 32 bytes of canonical base64",
            ))?;
        let extensions: Vec<String> = lines.map(str::to_owned).collect();
        Self::new(origin, size, root)?.with_extensions(extensions)
    }

    /// Signs the checkpoint as `log` and returns the signed note, to which
    /// witness cosignatures can be added.
    pub fn sign(&self, log: &Ed25519NoteSigner) -> Result<Note, CheckpointError> {
        let mut note = Note::new(self.to_text())?;
        note.sign(log)?;
        Ok(note)
    }
}

/// A verified witness cosignature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cosignature {
    name: String,
    key_id: u32,
    timestamp: u64,
}

impl Cosignature {
    /// The witness name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The witness key ID.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// When the witness cosigned, in POSIX seconds.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// A checkpoint whose log signature, and every cosignature from a known
/// witness, verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    checkpoint: Checkpoint,
    cosignatures: Vec<Cosignature>,
}

impl VerifiedCheckpoint {
    /// The verified checkpoint.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// The verified cosignatures from known witnesses, in note order.
    /// Whether they meet a quorum is the caller's policy decision.
    pub fn cosignatures(&self) -> &[Cosignature] {
        &self.cosignatures
    }
}

/// Opens a signed checkpoint from the log `origin` whose key is `log_key`.
///
/// Fails unless the note parses, no two signature lines share a key name
/// and key ID, the log's signature verifies, the text is a valid checkpoint
/// for `origin`, and every cosignature from a key in `witnesses` verifies.
/// Signatures from other keys are ignored. An ML-DSA-44 cosignature on a
/// checkpoint with extension lines does not verify, because it would not
/// cover them.
pub fn open_checkpoint(
    msg: &[u8],
    origin: &str,
    log_key: &Ed25519NoteVerifier,
    witnesses: &[WitnessVerifier],
) -> Result<VerifiedCheckpoint, CheckpointError> {
    let note = Note::parse(msg)?;
    let signatures = note.signatures();
    for (i, signature) in signatures.iter().enumerate() {
        if signatures[..i]
            .iter()
            .any(|s| s.name() == signature.name() && s.key_id() == signature.key_id())
        {
            return Err(CheckpointError::DuplicateSignature {
                name: signature.name().to_owned(),
                key_id: signature.key_id(),
            });
        }
    }

    let mut verifiers: Vec<&dyn NoteVerifier> = Vec::with_capacity(1 + witnesses.len());
    verifiers.push(log_key);
    verifiers.extend(witnesses.iter().map(|w| w as &dyn NoteVerifier));
    let verified = match note.verify(&verifiers) {
        Ok(verified) => verified,
        Err(NoteError::NoVerifiedSignature) => return Err(CheckpointError::MissingLogSignature),
        Err(err) => return Err(err.into()),
    };
    let is_log = |name: &str, key_id: u32| name == log_key.name() && key_id == log_key.key_id();
    if !verified
        .verified()
        .iter()
        .any(|s| is_log(s.name(), s.key_id()))
    {
        return Err(CheckpointError::MissingLogSignature);
    }

    let checkpoint = Checkpoint::parse_text(verified.text())?;
    if checkpoint.origin() != origin {
        return Err(CheckpointError::WrongOrigin {
            expected: origin.to_owned(),
            got: checkpoint.origin().to_owned(),
        });
    }

    let cosignatures = verified
        .verified()
        .iter()
        .filter(|s| !is_log(s.name(), s.key_id()))
        .filter_map(|s| {
            Some(Cosignature {
                name: s.name().to_owned(),
                key_id: s.key_id(),
                timestamp: cosignature_timestamp(s)?,
            })
        })
        .collect();
    Ok(VerifiedCheckpoint {
        checkpoint,
        cosignatures,
    })
}
