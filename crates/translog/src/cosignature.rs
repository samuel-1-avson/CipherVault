//! Ed25519 `cosignature/v1` checkpoint cosignatures
//! (`c2sp.org/tlog-cosignature@v1.1.0` and `c2sp.org/tlog-checkpoint@v1.1.0`).
//!
//! A witness signs, with Ed25519, the lines
//!
//! ```text
//! cosignature/v1
//! time <POSIX timestamp>
//! <checkpoint text>
//! ```
//!
//! where the checkpoint text is the origin, tree size, base64 root hash and
//! any extension lines, each ending in a newline. The note signature is
//! the 8-byte big-endian timestamp followed by the 64-byte Ed25519
//! signature, under key ID `SHA-256(name || 0x0A || 0x04 || key)[:4]`.
//!
//! The Ed25519 message does not include the cosigner name, so one key must
//! never serve two cosigner names.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

use crate::checkpoint::Checkpoint;
use crate::encoding::is_valid_cosigner_name;
use crate::mldsa::{MlDsa44CosignatureVerifier, MLDSA44_COSIGNATURE_LEN, SIG_TYPE_MLDSA44};
use crate::note::{
    checked_ed25519_key, ed25519_key_from_vkey, ed25519_verify, key_id, KeyError, NoteError,
    NoteSignature, NoteVerifier, VerifierKey,
};

/// Signature type byte of timestamped Ed25519 checkpoint cosignatures.
pub const SIG_TYPE_COSIGNATURE_V1: u8 = 0x04;

/// Length of a `cosignature/v1` note signature after the key ID: an 8-byte
/// timestamp and a 64-byte Ed25519 signature.
pub const COSIGNATURE_V1_LEN: usize = 8 + 64;

/// The largest timestamp accepted. Timestamps are POSIX seconds; values
/// above 2^63 - 1 are rejected, as the reference implementations do.
pub const MAX_TIMESTAMP: u64 = i64::MAX as u64;

/// The exact bytes an Ed25519 `cosignature/v1` signs.
pub fn signed_message(checkpoint: &Checkpoint, timestamp: u64) -> Vec<u8> {
    format!("cosignature/v1\ntime {timestamp}\n{}", checkpoint.to_text()).into_bytes()
}

/// The timestamp of a checkpoint cosignature, Ed25519 `cosignature/v1` or
/// ML-DSA-44, or `None` if the signature has neither length or has an
/// out-of-range timestamp.
///
/// This only reads the bytes. The timestamp is authenticated only once the
/// signature has verified, for example through
/// [`crate::checkpoint::open_checkpoint`].
pub fn cosignature_timestamp(signature: &NoteSignature) -> Option<u64> {
    let raw = signature.signature();
    if raw.len() != COSIGNATURE_V1_LEN && raw.len() != MLDSA44_COSIGNATURE_LEN {
        return None;
    }
    leading_timestamp(raw)
}

fn timestamp_of(signature: &[u8]) -> Option<u64> {
    if signature.len() != COSIGNATURE_V1_LEN {
        return None;
    }
    leading_timestamp(signature)
}

fn leading_timestamp(signature: &[u8]) -> Option<u64> {
    let mut ts = [0u8; 8];
    ts.copy_from_slice(signature.get(..8)?);
    let timestamp = u64::from_be_bytes(ts);
    (timestamp <= MAX_TIMESTAMP).then_some(timestamp)
}

/// Verifies Ed25519 `cosignature/v1` cosignatures from one witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignatureV1Verifier {
    name: String,
    key_id: u32,
    key: VerifyingKey,
}

impl CosignatureV1Verifier {
    /// A verifier for the witness `name` with public key `key`.
    pub fn new(name: impl Into<String>, key: VerifyingKey) -> Result<Self, KeyError> {
        let name = name.into();
        if !is_valid_cosigner_name(&name) {
            return Err(KeyError::InvalidName);
        }
        let key = checked_ed25519_key(key.as_bytes())?;
        Ok(Self {
            key_id: key_id(&name, SIG_TYPE_COSIGNATURE_V1, key.as_bytes()),
            name,
            key,
        })
    }

    /// A verifier from a verifier key string of type `0x04`.
    pub fn from_vkey(vkey: &str) -> Result<Self, KeyError> {
        Self::from_verifier_key(&VerifierKey::parse(vkey)?)
    }

    /// A verifier from a parsed verifier key of type `0x04`.
    pub fn from_verifier_key(vkey: &VerifierKey) -> Result<Self, KeyError> {
        let key = ed25519_key_from_vkey(vkey, SIG_TYPE_COSIGNATURE_V1)?;
        Self::new(vkey.name(), key)
    }

    /// The verifier key for this witness.
    pub fn verifier_key(&self) -> Result<VerifierKey, KeyError> {
        VerifierKey::new(
            self.name.clone(),
            SIG_TYPE_COSIGNATURE_V1,
            self.key.as_bytes().to_vec(),
        )
    }

    /// The Ed25519 public key.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.key
    }

    /// Verifies a cosignature (without its key ID) over `checkpoint` and
    /// returns its timestamp.
    pub fn verify_cosignature(&self, checkpoint: &Checkpoint, signature: &[u8]) -> Option<u64> {
        let timestamp = timestamp_of(signature)?;
        let message = signed_message(checkpoint, timestamp);
        ed25519_verify(&self.key, &message, &signature[8..]).then_some(timestamp)
    }
}

impl NoteVerifier for CosignatureV1Verifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.key_id
    }

    /// A cosignature only covers checkpoints, so a note whose text is not a
    /// valid checkpoint never verifies.
    fn verify(&self, text: &[u8], signature: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(text) else {
            return false;
        };
        let Ok(checkpoint) = Checkpoint::parse_text(text) else {
            return false;
        };
        self.verify_cosignature(&checkpoint, signature).is_some()
    }
}

/// Produces Ed25519 `cosignature/v1` cosignatures for one witness.
pub struct CosignatureV1Signer {
    name: String,
    key_id: u32,
    key: SigningKey,
}

impl CosignatureV1Signer {
    /// A signer for the witness `name`.
    pub fn new(name: impl Into<String>, key: SigningKey) -> Result<Self, KeyError> {
        let name = name.into();
        if !is_valid_cosigner_name(&name) {
            return Err(KeyError::InvalidName);
        }
        Ok(Self {
            key_id: key_id(
                &name,
                SIG_TYPE_COSIGNATURE_V1,
                key.verifying_key().as_bytes(),
            ),
            name,
            key,
        })
    }

    /// The witness name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key ID.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The matching verifier.
    pub fn verifier(&self) -> Result<CosignatureV1Verifier, KeyError> {
        CosignatureV1Verifier::new(self.name.clone(), self.key.verifying_key())
    }

    /// Cosigns `checkpoint` at `timestamp` (POSIX seconds). The caller
    /// must first have checked that the checkpoint is consistent with
    /// every checkpoint of the same log this witness cosigned before.
    pub fn cosign(
        &self,
        checkpoint: &Checkpoint,
        timestamp: u64,
    ) -> Result<NoteSignature, NoteError> {
        if timestamp > MAX_TIMESTAMP {
            return Err(NoteError::TimestampOutOfRange);
        }
        let signature = self.key.sign(&signed_message(checkpoint, timestamp));
        let mut raw = Vec::with_capacity(COSIGNATURE_V1_LEN);
        raw.extend_from_slice(&timestamp.to_be_bytes());
        raw.extend_from_slice(&signature.to_bytes());
        NoteSignature::new(self.name.clone(), self.key_id, raw)
    }
}

impl fmt::Debug for CosignatureV1Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CosignatureV1Signer")
            .field("name", &self.name)
            .field("key_id", &format_args!("{:08x}", self.key_id))
            .finish_non_exhaustive()
    }
}

/// A trusted witness key of either checkpoint cosignature type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessVerifier {
    /// An Ed25519 `cosignature/v1` key (type `0x04`).
    Ed25519(CosignatureV1Verifier),
    /// An ML-DSA-44 cosignature key (type `0x06`).
    MlDsa44(MlDsa44CosignatureVerifier),
}

impl WitnessVerifier {
    /// A witness key from a verifier key string of type `0x04` or `0x06`.
    pub fn from_vkey(vkey: &str) -> Result<Self, KeyError> {
        Self::from_verifier_key(&VerifierKey::parse(vkey)?)
    }

    /// A witness key from a parsed verifier key of type `0x04` or `0x06`.
    pub fn from_verifier_key(vkey: &VerifierKey) -> Result<Self, KeyError> {
        match vkey.sig_type() {
            SIG_TYPE_COSIGNATURE_V1 => {
                CosignatureV1Verifier::from_verifier_key(vkey).map(Self::Ed25519)
            }
            SIG_TYPE_MLDSA44 => {
                MlDsa44CosignatureVerifier::from_verifier_key(vkey).map(Self::MlDsa44)
            }
            other => Err(KeyError::UnsupportedType(other)),
        }
    }

    /// The witness name.
    pub fn name(&self) -> &str {
        match self {
            Self::Ed25519(v) => NoteVerifier::name(v),
            Self::MlDsa44(v) => v.name(),
        }
    }

    /// The key ID.
    pub fn key_id(&self) -> u32 {
        match self {
            Self::Ed25519(v) => NoteVerifier::key_id(v),
            Self::MlDsa44(v) => v.key_id(),
        }
    }

    /// The signature type byte.
    pub fn sig_type(&self) -> u8 {
        match self {
            Self::Ed25519(_) => SIG_TYPE_COSIGNATURE_V1,
            Self::MlDsa44(_) => SIG_TYPE_MLDSA44,
        }
    }

    /// The verifier key for this witness.
    pub fn verifier_key(&self) -> Result<VerifierKey, KeyError> {
        match self {
            Self::Ed25519(v) => v.verifier_key(),
            Self::MlDsa44(v) => v.verifier_key(),
        }
    }

    /// Verifies a cosignature (without its key ID) over `checkpoint` and
    /// returns its timestamp.
    pub fn verify_cosignature(&self, checkpoint: &Checkpoint, signature: &[u8]) -> Option<u64> {
        match self {
            Self::Ed25519(v) => v.verify_cosignature(checkpoint, signature),
            Self::MlDsa44(v) => v.verify_cosignature(checkpoint, signature),
        }
    }
}

impl From<CosignatureV1Verifier> for WitnessVerifier {
    fn from(verifier: CosignatureV1Verifier) -> Self {
        Self::Ed25519(verifier)
    }
}

impl From<MlDsa44CosignatureVerifier> for WitnessVerifier {
    fn from(verifier: MlDsa44CosignatureVerifier) -> Self {
        Self::MlDsa44(verifier)
    }
}

impl NoteVerifier for WitnessVerifier {
    fn name(&self) -> &str {
        WitnessVerifier::name(self)
    }

    fn key_id(&self) -> u32 {
        WitnessVerifier::key_id(self)
    }

    fn verify(&self, text: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Ed25519(v) => v.verify(text, signature),
            Self::MlDsa44(v) => v.verify(text, signature),
        }
    }
}
