//! ML-DSA-44 checkpoint and subtree cosignatures
//! (`c2sp.org/tlog-cosignature`, signature type `0x06` of
//! `c2sp.org/tlog-checkpoint`).
//!
//! A cosigner signs, with pure FIPS 204 ML-DSA-44 and an empty context
//! string, the `CosignedSubtree` structure:
//!
//! ```text
//! "subtree/v1\n\0"                  12 bytes
//! u8 length || cosigner name        1 to 255 bytes
//! timestamp                         u64, big-endian
//! u8 length || log origin           1 to 255 bytes
//! start                             u64, big-endian; 0 for a checkpoint
//! end                               u64, big-endian; the tree size for a checkpoint
//! hash                              32 bytes
//! ```
//!
//! A checkpoint cosignature is the 8-byte big-endian timestamp followed by
//! the 2,420-byte signature, under key ID
//! `SHA-256(name || 0x0A || 0x06 || 1,312-byte public key)[:4]`. A subtree
//! cosignature is the bare signature with a zero timestamp in the message.
//!
//! Unlike Ed25519 `cosignature/v1`, the message commits to the cosigner
//! name. It covers only the origin, size and root of a checkpoint, never
//! extension lines, so this module refuses to sign or accept a checkpoint
//! that has any.
//!
//! Signing uses FIPS 204's deterministic variant: the same key and message
//! always give the same signature. Verification accepts signatures from
//! the hedged variant too, as FIPS 204 requires.
//!
//! The ML-DSA implementation is the RustCrypto `ml-dsa` crate, which has
//! not been independently audited.

use std::fmt;

use ml_dsa::{
    EncodedVerifyingKey, MlDsa44, Seed, Signature, Signer as _, SigningKey, VerifyingKey,
};
use zeroize::Zeroize as _;

use crate::checkpoint::Checkpoint;
use crate::cosignature::MAX_TIMESTAMP;
use crate::encoding::is_valid_cosigner_name;
use crate::hash::{Hash, HASH_SIZE};
use crate::note::{key_id, KeyError, NoteError, NoteSignature, NoteVerifier, VerifierKey};

/// Signature type byte of ML-DSA-44 checkpoint cosignatures.
pub const SIG_TYPE_MLDSA44: u8 = 0x06;

/// Length of an encoded ML-DSA-44 public key.
pub const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;

/// Length of an encoded ML-DSA-44 signature.
pub const MLDSA44_SIGNATURE_LEN: usize = 2420;

/// Length of an ML-DSA-44 checkpoint cosignature after the key ID: an
/// 8-byte timestamp and the signature.
pub const MLDSA44_COSIGNATURE_LEN: usize = 8 + MLDSA44_SIGNATURE_LEN;

/// Length of an ML-DSA-44 private key seed.
pub const MLDSA44_SEED_LEN: usize = 32;

/// The fixed label that starts every `CosignedSubtree`.
const SUBTREE_LABEL: &[u8; 12] = b"subtree/v1\n\0";

/// The exact bytes an ML-DSA-44 cosigner signs: the `CosignedSubtree` for
/// the subtree `[start, end)` of the log `log_origin` with root `hash`.
///
/// A checkpoint cosignature has `start` 0, `end` the tree size and the
/// cosigning time as `timestamp`; a subtree cosignature has `timestamp` 0.
/// Returns `None` if either name is not a valid cosigner name, if
/// `start > end`, if a subtree that does not start at 0 has a timestamp,
/// or if the timestamp is above 2^63 - 1.
pub fn cosigned_subtree(
    cosigner_name: &str,
    timestamp: u64,
    log_origin: &str,
    start: u64,
    end: u64,
    hash: &Hash,
) -> Option<Vec<u8>> {
    if !is_valid_cosigner_name(cosigner_name) || !is_valid_cosigner_name(log_origin) {
        return None;
    }
    if start > end || (start != 0 && timestamp != 0) || timestamp > MAX_TIMESTAMP {
        return None;
    }
    let mut message = Vec::with_capacity(
        SUBTREE_LABEL.len() + 2 + cosigner_name.len() + log_origin.len() + 3 * 8 + HASH_SIZE,
    );
    message.extend_from_slice(SUBTREE_LABEL);
    // Both lengths fit in a byte: cosigner names are at most 255 bytes.
    message.push(u8::try_from(cosigner_name.len()).ok()?);
    message.extend_from_slice(cosigner_name.as_bytes());
    message.extend_from_slice(&timestamp.to_be_bytes());
    message.push(u8::try_from(log_origin.len()).ok()?);
    message.extend_from_slice(log_origin.as_bytes());
    message.extend_from_slice(&start.to_be_bytes());
    message.extend_from_slice(&end.to_be_bytes());
    message.extend_from_slice(hash);
    Some(message)
}

/// The `CosignedSubtree` of a checkpoint cosignature, or `None` if the
/// checkpoint has extension lines, which ML-DSA-44 cosignatures do not
/// cover.
fn checkpoint_message(name: &str, checkpoint: &Checkpoint, timestamp: u64) -> Option<Vec<u8>> {
    if !checkpoint.extensions().is_empty() {
        return None;
    }
    cosigned_subtree(
        name,
        timestamp,
        checkpoint.origin(),
        0,
        checkpoint.size(),
        checkpoint.root(),
    )
}

/// Verifies ML-DSA-44 cosignatures from one cosigner.
#[derive(Clone)]
pub struct MlDsa44CosignatureVerifier {
    name: String,
    key_id: u32,
    public_key: Vec<u8>,
    key: VerifyingKey<MlDsa44>,
}

impl MlDsa44CosignatureVerifier {
    /// A verifier for the cosigner `name` with the 1,312-byte encoded
    /// ML-DSA-44 public key `public_key`.
    pub fn new(name: impl Into<String>, public_key: &[u8]) -> Result<Self, KeyError> {
        let name = name.into();
        if !is_valid_cosigner_name(&name) {
            return Err(KeyError::InvalidName);
        }
        let encoded = EncodedVerifyingKey::<MlDsa44>::try_from(public_key)
            .map_err(|_| KeyError::InvalidPublicKey)?;
        // FIPS 204 pkDecode accepts every byte string of the right length,
        // and re-encoding gives the same bytes back.
        let key = VerifyingKey::<MlDsa44>::decode(&encoded);
        Ok(Self {
            key_id: key_id(&name, SIG_TYPE_MLDSA44, public_key),
            name,
            public_key: public_key.to_vec(),
            key,
        })
    }

    /// A verifier from a verifier key string of type `0x06`.
    pub fn from_vkey(vkey: &str) -> Result<Self, KeyError> {
        Self::from_verifier_key(&VerifierKey::parse(vkey)?)
    }

    /// A verifier from a parsed verifier key of type `0x06`.
    pub fn from_verifier_key(vkey: &VerifierKey) -> Result<Self, KeyError> {
        if vkey.sig_type() != SIG_TYPE_MLDSA44 {
            return Err(KeyError::UnsupportedType(vkey.sig_type()));
        }
        Self::new(vkey.name(), vkey.public_key())
    }

    /// The cosigner name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key ID.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The encoded ML-DSA-44 public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The verifier key for this cosigner.
    pub fn verifier_key(&self) -> Result<VerifierKey, KeyError> {
        VerifierKey::new(self.name.clone(), SIG_TYPE_MLDSA44, self.public_key.clone())
    }

    /// Verifies a checkpoint cosignature (without its key ID) over
    /// `checkpoint` and returns its timestamp. Fails for a checkpoint with
    /// extension lines.
    pub fn verify_cosignature(&self, checkpoint: &Checkpoint, signature: &[u8]) -> Option<u64> {
        if signature.len() != MLDSA44_COSIGNATURE_LEN {
            return None;
        }
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&signature[..8]);
        let timestamp = u64::from_be_bytes(ts);
        let message = checkpoint_message(&self.name, checkpoint, timestamp)?;
        self.verify_message(&message, &signature[8..])
            .then_some(timestamp)
    }

    /// Verifies a subtree cosignature, the bare ML-DSA-44 signature, over
    /// the subtree `[start, end)` of `log_origin` with root `hash`.
    pub fn verify_subtree(
        &self,
        log_origin: &str,
        start: u64,
        end: u64,
        hash: &Hash,
        signature: &[u8],
    ) -> bool {
        cosigned_subtree(&self.name, 0, log_origin, start, end, hash)
            .is_some_and(|message| self.verify_message(&message, signature))
    }

    fn verify_message(&self, message: &[u8], signature: &[u8]) -> bool {
        if signature.len() != MLDSA44_SIGNATURE_LEN {
            return false;
        }
        // sigDecode rejects malformed hints and out-of-range responses.
        let Ok(signature) = Signature::<MlDsa44>::try_from(signature) else {
            return false;
        };
        self.key.verify_with_context(message, &[], &signature)
    }
}

impl PartialEq for MlDsa44CosignatureVerifier {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.public_key == other.public_key
    }
}

impl Eq for MlDsa44CosignatureVerifier {}

impl fmt::Debug for MlDsa44CosignatureVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa44CosignatureVerifier")
            .field("name", &self.name)
            .field("key_id", &format_args!("{:08x}", self.key_id))
            .finish_non_exhaustive()
    }
}

impl NoteVerifier for MlDsa44CosignatureVerifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.key_id
    }

    /// A cosignature only covers checkpoints, so a note whose text is not a
    /// valid checkpoint without extension lines never verifies.
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

/// Produces ML-DSA-44 cosignatures for one cosigner.
pub struct MlDsa44CosignatureSigner {
    name: String,
    key_id: u32,
    key: SigningKey<MlDsa44>,
    public_key: Vec<u8>,
}

impl MlDsa44CosignatureSigner {
    /// A signer for the cosigner `name` with the private key derived from
    /// the 32-byte `seed` (FIPS 204 `ML-DSA.KeyGen_internal`).
    pub fn from_seed(
        name: impl Into<String>,
        seed: &[u8; MLDSA44_SEED_LEN],
    ) -> Result<Self, KeyError> {
        let name = name.into();
        if !is_valid_cosigner_name(&name) {
            return Err(KeyError::InvalidName);
        }
        let mut xi = Seed::default();
        xi.copy_from_slice(seed);
        let key = SigningKey::<MlDsa44>::from_seed(&xi);
        xi.zeroize();
        let public_key = AsRef::<VerifyingKey<MlDsa44>>::as_ref(&key)
            .encode()
            .to_vec();
        Ok(Self {
            key_id: key_id(&name, SIG_TYPE_MLDSA44, &public_key),
            name,
            key,
            public_key,
        })
    }

    /// The cosigner name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key ID.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The encoded ML-DSA-44 public key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The matching verifier.
    pub fn verifier(&self) -> Result<MlDsa44CosignatureVerifier, KeyError> {
        MlDsa44CosignatureVerifier::new(self.name.clone(), &self.public_key)
    }

    /// The verifier key for this cosigner.
    pub fn verifier_key(&self) -> Result<VerifierKey, KeyError> {
        VerifierKey::new(self.name.clone(), SIG_TYPE_MLDSA44, self.public_key.clone())
    }

    /// Cosigns `checkpoint` at `timestamp` (POSIX seconds). The caller
    /// must first have checked that the checkpoint is consistent with
    /// every checkpoint of the same log this cosigner signed before.
    pub fn cosign(
        &self,
        checkpoint: &Checkpoint,
        timestamp: u64,
    ) -> Result<NoteSignature, NoteError> {
        if timestamp > MAX_TIMESTAMP {
            return Err(NoteError::TimestampOutOfRange);
        }
        if !checkpoint.extensions().is_empty() {
            return Err(NoteError::UncoveredExtensions);
        }
        let message = checkpoint_message(&self.name, checkpoint, timestamp)
            .ok_or(NoteError::Malformed("invalid cosigned subtree"))?;
        let signature = self.sign_message(&message)?;
        let mut raw = Vec::with_capacity(MLDSA44_COSIGNATURE_LEN);
        raw.extend_from_slice(&timestamp.to_be_bytes());
        raw.extend_from_slice(&signature);
        NoteSignature::new(self.name.clone(), self.key_id, raw)
    }

    /// Signs the subtree `[start, end)` of `log_origin` with root `hash`
    /// and returns the bare signature. The caller must first have checked
    /// the subtree against a checkpoint this cosigner signed.
    pub fn sign_subtree(
        &self,
        log_origin: &str,
        start: u64,
        end: u64,
        hash: &Hash,
    ) -> Result<Vec<u8>, NoteError> {
        let message = cosigned_subtree(&self.name, 0, log_origin, start, end, hash)
            .ok_or(NoteError::Malformed("invalid cosigned subtree"))?;
        self.sign_message(&message)
    }

    fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, NoteError> {
        let signature = self
            .key
            .try_sign(message)
            .map_err(|_| NoteError::SigningFailed)?;
        Ok(signature.encode().to_vec())
    }
}

impl fmt::Debug for MlDsa44CosignatureSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa44CosignatureSigner")
            .field("name", &self.name)
            .field("key_id", &format_args!("{:08x}", self.key_id))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosigned_subtree_layout() {
        let hash = [7u8; 32];
        let message = cosigned_subtree("w", 0x0102, "log", 0, 5, &hash).unwrap();
        let mut expected = b"subtree/v1\n\0".to_vec();
        expected.extend_from_slice(&[1, b'w']);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 2]);
        expected.extend_from_slice(&[3, b'l', b'o', b'g']);
        expected.extend_from_slice(&[0; 8]);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
        expected.extend_from_slice(&hash);
        assert_eq!(message, expected);
    }

    #[test]
    fn cosigned_subtree_rejects_bad_inputs() {
        let hash = [0u8; 32];
        assert!(cosigned_subtree("", 0, "log", 0, 1, &hash).is_none());
        assert!(cosigned_subtree("w", 0, "", 0, 1, &hash).is_none());
        assert!(cosigned_subtree("w", 0, "a b", 0, 1, &hash).is_none());
        assert!(cosigned_subtree(&"w".repeat(256), 0, "log", 0, 1, &hash).is_none());
        assert!(cosigned_subtree("w", 0, &"l".repeat(256), 0, 1, &hash).is_none());
        assert!(cosigned_subtree("w", 0, "log", 2, 1, &hash).is_none());
        assert!(cosigned_subtree("w", 1, "log", 1, 2, &hash).is_none());
        assert!(cosigned_subtree("w", MAX_TIMESTAMP + 1, "log", 0, 1, &hash).is_none());
        assert!(cosigned_subtree(
            &"w".repeat(255),
            MAX_TIMESTAMP,
            &"l".repeat(255),
            0,
            0,
            &hash
        )
        .is_some());
    }
}
