//! C2SP signed notes (`c2sp.org/signed-note@v1.1.0`).
//!
//! A signed note is a UTF-8 text ending in a newline, a blank line, and one
//! or more signature lines `— <key name> <base64(key ID || signature)>`.
//! The text must be ignored unless a trusted key has signed it, so the
//! only way to read a note's text as trusted is [`Note::verify`].
//!
//! Verification follows the spec: a signature whose key name and key ID
//! do not both match a known key is ignored; a signature from a known key
//! must verify, or the whole note is rejected; and at least one known key
//! must have signed.
//!
//! This module implements the Ed25519 note signature type (`0x01`). The
//! `cosignature/v1` type (`0x04`) is in [`crate::cosignature`].

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::encoding::{b64_decode, b64_encode, is_forbidden_control, is_valid_key_name};

/// Signature type byte of plain Ed25519 note signatures.
pub const SIG_TYPE_ED25519: u8 = 0x01;

/// The most signature lines a note may carry. The spec requires accepting
/// at least 16; this matches the Go reference implementation's limit.
pub const MAX_SIGNATURES: usize = 100;

/// The largest encoded note accepted, in bytes.
pub const MAX_NOTE_SIZE: usize = 1 << 20;

/// Every signature line starts with an em dash (U+2014) and a space.
const SIGNATURE_PREFIX: &str = "\u{2014} ";

/// Why a note could not be built, parsed, signed or verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoteError {
    /// The note does not follow the signed-note syntax.
    #[error("malformed note: {0}")]
    Malformed(&'static str),
    /// A key name is empty or contains a space, a `+` or a control
    /// character.
    #[error("invalid key name")]
    InvalidKeyName,
    /// The note is larger than [`MAX_NOTE_SIZE`].
    #[error("note is larger than {MAX_NOTE_SIZE} bytes")]
    TooLarge,
    /// The note has more than [`MAX_SIGNATURES`] signature lines.
    #[error("note has more than {MAX_SIGNATURES} signatures")]
    TooManySignatures,
    /// The note has no signature lines, so it cannot be encoded.
    #[error("note has no signatures")]
    Unsigned,
    /// Two of the supplied verifiers have the same key name and key ID.
    #[error("two verifiers share key name {name:?} and key ID {key_id:08x}")]
    AmbiguousVerifier {
        /// The shared key name.
        name: String,
        /// The shared key ID.
        key_id: u32,
    },
    /// A signature from a known key failed to verify.
    #[error("signature from key {name}+{key_id:08x} does not verify")]
    InvalidSignature {
        /// Key name of the signature.
        name: String,
        /// Key ID of the signature.
        key_id: u32,
    },
    /// No signature in the note is from a known key.
    #[error("note has no signature from a known key")]
    NoVerifiedSignature,
    /// A cosignature timestamp is above 2^63 - 1.
    #[error("cosignature timestamp is above 2^63 - 1")]
    TimestampOutOfRange,
}

/// Why a verifier or signer key could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The verifier key string does not follow `<name>+<id>+<key>`.
    #[error("malformed verifier key: {0}")]
    Malformed(&'static str),
    /// The key name is not a valid key name (or cosigner name).
    #[error("invalid key name")]
    InvalidName,
    /// The key ID in the verifier key does not match the key.
    #[error("key ID {got:08x} does not match the key, which has ID {expected:08x}")]
    KeyIdMismatch {
        /// The key ID written in the verifier key.
        got: u32,
        /// The key ID computed from the name, type and key.
        expected: u32,
    },
    /// The key has a signature type this verifier does not support.
    #[error("unsupported signature type {0:#04x}")]
    UnsupportedType(u8),
    /// The public key is malformed or weak.
    #[error("invalid public key")]
    InvalidPublicKey,
}

/// `SHA-256(name || 0x0A || sig_type || public_key)[:4]` as a big-endian
/// integer: the key ID the signed-note spec recommends, and the one every
/// signature type in this crate uses.
pub fn key_id(name: &str, sig_type: u8, public_key: &[u8]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([b'\n', sig_type]);
    hasher.update(public_key);
    let digest = hasher.finalize();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// One signature line of a note.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NoteSignature {
    name: String,
    key_id: u32,
    signature: Vec<u8>,
}

impl NoteSignature {
    /// A signature line. `signature` excludes the 4-byte key ID and must
    /// not be empty.
    pub fn new(
        name: impl Into<String>,
        key_id: u32,
        signature: Vec<u8>,
    ) -> Result<Self, NoteError> {
        let name = name.into();
        if !is_valid_key_name(&name) {
            return Err(NoteError::InvalidKeyName);
        }
        if signature.is_empty() {
            return Err(NoteError::Malformed("empty signature"));
        }
        Ok(Self {
            name,
            key_id,
            signature,
        })
    }

    /// Parses one signature line, without its trailing newline.
    pub fn parse_line(line: &str) -> Result<Self, NoteError> {
        let rest = line
            .strip_prefix(SIGNATURE_PREFIX)
            .ok_or(NoteError::Malformed(
                "signature line must start with an em dash and a space",
            ))?;
        let (name, encoded) = rest
            .split_once(' ')
            .ok_or(NoteError::Malformed("signature line has no signature"))?;
        if !is_valid_key_name(name) {
            return Err(NoteError::InvalidKeyName);
        }
        let raw =
            b64_decode(encoded).ok_or(NoteError::Malformed("signature is not canonical base64"))?;
        if raw.len() < 5 {
            return Err(NoteError::Malformed("signature is too short"));
        }
        Ok(Self {
            name: name.to_owned(),
            key_id: u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            signature: raw[4..].to_vec(),
        })
    }

    /// The key name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key ID.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The signature bytes after the key ID.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The encoded line, including its trailing newline.
    pub fn to_line(&self) -> String {
        let mut raw = Vec::with_capacity(4 + self.signature.len());
        raw.extend_from_slice(&self.key_id.to_be_bytes());
        raw.extend_from_slice(&self.signature);
        format!("{SIGNATURE_PREFIX}{} {}\n", self.name, b64_encode(&raw))
    }

    fn is_from(&self, name: &str, key_id: u32) -> bool {
        self.key_id == key_id && self.name == name
    }
}

/// Checks a note text: non-empty, ending in a newline, and free of control
/// characters other than newline.
fn validate_text(text: &str) -> Result<(), NoteError> {
    if !text.ends_with('\n') {
        return Err(NoteError::Malformed(
            "text must be non-empty and end in a newline",
        ));
    }
    if text.chars().any(is_forbidden_control) {
        return Err(NoteError::Malformed("text contains a control character"));
    }
    Ok(())
}

/// A signed note: its text and its signature lines, none of them verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    text: String,
    signatures: Vec<NoteSignature>,
}

impl Note {
    /// An unsigned note with `text`, which must end in a newline.
    pub fn new(text: impl Into<String>) -> Result<Self, NoteError> {
        let text = text.into();
        validate_text(&text)?;
        Ok(Self {
            text,
            signatures: Vec::new(),
        })
    }

    /// Parses an encoded note without verifying any signature.
    pub fn parse(msg: &[u8]) -> Result<Self, NoteError> {
        if msg.len() > MAX_NOTE_SIZE {
            return Err(NoteError::TooLarge);
        }
        let msg = std::str::from_utf8(msg).map_err(|_| NoteError::Malformed("not UTF-8"))?;
        if msg.chars().any(is_forbidden_control) {
            return Err(NoteError::Malformed("note contains a control character"));
        }
        // The text ends at the last blank line; it may contain blank lines
        // itself.
        let split = msg
            .rfind("\n\n")
            .ok_or(NoteError::Malformed("no blank line before the signatures"))?;
        let (text, block) = (&msg[..=split], &msg[split + 2..]);
        let lines = block.strip_suffix('\n').ok_or(NoteError::Malformed(
            "signature block must end in a newline",
        ))?;
        if lines.is_empty() {
            return Err(NoteError::Malformed("no signature lines"));
        }
        let mut signatures = Vec::new();
        for line in lines.split('\n') {
            if signatures.len() == MAX_SIGNATURES {
                return Err(NoteError::TooManySignatures);
            }
            signatures.push(NoteSignature::parse_line(line)?);
        }
        validate_text(text)?;
        Ok(Self {
            text: text.to_owned(),
            signatures,
        })
    }

    /// The note text, including its final newline. It is not trusted until
    /// [`Note::verify`] succeeds.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The signature lines, in order.
    pub fn signatures(&self) -> &[NoteSignature] {
        &self.signatures
    }

    /// Appends a signature line.
    pub fn add_signature(&mut self, signature: NoteSignature) -> Result<(), NoteError> {
        if self.signatures.len() == MAX_SIGNATURES {
            return Err(NoteError::TooManySignatures);
        }
        self.signatures.push(signature);
        Ok(())
    }

    /// Signs the text with `signer` and appends the signature line.
    pub fn sign(&mut self, signer: &dyn NoteSigner) -> Result<(), NoteError> {
        let signature = signer.sign(self.text.as_bytes())?;
        self.add_signature(NoteSignature::new(
            signer.name(),
            signer.key_id(),
            signature,
        )?)
    }

    /// The encoded note. It needs at least one signature.
    pub fn encode(&self) -> Result<String, NoteError> {
        if self.signatures.is_empty() {
            return Err(NoteError::Unsigned);
        }
        let mut out = String::with_capacity(self.text.len() + 1 + 128 * self.signatures.len());
        out.push_str(&self.text);
        out.push('\n');
        for signature in &self.signatures {
            out.push_str(&signature.to_line());
        }
        Ok(out)
    }

    /// Verifies the note against the known keys in `verifiers`.
    ///
    /// Signatures from unknown keys are returned as unverified. A signature
    /// from a known key that fails to verify rejects the whole note, and so
    /// does a note that no known key signed.
    pub fn verify(&self, verifiers: &[&dyn NoteVerifier]) -> Result<VerifiedNote, NoteError> {
        for (i, a) in verifiers.iter().enumerate() {
            if verifiers[..i]
                .iter()
                .any(|b| b.name() == a.name() && b.key_id() == a.key_id())
            {
                return Err(NoteError::AmbiguousVerifier {
                    name: a.name().to_owned(),
                    key_id: a.key_id(),
                });
            }
        }

        let mut verified: Vec<NoteSignature> = Vec::new();
        let mut unverified: Vec<NoteSignature> = Vec::new();
        for signature in &self.signatures {
            let known = verifiers
                .iter()
                .find(|v| signature.is_from(v.name(), v.key_id()));
            match known {
                None => {
                    if !unverified.contains(signature) {
                        unverified.push(signature.clone());
                    }
                }
                Some(verifier) => {
                    if !verifier.verify(self.text.as_bytes(), &signature.signature) {
                        return Err(NoteError::InvalidSignature {
                            name: signature.name.clone(),
                            key_id: signature.key_id,
                        });
                    }
                    if !verified.contains(signature) {
                        verified.push(signature.clone());
                    }
                }
            }
        }
        if verified.is_empty() {
            return Err(NoteError::NoVerifiedSignature);
        }
        Ok(VerifiedNote {
            text: self.text.clone(),
            verified,
            unverified,
        })
    }
}

/// A note at least one known key has signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNote {
    text: String,
    verified: Vec<NoteSignature>,
    unverified: Vec<NoteSignature>,
}

impl VerifiedNote {
    /// The verified text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The signatures from known keys, all of which verified, without
    /// repeats.
    pub fn verified(&self) -> &[NoteSignature] {
        &self.verified
    }

    /// The signatures from unknown keys, without repeats. They prove
    /// nothing.
    pub fn unverified(&self) -> &[NoteSignature] {
        &self.unverified
    }
}

/// A key that can check note signatures.
pub trait NoteVerifier {
    /// The key name.
    fn name(&self) -> &str;
    /// The key ID.
    fn key_id(&self) -> u32;
    /// Whether `signature` (without the key ID) is valid for `text`.
    fn verify(&self, text: &[u8], signature: &[u8]) -> bool;
}

/// A key that can sign notes.
pub trait NoteSigner {
    /// The key name.
    fn name(&self) -> &str;
    /// The key ID.
    fn key_id(&self) -> u32;
    /// Signs `text`, returning the signature without the key ID.
    fn sign(&self, text: &[u8]) -> Result<Vec<u8>, NoteError>;
}

/// A verifier key (vkey): `<name>+<hex key ID>+<base64(type || key)>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifierKey {
    name: String,
    key_id: u32,
    sig_type: u8,
    public_key: Vec<u8>,
}

impl VerifierKey {
    /// A verifier key, with the recommended key ID.
    pub fn new(
        name: impl Into<String>,
        sig_type: u8,
        public_key: Vec<u8>,
    ) -> Result<Self, KeyError> {
        let name = name.into();
        if !is_valid_key_name(&name) {
            return Err(KeyError::InvalidName);
        }
        if public_key.is_empty() {
            return Err(KeyError::InvalidPublicKey);
        }
        Ok(Self {
            key_id: key_id(&name, sig_type, &public_key),
            name,
            sig_type,
            public_key,
        })
    }

    /// Parses a verifier key. The key ID must be eight lowercase hex digits
    /// and must match the key.
    pub fn parse(vkey: &str) -> Result<Self, KeyError> {
        let mut parts = vkey.splitn(3, '+');
        let (Some(name), Some(id_hex), Some(encoded)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(KeyError::Malformed("expected <name>+<key ID>+<key>"));
        };
        if !is_valid_key_name(name) {
            return Err(KeyError::InvalidName);
        }
        if id_hex.len() != 8
            || !id_hex
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(KeyError::Malformed(
                "key ID must be eight lowercase hex digits",
            ));
        }
        let got = u32::from_str_radix(id_hex, 16)
            .map_err(|_| KeyError::Malformed("key ID must be eight lowercase hex digits"))?;
        let raw = b64_decode(encoded).ok_or(KeyError::Malformed("key is not canonical base64"))?;
        let Some((&sig_type, public_key)) = raw.split_first() else {
            return Err(KeyError::Malformed("key is empty"));
        };
        if public_key.is_empty() {
            return Err(KeyError::Malformed("key has a type but no key material"));
        }
        let expected = key_id(name, sig_type, public_key);
        if got != expected {
            return Err(KeyError::KeyIdMismatch { got, expected });
        }
        Ok(Self {
            name: name.to_owned(),
            key_id: got,
            sig_type,
            public_key: public_key.to_vec(),
        })
    }

    /// The key name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key ID.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The signature type byte.
    pub fn sig_type(&self) -> u8 {
        self.sig_type
    }

    /// The public key material, without the type byte.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl fmt::Display for VerifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = Vec::with_capacity(1 + self.public_key.len());
        raw.push(self.sig_type);
        raw.extend_from_slice(&self.public_key);
        write!(f, "{}+{:08x}+{}", self.name, self.key_id, b64_encode(&raw))
    }
}

impl FromStr for VerifierKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Decodes an Ed25519 public key of a verifier key with type `sig_type`,
/// rejecting malformed and weak (small-order) keys.
pub(crate) fn ed25519_key_from_vkey(
    vkey: &VerifierKey,
    sig_type: u8,
) -> Result<VerifyingKey, KeyError> {
    if vkey.sig_type != sig_type {
        return Err(KeyError::UnsupportedType(vkey.sig_type));
    }
    let bytes: &[u8; 32] = vkey
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| KeyError::InvalidPublicKey)?;
    checked_ed25519_key(bytes)
}

/// Decodes a 32-byte Ed25519 public key, rejecting weak keys.
pub(crate) fn checked_ed25519_key(bytes: &[u8; 32]) -> Result<VerifyingKey, KeyError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| KeyError::InvalidPublicKey)?;
    if key.is_weak() {
        return Err(KeyError::InvalidPublicKey);
    }
    Ok(key)
}

/// Strict Ed25519 verification of a 64-byte signature.
pub(crate) fn ed25519_verify(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    let Ok(bytes) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(bytes))
        .is_ok()
}

/// Verifies plain Ed25519 note signatures (type `0x01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519NoteVerifier {
    name: String,
    key_id: u32,
    key: VerifyingKey,
}

impl Ed25519NoteVerifier {
    /// A verifier for `key` under `name`.
    pub fn new(name: impl Into<String>, key: VerifyingKey) -> Result<Self, KeyError> {
        let name = name.into();
        if !is_valid_key_name(&name) {
            return Err(KeyError::InvalidName);
        }
        let key = checked_ed25519_key(key.as_bytes())?;
        Ok(Self {
            key_id: key_id(&name, SIG_TYPE_ED25519, key.as_bytes()),
            name,
            key,
        })
    }

    /// A verifier from a verifier key string of type `0x01`.
    pub fn from_vkey(vkey: &str) -> Result<Self, KeyError> {
        Self::from_verifier_key(&VerifierKey::parse(vkey)?)
    }

    /// A verifier from a parsed verifier key of type `0x01`.
    pub fn from_verifier_key(vkey: &VerifierKey) -> Result<Self, KeyError> {
        let key = ed25519_key_from_vkey(vkey, SIG_TYPE_ED25519)?;
        Self::new(vkey.name.clone(), key)
    }

    /// The verifier key for this key.
    pub fn verifier_key(&self) -> VerifierKey {
        VerifierKey {
            name: self.name.clone(),
            key_id: self.key_id,
            sig_type: SIG_TYPE_ED25519,
            public_key: self.key.as_bytes().to_vec(),
        }
    }

    /// The Ed25519 public key.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.key
    }
}

impl NoteVerifier for Ed25519NoteVerifier {
    fn name(&self) -> &str {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.key_id
    }

    fn verify(&self, text: &[u8], signature: &[u8]) -> bool {
        ed25519_verify(&self.key, text, signature)
    }
}

/// Signs notes with Ed25519 (type `0x01`), for example a log signing its
/// checkpoints.
pub struct Ed25519NoteSigner {
    name: String,
    key_id: u32,
    key: SigningKey,
}

impl Ed25519NoteSigner {
    /// A signer for `key` under `name`.
    pub fn new(name: impl Into<String>, key: SigningKey) -> Result<Self, KeyError> {
        let name = name.into();
        if !is_valid_key_name(&name) {
            return Err(KeyError::InvalidName);
        }
        Ok(Self {
            key_id: key_id(&name, SIG_TYPE_ED25519, key.verifying_key().as_bytes()),
            name,
            key,
        })
    }

    /// The matching verifier.
    pub fn verifier(&self) -> Result<Ed25519NoteVerifier, KeyError> {
        Ed25519NoteVerifier::new(self.name.clone(), self.key.verifying_key())
    }
}

impl fmt::Debug for Ed25519NoteSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519NoteSigner")
            .field("name", &self.name)
            .field("key_id", &format_args!("{:08x}", self.key_id))
            .finish_non_exhaustive()
    }
}

impl NoteSigner for Ed25519NoteSigner {
    fn name(&self) -> &str {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.key_id
    }

    fn sign(&self, text: &[u8]) -> Result<Vec<u8>, NoteError> {
        Ok(self.key.sign(text).to_bytes().to_vec())
    }
}
