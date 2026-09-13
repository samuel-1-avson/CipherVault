//! # CipherVault Cryptographic Primitives
//!
//! Provides memory-zeroized key lifecycle, XChaCha20-Poly1305 authenticated chunk encryption,
//! domain-separated KDF, sealed-box epoch key envelopes, and Ed25519 signatures.

pub mod aead;
pub mod error;
pub mod hsm;
pub mod kdf;
pub mod keys;
pub mod password;
pub mod piv;
pub mod sealed_box;
pub mod shamir;
pub mod signatures;

pub use aead::{
    decrypt_chunk, encrypt_chunk, encrypt_chunk_with_nonce, encrypt_with_nonce, KEY_SIZE,
    NONCE_SIZE, TAG_SIZE,
};
pub use error::CryptoError;
pub use hsm::{
    clear_cached_pin, get_cached_pin, list_pcsc_readers, list_readers, probe_all,
    probe_with_reader, set_cached_pin, HardwareSecurityModule, HsmDevice, HsmSlot, HsmSlotInfo,
    PcscHardwareToken, SoftwareHsmSimulator,
};
pub use kdf::{derive_chunk_nonce, derive_file_version_id, derive_file_version_key, derive_subkey};
pub use keys::{FileVersionKey, RecoverySecret, VaultEpochKey};
pub use password::{derive_key_from_password, generate_salt, ARGON2_SALT_LEN, DERIVED_KEY_LEN};
pub use piv::{CommandApdu, ResponseApdu};
pub use sealed_box::{open_sealed_box, seal_box, SEALED_BOX_OVERHEAD};
pub use shamir::{combine_shares, split_secret, ShamirShare};
pub use signatures::{generate_signing_key, sign_with_domain, verify_with_domain};
