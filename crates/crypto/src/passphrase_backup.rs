//! Passphrase-wrapped backup envelope (`docs/PASSPHRASE_KEY_BACKUP.md`).
//!
//! Seals opaque bytes (canonically: printable recovery-kit text) with a key
//! derived from a user passphrase. Layout `CVKB1`: magic, KDF id, salt,
//! nonce, then XChaCha20-Poly1305 ciphertext over the header as AAD. Every
//! open failure — wrong passphrase, tampering, truncation, unknown version —
//! surfaces identically so callers cannot oracle one cause from another.

use rand::RngCore;
use zeroize::Zeroizing;

use crate::aead::{decrypt_with_nonce, encrypt_with_nonce, NONCE_SIZE, TAG_SIZE};
use crate::error::CryptoError;
use crate::password::{derive_key_from_password, generate_salt, ARGON2_SALT_LEN};

pub const BACKUP_MAGIC: &[u8; 5] = b"CVKB1";
/// Argon2id with the `derive_key_from_password` parameters (64 MiB, 3
/// iterations, 4 lanes, 32-byte output). New parameter sets take new IDs.
pub const BACKUP_KDF_ARGON2ID_64M: u8 = 0x01;
pub const BACKUP_HEADER_LEN: usize = 5 + 1 + ARGON2_SALT_LEN + NONCE_SIZE;

fn open_failed() -> CryptoError {
    CryptoError::AuthTagVerificationFailed
}

/// Seals `plaintext` under `passphrase` with a fresh random salt and nonce.
pub fn seal_passphrase_backup(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::PasswordHashError(
            "passphrase must not be empty".to_string(),
        ));
    }
    let salt = generate_salt();
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = Zeroizing::new(derive_key_from_password(passphrase, &salt)?);
    let mut header = Vec::with_capacity(BACKUP_HEADER_LEN);
    header.extend_from_slice(BACKUP_MAGIC);
    header.push(BACKUP_KDF_ARGON2ID_64M);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let ciphertext = encrypt_with_nonce(&key, &nonce, plaintext, &header)?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

/// Opens an envelope sealed by [`seal_passphrase_backup`]. Fails closed on
/// any malformed input; wrong passphrases and tampering are indistinguishable.
pub fn open_passphrase_backup(passphrase: &[u8], envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if passphrase.is_empty() || envelope.len() < BACKUP_HEADER_LEN + TAG_SIZE {
        return Err(open_failed());
    }
    let (header, ciphertext) = envelope.split_at(BACKUP_HEADER_LEN);
    if header[..5] != *BACKUP_MAGIC || header[5] != BACKUP_KDF_ARGON2ID_64M {
        return Err(open_failed());
    }
    let salt: &[u8; ARGON2_SALT_LEN] = header[6..6 + ARGON2_SALT_LEN]
        .try_into()
        .map_err(|_| open_failed())?;
    let nonce: &[u8; NONCE_SIZE] = header[6 + ARGON2_SALT_LEN..BACKUP_HEADER_LEN]
        .try_into()
        .map_err(|_| open_failed())?;
    let key = Zeroizing::new(derive_key_from_password(passphrase, salt)?);
    decrypt_with_nonce(&key, nonce, ciphertext, header).map_err(|_| open_failed())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"correct horse battery staple plus two";
    const PLAINTEXT: &[u8] = b"CIPERVAULT-KIT-TEST-PRINTABLE-BODY";

    #[test]
    fn roundtrip_with_fresh_randomness() {
        let first = seal_passphrase_backup(PASS, PLAINTEXT).unwrap();
        let second = seal_passphrase_backup(PASS, PLAINTEXT).unwrap();
        assert_ne!(first, second, "salt/nonce must reroll per seal");
        assert_eq!(open_passphrase_backup(PASS, &first).unwrap(), PLAINTEXT);
        assert_eq!(open_passphrase_backup(PASS, &second).unwrap(), PLAINTEXT);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let envelope = seal_passphrase_backup(PASS, PLAINTEXT).unwrap();
        assert!(open_passphrase_backup(b"wrong passphrase entirely here!!", &envelope).is_err());
    }

    #[test]
    fn tampering_anywhere_fails() {
        let envelope = seal_passphrase_backup(PASS, PLAINTEXT).unwrap();
        for index in [0, 5, 6, 21, 22, 45, 46, envelope.len() - 1] {
            let mut tampered = envelope.clone();
            tampered[index] ^= 0x01;
            assert!(
                open_passphrase_backup(PASS, &tampered).is_err(),
                "byte {index} must be authenticated"
            );
        }
    }

    #[test]
    fn unknown_kdf_and_truncation_fail_closed() {
        let envelope = seal_passphrase_backup(PASS, PLAINTEXT).unwrap();
        let mut unknown = envelope.clone();
        unknown[5] = 0x7f;
        assert!(open_passphrase_backup(PASS, &unknown).is_err());
        assert!(open_passphrase_backup(PASS, &envelope[..BACKUP_HEADER_LEN]).is_err());
        assert!(open_passphrase_backup(PASS, &[]).is_err());
        assert!(open_passphrase_backup(PASS, b"short").is_err());
    }

    #[test]
    fn empty_passphrase_rejected() {
        assert!(seal_passphrase_backup(b"", PLAINTEXT).is_err());
        let envelope = seal_passphrase_backup(PASS, PLAINTEXT).unwrap();
        assert!(open_passphrase_backup(b"", &envelope).is_err());
    }
}
