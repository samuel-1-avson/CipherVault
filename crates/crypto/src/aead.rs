use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

use crate::error::CryptoError;

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

/// Encrypts plaintext bytes using XChaCha20-Poly1305 with an explicit 24-byte nonce and AAD.
/// Returns (nonce, ciphertext_with_tag).
pub fn encrypt_with_nonce(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength { expected: KEY_SIZE, actual: key.len() })?;

    let xnonce = XNonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(xnonce, payload)
        .map_err(|_| CryptoError::AuthTagVerificationFailed)?;

    Ok(ciphertext)
}

/// Generates a fresh 24-byte random nonce and encrypts plaintext with AAD.
/// The returned payload is: [nonce (24 bytes) || ciphertext + tag].
pub fn encrypt_chunk(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = encrypt_with_nonce(key, &nonce, plaintext, aad)?;
    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts a chunk payload formatted as [nonce (24 bytes) || ciphertext + tag] with AAD.
pub fn decrypt_chunk(
    key: &[u8; KEY_SIZE],
    chunk_payload: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if chunk_payload.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::AuthTagVerificationFailed);
    }

    let (nonce, ciphertext) = chunk_payload.split_at(NONCE_SIZE);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength { expected: KEY_SIZE, actual: key.len() })?;

    let xnonce = XNonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let plaintext = cipher
        .decrypt(xnonce, payload)
        .map_err(|_| CryptoError::AuthTagVerificationFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x77u8; KEY_SIZE];
        let secret_env = b"DATABASE_URL=postgres://user:pass@localhost/db\nAPI_KEY=sk_live_12345";
        let aad = b"vault_id:001|chunk:0|total:1";

        let encrypted = encrypt_chunk(&key, secret_env, aad).unwrap();
        assert_ne!(&encrypted[NONCE_SIZE..], secret_env);

        let decrypted = decrypt_chunk(&key, &encrypted, aad).unwrap();
        assert_eq!(decrypted, secret_env);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x77u8; KEY_SIZE];
        let secret_env = b"DATABASE_URL=postgres://user:pass@localhost/db";
        let aad = b"vault_id:001";

        let mut encrypted = encrypt_chunk(&key, secret_env, aad).unwrap();
        // Corrupt one byte of ciphertext
        encrypted[NONCE_SIZE + 5] ^= 0x01;

        assert!(decrypt_chunk(&key, &encrypted, aad).is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [0x77u8; KEY_SIZE];
        let secret_env = b"SECRET=true";
        let aad1 = b"vault_id:001";
        let aad2 = b"vault_id:002";

        let encrypted = encrypt_chunk(&key, secret_env, aad1).unwrap();
        assert!(decrypt_chunk(&key, &encrypted, aad2).is_err());
    }
}
