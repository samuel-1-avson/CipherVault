use blake2::{Blake2b512, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::error::CryptoError;

pub const SEALED_BOX_OVERHEAD: usize = 32 + 16; // ephemeral public key (32) + Poly1305 tag (16)

/// Derives an encryption key and nonce from an ephemeral-recipient DH exchange,
/// matching the sealed box design pattern.
fn derive_box_seal_key_and_nonce(
    ephemeral_pk: &X25519PublicKey,
    recipient_pk: &X25519PublicKey,
    shared_secret: &[u8; 32],
) -> ([u8; 32], [u8; 24]) {
    let mut hasher = Blake2b512::new();
    hasher.update(b"CipherVault-BoxSeal-v1");
    hasher.update(ephemeral_pk.as_bytes());
    hasher.update(recipient_pk.as_bytes());
    hasher.update(shared_secret);
    let hash = hasher.finalize();

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];
    key.copy_from_slice(&hash[0..32]);
    nonce.copy_from_slice(&hash[32..56]);
    (key, nonce)
}

/// Seals a payload to an X25519 recipient public key using an ephemeral sender keypair.
/// The sender does NOT need a persistent private key.
/// Output: `[ephemeral_public_key (32 bytes) || ciphertext + tag]`.
pub fn seal_box(recipient_pk: &X25519PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut ephemeral_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral_bytes);
    let ephemeral_sk = X25519StaticSecret::from(ephemeral_bytes);
    let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);

    let shared_point = ephemeral_sk.diffie_hellman(recipient_pk);
    let (key, nonce) =
        derive_box_seal_key_and_nonce(&ephemeral_pk, recipient_pk, shared_point.as_bytes());

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 32,
        })?;
    let xnonce = XNonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad: b"CipherVault-SealedBox",
            },
        )
        .map_err(|_| CryptoError::AuthTagVerificationFailed)?;

    let mut out = Vec::with_capacity(32 + ciphertext.len());
    out.extend_from_slice(ephemeral_pk.as_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseals a sealed box payload using the recipient's private key and expected public key.
pub fn open_sealed_box(
    recipient_sk: &X25519StaticSecret,
    recipient_pk: &X25519PublicKey,
    sealed_box: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed_box.len() < SEALED_BOX_OVERHEAD {
        return Err(CryptoError::SealedBoxPayloadTooShort {
            min_len: SEALED_BOX_OVERHEAD,
        });
    }

    let (ephemeral_pk_bytes, ciphertext) = sealed_box.split_at(32);
    let mut epk_arr = [0u8; 32];
    epk_arr.copy_from_slice(ephemeral_pk_bytes);
    let ephemeral_pk = X25519PublicKey::from(epk_arr);

    let shared_point = recipient_sk.diffie_hellman(&ephemeral_pk);
    let (key, nonce) =
        derive_box_seal_key_and_nonce(&ephemeral_pk, recipient_pk, shared_point.as_bytes());

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 32,
        })?;
    let xnonce = XNonce::from_slice(&nonce);

    let plaintext = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext,
                aad: b"CipherVault-SealedBox",
            },
        )
        .map_err(|_| CryptoError::AuthTagVerificationFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_roundtrip() {
        let recipient_sk = X25519StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_pk = X25519PublicKey::from(&recipient_sk);

        let vault_epoch_key = [0x55u8; 32];
        let sealed = seal_box(&recipient_pk, &vault_epoch_key).unwrap();

        assert_ne!(&sealed[32..], &vault_epoch_key[..]);

        let opened = open_sealed_box(&recipient_sk, &recipient_pk, &sealed).unwrap();
        assert_eq!(opened, vault_epoch_key);
    }

    #[test]
    fn test_wrong_recipient_fails_open() {
        let recipient_sk1 = X25519StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_pk1 = X25519PublicKey::from(&recipient_sk1);

        let recipient_sk2 = X25519StaticSecret::random_from_rng(rand::thread_rng());
        let recipient_pk2 = X25519PublicKey::from(&recipient_sk2);

        let payload = b"secret epoch key 123";
        let sealed = seal_box(&recipient_pk1, payload).unwrap();

        assert!(open_sealed_box(&recipient_sk2, &recipient_pk2, &sealed).is_err());
    }
}
