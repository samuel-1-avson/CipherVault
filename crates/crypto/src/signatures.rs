use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::error::CryptoError;

pub const SIGNATURE_DOMAIN_PREFIX: &[u8] = b"CipherVault-Ed25519-v1:";

/// Generates a new random Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Signs a message with a mandatory domain separation prefix.
pub fn sign_with_domain(
    signing_key: &SigningKey,
    context: &[u8],
    message: &[u8],
) -> [u8; 64] {
    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN_PREFIX.len() + context.len() + 1 + message.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN_PREFIX);
    payload.extend_from_slice(context);
    payload.push(b':');
    payload.extend_from_slice(message);

    let signature = signing_key.sign(&payload);
    signature.to_bytes()
}

/// Verifies an Ed25519 signature against a domain-separated context and message.
pub fn verify_with_domain(
    verifying_key_bytes: &[u8; 32],
    context: &[u8],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(verifying_key_bytes)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    let signature = Signature::from_bytes(signature_bytes);

    let mut payload = Vec::with_capacity(SIGNATURE_DOMAIN_PREFIX.len() + context.len() + 1 + message.len());
    payload.extend_from_slice(SIGNATURE_DOMAIN_PREFIX);
    payload.extend_from_slice(context);
    payload.push(b':');
    payload.extend_from_slice(message);

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_roundtrip() {
        let signing_key = generate_signing_key();
        let verifying_key = signing_key.verifying_key();

        let context = b"snapshot_record";
        let message = b"hash_of_manifest_and_parents";

        let sig = sign_with_domain(&signing_key, context, message);
        assert!(verify_with_domain(verifying_key.as_bytes(), context, message, &sig).is_ok());

        // Wrong context fails
        assert!(verify_with_domain(verifying_key.as_bytes(), b"device_cert", message, &sig).is_err());

        // Tampered message fails
        assert!(verify_with_domain(verifying_key.as_bytes(), context, b"tampered", &sig).is_err());
    }
}
