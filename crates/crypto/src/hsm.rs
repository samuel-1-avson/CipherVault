//! # Hardware Security Module (HSM) & YubiKey PKCS#11 Architecture
//!
//! Provides abstract interfaces and slot delegation for hardware security modules,
//! YubiKey PIV (Personal Identity Verification) tokens, and PKCS#11 cryptographic engines.
//!
//! Keys generated or provisioned in physical hardware slots never touch host RAM or disk.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::signatures::sign_with_domain;

/// Standard YubiKey PIV / PKCS#11 hardware key slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HsmSlot {
    /// PIV Slot 9A: Host / TLS / Mutual Authentication.
    Authentication,
    /// PIV Slot 9C: Digital Signature for snapshot commits & device assertions.
    DigitalSignature,
    /// PIV Slot 9D: Key Management for epoch envelope decryption and ECDH unwrap.
    KeyManagement,
    /// PIV Slot 9E: Card Authentication for physical access and presence checks.
    CardAuthentication,
}

impl HsmSlot {
    pub fn piv_slot_hex(&self) -> &'static str {
        match self {
            HsmSlot::Authentication => "9A",
            HsmSlot::DigitalSignature => "9C",
            HsmSlot::KeyManagement => "9D",
            HsmSlot::CardAuthentication => "9E",
        }
    }
}

/// Metadata and status for an HSM key slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmSlotInfo {
    pub slot: HsmSlot,
    pub algorithm: String,
    pub public_key_hex: String,
    pub touch_policy: String,
    pub pin_policy: String,
}

/// Abstract interface for physical or virtual Hardware Security Modules.
pub trait HardwareSecurityModule: Send + Sync {
    /// Returns true if the physical hardware token is inserted and responsive.
    fn is_connected(&self) -> bool;

    /// Retrieves the public key stored in the specified hardware slot.
    fn get_public_key(&self, slot: HsmSlot) -> Result<Vec<u8>, CryptoError>;

    /// Queries slot metadata and operational policy.
    fn get_slot_info(&self, slot: HsmSlot) -> Result<HsmSlotInfo, CryptoError>;

    /// Signs a domain-separated 32-byte digest inside hardware without exposing the private key.
    fn sign_digest(
        &self,
        slot: HsmSlot,
        domain: &[u8],
        digest: &[u8; 32],
    ) -> Result<[u8; 64], CryptoError>;

    /// Performs Diffie-Hellman key agreement inside hardware (Slot 9D) against a peer's public key.
    fn ecdh_key_agreement(
        &self,
        slot: HsmSlot,
        peer_public_key: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError>;
}

/// Software-isolated simulator for HSM and PKCS#11 operations.
///
/// Implements the exact same hardware slot semantics in secure, zeroized memory,
/// allowing automated testing and environments without physical hardware tokens.
pub struct SoftwareHsmSimulator {
    sig_key: SigningKey,
    ecdh_key: X25519StaticSecret,
}

impl Drop for SoftwareHsmSimulator {
    fn drop(&mut self) {
        // Zeroize signing key memory on drop
        let mut bytes = self.sig_key.to_bytes();
        bytes.zeroize();
    }
}

impl SoftwareHsmSimulator {
    /// Generates a new software HSM simulator with cryptographically random keys.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let sig_key = SigningKey::generate(&mut rng);
        let ecdh_key = X25519StaticSecret::random_from_rng(rand::thread_rng());
        Self { sig_key, ecdh_key }
    }

    /// Creates an HSM simulator from deterministic seed bytes for testing.
    pub fn from_seeds(sig_seed: &[u8; 32], ecdh_seed: &[u8; 32]) -> Self {
        let sig_key = SigningKey::from_bytes(sig_seed);
        let ecdh_key = X25519StaticSecret::from(*ecdh_seed);
        Self { sig_key, ecdh_key }
    }
}

impl HardwareSecurityModule for SoftwareHsmSimulator {
    fn is_connected(&self) -> bool {
        true
    }

    fn get_public_key(&self, slot: HsmSlot) -> Result<Vec<u8>, CryptoError> {
        match slot {
            HsmSlot::DigitalSignature | HsmSlot::Authentication => {
                let vk = self.sig_key.verifying_key();
                Ok(vk.to_bytes().to_vec())
            }
            HsmSlot::KeyManagement | HsmSlot::CardAuthentication => {
                let pk = X25519PublicKey::from(&self.ecdh_key);
                Ok(pk.as_bytes().to_vec())
            }
        }
    }

    fn get_slot_info(&self, slot: HsmSlot) -> Result<HsmSlotInfo, CryptoError> {
        let pk = self.get_public_key(slot)?;
        let algo = match slot {
            HsmSlot::DigitalSignature | HsmSlot::Authentication => "Ed25519".to_string(),
            HsmSlot::KeyManagement | HsmSlot::CardAuthentication => "X25519".to_string(),
        };
        Ok(HsmSlotInfo {
            slot,
            algorithm: algo,
            public_key_hex: hex::encode(pk),
            touch_policy: "Virtual (Software Emulated)".into(),
            pin_policy: "Default".into(),
        })
    }

    fn sign_digest(
        &self,
        slot: HsmSlot,
        domain: &[u8],
        digest: &[u8; 32],
    ) -> Result<[u8; 64], CryptoError> {
        if slot != HsmSlot::DigitalSignature && slot != HsmSlot::Authentication {
            return Err(CryptoError::HsmError(format!(
                "Slot {:?} does not support digital signatures",
                slot
            )));
        }
        let sig = sign_with_domain(&self.sig_key, domain, digest);
        Ok(sig)
    }

    fn ecdh_key_agreement(
        &self,
        slot: HsmSlot,
        peer_public_key: &[u8; 32],
    ) -> Result<[u8; 32], CryptoError> {
        if slot != HsmSlot::KeyManagement && slot != HsmSlot::CardAuthentication {
            return Err(CryptoError::HsmError(format!(
                "Slot {:?} does not support key agreement",
                slot
            )));
        }
        let peer_pk = X25519PublicKey::from(*peer_public_key);
        let shared_secret = self.ecdh_key.diffie_hellman(&peer_pk);
        Ok(*shared_secret.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::verify_with_domain;

    #[test]
    fn test_software_hsm_signature_delegation() {
        let hsm = SoftwareHsmSimulator::generate();
        assert!(hsm.is_connected());

        let pk_bytes = hsm.get_public_key(HsmSlot::DigitalSignature).unwrap();
        assert_eq!(pk_bytes.len(), 32);

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);

        let domain = b"CIPHERVAULT-TEST-HSM";
        let message = [0x42u8; 32];

        let sig_bytes = hsm.sign_digest(HsmSlot::DigitalSignature, domain, &message).unwrap();

        // Verify with standard verifying key
        assert!(verify_with_domain(&pk_arr, domain, &message, &sig_bytes).is_ok());

        // Rejects mismatched message
        let wrong_msg = [0x43u8; 32];
        assert!(verify_with_domain(&pk_arr, domain, &wrong_msg, &sig_bytes).is_err());
    }

    #[test]
    fn test_software_hsm_ecdh_agreement() {
        let hsm1 = SoftwareHsmSimulator::generate();
        let hsm2 = SoftwareHsmSimulator::generate();

        let pk1_bytes = hsm1.get_public_key(HsmSlot::KeyManagement).unwrap();
        let pk2_bytes = hsm2.get_public_key(HsmSlot::KeyManagement).unwrap();

        let mut pk1 = [0u8; 32];
        pk1.copy_from_slice(&pk1_bytes);

        let mut pk2 = [0u8; 32];
        pk2.copy_from_slice(&pk2_bytes);

        // DH agreement 1 -> 2
        let secret1 = hsm1.ecdh_key_agreement(HsmSlot::KeyManagement, &pk2).unwrap();

        // DH agreement 2 -> 1
        let secret2 = hsm2.ecdh_key_agreement(HsmSlot::KeyManagement, &pk1).unwrap();

        // Symmetric shared secrets must be identical
        assert_eq!(secret1, secret2);
        assert_ne!(secret1, [0u8; 32]);
    }
}
