//! Out-of-Band Cryptographic Approval Protocol
//!
//! Enables multi-party authorization for emergency recovery, key rotations,
//! and high-impact operations without sharing private keys or relying on SMS/email.

use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::RecoveryError;

/// Action category requiring out-of-band cryptographic approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalAction {
    EmergencyRecovery,
    KeyRotation,
    SnapshotRollback,
    GuardianRevocation,
}

/// A pending cryptographic challenge initiated by an unauthenticated or virgin machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub challenge_id: String,
    pub vault_id_hex: String,
    pub action: ApprovalAction,
    pub requester_device_id_hex: String,
    pub nonce_hex: String,
    pub created_at_utc: u64,
    pub expires_at_utc: u64,
    pub details: String,
}

impl ApprovalChallenge {
    pub fn new(
        vault_id: &[u8; 32],
        action: ApprovalAction,
        requester_device_id: &[u8; 32],
        details: String,
        validity_seconds: u64,
    ) -> Self {
        let mut id_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let now = Utc::now().timestamp() as u64;
        Self {
            challenge_id: hex::encode(id_bytes),
            vault_id_hex: hex::encode(vault_id),
            action,
            requester_device_id_hex: hex::encode(requester_device_id),
            nonce_hex: hex::encode(nonce_bytes),
            created_at_utc: now,
            expires_at_utc: now + validity_seconds,
            details,
        }
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"CipherVault-ApprovalChallenge-v1:");
        bytes.extend_from_slice(self.challenge_id.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.vault_id_hex.as_bytes());
        bytes.extend_from_slice(b":");
        let action_str = format!("{:?}", self.action);
        bytes.extend_from_slice(action_str.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.requester_device_id_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.nonce_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&self.expires_at_utc.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.details.as_bytes());
        bytes
    }

    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp() as u64;
        now > self.expires_at_utc
    }
}

/// Cryptographically signed approval receipt submitted by an authorized team lead or guardian.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedApprovalReceipt {
    pub challenge_id: String,
    pub approver_name: String,
    pub approver_pk_hex: String,
    pub approved_at_utc: u64,
    pub signature_hex: String,
}

impl SignedApprovalReceipt {
    pub fn compute_signing_bytes(
        challenge: &ApprovalChallenge,
        approver_name: &str,
        approver_pk_hex: &str,
        approved_at_utc: u64,
    ) -> Vec<u8> {
        let mut bytes = challenge.signing_bytes();
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(approver_name.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(approver_pk_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&approved_at_utc.to_le_bytes());
        bytes
    }

    pub fn signing_bytes(&self, challenge: &ApprovalChallenge) -> Vec<u8> {
        Self::compute_signing_bytes(
            challenge,
            &self.approver_name,
            &self.approver_pk_hex,
            self.approved_at_utc,
        )
    }

    pub fn sign(
        challenge: &ApprovalChallenge,
        approver_name: String,
        signing_key: &SigningKey,
    ) -> Self {
        let pk = signing_key.verifying_key().to_bytes();
        let pk_hex = hex::encode(pk);
        let approved_at_utc = Utc::now().timestamp() as u64;
        let msg = Self::compute_signing_bytes(challenge, &approver_name, &pk_hex, approved_at_utc);
        let sig = ciphervault_crypto::signatures::sign_with_domain(
            signing_key,
            b"out_of_band_approval",
            &msg,
        );
        Self {
            challenge_id: challenge.challenge_id.clone(),
            approver_name,
            approver_pk_hex: pk_hex,
            approved_at_utc,
            signature_hex: hex::encode(sig),
        }
    }

    pub fn verify(&self, challenge: &ApprovalChallenge) -> Result<(), RecoveryError> {
        if self.challenge_id != challenge.challenge_id {
            return Err(RecoveryError::InvalidSignature(
                "Receipt challenge ID does not match challenge".into(),
            ));
        }
        if challenge.is_expired() {
            return Err(RecoveryError::InvalidChallenge(
                "Approval challenge has expired".into(),
            ));
        }

        let pk_bytes = hex::decode(&self.approver_pk_hex).map_err(|e| {
            RecoveryError::InvalidSignature(format!("Invalid approver public key hex: {}", e))
        })?;
        if pk_bytes.len() != 32 {
            return Err(RecoveryError::InvalidSignature(
                "Approver public key must be 32 bytes".into(),
            ));
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);

        let sig_bytes = hex::decode(&self.signature_hex).map_err(|e| {
            RecoveryError::InvalidSignature(format!("Invalid signature hex: {}", e))
        })?;
        if sig_bytes.len() != 64 {
            return Err(RecoveryError::InvalidSignature(
                "Approval signature must be 64 bytes".into(),
            ));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        let msg = self.signing_bytes(challenge);
        ciphervault_crypto::signatures::verify_with_domain(
            &pk_arr,
            b"out_of_band_approval",
            &msg,
            &sig_arr,
        )
        .map_err(|e| RecoveryError::InvalidSignature(format!("Approval signature invalid: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::generate_signing_key;

    #[test]
    fn test_approval_challenge_and_signed_receipt_lifecycle() {
        let vault_id = [0x11u8; 32];
        let requester_id = [0x22u8; 32];
        let guardian_key = generate_signing_key();

        let challenge = ApprovalChallenge::new(
            &vault_id,
            ApprovalAction::EmergencyRecovery,
            &requester_id,
            "Clean-machine disaster recovery on replacement laptop".into(),
            600,
        );

        assert!(!challenge.is_expired());

        let receipt =
            SignedApprovalReceipt::sign(&challenge, "Security Lead Alice".into(), &guardian_key);

        // Valid receipt passes
        assert!(receipt.verify(&challenge).is_ok());

        // Tampered challenge fails
        let mut tampered_challenge = challenge.clone();
        tampered_challenge.details = "Attacker hijacked recovery details".into();
        assert!(receipt.verify(&tampered_challenge).is_err());

        // Expired challenge fails
        let mut expired_challenge = challenge.clone();
        expired_challenge.expires_at_utc = Utc::now().timestamp() as u64 - 10;
        assert!(expired_challenge.is_expired());
        assert!(receipt.verify(&expired_challenge).is_err());

        // Wrong key in receipt fails
        let other_key = generate_signing_key();
        let mut bad_receipt = receipt.clone();
        bad_receipt.approver_pk_hex = hex::encode(other_key.verifying_key().as_bytes());
        assert!(bad_receipt.verify(&challenge).is_err());
    }
}
