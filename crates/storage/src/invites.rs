//! Fleet-signed join invites (DON verified community join): admission tickets
//! for new operator nodes.
//!
//! Under barter economics anyone may run `ciphervault-operator`, but a node
//! joins the fleet routing table only by presenting a [`JoinInvite`] signed
//! with the offline fleet key. The fleet key never lives on a server: an
//! admin signs invites locally (`ciphervault invite issue`), hands the JSON
//! ticket to the joiner out of band, and every fleet node verifies against
//! its pinned `CIPHERVAULT_FLEET_KEY` copy.
//!
//! An invite binds one node public key to one expiry. Joining spends the
//! invite nonce (single-use per node), so a leaked ticket admits exactly
//! one node — the key holder — and cannot be replayed for a second identity.
//! Verification is fail-closed and transport agnostic.
//!
//! HTTP mapping: unconfigured join and forged/expired/mismatched invites
//! are 403; an already-spent ticket is 409 (the joiner needs a fresh
//! ticket, not a retry); malformed descriptors are 400.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

/// Only this invite version is accepted; bump on format change.
pub const INVITE_VERSION: u32 = 1;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn forbidden(message: impl Into<String>) -> StorageError {
    StorageError::ServerError {
        status: 403,
        message: message.into(),
    }
}

/// Decodes a hex field, requiring lowercase-canonical form. Case variants
/// decode to identical bytes, so without this rule one invite would verify
/// under many nonce spellings and the spent ledger (keyed by nonce string)
/// would honor each as a fresh ticket — a single-use bypass.
fn decode_canonical_hex(field: &str, what: &str, len: usize) -> Result<Vec<u8>, StorageError> {
    let bytes = hex::decode(field).map_err(|_| forbidden(format!("invite {what} must be hex")))?;
    if bytes.len() != len {
        return Err(forbidden(format!("invite {what} must be {len} bytes")));
    }
    if hex::encode(&bytes) != field {
        return Err(forbidden(format!("invite {what} must be lowercase hex")));
    }
    Ok(bytes)
}

/// A signed admission ticket: node `node_pk_hex` may join the fleet routing
/// table (into probation) until `expires_utc`. `nonce_hex` uniquely
/// identifies this grant for single-use spend accounting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinInvite {
    pub version: u32,
    pub issuer_pk_hex: String,
    pub node_pk_hex: String,
    pub expires_utc: u64,
    pub nonce_hex: String,
    pub signature_hex: String,
}

impl JoinInvite {
    /// Issues an invite for `node_pk_hex` good for the next `ttl_secs`
    /// seconds. Fails fast on malformed node keys and empty TTLs —
    /// verification would reject them anyway.
    pub fn issue(
        issuer: &SigningKey,
        node_pk_hex: String,
        ttl_secs: u64,
    ) -> Result<Self, StorageError> {
        let node =
            hex::decode(&node_pk_hex).map_err(|_| forbidden("invite node key must be hex"))?;
        if node.len() != 32 {
            return Err(forbidden("invite node key must be 32 bytes"));
        }
        if ttl_secs == 0 {
            return Err(forbidden("invite TTL must be positive"));
        }
        let nonce: [u8; 32] = rand::random();
        let mut invite = Self {
            version: INVITE_VERSION,
            issuer_pk_hex: hex::encode(issuer.verifying_key().to_bytes()),
            node_pk_hex,
            expires_utc: now_unix_secs().saturating_add(ttl_secs),
            nonce_hex: hex::encode(nonce),
            signature_hex: String::new(),
        };
        let msg = invite.signing_bytes();
        let sig =
            ciphervault_crypto::signatures::sign_with_domain(issuer, b"operator_join_invite", &msg);
        invite.signature_hex = hex::encode(sig);
        Ok(invite)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ciphervault-join-invite-v1:");
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.issuer_pk_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.node_pk_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&self.expires_utc.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(self.nonce_hex.as_bytes());
        bytes
    }

    /// Verifies everything except spend: version, issuer match, key shapes,
    /// signature, and expiry. Pure — no ledger access.
    pub fn verify(&self, expected_issuer_pk_hex: &str, now_utc: u64) -> Result<(), StorageError> {
        if self.version != INVITE_VERSION {
            return Err(forbidden(format!(
                "unsupported invite version {}",
                self.version
            )));
        }
        if !self
            .issuer_pk_hex
            .eq_ignore_ascii_case(expected_issuer_pk_hex)
        {
            return Err(forbidden("invite issuer mismatch"));
        }
        let issuer = decode_canonical_hex(&self.issuer_pk_hex, "issuer key", 32)?;
        let mut issuer_arr = [0u8; 32];
        issuer_arr.copy_from_slice(&issuer);
        decode_canonical_hex(&self.node_pk_hex, "node key", 32)?;
        decode_canonical_hex(&self.nonce_hex, "nonce", 32)?;
        let sig = decode_canonical_hex(&self.signature_hex, "signature", 64)?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        ciphervault_crypto::signatures::verify_with_domain(
            &issuer_arr,
            b"operator_join_invite",
            &self.signing_bytes(),
            &sig_arr,
        )
        .map_err(|_| forbidden("invite signature verification failed"))?;
        if now_utc > self.expires_utc {
            return Err(forbidden("invite expired"));
        }
        Ok(())
    }
}

/// Verified-join request: a fresh self-signed [`crate::types::PeerDescriptor`]
/// plus the fleet-signed [`JoinInvite`] admitting its node key. Public route
/// (`POST /v1/peers/join`): the ticket is the authorization, so no service
/// token is attached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub descriptor: crate::types::PeerDescriptor,
    pub invite: JoinInvite,
}

/// Verified-join response: `status` is `"probation"` for ticket joins
/// (full membership comes via graduation or a control-plane announce).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinResponse {
    pub status: String,
    pub operator_id: String,
    pub peer_count: usize,
}

/// Probation refresh request: a fresh self-signed
/// [`crate::types::PeerDescriptor`] that must match an existing
/// routing-table entry's operator id and signing key. Public route
/// (`POST /v1/peers/join/refresh`): proves liveness of the key holder
/// without the service token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRefreshRequest {
    pub descriptor: crate::types::PeerDescriptor,
}

/// Probation refresh response: `status` is `"probation"` or `"full"`.
/// The only standing signal a joiner can read without the fleet's
/// service token, so clients must surface it, not swallow it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinRefreshResponse {
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_response_carries_standing() {
        let parsed: JoinRefreshResponse =
            serde_json::from_str(r#"{"status":"probation"}"#).unwrap();
        assert_eq!(parsed.status, "probation");
    }

    fn fleet_key() -> SigningKey {
        ciphervault_crypto::generate_signing_key()
    }

    fn node_pk_hex() -> String {
        hex::encode(
            ciphervault_crypto::generate_signing_key()
                .verifying_key()
                .to_bytes(),
        )
    }

    fn fleet_pk_hex(key: &SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    #[test]
    fn issue_verify_round_trip() {
        let fleet = fleet_key();
        let invite = JoinInvite::issue(&fleet, node_pk_hex(), 3600).expect("issue");
        assert_eq!(invite.version, INVITE_VERSION);
        invite
            .verify(&fleet_pk_hex(&fleet), now_unix_secs())
            .expect("verify");
    }

    #[test]
    fn issue_rejects_malformed_node_and_empty_ttl() {
        let fleet = fleet_key();
        assert!(JoinInvite::issue(&fleet, "not-hex".into(), 3600).is_err());
        assert!(JoinInvite::issue(&fleet, hex::encode([7u8; 31]), 3600).is_err());
        assert!(JoinInvite::issue(&fleet, node_pk_hex(), 0).is_err());
    }

    #[test]
    fn verify_rejects_wrong_issuer_forgery_and_expiry() {
        let fleet = fleet_key();
        let other = fleet_key();
        let invite = JoinInvite::issue(&fleet, node_pk_hex(), 3600).expect("issue");
        let now = now_unix_secs();
        // Wrong fleet pin.
        assert!(invite.verify(&fleet_pk_hex(&other), now).is_err());
        // Tampered node binding breaks the signature.
        let mut tampered = invite.clone();
        tampered.node_pk_hex = node_pk_hex();
        assert!(tampered.verify(&fleet_pk_hex(&fleet), now).is_err());
        // Re-signed by a non-fleet key fails the issuer match first.
        let forged = JoinInvite::issue(&other, invite.node_pk_hex.clone(), 3600).expect("issue");
        assert!(forged.verify(&fleet_pk_hex(&fleet), now).is_err());
        // Expiry is enforced.
        assert!(invite
            .verify(&fleet_pk_hex(&fleet), invite.expires_utc + 1)
            .is_err());
    }

    #[test]
    fn verify_rejects_noncanonical_hex_spellings() {
        let fleet = fleet_key();
        let invite = JoinInvite::issue(&fleet, node_pk_hex(), 3600).expect("issue");
        let now = now_unix_secs();
        let mut upper = invite.clone();
        upper.nonce_hex = upper.nonce_hex.to_ascii_uppercase();
        assert!(upper.verify(&fleet_pk_hex(&fleet), now).is_err());
    }
}
