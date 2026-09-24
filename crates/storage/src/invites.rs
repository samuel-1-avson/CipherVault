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

/// Quorum invite version: one ticket body, K-of-N keyholder signatures.
/// Accepted alongside v1 (which counts as a single approval).
pub const INVITE_VERSION_V2: u32 = 2;

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
///
/// v1 tickets carry one signature in (`issuer_pk_hex`, `signature_hex`).
/// v2 (quorum) tickets carry K signatures in `signatures` and leave the
/// v1 fields empty; the formats never mix within one ticket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinInvite {
    pub version: u32,
    pub issuer_pk_hex: String,
    pub node_pk_hex: String,
    pub expires_utc: u64,
    pub nonce_hex: String,
    pub signature_hex: String,
    #[serde(default)]
    pub signatures: Vec<InviteSignature>,
}

/// One keyholder approval on a v2 ticket body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteSignature {
    pub signer_pk_hex: String,
    pub signature_hex: String,
}

/// Quorum ceremony step 1: the unsigned ticket body. Anyone (including
/// the joiner) may create it; the nonce is fixed here so every keyholder
/// signs the identical body. Node key is normalized to lowercase hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteRequest {
    pub node_pk_hex: String,
    pub expires_utc: u64,
    pub nonce_hex: String,
}

/// Quorum ceremony step 2: one keyholder's signature over a request.
/// The request is echoed so `combine` can prove every approval signs the
/// same body without trusting the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteApproval {
    pub request: InviteRequest,
    pub signer_pk_hex: String,
    pub signature_hex: String,
}

impl InviteRequest {
    /// Creates a request good for the next `ttl_secs` seconds.
    pub fn new(node_pk_hex: String, ttl_secs: u64) -> Result<Self, StorageError> {
        let node =
            hex::decode(&node_pk_hex).map_err(|_| forbidden("invite node key must be hex"))?;
        if node.len() != 32 {
            return Err(forbidden("invite node key must be 32 bytes"));
        }
        if ttl_secs == 0 {
            return Err(forbidden("invite TTL must be positive"));
        }
        let nonce: [u8; 32] = rand::random();
        Ok(Self {
            node_pk_hex: hex::encode(node),
            expires_utc: now_unix_secs().saturating_add(ttl_secs),
            nonce_hex: hex::encode(nonce),
        })
    }

    fn validate(&self, now_utc: u64) -> Result<(), StorageError> {
        decode_canonical_hex(&self.node_pk_hex, "node key", 32)?;
        decode_canonical_hex(&self.nonce_hex, "nonce", 32)?;
        if now_utc > self.expires_utc {
            return Err(forbidden("invite expired"));
        }
        Ok(())
    }
}

impl InviteApproval {
    /// Signs `request` with one keyholder seed. Fully offline.
    pub fn approve(signer: &SigningKey, request: &InviteRequest) -> Result<Self, StorageError> {
        request.validate(now_unix_secs())?;
        let msg = JoinInvite::quorum_signing_bytes(
            &request.node_pk_hex,
            request.expires_utc,
            &request.nonce_hex,
        );
        let sig =
            ciphervault_crypto::signatures::sign_with_domain(signer, b"operator_join_invite", &msg);
        Ok(Self {
            request: request.clone(),
            signer_pk_hex: hex::encode(signer.verifying_key().to_bytes()),
            signature_hex: hex::encode(sig),
        })
    }
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
            signatures: Vec::new(),
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
        if !self.signatures.is_empty() {
            return Err(forbidden("v1 invite must not carry quorum signatures"));
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

    /// Default quorum threshold for a key set: strict majority.
    pub fn quorum_default(set_size: usize) -> usize {
        set_size / 2 + 1
    }

    /// Signer-independent v2 ticket body. The `v2` prefix (plus the
    /// version field) separates it from v1 bodies, so a signature can
    /// never verify under the other version.
    pub fn quorum_signing_bytes(node_pk_hex: &str, expires_utc: u64, nonce_hex: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ciphervault-join-invite-v2:");
        bytes.extend_from_slice(&INVITE_VERSION_V2.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(node_pk_hex.as_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&expires_utc.to_le_bytes());
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(nonce_hex.as_bytes());
        bytes
    }

    /// Assembles a v2 ticket from a request plus keyholder approvals
    /// (`invite combine`). Validates that every approval signs this exact
    /// request, that signers are distinct, and that every signature
    /// verifies — the coordinator is never trusted. Threshold (`K`) is a
    /// server-side policy, not checked here.
    pub fn issue_quorum(
        request: &InviteRequest,
        approvals: &[InviteApproval],
    ) -> Result<Self, StorageError> {
        request.validate(now_unix_secs())?;
        if approvals.is_empty() {
            return Err(forbidden("quorum ticket needs at least one approval"));
        }
        let body = Self::quorum_signing_bytes(
            &request.node_pk_hex,
            request.expires_utc,
            &request.nonce_hex,
        );
        let mut seen: Vec<String> = Vec::new();
        let mut signatures: Vec<InviteSignature> = Vec::new();
        for approval in approvals {
            if approval.request != *request {
                return Err(forbidden("approval signs a different request"));
            }
            let signer = decode_canonical_hex(&approval.signer_pk_hex, "signer key", 32)?;
            let signer_norm = hex::encode(&signer);
            if seen.contains(&signer_norm) {
                return Err(forbidden("duplicate approval signer"));
            }
            let mut signer_arr = [0u8; 32];
            signer_arr.copy_from_slice(&signer);
            let sig = decode_canonical_hex(&approval.signature_hex, "signature", 64)?;
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig);
            ciphervault_crypto::signatures::verify_with_domain(
                &signer_arr,
                b"operator_join_invite",
                &body,
                &sig_arr,
            )
            .map_err(|_| forbidden("invite signature verification failed"))?;
            seen.push(signer_norm.clone());
            signatures.push(InviteSignature {
                signer_pk_hex: signer_norm,
                signature_hex: approval.signature_hex.clone(),
            });
        }
        Ok(Self {
            version: INVITE_VERSION_V2,
            issuer_pk_hex: String::new(),
            node_pk_hex: request.node_pk_hex.clone(),
            expires_utc: request.expires_utc,
            nonce_hex: request.nonce_hex.clone(),
            signature_hex: String::new(),
            signatures,
        })
    }

    /// Verifies a ticket against a quorum key set: at least `quorum_k`
    /// distinct valid approvals from pinned keys. A v1 ticket counts as
    /// one approval from its issuer. Returns the distinct signer keys
    /// (lowercase) for the admission evidence log. Pure — no ledger.
    pub fn verify_quorum(
        &self,
        pinned_keys: &[String],
        quorum_k: usize,
        now_utc: u64,
    ) -> Result<Vec<String>, StorageError> {
        if self.version != INVITE_VERSION && self.version != INVITE_VERSION_V2 {
            return Err(forbidden(format!(
                "unsupported invite version {}",
                self.version
            )));
        }
        if pinned_keys.is_empty() {
            return Err(forbidden("no fleet keys pinned"));
        }
        if quorum_k == 0 || quorum_k > pinned_keys.len() {
            return Err(forbidden("invalid quorum threshold"));
        }
        decode_canonical_hex(&self.node_pk_hex, "node key", 32)?;
        decode_canonical_hex(&self.nonce_hex, "nonce", 32)?;
        // Pinned set: local config, so normalize (trim + lowercase) rather
        // than demanding canonical form. Ticket-side fields stay strict.
        let mut set: Vec<String> = Vec::new();
        for key in pinned_keys {
            let bytes = hex::decode(key.trim().to_ascii_lowercase())
                .map_err(|_| forbidden("pinned fleet key must be hex"))?;
            if bytes.len() != 32 {
                return Err(forbidden("pinned fleet key must be 32 bytes"));
            }
            set.push(hex::encode(bytes));
        }
        let approvals: Vec<(String, &str, Vec<u8>)> = if self.version == INVITE_VERSION {
            if !self.signatures.is_empty() {
                return Err(forbidden("v1 invite must not carry quorum signatures"));
            }
            vec![(
                self.issuer_pk_hex.clone(),
                self.signature_hex.as_str(),
                self.signing_bytes(),
            )]
        } else {
            if !self.issuer_pk_hex.is_empty() || !self.signature_hex.is_empty() {
                return Err(forbidden("v2 invite must not carry v1 issuer fields"));
            }
            if self.signatures.is_empty() {
                return Err(forbidden("v2 invite carries no signatures"));
            }
            let body =
                Self::quorum_signing_bytes(&self.node_pk_hex, self.expires_utc, &self.nonce_hex);
            self.signatures
                .iter()
                .map(|s| {
                    (
                        s.signer_pk_hex.clone(),
                        s.signature_hex.as_str(),
                        body.clone(),
                    )
                })
                .collect()
        };
        let mut distinct: Vec<String> = Vec::new();
        for (signer_hex, sig_hex, body) in &approvals {
            let signer = decode_canonical_hex(signer_hex, "signer key", 32)?;
            let signer_norm = hex::encode(&signer);
            if !set.contains(&signer_norm) {
                return Err(forbidden("invite signer not in fleet key set"));
            }
            let mut signer_arr = [0u8; 32];
            signer_arr.copy_from_slice(&signer);
            let sig = decode_canonical_hex(sig_hex, "signature", 64)?;
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig);
            ciphervault_crypto::signatures::verify_with_domain(
                &signer_arr,
                b"operator_join_invite",
                body,
                &sig_arr,
            )
            .map_err(|_| forbidden("invite signature verification failed"))?;
            if !distinct.contains(&signer_norm) {
                distinct.push(signer_norm);
            }
        }
        if distinct.len() < quorum_k {
            return Err(forbidden(format!(
                "invite quorum not reached (have {} of {})",
                distinct.len(),
                quorum_k
            )));
        }
        if now_utc > self.expires_utc {
            return Err(forbidden("invite expired"));
        }
        Ok(distinct)
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

    fn quorum_keys(n: usize) -> (Vec<SigningKey>, Vec<String>) {
        let keys: Vec<SigningKey> = (0..n).map(|_| fleet_key()).collect();
        let pks = keys.iter().map(fleet_pk_hex).collect();
        (keys, pks)
    }

    #[test]
    fn quorum_default_is_strict_majority() {
        assert_eq!(JoinInvite::quorum_default(1), 1);
        assert_eq!(JoinInvite::quorum_default(2), 2);
        assert_eq!(JoinInvite::quorum_default(3), 2);
        assert_eq!(JoinInvite::quorum_default(4), 3);
        assert_eq!(JoinInvite::quorum_default(5), 3);
    }

    #[test]
    fn quorum_ceremony_round_trip() {
        let (keys, pks) = quorum_keys(3);
        let request = InviteRequest::new(node_pk_hex(), 3600).expect("request");
        let a0 = InviteApproval::approve(&keys[0], &request).expect("approve 0");
        let a1 = InviteApproval::approve(&keys[1], &request).expect("approve 1");
        let ticket = JoinInvite::issue_quorum(&request, &[a0, a1]).expect("combine");
        assert_eq!(ticket.version, INVITE_VERSION_V2);
        assert!(ticket.issuer_pk_hex.is_empty());
        assert_eq!(ticket.signatures.len(), 2);
        let signers = ticket
            .verify_quorum(&pks, 2, now_unix_secs())
            .expect("verify quorum");
        assert_eq!(signers, vec![pks[0].clone(), pks[1].clone()]);
    }

    #[test]
    fn quorum_combine_rejects_mismatched_duplicate_and_bad_approvals() {
        let (keys, _) = quorum_keys(2);
        let request = InviteRequest::new(node_pk_hex(), 3600).expect("request");
        let other_request = InviteRequest::new(node_pk_hex(), 3600).expect("request");
        let good = InviteApproval::approve(&keys[0], &request).expect("approve");
        // Approval for a different request body.
        let mismatched = InviteApproval::approve(&keys[1], &other_request).expect("approve");
        assert!(JoinInvite::issue_quorum(&request, &[good.clone(), mismatched]).is_err());
        // Same signer twice.
        let dup = InviteApproval::approve(&keys[0], &request).expect("approve");
        assert!(JoinInvite::issue_quorum(&request, &[good.clone(), dup]).is_err());
        // Tampered signature.
        let mut bad = InviteApproval::approve(&keys[1], &request).expect("approve");
        bad.signature_hex = hex::encode([9u8; 64]);
        assert!(JoinInvite::issue_quorum(&request, &[good, bad]).is_err());
        // Empty approval set.
        assert!(JoinInvite::issue_quorum(&request, &[]).is_err());
    }

    #[test]
    fn quorum_verify_enforces_threshold() {
        let (keys, pks) = quorum_keys(3);
        let request = InviteRequest::new(node_pk_hex(), 3600).expect("request");
        let a0 = InviteApproval::approve(&keys[0], &request).expect("approve");
        let ticket = JoinInvite::issue_quorum(&request, &[a0]).expect("combine");
        let err = ticket
            .verify_quorum(&pks, 2, now_unix_secs())
            .expect_err("below threshold");
        assert!(err.to_string().contains("have 1 of 2"), "{err}");
        // Same ticket passes at K=1.
        assert_eq!(
            ticket
                .verify_quorum(&pks, 1, now_unix_secs())
                .expect("K=1")
                .len(),
            1
        );
    }

    #[test]
    fn quorum_verify_rejects_unknown_signer() {
        let (keys, _) = quorum_keys(2);
        let outsider = fleet_key();
        let set = vec![fleet_pk_hex(&keys[0]), fleet_pk_hex(&keys[1])];
        let request = InviteRequest::new(node_pk_hex(), 3600).expect("request");
        let a0 = InviteApproval::approve(&keys[0], &request).expect("approve");
        let rogue = InviteApproval::approve(&outsider, &request).expect("rogue approve");
        // Combine succeeds (it checks signatures, not the pinned set)...
        let ticket = JoinInvite::issue_quorum(&request, &[a0, rogue]).expect("combine");
        // ...but verification against the pinned set rejects the ticket.
        let err = ticket
            .verify_quorum(&set, 1, now_unix_secs())
            .expect_err("unknown signer");
        assert!(err.to_string().contains("not in fleet key set"), "{err}");
    }

    #[test]
    fn quorum_v1_ticket_counts_as_single_approval() {
        let (keys, pks) = quorum_keys(2);
        let v1 = JoinInvite::issue(&keys[0], node_pk_hex(), 3600).expect("issue");
        let now = now_unix_secs();
        assert_eq!(v1.verify_quorum(&pks, 1, now).expect("K=1").len(), 1);
        assert!(v1.verify_quorum(&pks, 2, now).is_err());
        // v1 issuer outside the set is rejected, not counted.
        let outsider = fleet_key();
        let rogue = JoinInvite::issue(&outsider, node_pk_hex(), 3600).expect("issue");
        assert!(rogue.verify_quorum(&pks, 1, now).is_err());
    }

    #[test]
    fn quorum_cross_version_replay_fails() {
        let (keys, pks) = quorum_keys(2);
        let now = now_unix_secs();
        // A v1 signature transplanted into a v2 ticket cannot verify: the
        // v2 body differs from the v1 body it was computed over.
        let v1 = JoinInvite::issue(&keys[0], node_pk_hex(), 3600).expect("issue");
        let forged_v2 = JoinInvite {
            version: INVITE_VERSION_V2,
            issuer_pk_hex: String::new(),
            node_pk_hex: v1.node_pk_hex.clone(),
            expires_utc: v1.expires_utc,
            nonce_hex: v1.nonce_hex.clone(),
            signature_hex: String::new(),
            signatures: vec![InviteSignature {
                signer_pk_hex: v1.issuer_pk_hex.clone(),
                signature_hex: v1.signature_hex.clone(),
            }],
        };
        assert!(forged_v2.verify_quorum(&pks, 1, now).is_err());
        // Flipping a v1 ticket's version to 2 also fails (missing v2 sigs
        // plus stale v1 issuer fields).
        let mut flipped = v1.clone();
        flipped.version = INVITE_VERSION_V2;
        assert!(flipped.verify_quorum(&pks, 1, now).is_err());
    }

    #[test]
    fn quorum_rejects_mixed_formats() {
        let (keys, pks) = quorum_keys(2);
        let now = now_unix_secs();
        // v1 ticket carrying quorum signatures: rejected by both paths.
        let mut mixed_v1 = JoinInvite::issue(&keys[0], node_pk_hex(), 3600).expect("issue");
        mixed_v1.signatures.push(InviteSignature {
            signer_pk_hex: fleet_pk_hex(&keys[1]),
            signature_hex: hex::encode([1u8; 64]),
        });
        assert!(mixed_v1.verify(&fleet_pk_hex(&keys[0]), now).is_err());
        assert!(mixed_v1.verify_quorum(&pks, 1, now).is_err());
        // v2 ticket carrying v1 issuer fields: rejected.
        let request = InviteRequest::new(node_pk_hex(), 3600).expect("request");
        let a0 = InviteApproval::approve(&keys[0], &request).expect("approve");
        let mut mixed_v2 = JoinInvite::issue_quorum(&request, &[a0]).expect("combine");
        mixed_v2.issuer_pk_hex = fleet_pk_hex(&keys[0]);
        assert!(mixed_v2.verify_quorum(&pks, 1, now).is_err());
    }

    #[test]
    fn quorum_enforces_canonical_hex_and_expiry() {
        let (keys, pks) = quorum_keys(2);
        let request = InviteRequest::new(node_pk_hex(), 3600).expect("request");
        let a0 = InviteApproval::approve(&keys[0], &request).expect("approve");
        let a1 = InviteApproval::approve(&keys[1], &request).expect("approve");
        let ticket = JoinInvite::issue_quorum(&request, &[a0, a1]).expect("combine");
        let now = now_unix_secs();
        let mut upper = ticket.clone();
        upper.signatures[0].signer_pk_hex = upper.signatures[0].signer_pk_hex.to_ascii_uppercase();
        assert!(upper.verify_quorum(&pks, 2, now).is_err());
        assert!(ticket
            .verify_quorum(&pks, 2, ticket.expires_utc + 1)
            .is_err());
    }

    #[test]
    fn quorum_request_normalizes_node_key_and_validates_ttl() {
        let upper = node_pk_hex().to_ascii_uppercase();
        let request = InviteRequest::new(upper.clone(), 60).expect("request");
        assert_eq!(request.node_pk_hex, upper.to_ascii_lowercase());
        assert!(InviteRequest::new(node_pk_hex(), 0).is_err());
        assert!(InviteRequest::new("not-hex".into(), 60).is_err());
        assert!(InviteApproval::approve(&fleet_key(), &request).is_ok());
    }

    #[test]
    fn quorum_json_round_trip_and_v1_back_compat() {
        let (keys, _) = quorum_keys(2);
        let request = InviteRequest::new(node_pk_hex(), 3600).expect("request");
        let parsed_request: InviteRequest =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        assert_eq!(parsed_request, request);
        let approval = InviteApproval::approve(&keys[0], &request).expect("approve");
        let parsed_approval: InviteApproval =
            serde_json::from_str(&serde_json::to_string(&approval).unwrap()).unwrap();
        assert_eq!(parsed_approval, approval);
        let a1 = InviteApproval::approve(&keys[1], &request).expect("approve");
        let ticket = JoinInvite::issue_quorum(&request, &[approval, a1]).expect("combine");
        let parsed_ticket: JoinInvite =
            serde_json::from_str(&serde_json::to_string(&ticket).unwrap()).unwrap();
        assert_eq!(parsed_ticket, ticket);
        // v1 JSON (no `signatures` field) still parses with an empty vec.
        let v1 = JoinInvite::issue(&keys[0], node_pk_hex(), 3600).expect("issue");
        let mut v1_value = serde_json::to_value(&v1).unwrap();
        v1_value.as_object_mut().unwrap().remove("signatures");
        let parsed_v1: JoinInvite = serde_json::from_value(v1_value).unwrap();
        assert!(parsed_v1.signatures.is_empty());
        parsed_v1
            .verify(&fleet_pk_hex(&keys[0]), now_unix_secs())
            .expect("legacy v1 verify");
    }
}
