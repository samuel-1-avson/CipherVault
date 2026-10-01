//! Short-lived HMAC-signed scope tokens (Phase 3, T-302).
//!
//! Bearer format: `cvst1.<base64url(claims-json)>.<base64url(hmac-sha256)>`.
//! The MAC covers a domain string, the version prefix, and the payload, so a
//! token cannot be retargeted across versions or scopes. Verification is
//! constant-time on the MAC and fails closed (single generic error, no
//! oracle). Revocation before expiry uses the `scope_token_denylist` table;
//! tokens are short-lived (5–15 minutes) so the denylist stays tiny.
//!
//! Key rotation: a single HMAC key is active at a time. Rotation invalidates
//! outstanding tokens, which callers transparently re-mint via OIDC/session
//! login (Phase 4); the 5–15 minute TTL bounds the re-auth window. The `cvst1`
//! prefix versions the wire format for future algorithm agility.

use ring::hmac::{self, Key, HMAC_SHA256};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::AccountServiceError;
use crate::util::{b64_decode, b64_encode, random_hex};

pub(crate) const SCOPE_TOKEN_KEY_ENV: &str = "CIPHERVAULT_ACCOUNT_SCOPE_TOKEN_KEY";
pub(crate) const SCOPE_TOKEN_KEY_FILE_ENV: &str = "CIPHERVAULT_ACCOUNT_SCOPE_TOKEN_KEY_FILE";
pub(crate) const SCOPE_TOKEN_PREFIX: &str = "cvst1";
pub(crate) const SCOPE_TOKEN_MAX_PAYLOAD_BYTES: usize = 4096;
pub(crate) const SCOPE_TOKEN_SKEW_SECONDS: u64 = 60;

const MAC_DOMAIN: &[u8] = b"cv-scope-token-v1";

/// Authenticated scope claims carried by a token. `None` environment means a
/// project-management token that can never satisfy an environment target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeClaims {
    pub tenant_id: String,
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    /// Legacy branch metadata. This never establishes trusted attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Key confirmation (DPoP-lite, T-902): ed25519 public key hex the token
    /// is bound to. `Some` means every use must carry a `DPoP` proof signed
    /// by the key; `None` keeps plain bearer semantics. MAC'd with the rest
    /// of the payload, so binding cannot be stripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<String>,
    /// Source session hash binds issued credentials to logout, recovery and
    /// device/passkey revocation. No raw session token is placed in claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_session_hash: Option<String>,
    /// Bind this credential to the second-factor proof present at issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_proof_id: Option<String>,
    /// Explicit human elevation expires with the fresh authentication window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevated_until_utc: Option<u64>,
    pub principal_id: String,
    pub issued_at_utc: u64,
    pub expires_at_utc: u64,
    pub jti: String,
}

impl ScopeClaims {
    /// Builds claims with a fresh random `jti`; scope narrowed via builders.
    pub fn new(
        tenant_id: &str,
        project_id: &str,
        principal_id: &str,
        issued_at_utc: u64,
        expires_at_utc: u64,
    ) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            project_id: project_id.to_string(),
            environment_id: None,
            repository_binding_id: None,
            service_id: None,
            branch: None,
            cnf: None,
            origin_session_hash: None,
            mfa_proof_id: None,
            elevated_until_utc: None,
            principal_id: principal_id.to_string(),
            issued_at_utc,
            expires_at_utc,
            jti: random_hex(16),
        }
    }

    /// Narrows the token to one environment.
    pub fn with_environment(mut self, environment_id: &str) -> Self {
        self.environment_id = Some(environment_id.to_string());
        self
    }

    /// Narrows the token to one repository binding.
    pub fn with_repository_binding(mut self, binding_id: &str) -> Self {
        self.repository_binding_id = Some(binding_id.to_string());
        self
    }

    /// Narrows the token to one service.
    pub fn with_service(mut self, service_id: &str) -> Self {
        self.service_id = Some(service_id.to_string());
        self
    }

    /// Binds the token to an ed25519 public key (lowercase hex, validated at
    /// mint). Key-bound tokens require a `DPoP` proof on every use.
    pub fn with_cnf(mut self, public_key_hex: &str) -> Self {
        self.cnf = Some(public_key_hex.to_string());
        self
    }

    /// Synthesizes claims for an account-session caller. Identity comes from
    /// the verified session and scope from the explicit request path plus the
    /// project row; temporal fields are inert (expiry is enforced by the
    /// session itself, and these claims are never minted or denied).
    pub(crate) fn for_session(
        tenant_id: &str,
        project_id: &str,
        environment_id: Option<&str>,
        account_id: &str,
    ) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            project_id: project_id.to_string(),
            environment_id: environment_id.map(str::to_string),
            repository_binding_id: None,
            service_id: None,
            branch: None,
            cnf: None,
            origin_session_hash: None,
            mfa_proof_id: None,
            elevated_until_utc: None,
            principal_id: format!("account:{account_id}"),
            issued_at_utc: 0,
            expires_at_utc: u64::MAX,
            jti: "session".to_string(),
        }
    }

    fn validate_shape(&self) -> Result<(), AccountServiceError> {
        let invalid =
            |what: &str| AccountServiceError::Invalid(format!("invalid scope token ({what})"));
        if self.tenant_id.trim().is_empty()
            || self.project_id.trim().is_empty()
            || self.principal_id.trim().is_empty()
            || self.jti.trim().is_empty()
        {
            return Err(invalid("empty identity"));
        }
        if self.expires_at_utc <= self.issued_at_utc {
            return Err(invalid("expiry"));
        }
        Ok(())
    }
}

/// Loads the 32-byte hex HMAC key, preferring the file variable (mirrors
/// `totp_wrapping_key`). Split for testability: production passes the real
/// variable names.
pub(crate) fn scope_token_signing_key() -> Result<[u8; 32], AccountServiceError> {
    scope_token_signing_key_from(SCOPE_TOKEN_KEY_FILE_ENV, SCOPE_TOKEN_KEY_ENV)
}

pub(crate) fn scope_token_signing_key_from(
    file_env: &str,
    direct_env: &str,
) -> Result<[u8; 32], AccountServiceError> {
    let raw = match std::env::var(file_env) {
        Ok(path) if !path.trim().is_empty() => {
            std::fs::read_to_string(path.trim()).map_err(|_| {
                AccountServiceError::Invalid(format!(
                    "{file_env} must reference a readable 32-byte hex key file"
                ))
            })?
        }
        _ => std::env::var(direct_env).map_err(|_| {
            AccountServiceError::Invalid(format!(
                "{file_env} or {direct_env} must be configured before minting scope tokens"
            ))
        })?,
    };
    parse_signing_key(&raw)
}

fn parse_signing_key(raw: &str) -> Result<[u8; 32], AccountServiceError> {
    let bytes = hex::decode(raw.trim()).map_err(|_| {
        AccountServiceError::Invalid("scope-token signing key must be 32-byte hex".into())
    })?;
    bytes.try_into().map_err(|_| {
        AccountServiceError::Invalid("scope-token signing key must be 32-byte hex".into())
    })
}

/// Mints a signed bearer token for validated claims.
pub(crate) fn mint_scope_token(
    key: &[u8; 32],
    claims: &ScopeClaims,
) -> Result<String, AccountServiceError> {
    claims.validate_shape()?;
    let payload = serde_json::to_vec(claims)
        .map_err(|err| AccountServiceError::Invalid(format!("claims not encodable: {err}")))?;
    let payload_b64 = b64_encode(&payload);
    let tag = hmac::sign(&Key::new(HMAC_SHA256, key), &mac_input(&payload_b64));
    Ok(format!(
        "{SCOPE_TOKEN_PREFIX}.{payload_b64}.{}",
        b64_encode(tag.as_ref())
    ))
}

/// Verifies shape, MAC, and lifetime. Every failure maps to one generic
/// error so callers cannot distinguish bad-MAC from expired from malformed.
pub(crate) fn verify_scope_token(
    key: &[u8; 32],
    token: &str,
    now_utc: u64,
) -> Result<ScopeClaims, AccountServiceError> {
    let invalid = || AccountServiceError::Invalid("invalid scope token".into());
    let mut parts = token.trim().split('.');
    let (Some(prefix), Some(payload_b64), Some(mac_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid());
    };
    if prefix != SCOPE_TOKEN_PREFIX {
        return Err(invalid());
    }
    let mac = b64_decode(mac_b64, "scope_token").map_err(|_| invalid())?;
    hmac::verify(&Key::new(HMAC_SHA256, key), &mac_input(payload_b64), &mac)
        .map_err(|_| invalid())?;
    let payload = b64_decode(payload_b64, "scope_token").map_err(|_| invalid())?;
    if payload.len() > SCOPE_TOKEN_MAX_PAYLOAD_BYTES {
        return Err(invalid());
    }
    let claims: ScopeClaims = serde_json::from_slice(&payload).map_err(|_| invalid())?;
    claims.validate_shape().map_err(|_| invalid())?;
    if now_utc >= claims.expires_at_utc {
        return Err(invalid());
    }
    if claims.issued_at_utc > now_utc.saturating_add(SCOPE_TOKEN_SKEW_SECONDS) {
        return Err(invalid());
    }
    Ok(claims)
}

fn mac_input(payload_b64: &str) -> Vec<u8> {
    [
        MAC_DOMAIN,
        SCOPE_TOKEN_PREFIX.as_bytes(),
        b".",
        payload_b64.as_bytes(),
    ]
    .concat()
}

/// Resolve revocable issuer context against the same connection used for
/// policy/storage. This closes the gap between HTTP authentication and an
/// operation if logout or credential revocation happens between those steps.
pub(crate) fn scope_origin_active(
    db: &Connection,
    claims: &ScopeClaims,
    now: u64,
    require_strong: bool,
) -> Result<bool, rusqlite::Error> {
    if !crate::mfa::scope_mfa_active(db, claims, now)? {
        return Ok(false);
    }
    let Some(origin) = claims.origin_session_hash.as_deref() else {
        return Ok(true);
    };
    db.query_row("SELECT EXISTS(SELECT 1 FROM sessions s
        WHERE s.token_hash_hex = ?1 AND ('account:' || s.account_id) = ?2
          AND s.revoked_at_utc IS NULL AND s.expires_at_utc > ?3
          AND (?4 = 0 OR s.session_kind IN ('device', 'webauthn'))
          AND (s.device_id_hex IS NULL OR EXISTS(SELECT 1 FROM devices d
               WHERE d.account_id = s.account_id AND d.device_id_hex = s.device_id_hex AND d.revoked_at_utc IS NULL))
          AND (s.credential_id_hex IS NULL OR EXISTS(SELECT 1 FROM webauthn_credentials c
               WHERE c.account_id = s.account_id AND c.credential_id_hex = s.credential_id_hex AND c.revoked_at_utc IS NULL)))",
        params![origin, claims.principal_id, now, require_strong], |row| row.get(0))
}

/// Revokes a token id until its expiry (upsert: re-deny extends).
pub(crate) fn deny_scope_token(
    db: &Connection,
    jti: &str,
    expires_at_utc: u64,
) -> Result<(), rusqlite::Error> {
    db.execute(
        "INSERT INTO scope_token_denylist(jti, expires_at_utc) VALUES(?1, ?2)
         ON CONFLICT(jti) DO UPDATE SET expires_at_utc = excluded.expires_at_utc",
        params![jti, expires_at_utc],
    )?;
    Ok(())
}

/// Whether a token id is currently denied.
pub(crate) fn scope_token_denied(db: &Connection, jti: &str) -> Result<bool, rusqlite::Error> {
    Ok(db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM scope_token_denylist WHERE jti = ?1)",
            params![jti],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(false))
}

/// Drops denylist rows whose tokens have expired. Returns rows removed.
pub(crate) fn prune_scope_denylist(
    db: &Connection,
    now_utc: u64,
) -> Result<usize, rusqlite::Error> {
    db.execute(
        "DELETE FROM scope_token_denylist WHERE expires_at_utc <= ?1",
        params![now_utc],
    )?;
    Ok(db.changes() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{cleanup, test_app};

    const TEST_KEY: [u8; 32] = [0x11; 32];
    const OTHER_KEY: [u8; 32] = [0x22; 32];

    fn test_claims() -> ScopeClaims {
        ScopeClaims::new("t1", "p1", "account:alice", 1000, 1900).with_environment("e1")
    }

    #[test]
    fn mint_verify_roundtrip() {
        let claims = test_claims();
        let token = mint_scope_token(&TEST_KEY, &claims).unwrap();
        assert!(token.starts_with("cvst1."));
        let back = verify_scope_token(&TEST_KEY, &token, 1500).unwrap();
        assert_eq!(back, claims);
    }

    #[test]
    fn tampered_payload_mac_prefix_or_key_rejected() {
        let token = mint_scope_token(&TEST_KEY, &test_claims()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        // Flip a payload character (keeps valid base64url alphabet).
        let mut payload = parts[1].to_string();
        let first = payload.remove(0);
        payload.insert(0, if first == 'A' { 'B' } else { 'A' });
        let tampered = format!("{}.{}.{}", parts[0], payload, parts[2]);
        assert!(verify_scope_token(&TEST_KEY, &tampered, 1500).is_err());
        // Flip a MAC character.
        let mut mac = parts[2].to_string();
        let first = mac.remove(0);
        mac.insert(0, if first == 'A' { 'B' } else { 'A' });
        let tampered = format!("{}.{}.{}", parts[0], parts[1], mac);
        assert!(verify_scope_token(&TEST_KEY, &tampered, 1500).is_err());
        // Wrong prefix and wrong key.
        parts[0] = "cvst9";
        assert!(verify_scope_token(&TEST_KEY, &parts.join("."), 1500).is_err());
        assert!(verify_scope_token(&OTHER_KEY, &token, 1500).is_err());
        // Malformed shapes.
        for bad in ["", "cvst1", "cvst1.a", "cvst1.a.b.c", "cvst1.!!!.!!!"] {
            assert!(verify_scope_token(&TEST_KEY, bad, 1500).is_err(), "{bad}");
        }
    }

    #[test]
    fn expired_or_future_dated_rejected() {
        let token = mint_scope_token(&TEST_KEY, &test_claims()).unwrap();
        assert!(verify_scope_token(&TEST_KEY, &token, 1900).is_err());
        assert!(verify_scope_token(&TEST_KEY, &token, 9999).is_err());
        let future = ScopeClaims::new("t1", "p1", "a", 5000, 6000);
        let token = mint_scope_token(&TEST_KEY, &future).unwrap();
        assert!(verify_scope_token(&TEST_KEY, &token, 1000).is_err());
    }

    #[test]
    fn malformed_claims_rejected() {
        let mut empty = test_claims();
        empty.project_id.clear();
        assert!(mint_scope_token(&TEST_KEY, &empty).is_err());
        let inverted = ScopeClaims::new("t1", "p1", "a", 2000, 1000);
        assert!(mint_scope_token(&TEST_KEY, &inverted).is_err());
    }

    #[test]
    fn denylist_lifecycle() {
        let (root, state, _app) = test_app("scope-denylist");
        let db = state.connection().unwrap();
        assert!(!scope_token_denied(&db, "jti-1").unwrap());
        deny_scope_token(&db, "jti-1", 2000).unwrap();
        assert!(scope_token_denied(&db, "jti-1").unwrap());
        // Re-deny extends; prune drops only expired rows.
        deny_scope_token(&db, "jti-1", 3000).unwrap();
        deny_scope_token(&db, "jti-2", 1500).unwrap();
        assert_eq!(prune_scope_denylist(&db, 1600).unwrap(), 1);
        assert!(scope_token_denied(&db, "jti-1").unwrap());
        assert!(!scope_token_denied(&db, "jti-2").unwrap());
        cleanup(root);
    }

    #[test]
    fn signing_key_parsing() {
        assert!(parse_signing_key(&"ab".repeat(32)).is_ok());
        assert!(parse_signing_key("not-hex").is_err());
        assert!(parse_signing_key(&"ab".repeat(31)).is_err());
        assert!(parse_signing_key("").is_err());
    }

    #[test]
    fn signing_key_env_loading() {
        let file_var = "CIPHERVAULT_TEST_STSK_FILE_MINT";
        let direct_var = "CIPHERVAULT_TEST_STSK_DIRECT_MINT";
        std::env::remove_var(file_var);
        std::env::remove_var(direct_var);
        assert!(scope_token_signing_key_from(file_var, direct_var).is_err());
        std::env::set_var(direct_var, "zz-nope");
        assert!(scope_token_signing_key_from(file_var, direct_var).is_err());
        std::env::set_var(direct_var, "ab".repeat(32));
        let key = scope_token_signing_key_from(file_var, direct_var).unwrap();
        assert_eq!(key, [0xab; 32]);
        std::env::remove_var(direct_var);
    }
}
