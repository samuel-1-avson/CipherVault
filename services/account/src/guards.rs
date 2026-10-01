//! Role, membership, and session guards plus account-id codecs.

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::AccountState;
use crate::{error_response, service_error, AccountServiceError, SessionView};

pub(crate) fn normalize_vault_role(value: &str) -> Result<String, AccountServiceError> {
    let role = value.trim().to_ascii_lowercase();
    match role.as_str() {
        "owner" | "admin" | "editor" | "viewer" | "recovery" => Ok(role),
        _ => Err(AccountServiceError::Invalid(
            "role must be one of owner, admin, editor, viewer, or recovery".into(),
        )),
    }
}

pub(crate) fn role_rank(role: &str) -> u8 {
    match role {
        "owner" => 4,
        "admin" => 3,
        "editor" => 2,
        "viewer" => 1,
        "recovery" => 0,
        _ => 0,
    }
}

pub(crate) fn active_membership_role(
    db: &Connection,
    account_id: &str,
    member_account_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    if account_id == member_account_id {
        return Ok(Some("owner".into()));
    }
    db.query_row(
        "SELECT role FROM memberships
         WHERE account_id = ?1 AND member_account_id = ?2
           AND status = 'active' AND accepted_at_utc IS NOT NULL
           AND revoked_at_utc IS NULL",
        params![account_id, member_account_id],
        |row| row.get(0),
    )
    .optional()
}

/// Authorize a session against an account's active membership. Owners are
/// implicit; invited accounts must have an accepted, non-revoked membership.
#[allow(clippy::result_large_err)]
#[cfg(test)]
pub(crate) fn account_role_for(
    state: &AccountState,
    headers: &HeaderMap,
    account_id: &str,
    minimum_role: &str,
) -> Result<(SessionView, String), Box<Response>> {
    let db = state
        .connection()
        .map_err(|error| Box::new(service_error(error)))?;
    account_role_for_with_db(&db, headers, account_id, minimum_role)
}

/// Revalidate identity, policy and role while holding the connection used for
/// storage. An earlier SessionView cannot authorize a later mutation after
/// logout, factor/policy changes or membership revocation.
#[allow(clippy::result_large_err)]
pub(crate) fn account_role_for_with_db(
    db: &Connection,
    headers: &HeaderMap,
    account_id: &str,
    minimum_role: &str,
) -> Result<(SessionView, String), Box<Response>> {
    let mut session = crate::http::authenticated_session_with_db(db, headers).map_err(Box::new)?;
    session.mfa_required |= crate::mfa::policy_required(db, account_id)
        .map_err(|error| Box::new(service_error(error.into())))?;
    let role = active_membership_role(db, account_id, &session.account_id)
        .map_err(|error| Box::new(service_error(error.into())))?;
    let Some(role) = role else {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_MEMBERSHIP_REQUIRED",
            "Session is not an active member of this account",
        )));
    };
    if role_rank(&role) < role_rank(minimum_role) {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_ROLE_REQUIRED",
            format!("This action requires the {minimum_role} role"),
        )));
    }
    Ok((session, role))
}

pub(crate) fn require_recent_account_role_with_db(
    db: &Connection,
    headers: &HeaderMap,
    account_id: &str,
    minimum_role: &str,
) -> Result<(SessionView, String), Box<Response>> {
    let (session, role) = account_role_for_with_db(db, headers, account_id, minimum_role)?;
    require_recent_strong_session(&session, crate::state::now_utc())?;
    Ok((session, role))
}

/// Sensitive credential operations are owned by the authenticated account,
/// rather than delegated account administrators.
pub(crate) fn require_recent_account_session_with_db(
    db: &Connection,
    headers: &HeaderMap,
    account_id: &str,
) -> Result<SessionView, Box<Response>> {
    let session = crate::http::authenticated_session_with_db(db, headers).map_err(Box::new)?;
    if session.account_id != account_id {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        )));
    }
    require_recent_strong_session(&session, crate::state::now_utc())?;
    Ok(session)
}

/// Mutations require a strong (non-recovery) session even when the role gate
/// passes: recovery sessions read as their account's implicit owner, but must
/// enroll a device before changing account state.
pub(crate) fn require_strong_session(session: &SessionView) -> Result<(), Box<Response>> {
    if session.auth_method == "recovery" {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "RECOVERY_STEP_UP_REQUIRED",
            "Recovery sessions must enroll a device before account changes",
        )));
    }
    Ok(())
}

/// Credential issuance and sensitive scoped actions require fresh proof of a
/// signing key or passkey. TOTP login alone is an alternate login method, not
/// a verified second factor or an elevation ceremony.
pub(crate) const STEP_UP_MAX_AGE_SECONDS: u64 = 5 * 60;

pub(crate) fn require_recent_strong_session(
    session: &SessionView,
    now: u64,
) -> Result<(), Box<Response>> {
    require_recent_primary_session(session, now)?;
    if session.mfa_required
        && !session.mfa_verified_at_utc.is_some_and(|verified| {
            verified <= now && now.saturating_sub(verified) < STEP_UP_MAX_AGE_SECONDS
        })
    {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "MFA_STEP_UP_REQUIRED",
            "Verify your authenticator code for this session before this action",
        )));
    }
    Ok(())
}

pub(crate) fn require_recent_primary_session(
    session: &SessionView,
    now: u64,
) -> Result<(), Box<Response>> {
    require_strong_session(session)?;
    if !matches!(session.auth_method.as_str(), "device" | "webauthn")
        || session.issued_at_utc > now
        || now.saturating_sub(session.issued_at_utc) > STEP_UP_MAX_AGE_SECONDS
    {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "AUTHENTICATION_STEP_UP_REQUIRED",
            "Authenticate with a signing key or passkey within the last five minutes",
        )));
    }
    Ok(())
}

pub(crate) fn decode_32(value: &str, field: &str) -> Result<[u8; 32], AccountServiceError> {
    let bytes = hex::decode(value.trim())
        .map_err(|_| AccountServiceError::Invalid(format!("{field} must be 32-byte hex")))?;
    bytes
        .try_into()
        .map_err(|_| AccountServiceError::Invalid(format!("{field} must be 32-byte hex")))
}

pub(crate) fn normalize_account_id(value: &str) -> Result<String, AccountServiceError> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 39
        || !value.starts_with("cvacct_")
        || hex::decode(&value[7..]).map(|bytes| bytes.len()) != Ok(16)
    {
        return Err(AccountServiceError::Invalid(
            "account_id must use cvacct_<32 hex characters>".into(),
        ));
    }
    Ok(value)
}

pub(crate) fn derive_account_id(public_key_hex: &str) -> Result<String, AccountServiceError> {
    let public_key = decode_32(public_key_hex, "account_public_key_hex")?;
    Ok(format!(
        "cvacct_{}",
        hex::encode(&Sha256::digest(public_key)[..16])
    ))
}

#[cfg(test)]
mod storage_guard_tests {
    use super::*;
    use crate::state::now_utc;
    use crate::test_support::{cleanup, test_app};
    use crate::util::{hash_token, random_hex};

    fn fixture(name: &str) -> (std::path::PathBuf, AccountState, String, String, HeaderMap) {
        let (root, state, _) = test_app(name);
        let account = format!("cvacct_{}", random_hex(16));
        let token = random_hex(32);
        let now = now_utc();
        {
            let db = state.connection().unwrap();
            db.execute("INSERT INTO accounts(account_id,display_name,account_public_key_hex,created_at_utc)
                VALUES(?1,'Storage guard regression',?2,?3)",
                params![account, "22".repeat(32), now]).unwrap();
            db.execute("INSERT INTO sessions(token_hash_hex,account_id,session_kind,issued_at_utc,expires_at_utc)
                VALUES(?1,?2,'device',?3,?4)", params![hash_token(&token), account, now, now+1800]).unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        (root, state, account, token, headers)
    }

    #[test]
    fn revoked_session_between_initial_auth_and_storage_cannot_mutate() {
        let (root, state, account, token, headers) = fixture("guard-revocation");
        let (cached, _) = account_role_for(&state, &headers, &account, "owner").unwrap();
        assert!(require_recent_strong_session(&cached, now_utc()).is_ok());
        let db = state.connection().unwrap();
        db.execute(
            "UPDATE sessions SET revoked_at_utc=?2 WHERE token_hash_hex=?1",
            params![hash_token(&token), now_utc()],
        )
        .unwrap();
        // A cached view still passes, which is why credential handlers must
        // use the current held-connection guard before writing.
        assert!(require_recent_strong_session(&cached, now_utc()).is_ok());
        assert_eq!(
            require_recent_account_session_with_db(&db, &headers, &account)
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            require_recent_account_role_with_db(&db, &headers, &account, "owner")
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        drop(db);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn policy_enabled_between_initial_auth_and_storage_requires_current_factor() {
        let (root, state, account, _, headers) = fixture("guard-policy-change");
        let (cached, _) = account_role_for(&state, &headers, &account, "owner").unwrap();
        assert!(!cached.mfa_required);
        let db = state.connection().unwrap();
        db.execute(
            "INSERT INTO account_mfa_policy VALUES(?1,1,?2)",
            params![account, now_utc()],
        )
        .unwrap();
        assert!(require_recent_strong_session(&cached, now_utc()).is_ok());
        assert_eq!(
            require_recent_account_session_with_db(&db, &headers, &account)
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            require_recent_account_role_with_db(&db, &headers, &account, "owner")
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        drop(db);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn target_policy_or_revoked_role_is_rechecked_for_delegated_admin() {
        let (root, state, actor, _, headers) = fixture("guard-membership-change");
        let target = format!("cvacct_{}", random_hex(16));
        {
            let db = state.connection().unwrap();
            db.execute("INSERT INTO accounts(account_id,display_name,account_public_key_hex,created_at_utc)
                VALUES(?1,'Target',?2,?3)",
                params![target,"33".repeat(32),now_utc()]).unwrap();
            db.execute("INSERT INTO memberships(account_id,member_account_id,role,status,invited_at_utc,accepted_at_utc)
                VALUES(?1,?2,'admin','active',?3,?3)", params![target,actor,now_utc()]).unwrap();
        }
        let (cached, _) = account_role_for(&state, &headers, &target, "admin").unwrap();
        assert!(require_recent_strong_session(&cached, now_utc()).is_ok());
        let db = state.connection().unwrap();
        db.execute(
            "INSERT INTO account_mfa_policy VALUES(?1,1,?2)",
            params![target, now_utc()],
        )
        .unwrap();
        assert_eq!(
            require_recent_account_role_with_db(&db, &headers, &target, "admin")
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        db.execute(
            "UPDATE account_mfa_policy SET required=0 WHERE account_id=?1",
            [&target],
        )
        .unwrap();
        db.execute(
            "UPDATE memberships SET revoked_at_utc=?3 WHERE account_id=?1 AND member_account_id=?2",
            params![target, actor, now_utc()],
        )
        .unwrap();
        assert_eq!(
            require_recent_account_role_with_db(&db, &headers, &target, "admin")
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        drop(db);
        drop(state);
        cleanup(root);
    }
}
