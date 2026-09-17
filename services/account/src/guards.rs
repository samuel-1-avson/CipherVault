//! Role, membership, and session guards plus account-id codecs.

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::{
    authenticated_session, error_response, service_error, AccountServiceError, AccountState,
    SessionView,
};

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
pub(crate) fn account_role_for(
    state: &AccountState,
    headers: &HeaderMap,
    account_id: &str,
    minimum_role: &str,
) -> Result<(SessionView, String), Box<Response>> {
    let session = authenticated_session(state, headers).map_err(Box::new)?;
    let db = state
        .connection()
        .map_err(|error| Box::new(service_error(error)))?;
    let role = active_membership_role(&db, account_id, &session.account_id)
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
