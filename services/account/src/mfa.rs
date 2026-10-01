//! Durable account policy and session-bound TOTP second-factor verification.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;

use crate::guards::{
    normalize_account_id, require_recent_primary_session, STEP_UP_MAX_AGE_SECONDS,
};
use crate::http::{
    auth_rate_failure_with_db, auth_rate_key, auth_rate_success_with_db,
    authenticated_session_with_db, clear_session_cookie, error_response, service_error,
    session_token,
};
use crate::state::{now_utc, AccountState, SessionView, TotpCodeRequest};
use crate::util::{audit_event, hash_token, random_hex};

pub(crate) fn init_schema(db: &Connection) -> Result<(), rusqlite::Error> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS account_mfa_policy (
        account_id TEXT PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
        required INTEGER NOT NULL CHECK(required IN (0,1)),
        updated_at_utc INTEGER NOT NULL
    ); CREATE TABLE IF NOT EXISTS session_mfa (
        token_hash_hex TEXT PRIMARY KEY REFERENCES sessions(token_hash_hex) ON DELETE CASCADE,
        proof_id TEXT NOT NULL UNIQUE,
        verified_at_utc INTEGER NOT NULL,
        credential_fingerprint TEXT NOT NULL
    );",
    )
}

pub(crate) fn policy_required(db: &Connection, account_id: &str) -> Result<bool, rusqlite::Error> {
    Ok(db
        .query_row(
            "SELECT required FROM account_mfa_policy WHERE account_id = ?1",
            [account_id],
            |row| row.get::<_, bool>(0),
        )
        .optional()?
        .unwrap_or(false))
}

pub(crate) fn apply_session_status(
    db: &Connection,
    token_hash: &str,
    session: &mut SessionView,
    now: u64,
) -> Result<(), rusqlite::Error> {
    session.mfa_required = policy_required(db, &session.account_id)?;
    session.mfa_verified_at_utc = None;
    session.mfa_proof_id = None;
    let proof = db
        .query_row(
            "SELECT p.proof_id, p.verified_at_utc, p.credential_fingerprint,
          t.secret_ciphertext_b64 FROM session_mfa p
          JOIN sessions s ON s.token_hash_hex = p.token_hash_hex
          JOIN totp_credentials t ON t.account_id = s.account_id
          WHERE p.token_hash_hex = ?1 AND s.account_id = ?2
            AND t.enabled = 1 AND t.revoked_at_utc IS NULL",
            params![token_hash, session.account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    if let Some((id, verified, fingerprint, ciphertext)) = proof {
        if matches!(session.auth_method.as_str(), "device" | "webauthn")
            && verified <= now
            && now.saturating_sub(verified) < STEP_UP_MAX_AGE_SECONDS
            && fingerprint == hash_token(&ciphertext)
        {
            session.mfa_verified_at_utc = Some(verified);
            session.mfa_proof_id = Some(id);
        }
    }
    Ok(())
}

/// Check MFA against the held policy/storage connection, including legacy tokens.
pub(crate) fn scope_mfa_active(
    db: &Connection,
    claims: &crate::scope_tokens::ScopeClaims,
    now: u64,
) -> Result<bool, rusqlite::Error> {
    let Some(account_id) = claims.principal_id.strip_prefix("account:") else {
        return Ok(true);
    };
    if !policy_required(db, account_id)? && claims.mfa_proof_id.is_none() {
        return Ok(true);
    }
    let Some(origin) = claims.origin_session_hash.as_deref() else {
        return Ok(false);
    };
    let row = db
        .query_row(
            "SELECT session_kind, issued_at_utc, expires_at_utc FROM sessions
        WHERE token_hash_hex = ?1 AND account_id = ?2 AND revoked_at_utc IS NULL",
            params![origin, account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((auth_method, issued, expires)) = row else {
        return Ok(false);
    };
    let mut session = SessionView {
        account_id: account_id.into(),
        device_id_hex: None,
        auth_method,
        issued_at_utc: issued,
        expires_at_utc: expires,
        mfa_required: true,
        mfa_verified_at_utc: None,
        mfa_proof_id: None,
    };
    apply_session_status(db, origin, &mut session, now)?;
    Ok(expires > now
        && require_recent_primary_session(&session, now).is_ok()
        && session.mfa_proof_id.is_some()
        && session.mfa_proof_id == claims.mfa_proof_id)
}

pub async fn post_step_up(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(request): Json<TotpCodeRequest>,
) -> Response {
    // Lookup once for the rate-limit key, then repeat inside the immediate transaction.
    // Limiter initialization must also happen there: separate connections can
    // otherwise both observe a missing key and race its unique-key insertion.
    let session = match crate::http::authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let rate_key = auth_rate_key(&headers, &session.account_id, "mfa-totp");
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let tx = match db.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(error) => return service_error(error.into()),
    };
    if let Err(response) = crate::http::auth_rate_allowed_with_db(&tx, &rate_key) {
        return *response;
    }
    let now = now_utc();
    let mut session = match authenticated_session_with_db(&tx, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if let Err(response) = require_recent_primary_session(&session, now) {
        return *response;
    }
    let credential = match tx
        .query_row(
            "SELECT secret_ciphertext_b64, last_used_step
        FROM totp_credentials WHERE account_id = ?1 AND enabled = 1 AND revoked_at_utc IS NULL",
            [&session.account_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<u64>>(1)?)),
        )
        .optional()
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return error_response(
                StatusCode::FORBIDDEN,
                "MFA_ENROLLMENT_REQUIRED",
                "Enroll and confirm an authenticator before second-factor verification",
            )
        }
        Err(error) => return service_error(error.into()),
    };
    let secret = match crate::totp::decrypt_totp_secret(&credential.0) {
        Ok(secret) => zeroize::Zeroizing::new(secret),
        Err(error) => return service_error(error),
    };
    let step = match crate::totp::verify_code(&secret, &request.code, now, credential.1) {
        Ok(step) => step,
        Err(_) => {
            auth_rate_failure_with_db(&tx, &rate_key);
            if let Err(error) = tx.commit() {
                return service_error(error.into());
            }
            return error_response(
                StatusCode::UNAUTHORIZED,
                "MFA_CODE_INVALID",
                "Authenticator code is invalid or already used",
            );
        }
    };
    let changed = match tx.execute(
        "UPDATE totp_credentials SET last_used_step = ?2,
        last_used_at_utc = ?3 WHERE account_id = ?1 AND enabled = 1 AND revoked_at_utc IS NULL
          AND (last_used_step IS NULL OR last_used_step < ?2)",
        params![session.account_id, step, now],
    ) {
        Ok(changed) => changed,
        Err(error) => return service_error(error.into()),
    };
    if changed != 1 {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "MFA_CODE_INVALID",
            "Authenticator code is invalid or already used",
        );
    }
    let token_hash = hash_token(&session_token(&headers).expect("authenticated token"));
    let proof_id = random_hex(16);
    if let Err(error) = tx.execute("INSERT INTO session_mfa(token_hash_hex, proof_id,
        verified_at_utc, credential_fingerprint) VALUES(?1,?2,?3,?4)
        ON CONFLICT(token_hash_hex) DO UPDATE SET proof_id=excluded.proof_id,
          verified_at_utc=excluded.verified_at_utc, credential_fingerprint=excluded.credential_fingerprint",
        params![token_hash, proof_id, now, hash_token(&credential.0)]) { return service_error(error.into()) }
    if let Err(error) = audit_event(
        &tx,
        &session.account_id,
        "mfa_step_up_verified",
        serde_json::json!({"method":"totp", "expires_at_utc":now+STEP_UP_MAX_AGE_SECONDS}),
    ) {
        return service_error(error.into());
    }
    auth_rate_success_with_db(&tx, &rate_key);
    if let Err(error) = apply_session_status(&tx, &token_hash, &mut session, now) {
        return service_error(error.into());
    }
    if let Err(error) = tx.commit() {
        return service_error(error.into());
    }
    Json(serde_json::json!({"status":"verified", "session":session,
        "expires_at_utc":now+STEP_UP_MAX_AGE_SECONDS}))
    .into_response()
}

#[derive(Deserialize)]
pub(crate) struct PolicyRequest {
    required: bool,
}

fn own_session(
    db: &Connection,
    headers: &HeaderMap,
    account_id: &str,
) -> Result<SessionView, Box<Response>> {
    let session = authenticated_session_with_db(db, headers).map_err(Box::new)?;
    if session.account_id != account_id {
        return Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "MFA policy is controlled by this account's owner",
        )));
    }
    Ok(session)
}

pub async fn get_policy(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(id) => id,
        Err(error) => return service_error(error),
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let session = match own_session(&db, &headers, &account_id) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    Json(
        serde_json::json!({"required":session.mfa_required, "method":"totp",
        "verified_at_utc":session.mfa_verified_at_utc, "max_age_seconds":STEP_UP_MAX_AGE_SECONDS}),
    )
    .into_response()
}

pub async fn patch_policy(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<PolicyRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(id) => id,
        Err(error) => return service_error(error),
    };
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let tx = match db.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(error) => return service_error(error.into()),
    };
    let now = now_utc();
    let session = match own_session(&tx, &headers, &account_id) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(response) = require_recent_primary_session(&session, now) {
        return *response;
    }
    // Both enabling and disabling require an actual fresh second-factor proof.
    if session.mfa_proof_id.is_none() {
        return error_response(
            StatusCode::FORBIDDEN,
            "MFA_STEP_UP_REQUIRED",
            "Verify your authenticator before changing MFA policy",
        );
    }
    if request.required {
        let recoverable: bool = match tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_codes
            WHERE account_id=?1 AND used_at_utc IS NULL)",
            [&account_id],
            |row| row.get(0),
        ) {
            Ok(value) => value,
            Err(error) => return service_error(error.into()),
        };
        if !recoverable {
            return error_response(
                StatusCode::CONFLICT,
                "MFA_RECOVERY_CODES_REQUIRED",
                "Retain recovery codes before requiring MFA",
            );
        }
    }
    if let Err(error) = tx.execute(
        "INSERT INTO account_mfa_policy(account_id,required,updated_at_utc)
        VALUES(?1,?2,?3) ON CONFLICT(account_id) DO UPDATE SET required=excluded.required,
        updated_at_utc=excluded.updated_at_utc",
        params![account_id, request.required, now],
    ) {
        return service_error(error.into());
    }
    let current_hash = hash_token(&session_token(&headers).expect("authenticated token"));
    if let Err(error) = tx.execute(
        "UPDATE sessions SET revoked_at_utc=?2 WHERE account_id=?1
        AND token_hash_hex != ?3 AND revoked_at_utc IS NULL",
        params![account_id, now, current_hash],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = tx.execute(
        "UPDATE session_handoffs SET used_at_utc=?2 WHERE account_id=?1
        AND used_at_utc IS NULL",
        params![account_id, now],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &tx,
        &account_id,
        "mfa_policy_changed",
        serde_json::json!({"required":request.required,"other_sessions_revoked":true}),
    ) {
        return service_error(error.into());
    }
    if let Err(error) = tx.commit() {
        return service_error(error.into());
    }
    Json(serde_json::json!({"required":request.required, "other_sessions_revoked":true}))
        .into_response()
}

#[derive(Deserialize)]
pub(crate) struct RecoveryResetRequest {
    code: String,
}

/// Emergency recovery deliberately consumes an offline recovery credential and
/// revokes every session. It is a recovery ceremony, never an MFA attestation.
pub async fn post_recovery_reset(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<RecoveryResetRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(id) => id,
        Err(error) => return service_error(error),
    };
    let rate_key = auth_rate_key(&headers, &account_id, "mfa-recovery");
    if request.code.len() > 128 || !request.code.trim().starts_with("cvrc_") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_RECOVERY_CODE",
            "Supply an unused recovery code",
        );
    }
    let mut db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let tx = match db.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(error) => return service_error(error.into()),
    };
    let now = now_utc();
    let session = match own_session(&tx, &headers, &account_id) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(response) = require_recent_primary_session(&session, now) {
        return *response;
    }
    if let Err(response) = crate::http::auth_rate_allowed_with_db(&tx, &rate_key) {
        return *response;
    }
    let changed = match tx.execute(
        "UPDATE recovery_codes SET used_at_utc=?3
        WHERE account_id=?1 AND code_hash_hex=?2 AND used_at_utc IS NULL",
        params![account_id, hash_token(request.code.trim()), now],
    ) {
        Ok(n) => n,
        Err(error) => return service_error(error.into()),
    };
    if changed != 1 {
        auth_rate_failure_with_db(&tx, &rate_key);
        if let Err(error) = tx.commit() {
            return service_error(error.into());
        }
        return error_response(
            StatusCode::UNAUTHORIZED,
            "RECOVERY_CODE_INVALID",
            "Recovery code is unknown or already used",
        );
    }
    for sql in [
        "UPDATE account_mfa_policy SET required=0, updated_at_utc=?2 WHERE account_id=?1",
        "UPDATE totp_credentials SET enabled=0, revoked_at_utc=?2 WHERE account_id=?1",
        "UPDATE sessions SET revoked_at_utc=?2 WHERE account_id=?1 AND revoked_at_utc IS NULL",
        "UPDATE session_handoffs SET used_at_utc=?2 WHERE account_id=?1 AND used_at_utc IS NULL",
    ] {
        if let Err(error) = tx.execute(sql, params![account_id, now]) {
            return service_error(error.into());
        }
    }
    if let Err(error) = audit_event(
        &tx,
        &account_id,
        "mfa_recovery_reset",
        serde_json::json!({"all_sessions_revoked":true,"factor_revoked":true}),
    ) {
        return service_error(error.into());
    }
    auth_rate_success_with_db(&tx, &rate_key);
    if let Err(error) = tx.commit() {
        return service_error(error.into());
    }
    let mut response = Json(
        serde_json::json!({"status":"recovery_reset", "login_required":true,
        "enrollment_required":true}),
    )
    .into_response();
    clear_session_cookie(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope_tokens::{scope_origin_active, ScopeClaims};
    use crate::test_support::{cleanup, json, test_app, TOTP_ENV_LOCK};
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use tower05::ServiceExt;

    struct KeyEnvironment(Option<String>);
    impl KeyEnvironment {
        fn set() -> Self {
            let old = std::env::var(crate::state::TOTP_KEY_ENV).ok();
            std::env::set_var(crate::state::TOTP_KEY_ENV, "11".repeat(32));
            Self(old)
        }
    }
    impl Drop for KeyEnvironment {
        fn drop(&mut self) {
            if let Some(old) = &self.0 {
                std::env::set_var(crate::state::TOTP_KEY_ENV, old)
            } else {
                std::env::remove_var(crate::state::TOTP_KEY_ENV)
            }
        }
    }

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        token: &str,
        body: serde_json::Value,
    ) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn fixture(
        name: &str,
    ) -> (
        std::path::PathBuf,
        AccountState,
        Router,
        String,
        String,
        Vec<u8>,
    ) {
        let (root, state, app) = test_app(name);
        let key = ciphervault_crypto::generate_signing_key();
        let response = call(
            &app,
            "POST",
            "/v1/accounts",
            "",
            serde_json::json!({
            "display_name":"MFA regression",
            "account_public_key_hex":hex::encode(key.verifying_key().as_bytes())}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let account = json(response).await;
        let id = account["account_id"].as_str().unwrap().to_string();
        let token = random_hex(32);
        let secret = b"MFA synthetic seed12".to_vec();
        let ciphertext = crate::totp::encrypt_totp_secret(&secret).unwrap();
        let db = state.connection().unwrap();
        db.execute("INSERT INTO sessions(token_hash_hex,account_id,session_kind,issued_at_utc,expires_at_utc)
            VALUES(?1,?2,'device',?3,?4)", params![hash_token(&token), id, now_utc(), now_utc()+1800]).unwrap();
        db.execute(
            "INSERT INTO totp_credentials(account_id,secret_ciphertext_b64,enabled,created_at_utc)
            VALUES(?1,?2,1,?3)",
            params![id, ciphertext, now_utc()],
        )
        .unwrap();
        drop(db);
        (root, state, app, id, token, secret)
    }

    async fn step_up(app: &Router, token: &str, secret: &[u8]) -> Response {
        let code = crate::totp::code_for_step(secret, now_utc() / 30).unwrap();
        call(
            app,
            "POST",
            "/v1/sessions/mfa/totp",
            token,
            serde_json::json!({"code":code}),
        )
        .await
    }

    #[tokio::test]
    async fn policy_requires_factor_and_recovery_then_persists_and_rejects_handoff_upgrade() {
        let _lock = TOTP_ENV_LOCK.lock().await;
        let _key = KeyEnvironment::set();
        let (root, state, app, id, token, secret) = fixture("mfa-policy").await;
        let policy = format!("/v1/accounts/{id}/mfa");
        assert_eq!(
            call(
                &app,
                "PATCH",
                &policy,
                &token,
                serde_json::json!({"required":true})
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            step_up(&app, &token, &secret).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app,
                "PATCH",
                &policy,
                &token,
                serde_json::json!({"required":true})
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        {
            let db = state.connection().unwrap();
            db.execute(
                "INSERT INTO recovery_codes(account_id,code_hash_hex,created_at_utc)
                VALUES(?1,?2,?3)",
                params![id, hash_token("cvrc_synthetic_policy_code"), now_utc()],
            )
            .unwrap();
        }
        assert_eq!(
            call(
                &app,
                "PATCH",
                &policy,
                &token,
                serde_json::json!({"required":true})
            )
            .await
            .status(),
            StatusCode::OK
        );
        // Required-factor revocation cannot silently strand an account or disable MFA.
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("/v1/accounts/{id}/totp/revoke"),
                &token,
                serde_json::json!({})
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        let restarted = AccountState::open(&root).unwrap();
        let reapp = crate::create_router(restarted.clone());
        let view =
            json(call(&reapp, "GET", "/v1/sessions", &token, serde_json::json!({})).await).await;
        assert_eq!(view["mfa_required"], true);
        assert!(view["mfa_verified_at_utc"].is_u64());
        assert!(view.get("mfa_proof_id").is_none());
        let handoff = json(
            call(
                &app,
                "POST",
                "/v1/sessions/handoff",
                &token,
                serde_json::json!({}),
            )
            .await,
        )
        .await;
        let child = json(
            call(
                &app,
                "POST",
                "/v1/sessions/handoff/consume",
                &token,
                serde_json::json!({"handoff_code":handoff["handoff_code"]}),
            )
            .await,
        )
        .await;
        assert_eq!(child["session"]["mfa_required"], true);
        assert!(child["session"]["mfa_verified_at_utc"].is_null());
        let child_token = child["token"].as_str().unwrap();
        assert_eq!(
            step_up(&app, child_token, &secret).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let child_view = json(
            call(
                &app,
                "GET",
                "/v1/sessions",
                child_token,
                serde_json::json!({}),
            )
            .await,
        )
        .await;
        let parsed: SessionView = serde_json::from_value(child_view).unwrap();
        assert!(crate::guards::require_recent_strong_session(&parsed, now_utc()).is_err());
        drop(reapp);
        drop(restarted);
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[tokio::test]
    async fn scope_proof_is_bound_expires_and_revokes_on_factor_replacement() {
        let _lock = TOTP_ENV_LOCK.lock().await;
        let _key = KeyEnvironment::set();
        let (root, state, app, id, token, secret) = fixture("mfa-scope").await;
        assert_eq!(
            step_up(&app, &token, &secret).await.status(),
            StatusCode::OK
        );
        let db = state.connection().unwrap();
        db.execute(
            "INSERT INTO account_mfa_policy(account_id,required,updated_at_utc) VALUES(?1,1,?2)",
            params![id, now_utc()],
        )
        .unwrap();
        let proof: String = db
            .query_row(
                "SELECT proof_id FROM session_mfa WHERE token_hash_hex=?1",
                [hash_token(&token)],
                |r| r.get(0),
            )
            .unwrap();
        let mut claims = ScopeClaims::new(
            "tenant",
            "project",
            &format!("account:{id}"),
            now_utc(),
            now_utc() + 900,
        );
        assert!(!scope_origin_active(&db, &claims, now_utc(), true).unwrap());
        claims.origin_session_hash = Some(hash_token(&token));
        assert!(!scope_origin_active(&db, &claims, now_utc(), true).unwrap());
        claims.mfa_proof_id = Some(proof);
        assert!(scope_origin_active(&db, &claims, now_utc(), true).unwrap());
        assert!(!scope_origin_active(&db, &claims, now_utc() + 300, true).unwrap());
        db.execute(
            "UPDATE session_mfa SET proof_id=?1 WHERE token_hash_hex=?2",
            params![random_hex(16), hash_token(&token)],
        )
        .unwrap();
        assert!(!scope_origin_active(&db, &claims, now_utc(), true).unwrap());
        claims.mfa_proof_id = Some(
            db.query_row(
                "SELECT proof_id FROM session_mfa WHERE token_hash_hex=?1",
                [hash_token(&token)],
                |r| r.get(0),
            )
            .unwrap(),
        );
        db.execute(
            "UPDATE totp_credentials SET secret_ciphertext_b64='replaced' WHERE account_id=?1",
            [&id],
        )
        .unwrap();
        assert!(!scope_origin_active(&db, &claims, now_utc(), true).unwrap());
        drop(db);
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[tokio::test]
    async fn recovery_reset_requires_primary_consumes_code_and_revokes_every_session() {
        let _lock = TOTP_ENV_LOCK.lock().await;
        let _key = KeyEnvironment::set();
        let (root, state, app, id, token, secret) = fixture("mfa-reset").await;
        assert_eq!(
            step_up(&app, &token, &secret).await.status(),
            StatusCode::OK
        );
        let recovery_token = random_hex(32);
        let code = "cvrc_synthetic_emergency_code";
        {
            let db = state.connection().unwrap();
            db.execute(
                "INSERT INTO account_mfa_policy VALUES(?1,1,?2)",
                params![id, now_utc()],
            )
            .unwrap();
            db.execute("INSERT INTO recovery_codes(account_id,code_hash_hex,created_at_utc) VALUES(?1,?2,?3)",params![id,hash_token(code),now_utc()]).unwrap();
            db.execute("INSERT INTO sessions(token_hash_hex,account_id,session_kind,issued_at_utc,expires_at_utc)
                VALUES(?1,?2,'recovery',?3,?4)",params![hash_token(&recovery_token),id,now_utc(),now_utc()+900]).unwrap();
        }
        let path = format!("/v1/accounts/{id}/mfa/recovery-reset");
        assert_eq!(
            call(
                &app,
                "POST",
                &path,
                &recovery_token,
                serde_json::json!({"code":code})
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "POST",
                &path,
                &token,
                serde_json::json!({"code":code})
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(&app, "GET", "/v1/sessions", &token, serde_json::json!({}))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        {
            let db = state.connection().unwrap();
            assert!(!policy_required(&db, &id).unwrap());
            let active: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM sessions WHERE account_id=?1 AND revoked_at_utc IS NULL",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(active, 0);
            let enabled: bool = db
                .query_row(
                    "SELECT enabled FROM totp_credentials WHERE account_id=?1",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!enabled);
            db.execute("INSERT INTO sessions(token_hash_hex,account_id,session_kind,issued_at_utc,expires_at_utc)
            VALUES(?1,?2,'device',?3,?4)",params![hash_token("fresh_after_reset"),id,now_utc(),now_utc()+900]).unwrap();
        }
        assert_eq!(
            call(
                &app,
                "POST",
                &path,
                "fresh_after_reset",
                serde_json::json!({"code":code})
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_step_up_guesses_are_limited_across_connections() {
        let _lock = TOTP_ENV_LOCK.lock().await;
        let _key = KeyEnvironment::set();
        let (root, state, app, id, token, _secret) = fixture("mfa-rate").await;
        let second = AccountState::open(&root).unwrap();
        let second_app = crate::create_router(second.clone());
        for (path, code) in [
            ("/v1/sessions/mfa/totp".to_string(), "invalid"),
            (
                format!("/v1/accounts/{id}/mfa/recovery-reset"),
                "cvrc_synthetic_unknown_code",
            ),
        ] {
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..16 {
                let target = if index % 2 == 0 {
                    app.clone()
                } else {
                    second_app.clone()
                };
                let token = token.clone();
                let path = path.clone();
                tasks.spawn(async move {
                    call(
                        &target,
                        "POST",
                        &path,
                        &token,
                        serde_json::json!({"code":code}),
                    )
                    .await
                    .status()
                });
            }
            let mut denied = 0;
            let mut limited = 0;
            while let Some(result) = tasks.join_next().await {
                match result.unwrap() {
                    StatusCode::UNAUTHORIZED => denied += 1,
                    StatusCode::TOO_MANY_REQUESTS => limited += 1,
                    other => panic!("unexpected {other} for {path}"),
                }
            }
            assert_eq!(denied, 5, "{path}");
            assert_eq!(limited, 11, "{path}");
        }
        drop(second_app);
        drop(second);
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[tokio::test]
    async fn totp_only_and_stale_primary_sessions_cannot_establish_second_factor() {
        let _lock = TOTP_ENV_LOCK.lock().await;
        let _key = KeyEnvironment::set();
        let (root, state, app, _id, token, secret) = fixture("mfa-primary").await;
        {
            let db = state.connection().unwrap();
            db.execute(
                "UPDATE sessions SET session_kind='totp' WHERE token_hash_hex=?1",
                [hash_token(&token)],
            )
            .unwrap();
        }
        assert_eq!(
            step_up(&app, &token, &secret).await.status(),
            StatusCode::FORBIDDEN
        );
        {
            let db = state.connection().unwrap();
            db.execute("UPDATE sessions SET session_kind='device',issued_at_utc=?2 WHERE token_hash_hex=?1",params![hash_token(&token),now_utc()-301]).unwrap();
        }
        assert_eq!(
            step_up(&app, &token, &secret).await.status(),
            StatusCode::FORBIDDEN
        );
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[tokio::test]
    async fn full_account_recovery_requires_new_device_proof_and_two_distinct_unused_codes() {
        let _lock = TOTP_ENV_LOCK.lock().await;
        let _key = KeyEnvironment::set();
        let (root, state, app, id, original_token, secret) = fixture("mfa-full-recovery").await;
        let first_code = "cvrc_synthetic_recovery_enrollment_code";
        let second_code = "cvrc_synthetic_recovery_factor_reset_code";
        {
            let db = state.connection().unwrap();
            db.execute(
                "INSERT INTO account_mfa_policy VALUES(?1,1,?2)",
                params![id, now_utc()],
            )
            .unwrap();
            for code in [first_code, second_code] {
                db.execute(
                    "INSERT INTO recovery_codes(account_id,code_hash_hex,created_at_utc)
                    VALUES(?1,?2,?3)",
                    params![id, hash_token(code), now_utc()],
                )
                .unwrap();
            }
        }

        let redeemed = call(
            &app,
            "POST",
            "/v1/recovery/redeem",
            "",
            serde_json::json!({"account_id":id,"code":first_code}),
        )
        .await;
        assert_eq!(redeemed.status(), StatusCode::OK);
        let redeemed = json(redeemed).await;
        let recovery_token = redeemed["token"].as_str().unwrap();
        assert_eq!(redeemed["session"]["auth_method"], "recovery");
        assert_eq!(redeemed["session"]["mfa_required"], true);
        assert!(redeemed["session"]["mfa_verified_at_utc"].is_null());

        // The first code grants only the documented enrollment ceremony. It
        // cannot attest MFA, reset the factor, or mint an ordinary credential.
        assert_eq!(
            step_up(&app, recovery_token, &secret).await.status(),
            StatusCode::FORBIDDEN
        );
        let reset_path = format!("/v1/accounts/{id}/mfa/recovery-reset");
        assert_eq!(
            call(
                &app,
                "POST",
                &reset_path,
                recovery_token,
                serde_json::json!({"code":second_code})
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/scope-tokens",
                recovery_token,
                serde_json::json!({"project_id":"project_not_needed"})
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        {
            let db = state.connection().unwrap();
            let consumed: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM recovery_codes
                WHERE account_id=?1 AND used_at_utc IS NOT NULL",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(consumed, 1);
            assert!(policy_required(&db, &id).unwrap());
        }

        // This key was created after the original account key was lost. The
        // recovery token permits its self-signed enrollment, not account login.
        let device_key = ciphervault_crypto::generate_signing_key();
        let device_id = random_hex(32);
        let device_public_key = hex::encode(device_key.verifying_key().as_bytes());
        let challenge = call(
            &app,
            "POST",
            &format!("/v1/accounts/{id}/devices/challenge"),
            recovery_token,
            serde_json::json!({"device_id_hex":device_id,
                "public_key_hex":device_public_key}),
        )
        .await;
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge = json(challenge).await;
        let enrollment_proof = hex::encode(ciphervault_crypto::signatures::sign_with_domain(
            &device_key,
            b"account_device_enrollment",
            &crate::util::challenge_signing_bytes(
                &id,
                Some(&device_id),
                Some(&device_public_key),
                challenge["challenge_id"].as_str().unwrap(),
                challenge["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let enrollment = call(
            &app,
            "POST",
            &format!("/v1/accounts/{id}/devices"),
            recovery_token,
            serde_json::json!({"device_id_hex":device_id,"public_key_hex":device_public_key,
                "challenge_id":challenge["challenge_id"],"proof_signature_hex":enrollment_proof}),
        )
        .await;
        assert_eq!(enrollment.status(), StatusCode::CREATED);

        let challenge = call(
            &app,
            "POST",
            "/v1/sessions/challenge",
            "",
            serde_json::json!({"account_id":id,"device_id_hex":device_id}),
        )
        .await;
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge = json(challenge).await;
        let login_proof = hex::encode(ciphervault_crypto::signatures::sign_with_domain(
            &device_key,
            b"account_login",
            &crate::util::challenge_signing_bytes(
                &id,
                Some(&device_id),
                None,
                challenge["challenge_id"].as_str().unwrap(),
                challenge["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let login = call(
            &app,
            "POST",
            "/v1/sessions",
            "",
            serde_json::json!({
            "challenge_id":challenge["challenge_id"],"signature_hex":login_proof}),
        )
        .await;
        assert_eq!(login.status(), StatusCode::OK);
        let login = json(login).await;
        let device_token = login["token"].as_str().unwrap();
        assert_eq!(login["session"]["auth_method"], "device");
        assert_eq!(login["session"]["device_id_hex"], device_id);
        assert_eq!(login["session"]["mfa_required"], true);
        assert!(login["session"]["mfa_verified_at_utc"].is_null());
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/scope-tokens",
                device_token,
                serde_json::json!({"project_id":"project_not_needed"})
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );

        // The already consumed enrollment code cannot also reset MFA. Two
        // distinct codes from one recovery sheet remain one recovery factor.
        assert_eq!(
            call(
                &app,
                "POST",
                &reset_path,
                device_token,
                serde_json::json!({"code":first_code})
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let reset = call(
            &app,
            "POST",
            &reset_path,
            device_token,
            serde_json::json!({"code":second_code}),
        )
        .await;
        assert_eq!(reset.status(), StatusCode::OK);
        let reset = json(reset).await;
        assert_eq!(reset["login_required"], true);
        assert_eq!(reset["enrollment_required"], true);
        {
            let db = state.connection().unwrap();
            let consumed: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM recovery_codes
                WHERE account_id=?1 AND used_at_utc IS NOT NULL",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(consumed, 2);
            assert!(!policy_required(&db, &id).unwrap());
            let factor_revoked: bool = db
                .query_row(
                    "SELECT enabled=0 AND revoked_at_utc IS NOT NULL
                FROM totp_credentials WHERE account_id=?1",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(factor_revoked);
            let active_sessions: i64 = db
                .query_row(
                    "SELECT COUNT(*) FROM sessions
                WHERE account_id=?1 AND revoked_at_utc IS NULL",
                    [&id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(active_sessions, 0);
        }
        for revoked_token in [original_token.as_str(), recovery_token, device_token] {
            assert_eq!(
                call(
                    &app,
                    "GET",
                    "/v1/sessions",
                    revoked_token,
                    serde_json::json!({})
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        drop(app);
        drop(state);
        cleanup(root);
    }
}
