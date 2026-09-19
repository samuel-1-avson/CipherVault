//! HTTP plumbing: error envelope, rate limiting, CSRF guard, session cookies.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, Connection, OptionalExtension};

use crate::{
    account_exists, audit_event,
    error::AccountServiceError,
    hash_token, prune_expired,
    state::now_utc,
    state::{
        AccountState, ErrorBody, SessionView, AUTH_RATE_LOCK_SECONDS, AUTH_RATE_MAX_FAILURES,
        AUTH_RATE_MAX_KEYS, AUTH_RATE_WINDOW_SECONDS, SESSION_COOKIE_NAME, SESSION_TTL_SECONDS,
    },
    webauthn_crypto::webauthn_origin,
};

pub(crate) fn error_response(
    status: StatusCode,
    code: &'static str,
    error: impl Into<String>,
) -> Response {
    (
        status,
        Json(ErrorBody {
            status: "error",
            code,
            error: error.into(),
        }),
    )
        .into_response()
}

pub(crate) fn request_source(headers: &HeaderMap) -> String {
    // Forwarded headers are caller-controlled unless the service is explicitly
    // deployed behind a trusted proxy. Keep direct deployments on one stable
    // source key so an attacker cannot evade the limiter by spoofing XFF.
    let trust_proxy_headers = std::env::var("CIPHERVAULT_ACCOUNT_TRUST_PROXY_HEADERS")
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    if !trust_proxy_headers {
        return "direct".into();
    }
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .chars()
        .take(128)
        .collect()
}

pub(crate) fn auth_rate_key(headers: &HeaderMap, account_id: &str, ceremony: &str) -> String {
    format!("{ceremony}:{account_id}:{}", request_source(headers))
}

pub(crate) fn auth_rate_allowed(state: &AccountState, key: &str) -> Result<(), Box<Response>> {
    let now = now_utc();
    let db = state.connection().map_err(|_| {
        Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTH_RATE_UNAVAILABLE",
            "Authentication rate limiter unavailable",
        ))
    })?;
    db.execute(
        "DELETE FROM auth_rate_limits
         WHERE blocked_until_utc <= ?1
           AND (?1 - window_started_at_utc) > ?2",
        params![now as i64, AUTH_RATE_WINDOW_SECONDS as i64],
    )
    .map_err(|_| {
        Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTH_RATE_UNAVAILABLE",
            "Authentication rate limiter unavailable",
        ))
    })?;
    let current = db
        .query_row(
            "SELECT window_started_at_utc, failures, blocked_until_utc
             FROM auth_rate_limits WHERE rate_key = ?1",
            params![key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, i64>(1)? as u32,
                    row.get::<_, i64>(2)? as u64,
                ))
            },
        )
        .optional()
        .map_err(|_| {
            Box::new(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_RATE_UNAVAILABLE",
                "Authentication rate limiter unavailable",
            ))
        })?;
    let Some((window_started, failures, blocked_until)) = current else {
        let active_keys: i64 = db
            .query_row("SELECT COUNT(*) FROM auth_rate_limits", [], |row| {
                row.get(0)
            })
            .map_err(|_| {
                Box::new(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "AUTH_RATE_UNAVAILABLE",
                    "Authentication rate limiter unavailable",
                ))
            })?;
        if active_keys >= AUTH_RATE_MAX_KEYS as i64 {
            return Err(Box::new(error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "AUTH_RATE_LIMITED",
                "Too many authentication sources are active; try again later",
            )));
        }
        db.execute(
            "INSERT INTO auth_rate_limits(rate_key, window_started_at_utc, failures, blocked_until_utc, updated_at_utc)
             VALUES(?1, ?2, 0, 0, ?2)",
            params![key, now as i64],
        )
        .map_err(|_| {
            Box::new(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_RATE_UNAVAILABLE",
                "Authentication rate limiter unavailable",
            ))
        })?;
        return Ok(());
    };
    if blocked_until > now {
        return Err(Box::new(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "AUTH_RATE_LIMITED",
            "Too many failed authentication attempts; try again later",
        )));
    }
    if now.saturating_sub(window_started) > AUTH_RATE_WINDOW_SECONDS {
        db.execute(
            "UPDATE auth_rate_limits
             SET window_started_at_utc = ?2, failures = 0, blocked_until_utc = 0, updated_at_utc = ?2
             WHERE rate_key = ?1",
            params![key, now as i64],
        )
        .map_err(|_| {
            Box::new(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_RATE_UNAVAILABLE",
                "Authentication rate limiter unavailable",
            ))
        })?;
        return Ok(());
    }
    if failures >= AUTH_RATE_MAX_FAILURES {
        db.execute(
            "UPDATE auth_rate_limits SET blocked_until_utc = ?2, updated_at_utc = ?3 WHERE rate_key = ?1",
            params![key, (now + AUTH_RATE_LOCK_SECONDS) as i64, now as i64],
        )
        .map_err(|_| {
            Box::new(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "AUTH_RATE_UNAVAILABLE",
                "Authentication rate limiter unavailable",
            ))
        })?;
        return Err(Box::new(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "AUTH_RATE_LIMITED",
            "Too many failed authentication attempts; try again later",
        )));
    }
    Ok(())
}

pub(crate) fn auth_rate_failure_with_db(db: &Connection, key: &str) {
    let now = now_utc();
    let current = db
        .query_row(
            "SELECT window_started_at_utc, failures FROM auth_rate_limits WHERE rate_key = ?1",
            params![key],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u32)),
        )
        .optional()
        .ok()
        .flatten();
    let (window_started, failures) = current.unwrap_or((now, 0));
    let (window_started, failures) =
        if now.saturating_sub(window_started) > AUTH_RATE_WINDOW_SECONDS {
            (now, 1)
        } else {
            (window_started, failures.saturating_add(1))
        };
    let blocked_until = if failures >= AUTH_RATE_MAX_FAILURES {
        now + AUTH_RATE_LOCK_SECONDS
    } else {
        0
    };
    let _ = db.execute(
        "INSERT INTO auth_rate_limits(rate_key, window_started_at_utc, failures, blocked_until_utc, updated_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(rate_key) DO UPDATE SET
           window_started_at_utc = excluded.window_started_at_utc,
           failures = excluded.failures,
           blocked_until_utc = excluded.blocked_until_utc,
           updated_at_utc = excluded.updated_at_utc",
        params![key, window_started as i64, failures as i64, blocked_until as i64, now as i64],
    );
    if failures == AUTH_RATE_MAX_FAILURES {
        auth_rate_lockout_alert(db, key, now);
    }
}

/// Alert sink for fresh authentication lockouts: a queryable audit event plus a
/// stderr line for log aggregation. The rate key carries `ceremony:account:source`;
/// only the ceremony and source reach the alert trail, never secrets.
pub(crate) fn auth_rate_lockout_alert(db: &Connection, key: &str, now: u64) {
    let mut parts = key.splitn(3, ':');
    let ceremony = parts.next().unwrap_or("unknown");
    let account_id = parts.next().unwrap_or("");
    let source = parts.next().unwrap_or("unknown");
    eprintln!(
        "account auth rate lockout: ceremony={ceremony} source={source} blocked_until_utc={}",
        now + AUTH_RATE_LOCK_SECONDS
    );
    if account_id.trim().is_empty() {
        return;
    }
    // audit_events.account_id is FK-bound: lockouts for unknown accounts
    // (probing, typos) keep the stderr alert above but have no account row
    // to hang a queryable event on.
    if !account_exists(db, account_id).unwrap_or(false) {
        return;
    }
    let _ = audit_event(
        db,
        account_id,
        "auth_rate_lockout",
        serde_json::json!({
            "ceremony": ceremony,
            "source": source,
            "failures": AUTH_RATE_MAX_FAILURES,
            "blocked_until_utc": now + AUTH_RATE_LOCK_SECONDS,
        }),
    );
}

#[cfg(test)]
pub(crate) fn auth_rate_failure(state: &AccountState, key: &str) {
    if let Ok(db) = state.connection() {
        auth_rate_failure_with_db(&db, key);
    }
}

pub(crate) fn auth_rate_success(state: &AccountState, key: &str) {
    if let Ok(db) = state.connection() {
        let _ = db.execute(
            "DELETE FROM auth_rate_limits WHERE rate_key = ?1",
            params![key],
        );
    }
}

pub(crate) fn service_error(error: AccountServiceError) -> Response {
    match error {
        AccountServiceError::Invalid(message) => {
            error_response(StatusCode::BAD_REQUEST, "INVALID_REQUEST", message)
        }
        AccountServiceError::Database(message) => {
            eprintln!("account database error: {message}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ACCOUNT_DATABASE_ERROR",
                "Account service database failure",
            )
        }
        AccountServiceError::Io(message) => {
            eprintln!("account service I/O error: {message}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ACCOUNT_STORAGE_ERROR",
                "Account service storage failure",
            )
        }
    }
}

pub(crate) async fn csrf_origin_guard(request: Request<Body>, next: Next) -> Response {
    if request.method() == axum::http::Method::POST {
        if let Some(origin) = request.headers().get(axum::http::header::ORIGIN) {
            let origin = origin.to_str().unwrap_or_default();
            let configured = std::env::var("CIPHERVAULT_ACCOUNT_ALLOWED_ORIGINS")
                .ok()
                .into_iter()
                .flat_map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let allowed = configured.iter().any(|item| item == origin)
                || (configured.is_empty() && origin == webauthn_origin());
            if !allowed {
                return error_response(
                    StatusCode::FORBIDDEN,
                    "CSRF_ORIGIN_REJECTED",
                    "Request origin is not allowed",
                );
            }
        }
    }
    next.run(request).await
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

pub(crate) fn session_token(headers: &HeaderMap) -> Option<String> {
    bearer_token(headers).map(ToOwned::to_owned).or_else(|| {
        headers
            .get("Cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';').find_map(|cookie| {
                    let (name, value) = cookie.trim().split_once('=')?;
                    (name == SESSION_COOKIE_NAME && !value.is_empty()).then(|| value.to_string())
                })
            })
    })
}

pub(crate) fn attach_session_cookie(response: &mut Response, token: &str) {
    let secure = std::env::var("CIPHERVAULT_ACCOUNT_COOKIE_SECURE")
        .map(|value| !value.eq_ignore_ascii_case("false"))
        .unwrap_or_else(|_| !webauthn_origin().starts_with("http://localhost"));
    let secure_attribute = if secure { "; Secure" } else { "" };
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Lax{secure_attribute}"
    );
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie)
            .expect("generated account session cookie must be valid"),
    );
}

pub(crate) fn clear_session_cookie(response: &mut Response) {
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_static(
            "ciphervault_account_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        ),
    );
}

#[allow(clippy::result_large_err)]
pub(crate) fn authenticated_session(
    state: &AccountState,
    headers: &HeaderMap,
) -> Result<SessionView, Response> {
    let db = state.connection().map_err(service_error)?;
    authenticated_session_with_db(&db, headers)
}

/// Session lookup against an already-held connection. Callers that hold the
/// [`AccountState`] database guard (e.g. device enrollment's recovery branch)
/// must use this variant: `authenticated_session` would deadlock re-locking
/// the non-reentrant guard on the same thread.
#[allow(clippy::result_large_err)]
pub(crate) fn authenticated_session_with_db(
    db: &Connection,
    headers: &HeaderMap,
) -> Result<SessionView, Response> {
    let token = session_token(headers).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "SESSION_REQUIRED",
            "Missing bearer token",
        )
    })?;
    let token_hash = hash_token(&token);
    let now = now_utc();
    if let Err(error) = prune_expired(db, now) {
        return Err(service_error(error.into()));
    }
    let session = db
        .query_row(
            "SELECT account_id, device_id_hex, session_kind, issued_at_utc, expires_at_utc
             FROM sessions WHERE token_hash_hex = ?1 AND revoked_at_utc IS NULL AND expires_at_utc > ?2",
            params![token_hash, now],
            |row| {
                Ok(SessionView {
                    account_id: row.get(0)?,
                    device_id_hex: row.get(1)?,
                    auth_method: row.get(2)?,
                    issued_at_utc: row.get::<_, i64>(3)? as u64,
                    expires_at_utc: row.get::<_, i64>(4)? as u64,
                })
            },
        )
        .optional()
        .map_err(|error| service_error(error.into()))?;
    session.ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "SESSION_INVALID",
            "Session is missing, expired, or revoked",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random_hex;
    use std::fs;

    #[test]
    fn authentication_rate_limiter_blocks_repeated_failures() {
        let root = std::env::temp_dir().join(format!("cv-account-rate-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        // Lockout audit events are FK-bound to accounts: seed the account the
        // rate key names so the alert lands in the audit trail.
        state
                .connection()
                .expect("db")
                .execute(
                    "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc) VALUES(?1, 'Test', ?2, 1)",
                    params!["cvacct_test", random_hex(32)],
                )
                .expect("seed account");
        let key = "totp-login:cvacct_test:unknown";
        for _ in 0..AUTH_RATE_MAX_FAILURES {
            assert!(auth_rate_allowed(&state, key).is_ok());
            auth_rate_failure(&state, key);
        }
        assert!(auth_rate_allowed(&state, key).is_err());
        // Unknown accounts still lock out, but there is no account row to hang
        // an audit event on: the stderr alert fires, the audit count is unchanged.
        let unknown_key = "totp-login:cvacct_missing:unknown";
        for _ in 0..AUTH_RATE_MAX_FAILURES {
            assert!(auth_rate_allowed(&state, unknown_key).is_ok());
            auth_rate_failure(&state, unknown_key);
        }
        assert!(auth_rate_allowed(&state, unknown_key).is_err());
        let db = state.connection().expect("db");
        let lockouts: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE event = 'auth_rate_lockout'",
                [],
                |row| row.get(0),
            )
            .expect("count lockouts");
        assert_eq!(lockouts, 1);
        drop(db);
        drop(state);
        let reopened = AccountState::open(&root).expect("reopened state");
        assert!(auth_rate_allowed(&reopened, key).is_err());
        auth_rate_success(&reopened, key);
        assert!(auth_rate_allowed(&reopened, key).is_ok());
        let _ = fs::remove_dir_all(root);
    }
}
