//! Durable CipherVault control-plane account service.
//!
//! This service stores account metadata, enrolled device records, vault links,
//! and revocable sessions. Original file-backup vault plaintext and vault
//! private keys stay on clients. The hosted scoped-secret plane receives and
//! decrypts secret values under a server-held KEK. Browser WebAuthn registration and assertion verification are
//! supported for `none` attestation with Ed25519 and ES256 credentials, and
//! successful logins can use an HttpOnly managed-session cookie. The
//! account-key ceremony remains the explicit bootstrap/recovery path.

#[cfg(test)]
use axum::http::StatusCode;
use axum::Json;
#[cfg(test)]
use rusqlite::params;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};

mod abuse;
mod accounts;
mod audit_chain;
mod db;
mod devices;
pub mod disaster_recovery;
mod dpop;
mod error;
mod grants;
mod grants_routes;
mod guards;
mod http;
mod key_lifecycle;
mod memberships;
mod mfa;
mod migration_ledger;
mod migration_routes;
mod policy;
mod projects;
mod reconcile;
mod recovery;
mod rotation;
mod scope_tokens;
mod scoped;
mod scoped_enhancements;
mod secret_routes;
mod secrets;
mod sessions;
mod state;
#[cfg(test)]
mod test_support;
mod totp;
mod util;
mod vaults;
mod vcs;
mod webauthn;
mod webauthn_crypto;

use accounts::*;
use db::*;
use devices::*;
pub use error::AccountServiceError;
use grants_routes::*;
use http::*;
use memberships::*;
use migration_routes::*;
use recovery::*;
use scoped_enhancements::*;
use secret_routes::*;
use sessions::*;
use state::*;
pub use state::{
    sqlite_busy_retries, AccountState, AccountView, AuditEventView, ChallengeView,
    CreateAccountRequest, DeviceChallengeRequest, DeviceEnrollmentRequest, DeviceView, ErrorBody,
    InvitationAcceptRequest, InvitationRequest, InvitationView, LinkVaultRequest,
    LoginChallengeRequest, MembershipView, RecoveryCodesRequest, RecoveryRedeemRequest,
    RevocationResponse, SessionHandoffConsumeRequest, SessionHandoffResponse, SessionLoginRequest,
    SessionResponse, SessionView, TotpAuthenticationOptionsRequest, TotpAuthenticationOptionsView,
    TotpAuthenticationVerifyRequest, TotpCodeRequest, TotpEnrollmentView, VaultLinkView,
    WebAuthnAuthenticationOptionsRequest, WebAuthnAuthenticationVerifyRequest,
    WebAuthnCredentialView, WebAuthnOptionsView, WebAuthnRegistrationVerifyRequest,
};
#[cfg(test)]
use test_support::*;
use totp::*;
use util::*;
use vaults::*;
use webauthn::*;

/// Last-resort panic catcher (outermost layer): a panicking handler or
/// middleware becomes a 500 `{status, code, error}` envelope instead of a
/// dropped connection. The DB mutex recovers from poison via
/// `AccountState::connection`.
fn panic_response(_: Box<dyn std::any::Any + Send>) -> axum::response::Response {
    error_response(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_PANIC_CAUGHT",
        "Account service internal error",
    )
}

#[cfg(test)]
async fn test_panic_handler() -> &'static str {
    panic!("intentional test panic for CatchPanicLayer verification");
}

pub fn create_router(state: AccountState) -> axum::Router {
    use axum::routing::{delete, get, patch, post};
    let cors = std::env::var("CIPHERVAULT_ACCOUNT_ALLOWED_ORIGINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|origin| origin.trim().parse().ok())
                .collect::<Vec<axum::http::HeaderValue>>()
        })
        .filter(|origins| !origins.is_empty())
        .map(|origins| {
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PATCH,
                    axum::http::Method::DELETE,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ])
                .allow_credentials(true)
        })
        .unwrap_or_default();
    let router = axum::Router::new()
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({"status": "ready"})) }),
        )
        .route("/v1/capabilities", get(get_capabilities))
        .route("/v1/accounts", post(post_account))
        .route("/v1/accounts/:account_id", get(get_account))
        .route("/v1/accounts/:account_id/audit", get(get_account_audit))
        .route(
            "/v1/accounts/:account_id/devices/challenge",
            post(post_device_challenge),
        )
        .route(
            "/v1/accounts/:account_id/devices",
            post(post_device_enrollment),
        )
        .route(
            "/v1/accounts/:account_id/devices/:device_id_hex/revoke",
            post(post_device_revoke),
        )
        .route("/v1/sessions/challenge", post(post_login_challenge))
        .route("/v1/sessions", post(post_login).get(get_session))
        .route("/v1/sessions/revoke", post(post_session_revoke))
        .route("/v1/sessions/mfa/totp", post(mfa::post_step_up))
        .route(
            "/v1/accounts/:account_id/mfa",
            get(mfa::get_policy).patch(mfa::patch_policy),
        )
        .route(
            "/v1/accounts/:account_id/mfa/recovery-reset",
            post(mfa::post_recovery_reset),
        )
        .route("/v1/sessions/handoff", post(post_session_handoff))
        .route(
            "/v1/sessions/handoff/consume",
            post(post_session_handoff_consume),
        )
        .route(
            "/v1/accounts/:account_id/webauthn/registration/options",
            post(post_webauthn_registration_options),
        )
        .route(
            "/v1/accounts/:account_id/webauthn/credentials/:credential_id_hex/revoke",
            post(post_webauthn_revoke),
        )
        .route(
            "/v1/accounts/:account_id/webauthn/registration/verify",
            post(post_webauthn_registration_verify),
        )
        .route(
            "/v1/webauthn/authentication/options",
            post(post_webauthn_authentication_options),
        )
        .route(
            "/v1/webauthn/authentication/verify",
            post(post_webauthn_authentication_verify),
        )
        .route(
            "/v1/totp/authentication/options",
            post(post_totp_authentication_options),
        )
        .route(
            "/v1/totp/authentication/verify",
            post(post_totp_authentication_verify),
        )
        .route(
            "/v1/accounts/:account_id/totp/enrollment",
            post(post_totp_enrollment),
        )
        .route(
            "/v1/accounts/:account_id/totp/enrollment/verify",
            post(post_totp_enrollment_verify),
        )
        .route(
            "/v1/accounts/:account_id/totp/revoke",
            post(post_totp_revoke),
        )
        .route("/v1/accounts/:account_id/vaults", post(post_vault_link))
        .route(
            "/v1/accounts/:account_id/invitations",
            post(post_invitation).get(get_invitations),
        )
        .route("/v1/invitations/accept", post(post_invitation_accept))
        .route("/v1/accounts/:account_id/memberships", get(get_memberships))
        .route(
            "/v1/accounts/:account_id/memberships/:member_account_id/revoke",
            post(post_membership_revoke),
        )
        .route(
            "/v1/accounts/:account_id/recovery/codes",
            post(post_recovery_codes),
        )
        .route("/v1/recovery/redeem", post(post_recovery_redeem))
        .route(
            "/v1/projects/:project_id/environments/:environment_id/secrets",
            post(post_secret),
        )
        .route(
            "/v1/projects/:project_id/environments/:environment_id/secrets/:name",
            get(get_secret_value_route),
        )
        .route(
            "/v1/projects/:project_id/environments/:environment_id/materialize",
            post(post_materialize),
        )
        .route(
            "/v1/projects/:project_id/keys/rewrap",
            post(post_rewrap_keys),
        )
        .route("/v1/projects/:project_id/secrets", get(get_secrets))
        .route(
            "/v1/projects/:project_id/secrets/:secret_id",
            patch(patch_secret).delete(delete_secret_route),
        )
        .route(
            "/v1/projects/:project_id/secrets/:secret_id/move",
            post(post_secret_move),
        )
        .route(
            "/v1/projects/:project_id/secrets/:secret_id/rebind",
            post(post_secret_rebind),
        )
        .route(
            "/v1/projects/:project_id/secrets/:secret_id/rotate",
            post(post_secret_rotate),
        )
        .route(
            "/v1/projects/:project_id/members",
            post(post_project_member).delete(delete_project_member),
        )
        .route(
            "/v1/projects/:project_id/members/requests",
            get(list_grant_requests_route),
        )
        .route(
            "/v1/projects/:project_id/members/requests/:request_id/decision",
            post(decide_grant_request_route),
        )
        .route(
            "/v1/projects/:project_id/invites",
            post(create_invite_route).get(list_invites_route),
        )
        .route(
            "/v1/projects/:project_id/invites/:invite_id",
            delete(revoke_invite_route),
        )
        .route("/v1/invites/accept", post(accept_invite_route))
        .route(
            "/v1/projects/:project_id/migrations",
            post(post_migration).get(get_migrations),
        )
        .route(
            "/v1/projects/:project_id/migrations/:migration_id",
            get(get_migration),
        )
        .route(
            "/v1/projects/:project_id/migrations/:migration_id/entries",
            post(post_migration_entries),
        )
        .route(
            "/v1/projects/:project_id/migrations/:migration_id/entries/:ledger_id/migrated",
            post(post_migration_entry_migrated),
        )
        .route(
            "/v1/projects/:project_id/migrations/:migration_id/entries/:ledger_id/resolve",
            post(post_migration_entry_resolve),
        )
        .route(
            "/v1/projects/:project_id/migrations/:migration_id/verify",
            post(post_migration_verify),
        )
        .route(
            "/v1/projects/:project_id/migrations/:migration_id/disable-legacy",
            post(post_migration_disable_legacy),
        )
        .route(
            "/v1/projects/:project_id/migrations/:migration_id/abort",
            post(post_migration_abort),
        )
        .route(
            "/v1/scope-tokens",
            post(post_scope_token).delete(delete_scope_token),
        )
        .route(
            "/v1/projects/:project_id/repositories",
            post(post_repository).get(get_repositories),
        )
        .route(
            "/v1/projects/:project_id/repositories/:binding_id",
            delete(delete_repository),
        )
        .route(
            "/v1/projects/:project_id/repositories/:binding_id/prove",
            post(post_repository_prove),
        )
        .route(
            "/v1/projects/:project_id/repositories/:binding_id/reactivate",
            post(post_repository_reactivate),
        )
        .route("/v1/webhooks/vcs/:provider", post(post_vcs_webhook))
        .route("/v1/projects", get(get_projects))
        .route(
            "/v1/projects/:project_id/audit/export",
            get(get_audit_export),
        )
        .route("/v1/projects/:project_ref", get(get_project));
    #[cfg(test)]
    let router = router.route("/__test_panic", get(test_panic_handler));
    router
        .layer(cors)
        .layer(axum::middleware::from_fn(csrf_origin_guard))
        .layer(axum::middleware::from_fn(response_privacy_headers))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        // Outermost: added last so a panic anywhere below becomes a 500
        // envelope instead of a dropped connection.
        .layer(CatchPanicLayer::custom(panic_response))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower05::ServiceExt;

    #[tokio::test]
    async fn role_matrix_covers_gated_routes() {
        // `StatusCode` is a struct with associated constants, so the terse
        // aliases used by the case matrix below are bound as local constants.
        const OK: StatusCode = StatusCode::OK;
        const CREATED: StatusCode = StatusCode::CREATED;
        const NO_CONTENT: StatusCode = StatusCode::NO_CONTENT;
        const FORBIDDEN: StatusCode = StatusCode::FORBIDDEN;
        const UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;
        let (root, state, app) = test_app("matrix");
        let owner = format!("cvacct_{}", "11".repeat(16));
        let admin = format!("cvacct_{}", "33".repeat(16));
        let editor = format!("cvacct_{}", "55".repeat(16));
        let viewer = format!("cvacct_{}", "22".repeat(16));
        let doomed_a = format!("cvacct_{}", "66".repeat(16));
        let doomed_b = format!("cvacct_{}", "77".repeat(16));
        let outsider = format!("cvacct_{}", "88".repeat(16));
        let invitee = format!("cvacct_{}", "44".repeat(16));
        let owner_token = random_hex(32);
        let admin_token = random_hex(32);
        let editor_token = random_hex(32);
        let viewer_token = random_hex(32);
        let outsider_token = random_hex(32);
        let recovery_token = random_hex(32);
        {
            let db = state.connection().expect("db");
            for (account_id, key) in [
                (&owner, "aa".repeat(32)),
                (&admin, "bb".repeat(32)),
                (&editor, "cc".repeat(32)),
                (&viewer, "dd".repeat(32)),
                (&doomed_a, "ee".repeat(32)),
                (&doomed_b, "ff".repeat(32)),
                (&outsider, "ab".repeat(32)),
                (&invitee, "cd".repeat(32)),
            ] {
                db.execute(
                    "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                     VALUES(?1, ?2, ?3, ?4)",
                    params![account_id, account_id, key, now_utc() as i64],
                )
                .unwrap();
            }
            for (token, account_id, kind, device) in [
                (&owner_token, &owner, "device", Some("99".repeat(32))),
                (&admin_token, &admin, "device", Some("99".repeat(32))),
                (&editor_token, &editor, "device", Some("99".repeat(32))),
                (&viewer_token, &viewer, "device", Some("99".repeat(32))),
                (&outsider_token, &outsider, "device", Some("99".repeat(32))),
                (&recovery_token, &owner, "recovery", None),
            ] {
                if let Some(device_id) = device.as_deref() {
                    db.execute("INSERT INTO devices(account_id, device_id_hex, label, public_key_hex, enrolled_at_utc)
                        VALUES(?1, ?2, 'test', ?2, 1)", params![account_id, device_id]).unwrap();
                }
                db.execute(
                    "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc)
                     VALUES(?1, ?2, ?3, NULL, ?4, ?5, ?6)",
                    params![hash_token(token), account_id, device, kind, now_utc() as i64, (now_utc() + 3600) as i64],
                )
                .unwrap();
            }
            for (member, role) in [
                (&admin, "admin"),
                (&editor, "editor"),
                (&viewer, "viewer"),
                (&doomed_a, "viewer"),
                (&doomed_b, "viewer"),
            ] {
                db.execute(
                    "INSERT INTO memberships(account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc)
                     VALUES(?1, ?2, ?3, 'active', ?4, ?4)",
                    params![owner, member, role, now_utc() as i64],
                )
                .unwrap();
            }
        }
        // Actor index: 0 owner, 1 admin, 2 editor, 3 viewer, 4 outsider, 5 recovery.
        let token_for = |actor: usize| match actor {
            0 => owner_token.clone(),
            1 => admin_token.clone(),
            2 => editor_token.clone(),
            3 => viewer_token.clone(),
            4 => outsider_token.clone(),
            _ => recovery_token.clone(),
        };
        let uri_members = format!("/v1/accounts/{owner}/memberships");
        let uri_invites = format!("/v1/accounts/{owner}/invitations");
        let uri_vaults = format!("/v1/accounts/{owner}/vaults");
        let uri_revoke_a = format!("/v1/accounts/{owner}/memberships/{doomed_a}/revoke");
        let uri_revoke_b = format!("/v1/accounts/{owner}/memberships/{doomed_b}/revoke");
        let uri_codes = format!("/v1/accounts/{owner}/recovery/codes");
        let vault_body =
            serde_json::json!({"vault_id_hex": "55".repeat(32), "alias": "x", "role": "viewer"})
                .to_string();
        let invite_body =
            serde_json::json!({"invitee_account_id": invitee, "role": "viewer"}).to_string();
        let codes_body = r#"{"count":4}"#.to_string();
        type RoleMatrixCase<'a> = (&'a str, String, Option<String>, Option<usize>, StatusCode);
        let cases: Vec<RoleMatrixCase<'_>> = vec![
            ("GET", uri_members.clone(), None, Some(0), OK),
            ("GET", uri_members.clone(), None, Some(1), OK),
            ("GET", uri_members.clone(), None, Some(2), OK),
            ("GET", uri_members.clone(), None, Some(3), OK),
            ("GET", uri_members.clone(), None, Some(4), FORBIDDEN),
            ("GET", uri_members.clone(), None, Some(5), OK),
            ("GET", uri_members.clone(), None, None, UNAUTHORIZED),
            ("GET", uri_invites.clone(), None, Some(0), OK),
            ("GET", uri_invites.clone(), None, Some(1), OK),
            ("GET", uri_invites.clone(), None, Some(2), FORBIDDEN),
            ("GET", uri_invites.clone(), None, Some(3), FORBIDDEN),
            ("GET", uri_invites.clone(), None, Some(4), FORBIDDEN),
            ("GET", uri_invites.clone(), None, Some(5), OK),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(0),
                CREATED,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(1),
                CREATED,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(2),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(3),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(4),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_invites.clone(),
                Some(invite_body.clone()),
                Some(5),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(0),
                NO_CONTENT,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(1),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(2),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(3),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(4),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_vaults.clone(),
                Some(vault_body.clone()),
                Some(5),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(0),
                OK,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(1),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(2),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(3),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(4),
                FORBIDDEN,
            ),
            (
                "POST",
                uri_codes.clone(),
                Some(codes_body.clone()),
                Some(5),
                FORBIDDEN,
            ),
            ("POST", uri_revoke_b.clone(), None, Some(2), FORBIDDEN),
            ("POST", uri_revoke_b.clone(), None, Some(3), FORBIDDEN),
            ("POST", uri_revoke_b.clone(), None, Some(4), FORBIDDEN),
            ("POST", uri_revoke_b.clone(), None, Some(5), FORBIDDEN),
            ("POST", uri_revoke_b.clone(), None, None, UNAUTHORIZED),
            ("POST", uri_revoke_b.clone(), None, Some(1), OK),
            ("POST", uri_revoke_a.clone(), None, Some(0), OK),
        ];
        for (method, uri, body, actor, expected) in cases {
            let mut builder = if method == "GET" {
                Request::get(uri.as_str())
            } else {
                Request::post(uri.as_str())
            };
            if let Some(index) = actor {
                let header = format!("Bearer {}", token_for(index));
                builder = builder.header("authorization", header);
            }
            let request = match body {
                Some(payload) => builder
                    .header("content-type", "application/json")
                    .body(Body::from(payload)),
                None => builder.body(Body::empty()),
            }
            .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), expected, "{method} {uri}");
        }
        cleanup(root);
    }

    #[tokio::test]
    async fn panic_in_handler_returns_500_json_envelope() {
        let (root, _state, app) = test_app("panic");
        let request = Request::get("/__test_panic").body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["code"], "INTERNAL_PANIC_CAUGHT");
        cleanup(root);
    }
}
