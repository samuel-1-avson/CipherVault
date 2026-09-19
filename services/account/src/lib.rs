//! Durable CipherVault control-plane account service.
//!
//! This service stores account metadata, enrolled device records, vault links,
//! and revocable sessions. Vault plaintext and vault private keys never enter
//! the service. Browser WebAuthn registration and assertion verification are
//! supported for `none` attestation with Ed25519 and ES256 credentials, and
//! successful logins can use an HttpOnly managed-session cookie. The
//! account-key ceremony remains the explicit bootstrap/recovery path.

#[cfg(test)]
use axum::http::StatusCode;
use axum::Json;
#[cfg(test)]
use rusqlite::params;
use tower_http::cors::{AllowOrigin, CorsLayer};

mod accounts;
mod db;
mod devices;
mod error;
mod guards;
mod http;
mod memberships;
mod recovery;
mod sessions;
mod state;
#[cfg(test)]
mod test_support;
mod totp;
mod util;
mod vaults;
mod webauthn;
mod webauthn_crypto;

use accounts::*;
use db::*;
use devices::*;
pub use error::AccountServiceError;
use http::*;
use memberships::*;
use recovery::*;
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

pub fn create_router(state: AccountState) -> axum::Router {
    use axum::routing::{get, post};
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
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ])
                .allow_credentials(true)
        })
        .unwrap_or_default();
    axum::Router::new()
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
        .layer(cors)
        .layer(axum::middleware::from_fn(csrf_origin_guard))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
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
}
