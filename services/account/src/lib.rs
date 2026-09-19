//! Durable CipherVault control-plane account service.
//!
//! This service stores account metadata, enrolled device records, vault links,
//! and revocable sessions. Vault plaintext and vault private keys never enter
//! the service. Browser WebAuthn registration and assertion verification are
//! supported for `none` attestation with Ed25519 and ES256 credentials, and
//! successful logins can use an HttpOnly managed-session cookie. The
//! account-key ceremony remains the explicit bootstrap/recovery path.

use axum::Json;
#[cfg(test)]
use axum::{http::StatusCode, response::Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs;
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
mod totp;
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
use totp::*;
use vaults::*;
use webauthn::*;

pub(crate) fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub(crate) fn audit_event(
    db: &Connection,
    account_id: &str,
    event: &str,
    details: serde_json::Value,
) -> Result<(), rusqlite::Error> {
    db.execute(
        "INSERT INTO audit_events(account_id, event, details_json, created_at_utc)
         VALUES(?1, ?2, ?3, ?4)",
        params![account_id, event, details.to_string(), now_utc()],
    )?;
    Ok(())
}

pub(crate) fn prune_expired(db: &Connection, now: u64) -> Result<(), rusqlite::Error> {
    db.execute(
        "DELETE FROM challenges WHERE expires_at_utc <= ?1 OR used_at_utc IS NOT NULL",
        params![now],
    )?;
    db.execute(
        "DELETE FROM sessions WHERE expires_at_utc <= ?1 OR revoked_at_utc IS NOT NULL",
        params![now],
    )?;
    Ok(())
}

pub(crate) fn random_hex(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

pub(crate) fn b64_encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

pub(crate) fn b64_decode(value: &str, field: &str) -> Result<Vec<u8>, AccountServiceError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .map_err(|_| AccountServiceError::Invalid(format!("{field} must be base64url")))
}

pub(crate) fn challenge_signing_bytes(
    account_id: &str,
    device_id_hex: Option<&str>,
    public_key_hex: Option<&str>,
    challenge_id: &str,
    nonce_hex: &str,
) -> Vec<u8> {
    serde_json::to_vec(&(
        account_id,
        device_id_hex,
        public_key_hex,
        challenge_id,
        nonce_hex,
    ))
    .expect("challenge signing tuple is serializable")
}

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
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
    use ed25519_dalek::Signer;
    use tower05::ServiceExt;

    async fn json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .expect("body");
        serde_json::from_slice(&body).expect("json")
    }

    #[tokio::test]
    async fn account_device_proof_login_and_revocation_lifecycle() {
        let root = std::env::temp_dir().join(format!("cv-account-service-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state);
        let capabilities = app
            .clone()
            .oneshot(
                Request::get("/v1/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(capabilities.status(), StatusCode::OK);
        let capabilities_json = json(capabilities).await;
        assert_eq!(capabilities_json["webauthn"], true);
        assert_eq!(capabilities_json["managed_session_cookie"], true);
        let account_key = generate_signing_key();
        let account_pk = hex::encode(account_key.verifying_key().as_bytes());
        let created = app
            .clone()
            .oneshot(
                Request::post("/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "display_name": "Alice",
                            "account_public_key_hex": account_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let account = json(created).await;
        let account_id = account["account_id"].as_str().unwrap().to_string();
        let unauthenticated_account = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{account_id}").as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated_account.status(), StatusCode::UNAUTHORIZED);
        let device_key = generate_signing_key();
        let device_id = "aa".repeat(32);
        let device_pk = hex::encode(device_key.verifying_key().as_bytes());
        let challenge = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices/challenge").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_id,
                            "public_key_hex": device_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_json = json(challenge).await;
        let challenge_id = challenge_json["challenge_id"].as_str().unwrap();
        let nonce = challenge_json["nonce_hex"].as_str().unwrap();
        let proof_bytes = challenge_signing_bytes(
            &account_id,
            Some(&device_id),
            Some(&device_pk),
            challenge_id,
            nonce,
        );
        let proof = hex::encode(sign_with_domain(
            &account_key,
            b"account_device_enrollment",
            &proof_bytes,
        ));
        let enrolled = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_id,
                            "public_key_hex": device_pk,
                            "challenge_id": challenge_id,
                            "proof_signature_hex": proof,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enrolled.status(), StatusCode::CREATED);
        let login_challenge = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "device_id_hex": device_id,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let login_json = json(login_challenge).await;
        let login_id = login_json["challenge_id"].as_str().unwrap();
        let login_nonce = login_json["nonce_hex"].as_str().unwrap();
        let login_bytes =
            challenge_signing_bytes(&account_id, Some(&device_id), None, login_id, login_nonce);
        let login_signature = hex::encode(sign_with_domain(
            &account_key,
            b"account_login",
            &login_bytes,
        ));
        let session = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": login_id,
                            "signature_hex": login_signature,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        assert!(session
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("ciphervault_account_session=")));
        let session_json = json(session).await;
        let token = session_json["token"].as_str().unwrap().to_string();
        let current = app
            .clone()
            .oneshot(
                Request::get("/v1/sessions")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(current.status(), StatusCode::OK);
        let cookie_current = app
            .clone()
            .oneshot(
                Request::get("/v1/sessions")
                    .header("cookie", format!("{SESSION_COOKIE_NAME}={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cookie_current.status(), StatusCode::OK);
        let handoff = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/handoff")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(handoff.status(), StatusCode::OK);
        let handoff_json = json(handoff).await;
        let handoff_code = handoff_json["handoff_code"].as_str().unwrap().to_string();
        let browser_handoff = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/handoff/consume")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "handoff_code": handoff_code,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(browser_handoff.status(), StatusCode::OK);
        assert!(browser_handoff
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("ciphervault_account_session=")));
        let replay = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/handoff/consume")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "handoff_code": handoff_code,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        let registration_options = app
            .clone()
            .oneshot(
                Request::post(
                    format!("/v1/accounts/{account_id}/webauthn/registration/options").as_str(),
                )
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registration_options.status(), StatusCode::OK);
        let registration_options_json = json(registration_options).await;
        let registration_challenge_id = registration_options_json["challenge_id"].as_str().unwrap();
        let registration_challenge = registration_options_json["challenge"].as_str().unwrap();
        let credential_id = vec![0x42; 32];
        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&Sha256::digest(b"localhost"));
        authenticator_data.push(0x41); // user present + attested credential data
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        authenticator_data.extend_from_slice(&[0u8; 16]);
        authenticator_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        authenticator_data.extend_from_slice(&credential_id);
        let cose_key = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer((-8).into()),
            ),
            (
                ciborium::Value::Integer((-1).into()),
                ciborium::Value::Integer(6.into()),
            ),
            (
                ciborium::Value::Integer((-2).into()),
                ciborium::Value::Bytes(device_key.verifying_key().as_bytes().to_vec()),
            ),
        ]);
        let mut cose_bytes = Vec::new();
        ciborium::ser::into_writer(&cose_key, &mut cose_bytes).unwrap();
        authenticator_data.extend_from_slice(&cose_bytes);
        let attestation_object = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".into()),
                ciborium::Value::Text("none".into()),
            ),
            (
                ciborium::Value::Text("authData".into()),
                ciborium::Value::Bytes(authenticator_data),
            ),
            (
                ciborium::Value::Text("attStmt".into()),
                ciborium::Value::Map(Vec::new()),
            ),
        ]);
        let mut attestation_bytes = Vec::new();
        ciborium::ser::into_writer(&attestation_object, &mut attestation_bytes).unwrap();
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": registration_challenge,
            "origin": "http://localhost:8300",
        });
        let registration_verify = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/webauthn/registration/verify").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": registration_challenge_id,
                            "credential_id_b64": b64_encode(&credential_id),
                            "client_data_json_b64": b64_encode(&serde_json::to_vec(&client_data).unwrap()),
                            "attestation_object_b64": b64_encode(&attestation_bytes),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registration_verify.status(), StatusCode::CREATED);
        let authentication_options = app
            .clone()
            .oneshot(
                Request::post("/v1/webauthn/authentication/options")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"account_id": account_id})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authentication_options.status(), StatusCode::OK);
        let authentication_options_json = json(authentication_options).await;
        let authentication_challenge_id = authentication_options_json["challenge_id"]
            .as_str()
            .unwrap();
        let authentication_challenge = authentication_options_json["challenge"].as_str().unwrap();
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": authentication_challenge,
            "origin": "http://localhost:8300",
        });
        let client_data_bytes = serde_json::to_vec(&client_data).unwrap();
        let mut assertion_auth_data = Vec::new();
        assertion_auth_data.extend_from_slice(&Sha256::digest(b"localhost"));
        assertion_auth_data.push(0x01); // user present
        assertion_auth_data.extend_from_slice(&2u32.to_be_bytes());
        let mut signed_assertion = assertion_auth_data.clone();
        signed_assertion.extend_from_slice(&Sha256::digest(&client_data_bytes));
        let assertion_signature = device_key.sign(&signed_assertion);
        let authentication_verify = app
            .clone()
            .oneshot(
                Request::post("/v1/webauthn/authentication/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": authentication_challenge_id,
                            "credential_id_b64": b64_encode(&credential_id),
                            "client_data_json_b64": b64_encode(&client_data_bytes),
                            "authenticator_data_b64": b64_encode(&assertion_auth_data),
                            "signature_b64": b64_encode(&assertion_signature.to_bytes()),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authentication_verify.status(), StatusCode::OK);
        let authentication_json = json(authentication_verify).await;
        let webauthn_token = authentication_json["token"].as_str().unwrap().to_string();
        let authentication_replay = app
            .clone()
            .oneshot(
                Request::post("/v1/webauthn/authentication/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": authentication_challenge_id,
                            "credential_id_b64": b64_encode(&credential_id),
                            "client_data_json_b64": b64_encode(&client_data_bytes),
                            "authenticator_data_b64": b64_encode(&assertion_auth_data),
                            "signature_b64": b64_encode(&assertion_signature.to_bytes()),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authentication_replay.status(), StatusCode::UNAUTHORIZED);
        let credential_revoke = app
            .clone()
            .oneshot(
                Request::post(format!(
                    "/v1/accounts/{account_id}/webauthn/credentials/{}/revoke",
                    hex::encode(&credential_id)
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(credential_revoke.status(), StatusCode::OK);
        let authentication_after_credential_revoke = app
            .clone()
            .oneshot(
                Request::post("/v1/webauthn/authentication/options")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"account_id": account_id})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            authentication_after_credential_revoke.status(),
            StatusCode::NOT_FOUND
        );
        let account_view_response = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{account_id}").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(account_view_response.status(), StatusCode::OK);
        let account_view_json = json(account_view_response).await;
        assert_eq!(account_view_json["devices"].as_array().unwrap().len(), 1);
        assert_eq!(
            account_view_json["webauthn_credentials"][0]["device_id_hex"],
            device_id
        );
        let recovery_codes = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/recovery/codes").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"count":4}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovery_codes.status(), StatusCode::OK);
        let recovery_json = json(recovery_codes).await;
        let recovery_code = recovery_json["codes"][0].as_str().unwrap().to_string();
        let recovery_session = app
            .clone()
            .oneshot(
                Request::post("/v1/recovery/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "code": recovery_code,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovery_session.status(), StatusCode::OK);
        let recovery_replay = app
            .clone()
            .oneshot(
                Request::post("/v1/recovery/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "code": recovery_json["codes"][0],
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovery_replay.status(), StatusCode::UNAUTHORIZED);
        let audit_response = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{account_id}/audit").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(audit_response.status(), StatusCode::OK);
        let audit_json = json(audit_response).await;
        let events = audit_json["events"].as_array().unwrap();
        assert!(events
            .iter()
            .any(|event| event["event"] == "account_created"));
        assert!(events
            .iter()
            .any(|event| event["event"] == "device_enrolled"));
        assert!(events
            .iter()
            .any(|event| event["event"] == "session_created"));
        let revoke = app
            .clone()
            .oneshot(
                Request::post(
                    format!("/v1/accounts/{account_id}/devices/{device_id}/revoke").as_str(),
                )
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);
        let after = app
            .clone()
            .oneshot(
                Request::get("/v1/sessions")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
        let webauthn_after = app
            .oneshot(
                Request::get("/v1/sessions")
                    .header("authorization", format!("Bearer {webauthn_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(webauthn_after.status(), StatusCode::UNAUTHORIZED);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn totp_enrollment_login_and_replay_protection() {
        let previous_key = std::env::var(TOTP_KEY_ENV).ok();
        std::env::set_var(TOTP_KEY_ENV, "11".repeat(32));
        let root = std::env::temp_dir().join(format!("cv-account-totp-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state.clone());
        let account_key = generate_signing_key();
        let created = app
            .clone()
            .oneshot(
                Request::post("/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "display_name": "TOTP test",
                            "account_public_key_hex": hex::encode(account_key.verifying_key().as_bytes()),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let account = json(created).await;
        let account_id = account["account_id"].as_str().unwrap().to_string();
        let session_token = random_hex(32);
        {
            let db = state.connection().expect("db");
            let now = now_utc();
            db.execute(
                "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, issued_at_utc, expires_at_utc)
                 VALUES(?1, ?2, NULL, NULL, ?3, ?4)",
                params![hash_token(&session_token), account_id, now, now + SESSION_TTL_SECONDS],
            )
            .unwrap();
        }
        let bearer = format!("Bearer {session_token}");
        let enrollment = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/totp/enrollment").as_str())
                    .header("authorization", &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enrollment.status(), StatusCode::OK);
        let enrollment_json = json(enrollment).await;
        let secret =
            totp::base32_decode(enrollment_json["secret_base32"].as_str().unwrap()).unwrap();
        let current_step = now_utc() / totp::STEP_SECONDS;
        let code = totp::code_for_step(&secret, current_step.saturating_sub(1)).unwrap();
        let confirmed = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/totp/enrollment/verify").as_str())
                    .header("authorization", &bearer)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({"code": code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(confirmed.status(), StatusCode::OK);
        let options = app
            .clone()
            .oneshot(
                Request::post("/v1/totp/authentication/options")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"account_id": account_id}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(options.status(), StatusCode::OK);
        let options_json = json(options).await;
        let next_code = totp::code_for_step(&secret, current_step).unwrap();
        let verified = app
            .clone()
            .oneshot(
                Request::post("/v1/totp/authentication/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "account_id": account_id,
                            "challenge_id": options_json["challenge_id"],
                            "code": next_code,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verified.status(), StatusCode::OK);
        let replay = app
            .oneshot(
                Request::post("/v1/totp/authentication/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "account_id": account_id,
                            "challenge_id": options_json["challenge_id"],
                            "code": next_code,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        let _ = fs::remove_dir_all(root);
        if let Some(value) = previous_key {
            std::env::set_var(TOTP_KEY_ENV, value);
        } else {
            std::env::remove_var(TOTP_KEY_ENV);
        }
    }

    #[tokio::test]
    async fn membership_roles_and_origins_are_enforced() {
        let root = std::env::temp_dir().join(format!("cv-account-roles-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state.clone());
        let owner = format!("cvacct_{}", "11".repeat(16));
        let viewer = format!("cvacct_{}", "22".repeat(16));
        let admin = format!("cvacct_{}", "33".repeat(16));
        let invitee = format!("cvacct_{}", "44".repeat(16));
        let viewer_token = random_hex(32);
        let admin_token = random_hex(32);
        let owner_token = random_hex(32);
        {
            let db = state.connection().expect("db");
            for (account_id, key) in [
                (&owner, "aa".repeat(32)),
                (&viewer, "bb".repeat(32)),
                (&admin, "cc".repeat(32)),
                (&invitee, "dd".repeat(32)),
            ] {
                db.execute(
                    "INSERT INTO accounts(account_id, display_name, account_public_key_hex, created_at_utc)
                     VALUES(?1, ?2, ?3, ?4)",
                    params![account_id, account_id, key, now_utc() as i64],
                )
                .unwrap();
            }
            for (token, account_id) in [
                (&owner_token, &owner),
                (&viewer_token, &viewer),
                (&admin_token, &admin),
            ] {
                db.execute(
                    "INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc)
                     VALUES(?1, ?2, NULL, NULL, 'device', ?3, ?4)",
                    params![hash_token(token), account_id, now_utc() as i64, (now_utc() + SESSION_TTL_SECONDS) as i64],
                )
                .unwrap();
            }
            db.execute(
                "INSERT INTO memberships(account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc)
                 VALUES(?1, ?2, 'viewer', 'active', ?3, ?3)",
                params![owner, viewer, now_utc() as i64],
            )
            .unwrap();
            db.execute(
                "INSERT INTO memberships(account_id, member_account_id, role, status, invited_at_utc, accepted_at_utc)
                 VALUES(?1, ?2, 'admin', 'active', ?3, ?3)",
                params![owner, admin, now_utc() as i64],
            )
            .unwrap();
        }

        let viewer_memberships = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{owner}/memberships").as_str())
                    .header("authorization", format!("Bearer {viewer_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer_memberships.status(), StatusCode::OK);

        let viewer_invite = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{owner}/invitations").as_str())
                    .header("authorization", format!("Bearer {viewer_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"invitee_account_id": invitee, "role": "viewer"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer_invite.status(), StatusCode::FORBIDDEN);

        let viewer_link = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{owner}/vaults").as_str())
                    .header("authorization", format!("Bearer {viewer_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "vault_id_hex": "55".repeat(32),
                            "alias": "shared",
                            "role": "viewer"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(viewer_link.status(), StatusCode::FORBIDDEN);

        let admin_owner_invite = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{owner}/invitations").as_str())
                    .header("authorization", format!("Bearer {admin_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"invitee_account_id": invitee, "role": "admin"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin_owner_invite.status(), StatusCode::FORBIDDEN);

        let evil_origin = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{owner}/invitations").as_str())
                    .header("authorization", format!("Bearer {owner_token}"))
                    .header("origin", "https://evil.example")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"invitee_account_id": invitee, "role": "viewer"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(evil_origin.status(), StatusCode::FORBIDDEN);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn recovery_session_enrolls_replacement_device() {
        let root =
            std::env::temp_dir().join(format!("cv-account-recovery-enroll-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state);
        let account_key = generate_signing_key();
        let account_pk = hex::encode(account_key.verifying_key().as_bytes());
        let created = app
            .clone()
            .oneshot(
                Request::post("/v1/accounts")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "display_name": "Recovery",
                            "account_public_key_hex": account_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let account = json(created).await;
        let account_id = account["account_id"].as_str().unwrap().to_string();

        // Enroll device A through the standard account-signed path.
        let device_a_id = "aa".repeat(32);
        let device_a_key = generate_signing_key();
        let device_a_pk = hex::encode(device_a_key.verifying_key().as_bytes());
        let challenge_a = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices/challenge").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_a_id,
                            "public_key_hex": device_a_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_a_json = json(challenge_a).await;
        let proof_a = hex::encode(sign_with_domain(
            &account_key,
            b"account_device_enrollment",
            &challenge_signing_bytes(
                &account_id,
                Some(&device_a_id),
                Some(&device_a_pk),
                challenge_a_json["challenge_id"].as_str().unwrap(),
                challenge_a_json["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let enrolled_a = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_a_id,
                            "public_key_hex": device_a_pk,
                            "challenge_id": challenge_a_json["challenge_id"],
                            "proof_signature_hex": proof_a,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enrolled_a.status(), StatusCode::CREATED);

        // Log in device A and issue recovery codes.
        let login_challenge = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions/challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "device_id_hex": device_a_id,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let login_json = json(login_challenge).await;
        let login_proof = hex::encode(sign_with_domain(
            &account_key,
            b"account_login",
            &challenge_signing_bytes(
                &account_id,
                Some(&device_a_id),
                None,
                login_json["challenge_id"].as_str().unwrap(),
                login_json["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let session = app
            .clone()
            .oneshot(
                Request::post("/v1/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "challenge_id": login_json["challenge_id"],
                            "signature_hex": login_proof,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(session.status(), StatusCode::OK);
        let token = json(session)
            .await
            .get("token")
            .and_then(|value| value.as_str())
            .unwrap()
            .to_string();
        let codes = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/recovery/codes").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"count":4}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(codes.status(), StatusCode::OK);
        let recovery_code = json(codes)
            .await
            .get("codes")
            .and_then(|codes| codes.get(0))
            .and_then(|code| code.as_str())
            .unwrap()
            .to_string();

        // Redeem: short explicit TTL and a recovery-marked session.
        let redeemed = app
            .clone()
            .oneshot(
                Request::post("/v1/recovery/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "account_id": account_id,
                            "code": recovery_code,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redeemed.status(), StatusCode::OK);
        let redeemed_json = json(redeemed).await;
        let recovery_token = redeemed_json["token"].as_str().unwrap().to_string();
        assert_eq!(redeemed_json["session"]["auth_method"], "recovery");
        let issued = redeemed_json["session"]["issued_at_utc"].as_u64().unwrap();
        let expires = redeemed_json["session"]["expires_at_utc"].as_u64().unwrap();
        assert_eq!(expires - issued, RECOVERY_SESSION_TTL_SECONDS);

        // A device-signed proof alone (no recovery session) must fail.
        let device_c_id = "cc".repeat(32);
        let device_c_key = generate_signing_key();
        let device_c_pk = hex::encode(device_c_key.verifying_key().as_bytes());
        let challenge_c = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices/challenge").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_c_id,
                            "public_key_hex": device_c_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_c_json = json(challenge_c).await;
        let proof_c = hex::encode(sign_with_domain(
            &device_c_key,
            b"account_device_enrollment",
            &challenge_signing_bytes(
                &account_id,
                Some(&device_c_id),
                Some(&device_c_pk),
                challenge_c_json["challenge_id"].as_str().unwrap(),
                challenge_c_json["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let denied = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_c_id,
                            "public_key_hex": device_c_pk,
                            "challenge_id": challenge_c_json["challenge_id"],
                            "proof_signature_hex": proof_c,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        // With the recovery session, device B self-certifies and enrolls.
        let device_b_id = "bb".repeat(32);
        let device_b_key = generate_signing_key();
        let device_b_pk = hex::encode(device_b_key.verifying_key().as_bytes());
        let challenge_b = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices/challenge").as_str())
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_b_id,
                            "public_key_hex": device_b_pk,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge_b_json = json(challenge_b).await;
        let proof_b = hex::encode(sign_with_domain(
            &device_b_key,
            b"account_device_enrollment",
            &challenge_signing_bytes(
                &account_id,
                Some(&device_b_id),
                Some(&device_b_pk),
                challenge_b_json["challenge_id"].as_str().unwrap(),
                challenge_b_json["nonce_hex"].as_str().unwrap(),
            ),
        ));
        let enrolled_b = app
            .clone()
            .oneshot(
                Request::post(format!("/v1/accounts/{account_id}/devices").as_str())
                    .header("authorization", format!("Bearer {recovery_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "device_id_hex": device_b_id,
                            "public_key_hex": device_b_pk,
                            "challenge_id": challenge_b_json["challenge_id"],
                            "proof_signature_hex": proof_b,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enrolled_b.status(), StatusCode::CREATED);

        // The audit trail distinguishes the recovery enrollment path.
        let audit = app
            .clone()
            .oneshot(
                Request::get(format!("/v1/accounts/{account_id}/audit").as_str())
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(audit.status(), StatusCode::OK);
        let events = json(audit)
            .await
            .get("events")
            .and_then(|events| events.as_array())
            .unwrap()
            .clone();
        assert!(events
            .iter()
            .any(|event| event["event"] == "recovery_code_redeemed"
                && event["details"]["session_ttl_secs"] == RECOVERY_SESSION_TTL_SECONDS));
        assert!(events
            .iter()
            .any(|event| event["event"] == "device_enrolled"
                && event["details"]["enrollment"] == "recovery_session"));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn role_matrix_covers_gated_routes() {
        // `StatusCode` is a struct with associated constants, so the terse
        // aliases used by the case matrix below are bound as local constants.
        const OK: StatusCode = StatusCode::OK;
        const CREATED: StatusCode = StatusCode::CREATED;
        const NO_CONTENT: StatusCode = StatusCode::NO_CONTENT;
        const FORBIDDEN: StatusCode = StatusCode::FORBIDDEN;
        const UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;
        let root = std::env::temp_dir().join(format!("cv-account-matrix-{}", random_hex(8)));
        let state = AccountState::open(&root).expect("state");
        let app = create_router(state.clone());
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
        let _ = fs::remove_dir_all(root);
    }
}
