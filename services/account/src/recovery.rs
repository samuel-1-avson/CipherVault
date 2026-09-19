//! Recovery-code issuance and redemption handlers.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::params;

use crate::{
    audit_event,
    guards::{account_role_for, normalize_account_id},
    hash_token,
    http::{
        attach_session_cookie, auth_rate_allowed, auth_rate_failure_with_db, auth_rate_key,
        auth_rate_success, error_response, request_source, service_error,
    },
    random_hex,
    state::{
        now_utc, AccountState, RecoveryCodesRequest, RecoveryRedeemRequest, SessionResponse,
        SessionView, RECOVERY_SESSION_TTL_SECONDS,
    },
};

pub async fn post_recovery_codes(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<RecoveryCodesRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let (session, _) = match account_role_for(&state, &headers, &account_id, "owner") {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if session.device_id_hex.is_none() {
        return error_response(
            StatusCode::FORBIDDEN,
            "DEVICE_STEP_UP_REQUIRED",
            "Recovery codes require an enrolled device-bound session",
        );
    }
    let count = request.count.clamp(4, 16);
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if let Err(error) = db.execute(
        "DELETE FROM recovery_codes WHERE account_id = ?1 AND used_at_utc IS NULL",
        params![account_id],
    ) {
        return service_error(error.into());
    }
    let now = now_utc();
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let code = format!("cvrc_{}", random_hex(16));
        if let Err(error) = db.execute("INSERT INTO recovery_codes(account_id, code_hash_hex, created_at_utc) VALUES(?1, ?2, ?3)", params![account_id, hash_token(&code), now]) { return service_error(error.into()); }
        codes.push(code);
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "recovery_codes_issued",
        serde_json::json!({"count": count}),
    ) {
        return service_error(error.into());
    }
    Json(serde_json::json!({"account_id": account_id, "codes": codes, "generated_at_utc": now}))
        .into_response()
}

pub async fn post_recovery_redeem(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Json(request): Json<RecoveryRedeemRequest>,
) -> Response {
    let account_id = match normalize_account_id(&request.account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let rate_key = auth_rate_key(&headers, &account_id, "recovery");
    if let Err(response) = auth_rate_allowed(&state, &rate_key) {
        return *response;
    }
    let code = request.code.trim();
    if code.len() < 16 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_RECOVERY_CODE",
            "Recovery code is invalid",
        );
    }
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let now = now_utc();
    let code_hash = hash_token(code);
    let valid = db.query_row("SELECT EXISTS(SELECT 1 FROM recovery_codes WHERE account_id = ?1 AND code_hash_hex = ?2 AND used_at_utc IS NULL)", params![account_id, code_hash], |row| row.get::<_, bool>(0)).unwrap_or(false);
    if !valid {
        auth_rate_failure_with_db(&db, &rate_key);
        return error_response(
            StatusCode::UNAUTHORIZED,
            "RECOVERY_CODE_INVALID",
            "Recovery code is unknown or already used",
        );
    }
    if let Err(error) = db.execute("UPDATE recovery_codes SET used_at_utc = ?3 WHERE account_id = ?1 AND code_hash_hex = ?2 AND used_at_utc IS NULL", params![account_id, code_hash, now]) { return service_error(error.into()); }
    let token = random_hex(32);
    // Recovery sessions are deliberately short-lived; the session cookie may outlive
    // this TTL, but the server rejects the expired session on every request.
    let expires_at = now + RECOVERY_SESSION_TTL_SECONDS;
    if let Err(error) = db.execute("INSERT INTO sessions(token_hash_hex, account_id, device_id_hex, credential_id_hex, session_kind, issued_at_utc, expires_at_utc) VALUES(?1, ?2, NULL, NULL, 'recovery', ?3, ?4)", params![hash_token(&token), account_id, now, expires_at]) { return service_error(error.into()); }
    let source = request_source(&headers);
    eprintln!("account recovery redeemed: account={account_id} source={source}");
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "recovery_code_redeemed",
        serde_json::json!({
            "source": source,
            "expires_at_utc": expires_at,
            "session_ttl_secs": RECOVERY_SESSION_TTL_SECONDS,
        }),
    ) {
        return service_error(error.into());
    }
    drop(db);
    auth_rate_success(&state, &rate_key);
    let mut response = (
        StatusCode::OK,
        Json(SessionResponse {
            token: token.clone(),
            session: SessionView {
                account_id,
                device_id_hex: None,
                auth_method: "recovery".into(),
                issued_at_utc: now,
                expires_at_utc: expires_at,
            },
        }),
    )
        .into_response();
    attach_session_cookie(&mut response, &token);
    response
}

pub(crate) async fn propagate_device_revocation(
    state: &AccountState,
    public_key_hex: &str,
    vault_ids: &[String],
) -> (usize, usize, usize) {
    let endpoints = std::env::var("CIPHERVAULT_OPERATOR_ENDPOINTS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.trim_end_matches('/').to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let service_token = std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN").ok();
    let targets = endpoints.len().saturating_mul(vault_ids.len());
    if targets == 0 || service_token.as_deref().unwrap_or_default().is_empty() {
        return (targets, 0, targets);
    }
    let mut successes = 0;
    let mut failures = 0;
    for endpoint in endpoints {
        for vault_id in vault_ids {
            let url = format!("{endpoint}/v1/identities/revoke");
            let request = state
                .http
                .post(url)
                .header(
                    "X-CipherVault-Service-Token",
                    service_token.as_deref().unwrap_or_default(),
                )
                .json(&serde_json::json!({
                    "vault_id_hex": vault_id,
                    "public_key_hex": public_key_hex,
                }));
            match request.send().await {
                Ok(response)
                    if response.status().is_success()
                        || response.status() == StatusCode::NOT_FOUND =>
                {
                    successes += 1
                }
                _ => failures += 1,
            }
        }
    }
    (targets, successes, failures)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{cleanup, json, test_app};
    use crate::util::challenge_signing_bytes;
    use axum::body::Body;
    use axum::http::Request;
    use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
    use tower05::ServiceExt;

    #[tokio::test]
    async fn recovery_session_enrolls_replacement_device() {
        let (root, _state, app) = test_app("recovery-enroll");
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
        cleanup(root);
    }
}
