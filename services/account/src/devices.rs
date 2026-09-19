//! Device challenge and enrollment handlers.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ciphervault_crypto::signatures::verify_with_domain;
use ed25519_dalek::VerifyingKey;
use rusqlite::{params, OptionalExtension};

use crate::{
    audit_event, challenge_signing_bytes,
    db::account_exists,
    error::AccountServiceError,
    guards::{decode_32, normalize_account_id},
    http::{authenticated_session, authenticated_session_with_db, error_response, service_error},
    prune_expired, random_hex,
    recovery::propagate_device_revocation,
    state::{
        now_utc, AccountState, ChallengeView, DeviceChallengeRequest, DeviceEnrollmentRequest,
        DeviceView, RevocationResponse, CHALLENGE_TTL_SECONDS,
    },
};

pub async fn post_device_challenge(
    State(state): State<AccountState>,
    Path(account_id): Path<String>,
    Json(request): Json<DeviceChallengeRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if let Err(error) = decode_32(&request.device_id_hex, "device_id_hex")
        .and(decode_32(&request.public_key_hex, "public_key_hex"))
    {
        return service_error(error);
    }
    let challenge_id = random_hex(16);
    let nonce_hex = random_hex(32);
    let expires_at = now_utc() + CHALLENGE_TTL_SECONDS;
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    if let Err(error) = prune_expired(&db, now_utc()) {
        return service_error(error.into());
    }
    match account_exists(&db, &account_id) {
        Ok(false) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "ACCOUNT_NOT_FOUND",
                "Account does not exist",
            )
        }
        Err(error) => return service_error(error.into()),
        Ok(true) => {}
    }
    if let Err(error) = db.execute(
        "INSERT INTO challenges(challenge_id, kind, account_id, device_id_hex, public_key_hex, nonce_hex, expires_at_utc)
         VALUES(?1, 'device_enrollment', ?2, ?3, ?4, ?5, ?6)",
        params![challenge_id, account_id, request.device_id_hex.to_ascii_lowercase(), request.public_key_hex.to_ascii_lowercase(), nonce_hex, expires_at],
    ) {
        return service_error(error.into());
    }
    (
        StatusCode::OK,
        Json(ChallengeView {
            challenge_id,
            nonce_hex,
            expires_at_utc: expires_at,
            ceremony: "account_signed_device_enrollment_v1".into(),
        }),
    )
        .into_response()
}

pub async fn post_device_enrollment(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(request): Json<DeviceEnrollmentRequest>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    if let Err(error) = decode_32(&request.device_id_hex, "device_id_hex")
        .and(decode_32(&request.public_key_hex, "public_key_hex"))
    {
        return service_error(error);
    }
    let signature_bytes = match hex::decode(&request.proof_signature_hex) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_SIGNATURE",
                "proof_signature_hex must be 64-byte hex",
            )
        }
    };
    let db = match state.connection() {
        Ok(db) => db,
        Err(error) => return service_error(error),
    };
    let account_key_hex: Option<String> = match db
        .query_row(
            "SELECT account_public_key_hex FROM accounts WHERE account_id = ?1",
            params![account_id],
            |row| row.get(0),
        )
        .optional()
    {
        Ok(value) => value,
        Err(error) => return service_error(error.into()),
    };
    let Some(account_key_hex) = account_key_hex else {
        return error_response(
            StatusCode::NOT_FOUND,
            "ACCOUNT_NOT_FOUND",
            "Account does not exist",
        );
    };
    let challenge = match db
        .query_row(
            "SELECT nonce_hex, device_id_hex, public_key_hex, expires_at_utc, used_at_utc
             FROM challenges WHERE challenge_id = ?1 AND kind = 'device_enrollment' AND account_id = ?2",
            params![request.challenge_id, account_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(value)) => value,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, "CHALLENGE_INVALID", "Enrollment challenge is unknown"),
        Err(error) => return service_error(error.into()),
    };
    if challenge.3 <= now_utc() || challenge.4.is_some() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_EXPIRED",
            "Enrollment challenge is expired or already used",
        );
    }
    if !challenge.1.eq_ignore_ascii_case(&request.device_id_hex)
        || !challenge.2.eq_ignore_ascii_case(&request.public_key_hex)
    {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "CHALLENGE_BINDING_MISMATCH",
            "Enrollment proof does not match the challenge",
        );
    }
    let account_key = match decode_32(&account_key_hex, "account public key").and_then(|key| {
        VerifyingKey::from_bytes(&key)
            .map_err(|_| AccountServiceError::Invalid("account public key is invalid".into()))
    }) {
        Ok(key) => key,
        Err(error) => return service_error(error),
    };
    let signing_bytes = challenge_signing_bytes(
        &account_id,
        Some(&request.device_id_hex.to_ascii_lowercase()),
        Some(&request.public_key_hex.to_ascii_lowercase()),
        &request.challenge_id,
        &challenge.0,
    );
    let signature: [u8; 64] = match signature_bytes.as_slice().try_into() {
        Ok(value) => value,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "INVALID_SIGNATURE",
                "Invalid proof signature length",
            )
        }
    };
    let account_proof_valid = verify_with_domain(
        account_key.as_bytes(),
        b"account_device_enrollment",
        &signing_bytes,
        &signature,
    )
    .is_ok();
    // Recovery-only holders lost the account key with their devices. A valid,
    // unexpired recovery session authorizes the account, and a proof signed by
    // the new device key itself proves possession of the enrolled keypair.
    let mut enrolled_via_recovery = false;
    if !account_proof_valid {
        let recovery_authorized = authenticated_session_with_db(&db, &headers)
            .ok()
            .is_some_and(|session| {
                session.account_id == account_id && session.auth_method == "recovery"
            });
        if !recovery_authorized {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "PROOF_INVALID",
                "Account-signed enrollment proof is invalid",
            );
        }
        let device_key_bytes = match decode_32(&request.public_key_hex, "device public key") {
            Ok(key) => key,
            Err(error) => return service_error(error),
        };
        let device_key = match VerifyingKey::from_bytes(&device_key_bytes)
            .map_err(|_| AccountServiceError::Invalid("device public key is invalid".into()))
        {
            Ok(key) => key,
            Err(error) => return service_error(error),
        };
        if verify_with_domain(
            device_key.as_bytes(),
            b"account_device_enrollment",
            &signing_bytes,
            &signature,
        )
        .is_err()
        {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "PROOF_INVALID",
                "Recovery enrollment proof is invalid",
            );
        }
        enrolled_via_recovery = true;
    }
    let now = now_utc();
    if let Err(error) = db.execute(
        "INSERT INTO devices(account_id, device_id_hex, public_key_hex, label, enrolled_at_utc, last_seen_at_utc, revoked_at_utc)
         VALUES(?1, ?2, ?3, ?4, ?5, ?5, NULL)
         ON CONFLICT(account_id, device_id_hex) DO UPDATE SET
           public_key_hex = excluded.public_key_hex, label = excluded.label,
           last_seen_at_utc = excluded.last_seen_at_utc, revoked_at_utc = NULL",
        params![account_id, request.device_id_hex.to_ascii_lowercase(), request.public_key_hex.to_ascii_lowercase(), request.label.trim().chars().take(120).collect::<String>(), now],
    ) {
        return service_error(error.into());
    }
    if let Err(error) = audit_event(
        &db,
        &account_id,
        "device_enrolled",
        serde_json::json!({
            "device_id_hex": request.device_id_hex.to_ascii_lowercase(),
            "label": request.label,
            "enrollment": if enrolled_via_recovery {
                "recovery_session"
            } else {
                "account_signed"
            },
        }),
    ) {
        return service_error(error.into());
    }
    if enrolled_via_recovery {
        eprintln!("account device enrolled via recovery session: account_id={account_id}");
    }
    if let Err(error) = db.execute(
        "UPDATE challenges SET used_at_utc = ?2 WHERE challenge_id = ?1",
        params![request.challenge_id, now],
    ) {
        return service_error(error.into());
    }
    match db
        .query_row(
            "SELECT device_id_hex, public_key_hex, label, enrolled_at_utc, last_seen_at_utc, revoked_at_utc
             FROM devices WHERE account_id = ?1 AND device_id_hex = ?2",
            params![account_id, request.device_id_hex.to_ascii_lowercase()],
            |row| {
                Ok(DeviceView {
                    device_id_hex: row.get(0)?,
                    public_key_hex: row.get(1)?,
                    label: row.get(2)?,
                    enrolled_at_utc: row.get::<_, i64>(3)? as u64,
                    last_seen_at_utc: row.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    revoked_at_utc: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                })
            },
        )
    {
        Ok(device) => (StatusCode::CREATED, Json(device)).into_response(),
        Err(error) => service_error(error.into()),
    }
}

pub async fn post_device_revoke(
    State(state): State<AccountState>,
    headers: HeaderMap,
    Path((account_id, device_id_hex)): Path<(String, String)>,
) -> Response {
    let account_id = match normalize_account_id(&account_id) {
        Ok(value) => value,
        Err(error) => return service_error(error),
    };
    let device_id_hex = match decode_32(&device_id_hex, "device_id_hex") {
        Ok(_) => device_id_hex.to_ascii_lowercase(),
        Err(error) => return service_error(error),
    };
    let session = match authenticated_session(&state, &headers) {
        Ok(session) => session,
        Err(response) => return response,
    };
    if session.account_id != account_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "ACCOUNT_SCOPE_MISMATCH",
            "Session is outside this account",
        );
    }
    let (public_key_hex, vault_ids, changed) = {
        let db = match state.connection() {
            Ok(db) => db,
            Err(error) => return service_error(error),
        };
        let public_key: Option<String> = match db
            .query_row(
                "SELECT public_key_hex FROM devices WHERE account_id = ?1 AND device_id_hex = ?2 AND revoked_at_utc IS NULL",
                params![account_id, device_id_hex],
                |row| row.get(0),
            )
            .optional()
        {
            Ok(value) => value,
            Err(error) => return service_error(error.into()),
        };
        let Some(public_key) = public_key else {
            return error_response(
                StatusCode::NOT_FOUND,
                "DEVICE_NOT_FOUND",
                "Device is not enrolled or is already revoked",
            );
        };
        let now = now_utc();
        if let Err(error) = db.execute(
            "UPDATE devices SET revoked_at_utc = ?3 WHERE account_id = ?1 AND device_id_hex = ?2",
            params![account_id, device_id_hex, now],
        ) {
            return service_error(error.into());
        }
        if let Err(error) = db.execute(
            "UPDATE sessions SET revoked_at_utc = ?3 WHERE account_id = ?1 AND device_id_hex = ?2 AND revoked_at_utc IS NULL",
            params![account_id, device_id_hex, now],
        ) {
            return service_error(error.into());
        }
        if let Err(error) = audit_event(
            &db,
            &account_id,
            "device_revoked",
            serde_json::json!({"device_id_hex": device_id_hex}),
        ) {
            return service_error(error.into());
        }
        let mut vault_ids = Vec::new();
        let mut statement =
            match db.prepare("SELECT vault_id_hex FROM vault_links WHERE account_id = ?1") {
                Ok(statement) => statement,
                Err(error) => return service_error(error.into()),
            };
        let mut rows = match statement.query(params![account_id]) {
            Ok(rows) => rows,
            Err(error) => return service_error(error.into()),
        };
        while let Ok(Some(row)) = rows.next() {
            if let Ok(vault_id) = row.get::<_, String>(0) {
                vault_ids.push(vault_id);
            }
        }
        (public_key, vault_ids, true)
    };
    let (operator_targets, operator_revocations, operator_failures) =
        propagate_device_revocation(&state, &public_key_hex, &vault_ids).await;
    Json(RevocationResponse {
        revoked: changed,
        operator_targets,
        operator_revocations,
        operator_failures,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SESSION_COOKIE_NAME;
    use crate::test_support::{cleanup, json, test_app};
    use crate::util::b64_encode;
    use axum::body::Body;
    use axum::http::Request;
    use ciphervault_crypto::{generate_signing_key, signatures::sign_with_domain};
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    use tower05::ServiceExt;

    #[tokio::test]
    async fn account_device_proof_login_and_revocation_lifecycle() {
        let (root, _state, app) = test_app("service");
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
        cleanup(root);
    }
}
