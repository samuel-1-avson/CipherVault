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
    http::{authenticated_session_with_db, error_response, service_error},
    prune_expired, random_hex,
    state::{
        now_utc, AccountState, ChallengeView, DeviceChallengeRequest, DeviceEnrollmentRequest,
        DeviceView, CHALLENGE_TTL_SECONDS,
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
