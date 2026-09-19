//! WebAuthn RP config, CBOR parsing, attestation verification helpers.

use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use ring::signature::{self, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use std::io::Cursor;

use crate::error::AccountServiceError;

pub(crate) fn webauthn_rp_id() -> String {
    std::env::var("CIPHERVAULT_WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".into())
}

pub(crate) fn webauthn_origin() -> String {
    std::env::var("CIPHERVAULT_WEBAUTHN_ORIGIN").unwrap_or_else(|_| "http://localhost:8300".into())
}

pub(crate) fn webauthn_user_id(account_id: &str) -> Vec<u8> {
    Sha256::digest(account_id.as_bytes())[..16].to_vec()
}

pub(crate) fn cbor_map_value(
    map: &[(ciborium::Value, ciborium::Value)],
    key: i128,
) -> Option<&ciborium::Value> {
    map.iter().find_map(|(candidate, value)| {
        (candidate
            .as_integer()
            .is_some_and(|integer| i128::from(integer) == key))
        .then_some(value)
    })
}

pub(crate) fn cbor_text_value<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a str> {
    map.iter().find_map(|(candidate, value)| {
        (candidate.as_text() == Some(key))
            .then(|| value.as_text())
            .flatten()
    })
}

pub(crate) fn cbor_bytes_value(
    map: &[(ciborium::Value, ciborium::Value)],
    key: i128,
) -> Option<&[u8]> {
    cbor_map_value(map, key)
        .and_then(ciborium::Value::as_bytes)
        .map(Vec::as_slice)
}

pub(crate) fn cbor_bytes_text_value<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a [u8]> {
    map.iter().find_map(|(candidate, value)| {
        (candidate.as_text() == Some(key))
            .then(|| value.as_bytes())
            .flatten()
            .map(Vec::as_slice)
    })
}

#[derive(Debug)]
pub(crate) struct ParsedAuthenticatorData {
    pub(crate) sign_count: u32,
    pub(crate) credential_id: Option<Vec<u8>>,
    pub(crate) algorithm: Option<i64>,
    pub(crate) public_key: Option<Vec<u8>>,
}

pub(crate) fn parse_authenticator_data(
    bytes: &[u8],
    registration: bool,
) -> Result<ParsedAuthenticatorData, AccountServiceError> {
    if bytes.len() < 37 {
        return Err(AccountServiceError::Invalid(
            "authenticator_data is shorter than the WebAuthn minimum".into(),
        ));
    }
    let rp_hash = Sha256::digest(webauthn_rp_id().as_bytes());
    if bytes[..32] != rp_hash[..] {
        return Err(AccountServiceError::Invalid(
            "WebAuthn RP ID hash does not match the configured RP ID".into(),
        ));
    }
    let flags = bytes[32];
    if flags & 0x01 == 0 {
        return Err(AccountServiceError::Invalid(
            "WebAuthn user presence flag is not set".into(),
        ));
    }
    if std::env::var("CIPHERVAULT_WEBAUTHN_REQUIRE_UV")
        .ok()
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        && flags & 0x04 == 0
    {
        return Err(AccountServiceError::Invalid(
            "WebAuthn user verification flag is required".into(),
        ));
    }
    let sign_count = u32::from_be_bytes(bytes[33..37].try_into().expect("length checked"));
    if !registration {
        return Ok(ParsedAuthenticatorData {
            sign_count,
            credential_id: None,
            algorithm: None,
            public_key: None,
        });
    }
    if flags & 0x40 == 0 {
        return Err(AccountServiceError::Invalid(
            "registration authenticator data does not contain attested credential data".into(),
        ));
    }
    if bytes.len() < 55 {
        return Err(AccountServiceError::Invalid(
            "registration authenticator data is truncated".into(),
        ));
    }
    let credential_len =
        u16::from_be_bytes(bytes[53..55].try_into().expect("length checked")) as usize;
    let credential_start: usize = 55;
    let credential_end = credential_start
        .checked_add(credential_len)
        .ok_or_else(|| AccountServiceError::Invalid("credential ID length overflow".into()))?;
    if credential_end > bytes.len() {
        return Err(AccountServiceError::Invalid(
            "registration credential ID is truncated".into(),
        ));
    }
    let credential_id = bytes[credential_start..credential_end].to_vec();
    let cose: ciborium::Value = ciborium::from_reader(Cursor::new(&bytes[credential_end..]))
        .map_err(|_| {
            AccountServiceError::Invalid("credential public key CBOR is invalid".into())
        })?;
    let cose_map = cose.as_map().ok_or_else(|| {
        AccountServiceError::Invalid("credential public key must be a CBOR map".into())
    })?;
    let kty = cbor_map_value(cose_map, 1)
        .and_then(ciborium::Value::as_integer)
        .map(i128::from)
        .ok_or_else(|| {
            AccountServiceError::Invalid("credential public key has no key type".into())
        })?;
    let algorithm = cbor_map_value(cose_map, 3)
        .and_then(ciborium::Value::as_integer)
        .map(i128::from)
        .ok_or_else(|| {
            AccountServiceError::Invalid("credential public key has no algorithm".into())
        })?;
    let curve = cbor_map_value(cose_map, -1)
        .and_then(ciborium::Value::as_integer)
        .map(i128::from);
    let (algorithm, public_key) = match (kty, algorithm, curve) {
        (1, -8, Some(6)) => {
            let key = cbor_bytes_value(cose_map, -2).ok_or_else(|| {
                AccountServiceError::Invalid("Ed25519 credential public key has no x value".into())
            })?;
            if key.len() != 32 {
                return Err(AccountServiceError::Invalid(
                    "Ed25519 credential public key must be 32 bytes".into(),
                ));
            }
            (-8, key.to_vec())
        }
        (2, -7, Some(1)) => {
            let x = cbor_bytes_value(cose_map, -2).ok_or_else(|| {
                AccountServiceError::Invalid("ES256 credential public key has no x value".into())
            })?;
            let y = cbor_bytes_value(cose_map, -3).ok_or_else(|| {
                AccountServiceError::Invalid("ES256 credential public key has no y value".into())
            })?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AccountServiceError::Invalid(
                    "ES256 credential coordinates must be 32 bytes each".into(),
                ));
            }
            let mut key = Vec::with_capacity(65);
            key.push(0x04);
            key.extend_from_slice(x);
            key.extend_from_slice(y);
            (-7, key)
        }
        _ => {
            return Err(AccountServiceError::Invalid(
                "only Ed25519 (-8) and ES256 (-7) WebAuthn credentials are supported".into(),
            ))
        }
    };
    Ok(ParsedAuthenticatorData {
        sign_count,
        credential_id: Some(credential_id),
        algorithm: Some(algorithm),
        public_key: Some(public_key),
    })
}

pub(crate) fn parse_attestation_object(
    value: &[u8],
) -> Result<ParsedAuthenticatorData, AccountServiceError> {
    let attestation: ciborium::Value = ciborium::from_reader(Cursor::new(value))
        .map_err(|_| AccountServiceError::Invalid("attestation_object CBOR is invalid".into()))?;
    let map = attestation.as_map().ok_or_else(|| {
        AccountServiceError::Invalid("attestation_object must be a CBOR map".into())
    })?;
    let format = cbor_text_value(map, "fmt")
        .ok_or_else(|| AccountServiceError::Invalid("attestation_object has no format".into()))?;
    if format != "none" {
        return Err(AccountServiceError::Invalid(
            "only WebAuthn fmt=none attestation is accepted; packed and enterprise attestation require an explicit policy".into(),
        ));
    }
    let attestation_statement = map
        .iter()
        .find_map(|(key, value)| (key.as_text() == Some("attStmt")).then_some(value))
        .ok_or_else(|| AccountServiceError::Invalid("attestation_object has no attStmt".into()))?;
    if !matches!(attestation_statement, ciborium::Value::Map(values) if values.is_empty()) {
        return Err(AccountServiceError::Invalid(
            "fmt=none attestation must contain an empty attStmt".into(),
        ));
    }
    let auth_data = cbor_bytes_text_value(map, "authData")
        .ok_or_else(|| AccountServiceError::Invalid("attestation_object has no authData".into()))?;
    parse_authenticator_data(auth_data, true)
}

pub(crate) fn validate_client_data(
    bytes: &[u8],
    expected_type: &str,
    expected_challenge: &str,
) -> Result<(), AccountServiceError> {
    let client_data: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| AccountServiceError::Invalid("client_data_json is invalid JSON".into()))?;
    if client_data.get("type").and_then(serde_json::Value::as_str) != Some(expected_type) {
        return Err(AccountServiceError::Invalid(
            "WebAuthn client data type does not match the ceremony".into(),
        ));
    }
    if client_data
        .get("challenge")
        .and_then(serde_json::Value::as_str)
        != Some(expected_challenge)
    {
        return Err(AccountServiceError::Invalid(
            "WebAuthn challenge does not match the issued challenge".into(),
        ));
    }
    if client_data
        .get("origin")
        .and_then(serde_json::Value::as_str)
        != Some(webauthn_origin().as_str())
    {
        return Err(AccountServiceError::Invalid(
            "WebAuthn origin does not match the configured origin".into(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_webauthn_signature(
    algorithm: i64,
    public_key: &[u8],
    signed_data: &[u8],
    signature_bytes: &[u8],
) -> Result<(), AccountServiceError> {
    match algorithm {
        -8 => {
            let key: [u8; 32] = public_key.try_into().map_err(|_| {
                AccountServiceError::Invalid("Ed25519 credential public key is invalid".into())
            })?;
            let key = VerifyingKey::from_bytes(&key).map_err(|_| {
                AccountServiceError::Invalid("Ed25519 credential public key is invalid".into())
            })?;
            let signature = Ed25519Signature::from_slice(signature_bytes).map_err(|_| {
                AccountServiceError::Invalid("Ed25519 WebAuthn signature is invalid".into())
            })?;
            key.verify(signed_data, &signature).map_err(|_| {
                AccountServiceError::Invalid("WebAuthn assertion signature is invalid".into())
            })
        }
        -7 => UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key)
            .verify(signed_data, signature_bytes)
            .map_err(|_| {
                AccountServiceError::Invalid("WebAuthn assertion signature is invalid".into())
            }),
        _ => Err(AccountServiceError::Invalid(
            "unsupported WebAuthn algorithm".into(),
        )),
    }
}
