//! RFC 6238 time-based one-time passwords.
//!
//! CipherVault uses TOTP as an account-session factor. It is deliberately
//! separate from vault encryption keys and is never used to derive or expose
//! vault plaintext.

use rand::RngCore;
use ring::hmac;
use subtle::ConstantTimeEq;

pub const STEP_SECONDS: u64 = 30;
pub const DIGITS: usize = 6;
const SECRET_BYTES: usize = 20;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("TOTP code must contain exactly six digits")]
    InvalidCode,
    #[error("TOTP secret is empty or malformed")]
    InvalidSecret,
    #[error("TOTP code is outside the accepted time window")]
    CodeMismatch,
    #[error("TOTP code was already used")]
    Replay,
}

pub fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; SECRET_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    secret
}

pub fn base32_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for &byte in bytes {
        buffer = (buffer << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

#[allow(dead_code)]
pub fn base32_decode(value: &str) -> Result<Vec<u8>, TotpError> {
    let mut output = Vec::with_capacity(value.len() * 5 / 8);
    let mut buffer = 0u16;
    let mut bits = 0u8;
    let mut saw_symbol = false;
    for byte in value.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() || byte == b'-' {
            continue;
        }
        let upper = byte.to_ascii_uppercase();
        let index = match upper {
            b'A'..=b'Z' => upper - b'A',
            b'2'..=b'7' => upper - b'2' + 26,
            _ => return Err(TotpError::InvalidSecret),
        };
        saw_symbol = true;
        buffer = (buffer << 5) | index as u16;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            if bits == 0 {
                buffer = 0;
            } else {
                buffer &= (1u16 << bits) - 1;
            }
        }
    }
    if !saw_symbol || output.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    Ok(output)
}

pub fn code_for_step(secret: &[u8], step: u64) -> Result<String, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::InvalidSecret);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let bytes = tag.as_ref();
    let offset = (bytes[bytes.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(bytes[offset]) & 0x7f) << 24)
        | (u32::from(bytes[offset + 1]) << 16)
        | (u32::from(bytes[offset + 2]) << 8)
        | u32::from(bytes[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

/// Verify a code in the current step plus or minus one 30-second step.
/// Returns the matched step so callers can persist a replay barrier.
pub fn verify_code(
    secret: &[u8],
    code: &str,
    now_seconds: u64,
    last_used_step: Option<u64>,
) -> Result<u64, TotpError> {
    let normalized = code.trim();
    if normalized.len() != DIGITS || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TotpError::InvalidCode);
    }
    let current_step = now_seconds / STEP_SECONDS;
    for candidate in [
        current_step.saturating_sub(1),
        current_step,
        current_step + 1,
    ] {
        if last_used_step.is_some_and(|last| candidate <= last) {
            continue;
        }
        let expected = code_for_step(secret, candidate)?;
        if expected.as_bytes().ct_eq(normalized.as_bytes()).into() {
            return Ok(candidate);
        }
    }
    if last_used_step.is_some_and(|last| last >= current_step.saturating_sub(1)) {
        Err(TotpError::Replay)
    } else {
        Err(TotpError::CodeMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trip() {
        let input = b"12345678901234567890";
        let encoded = base32_encode(input);
        assert_eq!(encoded, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&encoded).unwrap(), input);
        for length in 1..=32 {
            let sample: Vec<u8> = (0..length).map(|value| value as u8).collect();
            assert_eq!(base32_decode(&base32_encode(&sample)).unwrap(), sample);
        }
    }

    #[test]
    fn rfc6238_sha1_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(
            code_for_step(secret, 1_111_111_111 / STEP_SECONDS).unwrap(),
            "050471"
        );
    }

    #[test]
    fn replay_is_rejected() {
        let secret = b"test secret";
        let now = 30 * 100;
        let code = code_for_step(secret, 100).unwrap();
        assert_eq!(
            verify_code(secret, &code, now, Some(100)),
            Err(TotpError::Replay)
        );
        assert_eq!(verify_code(secret, &code, now, None), Ok(100));
    }
}
