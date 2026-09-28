//! Log scrubber for the §20 Audit Privacy Rule (T-901).
//!
//! Plaintext secret values must never appear in audit records, error
//! responses, stack traces, or metrics logs. Values are kept out of those
//! sinks by construction ([`SecretValue`][ciphervault_format] has no
//! `Display`/`Serialize` and a redacted `Debug`), but free-text fields —
//! audit `reason` strings, operator-supplied labels, wrapped error chains —
//! can still smuggle credential-shaped material into the log stream. This
//! crate is the last-chance filter: [`redact_text`] rewrites value-shaped
//! spans to `[REDACTED]` placeholders, and [`contains_secret_shaped`]
//! backs the entropy/canary CI gate.
//!
//! Recognized shapes (std-only scanners, no regex dependency):
//!
//! * `cvst1.*` scope tokens (`cvst1.<b64url>.<b64url>` wire format).
//! * `Bearer <token>` HTTP credential fragments (case-insensitive scheme).
//! * `-----BEGIN <label>----- … -----END …-----` PEM blocks whose label
//!   contains `PRIVATE` (public certs/keys pass through: they are not
//!   secrets and stay useful in logs).
//! * `key=value` / `key: value` assignments for a fixed credential-key
//!   list (`password`, `secret`, `api_key`, …); the key and separator are
//!   kept so the log stays intelligible.
//!
//! Deliberately **not** redacted: hex digests, UUIDs, snapshot IDs, event
//! hashes, and `secret_id` references. Those are non-sensitive pointers;
//! scrubbing them would blind debugging and break byte-stable golden
//! output. High-entropy blob detection is intentionally absent for the
//! same reason — digests are high-entropy by design. The canary gate
//! ([`contains_secret_shaped`] + the `audit_chain` canary test) proves
//! values stay out instead of guessing at randomness.
//!
//! [ciphervault_format]: https://docs.rs/crate/ciphervault-format
#![forbid(unsafe_code)]

/// Placeholder substituted for redacted credential material.
pub const REDACTED: &str = "[REDACTED]";

/// Credential keys matched (ASCII case-insensitive) in `key=value` /
/// `key: value` assignments. Word-bounded: `secret_id` does NOT match
/// `secret` because `_` is a word character.
const CREDENTIAL_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth_token",
    "private_key",
    "client_secret",
    "session_token",
];

/// Rewrite every credential-shaped span in `input` to [`REDACTED`]
/// placeholders. The transform is idempotent and never fails; unrecognized
/// text passes through byte-identical.
///
/// ```
/// # use ciphervault_redact::redact_text;
/// let scrubbed = redact_text("login with password=hunter2 failed");
/// assert_eq!(scrubbed, "login with password=[REDACTED] failed");
/// ```
#[must_use]
pub fn redact_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if let Some(end) = match_scope_token(bytes, idx) {
            out.push_str("cvst1.");
            out.push_str(REDACTED);
            idx = end;
        } else if let Some(end) = match_bearer(bytes, idx) {
            // Keep the scheme so the sink stays intelligible.
            out.push_str(&input[idx..idx + 6]);
            out.push(' ');
            out.push_str(REDACTED);
            idx = end;
        } else if let Some(end) = match_private_pem(bytes, idx) {
            out.push_str(REDACTED);
            out.push_str(" PRIVATE KEY");
            idx = end;
        } else if let Some((key_end, value_end)) = match_credential_assignment(bytes, idx) {
            out.push_str(&input[idx..key_end]);
            out.push_str(REDACTED);
            idx = value_end;
        } else {
            // Copy one scalar value (inputs are &str, always a boundary).
            let ch = input[idx..].chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            idx += ch.len_utf8();
        }
    }
    out
}

/// Returns `true` when `input` contains any credential-shaped span that
/// [`redact_text`] would rewrite. Used by the canary gate: audit rows,
/// exported audit JSONL, and rendered errors must all scan clean.
///
/// ```
/// # use ciphervault_redact::contains_secret_shaped;
/// assert!(contains_secret_shaped("token cvst1.e30.e30 arrived"));
/// assert!(!contains_secret_shaped("snapshot 9f2c head replicated"));
/// ```
#[must_use]
pub fn contains_secret_shaped(input: &str) -> bool {
    let bytes = input.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if match_scope_token(bytes, idx).is_some()
            || match_bearer(bytes, idx).is_some()
            || match_private_pem(bytes, idx).is_some()
            || match_credential_assignment(bytes, idx).is_some()
        {
            return true;
        }
        let ch = input[idx..].chars().next().unwrap_or('\u{FFFD}');
        idx += ch.len_utf8();
    }
    false
}

/// `cvst1.<segment>(.<segment>)*` where segments are base64url runs.
/// Requires at least one payload segment; a trailing `.` is not consumed
/// (sentence punctuation survives).
fn match_scope_token(bytes: &[u8], start: usize) -> Option<usize> {
    if !bytes[start..].starts_with(b"cvst1.") {
        return None;
    }
    let mut idx = start + "cvst1.".len();
    let mut consumed = false;
    loop {
        let seg_start = idx;
        while idx < bytes.len() && is_token_char(bytes[idx]) {
            idx += 1;
        }
        if seg_start == idx {
            break;
        }
        consumed = true;
        // An internal dot continues only when followed by a token char.
        if idx + 1 < bytes.len() && bytes[idx] == b'.' && is_token_char(bytes[idx + 1]) {
            idx += 1;
        } else {
            break;
        }
    }
    consumed.then_some(idx)
}

/// Case-insensitive `Bearer <token-run>`; the scheme must be word-bounded
/// on the left so `keybearer x` does not match.
fn match_bearer(bytes: &[u8], start: usize) -> Option<usize> {
    if start > 0 && is_word_char(bytes[start - 1]) {
        return None;
    }
    if bytes.len() < start + 7 || !bytes[start..start + 6].eq_ignore_ascii_case(b"bearer") {
        return None;
    }
    if !bytes[start + 6].is_ascii_whitespace() {
        return None;
    }
    let mut idx = start + 7;
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    let value_start = idx;
    while idx < bytes.len() && is_token_char(bytes[idx]) {
        idx += 1;
    }
    (idx > value_start).then_some(idx)
}

/// `-----BEGIN <label>----- … -----END …-----` with `PRIVATE` in the label.
/// Returns the end of the END line (or end of input when unterminated, so a
/// truncated key dump still redacts).
fn match_private_pem(bytes: &[u8], start: usize) -> Option<usize> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    if !bytes[start..].starts_with(BEGIN) {
        return None;
    }
    // The closing fence is searched past the opening fence (position 0
    // would match the fence we already consumed).
    const END_MARK: &[u8] = b"-----END ";
    let header_end = bytes[start + BEGIN.len()..]
        .windows(5)
        .position(|w| w == b"-----")
        .map(|pos| start + BEGIN.len() + pos + 5)?;
    let label = &bytes[start + BEGIN.len()..header_end.saturating_sub(5)];
    if label.len() < 7 || !label.windows(7).any(|w| w.eq_ignore_ascii_case(b"PRIVATE")) {
        return None;
    }
    // Find the END fence; tolerate a truncated dump (redact to EOF).
    let mut idx = header_end;
    while idx < bytes.len() {
        if bytes[idx..].starts_with(END_MARK) {
            let end = bytes[idx + END_MARK.len()..]
                .windows(5)
                .position(|w| w == b"-----")
                .map(|pos| idx + END_MARK.len() + pos + 5)
                .unwrap_or(bytes.len());
            // Swallow one trailing newline so no key bytes leak past it.
            return Some(if end < bytes.len() && bytes[end] == b'\n' {
                end + 1
            } else {
                end
            });
        }
        idx += 1;
    }
    Some(bytes.len())
}

/// `<credential-key> <sep> <value>` with word-bounded key (left and right)
/// and `:`/`=` separator. Returns `(key_end, value_end)` so the caller can
/// keep `key + separator` and replace only the value.
fn match_credential_assignment(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if start > 0 && is_word_char(bytes[start - 1]) {
        return None;
    }
    for key in CREDENTIAL_KEYS {
        if bytes.len() < start + key.len()
            || !bytes[start..start + key.len()].eq_ignore_ascii_case(key.as_bytes())
        {
            continue;
        }
        let after_key = start + key.len();
        if after_key < bytes.len() && is_word_char(bytes[after_key]) {
            continue; // `secret_id`, `passwords`, … are not assignments.
        }
        let mut idx = after_key;
        // JSON-style quoted keys: `"api_key": "…"`.
        if idx < bytes.len() && (bytes[idx] == b'"' || bytes[idx] == b'\'') {
            idx += 1;
        }
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        // The separator must be `:` or `=`.
        if idx >= bytes.len() || (bytes[idx] != b':' && bytes[idx] != b'=') {
            continue;
        }
        idx += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        let value_start = idx;
        // Quoted values consume through the closing quote.
        if idx < bytes.len() && (bytes[idx] == b'"' || bytes[idx] == b'\'') {
            let quote = bytes[idx];
            idx += 1;
            while idx < bytes.len() && bytes[idx] != quote {
                idx += 1;
            }
            if idx < bytes.len() {
                idx += 1; // closing quote
            }
        } else {
            while idx < bytes.len() && is_value_char(bytes[idx]) {
                idx += 1;
            }
        }
        if idx > value_start {
            return Some((value_start, idx));
        }
    }
    None
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'=' | b'~')
}

fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Unquoted assignment values end at whitespace or JSON/log punctuation.
fn is_value_char(byte: u8) -> bool {
    !(byte.is_ascii_whitespace()
        || matches!(
            byte,
            b',' | b';' | b'"' | b'\'' | b'}' | b']' | b')' | b'(' | b'{' | b'['
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_token_redacts_payload_but_keeps_prefix() {
        let token = "cvst1.eyJwcm9qZWN0Ijoiez99.MEUCIBxYzQ";
        assert_eq!(redact_text(token), format!("cvst1.{REDACTED}"));
        assert!(contains_secret_shaped(token));
        // Trailing sentence punctuation survives.
        assert_eq!(
            redact_text("saw cvst1.abc.def."),
            format!("saw cvst1.{REDACTED}.")
        );
    }

    #[test]
    fn bare_prefix_without_payload_passes_through() {
        assert_eq!(redact_text("prefix cvst1. here"), "prefix cvst1. here");
        assert!(!contains_secret_shaped("prefix cvst1. here"));
    }

    #[test]
    fn bearer_scheme_kept_token_redacted() {
        assert_eq!(
            redact_text("Authorization: Bearer abcDEF123-_"),
            format!("Authorization: Bearer {REDACTED}")
        );
        assert!(contains_secret_shaped("bearer abc"));
        // Not word-bounded: no match.
        assert!(!contains_secret_shaped("keybearer abc"));
        assert!(!contains_secret_shaped("Bearer"));
    }

    #[test]
    fn private_pem_redacted_public_pem_kept() {
        let private =
            "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...\n-----END EC PRIVATE KEY-----\n";
        let scrubbed = redact_text(&format!("key:\n{private}done"));
        assert!(scrubbed.contains("[REDACTED] PRIVATE KEY"));
        assert!(!scrubbed.contains("MHcCAQEEI"));
        assert!(contains_secret_shaped(private));
        // Truncated dump still redacts to EOF.
        assert!(redact_text("-----BEGIN PRIVATE KEY-----\nabc").ends_with("PRIVATE KEY"));
        // Public material passes through.
        let public = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----";
        assert_eq!(redact_text(public), public);
        assert!(!contains_secret_shaped(public));
    }

    #[test]
    fn credential_assignments_keep_key_redact_value() {
        assert_eq!(
            redact_text("login password=hunter2 failed"),
            format!("login password={REDACTED} failed")
        );
        assert_eq!(
            redact_text(r#"{"api_key": "AKIA-SECRET"}"#),
            format!(r#"{{"api_key": {REDACTED}}}"#)
        );
        assert_eq!(
            redact_text("client_secret : 's3cr3t'; next"),
            format!("client_secret : {REDACTED}; next")
        );
        assert!(contains_secret_shaped("SECRET=topsecret"));
    }

    #[test]
    fn identifier_lookalikes_pass_through() {
        // secret_id / passwords / api_keys are references, not assignments.
        for clean in [
            "secret_id 01923f11 loaded",
            "rotation of passwords policy",
            "api_keys table migrated",
            "snapshot 9f2c1a head replicated",
            "event_hash 64-hex digest stored",
            "cvst1 prefix versions the wire format",
        ] {
            assert_eq!(redact_text(clean), clean, "{clean}");
            assert!(!contains_secret_shaped(clean), "{clean}");
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = redact_text("pw password=x token cvst1.a.b");
        assert_eq!(redact_text(&once), once);
    }

    #[test]
    fn unicode_passthrough() {
        assert_eq!(
            redact_text("caf\u{e9} \u{1f511} ok"),
            "caf\u{e9} \u{1f511} ok"
        );
    }
}
