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

/// Key-name suffixes (ASCII case-insensitive) that mark an assignment's
/// value as credential material even when the full key is not in
/// [`CREDENTIAL_KEYS`] — e.g. `aws_secret_access_key`, `STRIPE_SECRET_KEY`,
/// `MY_SERVICE_TOKEN`. `_ID`/`_NAME` style identifiers deliberately do
/// not match: they are references, not values.
const CREDENTIAL_KEY_SUFFIXES: &[&str] = &[
    "_SECRET",
    "_TOKEN",
    "_PASSWORD",
    "_PASSWD",
    "_API_KEY",
    "_APIKEY",
    "_PRIVATE_KEY",
    "_ACCESS_KEY",
    "_SECRET_KEY",
    "_AUTH",
    "_CREDENTIALS",
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
    redact_text_counted(input).0
}

/// [`redact_text`] plus the number of spans it rewrote, so callers can
/// report honest counts. A value that is already a `[REDACTED…]` marker
/// (for example from exact-value scrubbing) is normalized but not
/// counted a second time.
#[must_use]
pub fn redact_text_counted(input: &str) -> (String, usize) {
    let mut out = String::with_capacity(input.len());
    let mut count = 0usize;
    let bytes = input.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if let Some(end) = match_scope_token(bytes, idx) {
            count += usize::from(!is_redaction_marker(&input[idx + 6..end]));
            out.push_str("cvst1.");
            out.push_str(REDACTED);
            idx = end;
        } else if let Some(end) = match_bearer(bytes, idx) {
            count += usize::from(!is_redaction_marker(&input[idx + 6..end]));
            // Keep the scheme so the sink stays intelligible.
            out.push_str(&input[idx..idx + 6]);
            out.push(' ');
            out.push_str(REDACTED);
            idx = end;
        } else if let Some(end) = match_private_pem(bytes, idx) {
            count += usize::from(!is_redaction_marker(&input[idx..end]));
            out.push_str(REDACTED);
            out.push_str(" PRIVATE KEY");
            idx = end;
        } else if let Some((keep_end, value_end)) = match_credential_url(bytes, idx) {
            count += usize::from(!is_redaction_marker(&input[keep_end..value_end]));
            out.push_str(&input[idx..keep_end]);
            out.push_str(REDACTED);
            idx = value_end;
        } else if let Some((key_end, value_end)) = match_credential_assignment(bytes, idx) {
            count += usize::from(!is_redaction_marker(&input[key_end..value_end]));
            out.push_str(&input[idx..key_end]);
            out.push_str(REDACTED);
            idx = value_end;
        } else if let Some((key_end, value_end)) = match_generic_credential(bytes, idx) {
            count += usize::from(!is_redaction_marker(&input[key_end..value_end]));
            out.push_str(&input[idx..key_end]);
            out.push_str(REDACTED);
            idx = value_end;
        } else if let Some((keep_end, value_end)) = match_vendor_token(bytes, idx) {
            // Keep the vendor prefix so the sink still says what leaked.
            count += 1;
            out.push_str(&input[idx..keep_end]);
            out.push_str(REDACTED);
            idx = value_end;
        } else if let Some(end) = match_jwt(bytes, idx) {
            count += 1;
            out.push_str(REDACTED);
            idx = end;
        } else {
            // Copy one scalar value (inputs are &str, always a boundary).
            let ch = input[idx..].chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            idx += ch.len_utf8();
        }
    }
    (out, count)
}

/// True when a matched value is already a redaction placeholder.
fn is_redaction_marker(value: &str) -> bool {
    value
        .trim_start_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace())
        .starts_with("[REDACTED")
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
            || match_credential_url(bytes, idx).is_some()
            || match_credential_assignment(bytes, idx).is_some()
            || match_generic_credential(bytes, idx).is_some()
            || match_vendor_token(bytes, idx).is_some()
            || match_jwt(bytes, idx).is_some()
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
    // Dotted (JWT-style) and standard-base64 tokens are one value; a
    // trailing `.` is sentence punctuation and stays.
    while idx < bytes.len()
        && (is_token_char(bytes[idx]) || matches!(bytes[idx], b'.' | b'+' | b'/'))
    {
        idx += 1;
    }
    while idx > value_start && bytes[idx - 1] == b'.' {
        idx -= 1;
    }
    (idx > value_start).then_some(idx)
}

/// Vendor credential formats recognised without any surrounding key:
/// `(prefix, body byte class, minimum body length, exact length?, body
/// must mix letters and digits?)`. Formats are deliberately narrow (fixed
/// prefixes plus length rules) so digests, UUIDs and prose pass through.
type BodyClass = fn(u8) -> bool;
const VENDOR_FORMATS: &[(&[u8], BodyClass, usize, bool, bool)] = &[
    (b"ghp_", is_alnum, 30, false, false),
    (b"gho_", is_alnum, 30, false, false),
    (b"ghu_", is_alnum, 30, false, false),
    (b"ghs_", is_alnum, 30, false, false),
    (b"ghr_", is_alnum, 30, false, false),
    (b"github_pat_", is_word_char, 22, false, false),
    (b"AKIA", is_upper_or_digit, 16, true, false),
    (b"ASIA", is_upper_or_digit, 16, true, false),
    (b"sk_live_", is_alnum, 10, false, false),
    (b"sk_test_", is_alnum, 10, false, false),
    (b"rk_live_", is_alnum, 10, false, false),
    (b"rk_test_", is_alnum, 10, false, false),
    (b"xoxa-", is_alnum_or_dash, 10, false, true),
    (b"xoxb-", is_alnum_or_dash, 10, false, true),
    (b"xoxp-", is_alnum_or_dash, 10, false, true),
    (b"xoxr-", is_alnum_or_dash, 10, false, true),
    (b"xoxs-", is_alnum_or_dash, 10, false, true),
    (b"sk-", is_base64url, 20, false, true),
    (b"AIza", is_base64url, 35, true, false),
];

/// A vendor token at `start`; returns `(prefix_end, token_end)`. Both
/// edges are bounded: `task-force-…` does not match `sk-`, and a
/// 17-character AWS-looking run is not an access key id.
fn match_vendor_token(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if start > 0 && (is_word_char(bytes[start - 1]) || bytes[start - 1] == b'-') {
        return None;
    }
    for (prefix, body_class, min_len, exact, needs_mix) in VENDOR_FORMATS {
        if !bytes[start..].starts_with(prefix) {
            continue;
        }
        let body_start = start + prefix.len();
        let mut end = body_start;
        while end < bytes.len() && body_class(bytes[end]) {
            end += 1;
        }
        let body = &bytes[body_start..end];
        let length_ok = if *exact {
            body.len() == *min_len
        } else {
            body.len() >= *min_len
        };
        let bounded = end >= bytes.len() || !is_word_char(bytes[end]);
        let mixed = !needs_mix
            || (body.iter().any(u8::is_ascii_digit) && body.iter().any(u8::is_ascii_alphabetic));
        if length_ok && bounded && mixed {
            return Some((body_start, end));
        }
    }
    None
}

/// `eyJ<header>.<payload>.<signature>` (base64url JSON web token).
fn match_jwt(bytes: &[u8], start: usize) -> Option<usize> {
    if start > 0 && (is_base64url(bytes[start - 1]) || bytes[start - 1] == b'.') {
        return None;
    }
    if !bytes[start..].starts_with(b"eyJ") {
        return None;
    }
    let mut idx = start;
    for segment in 0..3 {
        let seg_start = idx;
        while idx < bytes.len() && is_base64url(bytes[idx]) {
            idx += 1;
        }
        if idx - seg_start < 8 {
            return None;
        }
        if segment < 2 {
            if idx >= bytes.len() || bytes[idx] != b'.' {
                return None;
            }
            idx += 1;
        }
    }
    Some(idx)
}

/// Keys that only count when their value also looks like a credential:
/// bare `token`, `SECRET_KEY` / `ACCESS_KEY`, and hyphenated header-style
/// names (`x-api-key`, `X-Auth-Token`) whose underscore form is a
/// credential key. The value test keeps code (`token = tokens[i]`,
/// `secret_key=settings.SECRET_KEY`) and `$VAR` references untouched.
fn match_generic_credential(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if start > 0 && (is_word_char(bytes[start - 1]) || bytes[start - 1] == b'-') {
        return None;
    }
    let mut key_end = start;
    while key_end < bytes.len() && (is_word_char(bytes[key_end]) || bytes[key_end] == b'-') {
        key_end += 1;
    }
    if key_end == start {
        return None;
    }
    let ident = std::str::from_utf8(&bytes[start..key_end]).ok()?;
    let normalized = ident.to_ascii_uppercase().replace('-', "_");
    let generic = matches!(normalized.as_str(), "TOKEN" | "SECRET_KEY" | "ACCESS_KEY")
        || (ident.contains('-')
            && (CREDENTIAL_KEYS
                .iter()
                .any(|key| key.eq_ignore_ascii_case(&normalized))
                || CREDENTIAL_KEY_SUFFIXES
                    .iter()
                    .any(|sfx| normalized.len() > sfx.len() && normalized.ends_with(sfx))));
    if !generic {
        return None;
    }
    let (value_start, value_end) = match_assignment_value(bytes, key_end)?;
    let inner = bytes[value_start..value_end]
        .strip_prefix(b"\"")
        .or_else(|| bytes[value_start..value_end].strip_prefix(b"'"))
        .map(|rest| {
            rest.strip_suffix(b"\"")
                .or_else(|| rest.strip_suffix(b"'"))
                .unwrap_or(rest)
        })
        .unwrap_or(&bytes[value_start..value_end]);
    looks_like_credential(inner).then_some((value_start, value_end))
}

/// Credential-like value: 12+ chars of token alphabet mixing letters and
/// digits, and not a dotted identifier path (`config.v2.access_key`).
fn looks_like_credential(value: &[u8]) -> bool {
    if value.len() < 12
        || !value.iter().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=' | b':' | b'@'
                )
        })
        || !value.iter().any(u8::is_ascii_digit)
        || !value.iter().any(u8::is_ascii_alphabetic)
    {
        return false;
    }
    let identifier_path = value.contains(&b'.')
        && value.split(|b| *b == b'.').all(|segment| {
            segment
                .first()
                .is_some_and(|first| first.is_ascii_alphabetic() || *first == b'_')
                && segment.iter().all(|b| is_word_char(*b))
        });
    !identifier_path
}

fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_upper_or_digit(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

fn is_alnum_or_dash(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
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

/// `scheme://user:password@host` — redact only the password span.
/// Returns `(keep_end, value_end)`: text up to `keep_end` (through the
/// `:` after the user) is kept, the password is replaced.
fn match_credential_url(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    // Scheme: [A-Za-z][A-Za-z0-9+.-]* followed by "://".
    if start >= bytes.len() || !bytes[start].is_ascii_alphabetic() {
        return None;
    }
    if start > 0 && (is_word_char(bytes[start - 1]) || bytes[start - 1] == b'/') {
        return None;
    }
    let mut idx = start;
    while idx < bytes.len()
        && (bytes[idx].is_ascii_alphanumeric() || matches!(bytes[idx], b'+' | b'.' | b'-'))
    {
        idx += 1;
    }
    if !bytes[idx..].starts_with(b"://") {
        return None;
    }
    idx += 3;
    // Userinfo: user ':' password '@' — bail on '/', '?', '#', whitespace.
    let user_start = idx;
    while idx < bytes.len()
        && !matches!(bytes[idx], b':' | b'@' | b'/' | b'?' | b'#')
        && !bytes[idx].is_ascii_whitespace()
    {
        idx += 1;
    }
    if idx == user_start || idx >= bytes.len() || bytes[idx] != b':' {
        return None;
    }
    let keep_end = idx + 1;
    let pass_start = keep_end;
    idx = pass_start;
    while idx < bytes.len()
        && bytes[idx] != b'@'
        && !bytes[idx].is_ascii_whitespace()
        && !matches!(bytes[idx], b'/' | b'?' | b'#')
    {
        idx += 1;
    }
    if idx == pass_start || idx >= bytes.len() || bytes[idx] != b'@' {
        return None;
    }
    Some((keep_end, idx))
}

/// Minimum length for an exact value to be scrubbed by
/// [`scrub_exact_values`]; shorter values would mangle ordinary output.
pub const MIN_EXACT_VALUE_LEN: usize = 6;

/// Scrub *known* secret values (not just shapes) from `input`: every
/// occurrence of each value, plus its percent-encoded and standard
/// base64 forms, is replaced with `[REDACTED:<name>]`. Values shorter
/// than [`MIN_EXACT_VALUE_LEN`] are skipped. Longest values are replaced
/// first so overlapping values redact cleanly. Returns the scrubbed
/// text and the number of replacements made. Value bytes are compared
/// as-is (values are expected to be valid UTF-8 env strings).
#[must_use]
pub fn scrub_exact_values<N: AsRef<str>, V: AsRef<str>>(
    input: &str,
    values: &[(N, V)],
) -> (String, usize) {
    let mut needles: Vec<(String, String)> = Vec::new();
    for (name, value) in values {
        let (name, value) = (name.as_ref(), value.as_ref());
        if value.chars().count() < MIN_EXACT_VALUE_LEN {
            continue;
        }
        let label = format!("[REDACTED:{name}]");
        needles.push((value.to_string(), label.clone()));
        let encoded = percent_encode(value);
        if encoded != *value {
            needles.push((encoded, label.clone()));
        }
        let b64 = base64_encode(value.as_bytes());
        if b64 != *value {
            needles.push((b64, label));
        }
    }
    needles.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
    needles.dedup_by(|a, b| a.0 == b.0);
    let mut out = input.to_string();
    let mut count = 0usize;
    for (needle, label) in &needles {
        if needle.is_empty() {
            continue;
        }
        let hits = out.matches(needle.as_str()).count();
        if hits > 0 {
            out = out.replace(needle.as_str(), label);
            count += hits;
        }
    }
    (out, count)
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Scan `<optional quote> <ws> [:=] <ws> <value>` starting just after a
/// credential key. Returns `(value_start, value_end)`.
fn match_assignment_value(bytes: &[u8], after_key: usize) -> Option<(usize, usize)> {
    let mut idx = after_key;
    if idx < bytes.len() && (bytes[idx] == b'"' || bytes[idx] == b'\'') {
        idx += 1;
    }
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    if idx >= bytes.len() || (bytes[idx] != b':' && bytes[idx] != b'=') {
        return None;
    }
    idx += 1;
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    let value_start = idx;
    if idx < bytes.len() && (bytes[idx] == b'"' || bytes[idx] == b'\'') {
        let quote = bytes[idx];
        idx += 1;
        while idx < bytes.len() && bytes[idx] != quote {
            idx += 1;
        }
        if idx < bytes.len() {
            idx += 1;
        }
    } else {
        while idx < bytes.len() && is_value_char(bytes[idx]) {
            idx += 1;
        }
    }
    (idx > value_start).then_some((value_start, idx))
}

/// `<credential-key> <sep> <value>` with word-bounded key (left and right)
/// and `:`/`=` separator. Returns `(key_end, value_end)` so the caller can
/// keep `key + separator` and replace only the value.
fn match_credential_assignment(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    if start > 0 && is_word_char(bytes[start - 1]) {
        return None;
    }
    // Generic credential-suffixed key: <IDENT ending in _SECRET/_TOKEN/…>.
    {
        let mut end = start;
        while end < bytes.len() && (is_word_char(bytes[end]) || bytes[end] == b'-') {
            end += 1;
        }
        if end > start {
            if let Ok(ident) = std::str::from_utf8(&bytes[start..end]) {
                let upper = ident.to_ascii_uppercase();
                let is_cred = CREDENTIAL_KEY_SUFFIXES
                    .iter()
                    .any(|sfx| upper.len() > sfx.len() && upper.ends_with(sfx));
                if is_cred {
                    if let Some(hit) = match_assignment_value(bytes, end) {
                        return Some(hit);
                    }
                }
            }
        }
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

    /// Fixture bodies: obviously fake, assembled at runtime so this file
    /// never contains a contiguous credential-shaped literal.
    fn fake_alnum(len: usize) -> String {
        "Fx7Ab3Cd9Ef1Gh5Jk2Lm8Np4Qr6St0Uv"
            .chars()
            .cycle()
            .take(len)
            .collect()
    }

    fn scheme() -> String {
        ["Bear", "er"].concat()
    }

    #[test]
    fn vendor_token_formats_redact_and_keep_their_prefix() {
        let cases: Vec<(String, String)> = vec![
            (["gh", "p_"].concat(), fake_alnum(36)),
            (["gh", "s_"].concat(), fake_alnum(36)),
            (
                ["github", "_pat_"].concat(),
                format!("{}_{}", fake_alnum(22), fake_alnum(59)),
            ),
            (["AK", "IA"].concat(), "FIXTURE000000011".to_string()),
            (["sk", "_live_"].concat(), fake_alnum(24)),
            (["sk", "_test_"].concat(), fake_alnum(24)),
            (["rk", "_live_"].concat(), fake_alnum(24)),
            (
                ["xo", "xb-"].concat(),
                format!("1234567890-{}", fake_alnum(24)),
            ),
            (["sk", "-"].concat(), format!("proj-{}", fake_alnum(40))),
            (["AI", "za"].concat(), fake_alnum(35)),
        ];
        for (prefix, body) in cases {
            let line = format!("value {prefix}{body} end");
            let (out, n) = redact_text_counted(&line);
            assert_eq!(out, format!("value {prefix}{REDACTED} end"), "{prefix}");
            assert_eq!(n, 1, "{prefix}");
            assert!(contains_secret_shaped(&line), "{prefix}");
        }
    }

    #[test]
    fn json_web_tokens_redact_whole() {
        let jwt = format!(
            "{}{}.{}{}.{}",
            ["ey", "J"].concat(),
            "hbGciOiJIUzI1NiJ9",
            ["ey", "J"].concat(),
            "zdWIiOiJmaXh0dXJlIn0",
            "c2lnbmF0dXJlLWZpeHR1cmU"
        );
        assert_eq!(
            redact_text(&format!("jwt {jwt} ok")),
            format!("jwt {REDACTED} ok")
        );
    }

    #[test]
    fn vendor_lookalikes_and_digests_stay_untouched() {
        let near_misses = [
            // `sk-` inside a word, too short, or without any digit.
            format!("task-force-{}", fake_alnum(24)),
            "sk-learn-compatible-estimator-module".to_string(),
            format!("{}{}", ["AK", "IA"].concat(), "FIXTURE00000001"), // 15 chars
            format!("{}{}", ["AK", "IA"].concat(), "FIXTURE0000000112"), // 17 chars
            format!("{}notatokenatall", ["xo", "xb-"].concat()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            "123e4567-e89b-12d3-a456-426614174000".to_string(),
        ];
        for text in near_misses {
            assert_eq!(redact_text(&text), text, "{text}");
            assert!(!contains_secret_shaped(&text), "{text}");
        }
    }

    #[test]
    fn dotted_bearer_tokens_redact_every_segment() {
        let s = scheme();
        assert_eq!(
            redact_text(&format!(
                "Authorization: {s} aaaafixture.bbbbfixture.ccccfixture"
            )),
            format!("Authorization: {s} {REDACTED}")
        );
        assert_eq!(
            redact_text(&format!("got {s} abc123fixture/x+y=. done")),
            format!("got {s} {REDACTED}. done")
        );
    }

    #[test]
    fn generic_credential_keys_redact_credential_like_values() {
        let value = ["fixture", "-sec-", "0012"].concat();
        for key in [
            "SECRET_KEY",
            "secret_key",
            "ACCESS_KEY",
            "x-api-key",
            "X-Auth-Token",
            "token",
        ] {
            assert_eq!(
                redact_text(&format!("{key}={value}")),
                format!("{key}={REDACTED}"),
                "{key}"
            );
            assert_eq!(
                redact_text(&format!("{key}: {value}")),
                format!("{key}: {REDACTED}"),
                "{key}"
            );
        }
        assert_eq!(
            redact_text(&format!("{{\"token\": \"{value}\"}}")),
            format!("{{\"token\": {REDACTED}}}")
        );
    }

    #[test]
    fn generic_keys_leave_code_and_short_values_alone() {
        for code in [
            "token = tokens[i]",
            "token: Token",
            "token=next()",
            "token: u32",
            "token=abc",
            "let token = self.token_value;",
            "secret_key=settings.SECRET_KEY",
            "x-api-key: $API_KEY",
            "access_key = config.v2.access_key",
        ] {
            assert_eq!(redact_text(code), code, "{code}");
        }
    }

    #[test]
    fn counted_redaction_reports_each_rewrite_once() {
        // Assembled at runtime so the source holds no credential shape.
        let key = ["pass", "word"].concat();
        let input = format!("a {key}=one-fixture b {key}=[REDACTED:X] c");
        let (out, n) = redact_text_counted(&input);
        assert_eq!(n, 1, "an existing marker must not be counted again");
        assert_eq!(out, redact_text(&input));
        assert_eq!(
            redact_text_counted("plain text"),
            ("plain text".to_string(), 0)
        );
    }

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

    #[test]
    fn suffixed_credential_keys_redact() {
        for input in [
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG",
            "STRIPE_SECRET_KEY=sk_live_abc123",
            "MY_SERVICE_TOKEN: tok-123456",
            "DATABASE_PASSWORD=hunter2",
        ] {
            let out = redact_text(input);
            assert!(!out.contains("wJalr"), "{input} -> {out}");
            assert!(!out.contains("hunter2"), "{input} -> {out}");
            assert!(contains_secret_shaped(input), "{input}");
        }
        // Identifier-like keys are NOT values.
        assert_eq!(redact_text("token_id = abc123"), "token_id = abc123");
        assert_eq!(redact_text("secret_name = prod"), "secret_name = prod");
    }

    #[test]
    fn credential_url_password_redacts() {
        let out = redact_text("DATABASE_URL=postgres://user:p4ssw0rd@db.internal:5432/app");
        assert!(!out.contains("p4ssw0rd"), "{out}");
        assert!(out.contains("postgres://user:"), "{out}");
        // No password -> untouched.
        assert_eq!(
            redact_text("see https://example.com/path"),
            "see https://example.com/path"
        );
    }

    #[test]
    fn exact_values_scrub_raw_encoded_and_b64() {
        let values = vec![
            ("API_KEY".to_string(), "test_value_123456".to_string()),
            ("SHORT".to_string(), "abc".to_string()),
        ];
        let (out, n) = scrub_exact_values("key is test_value_123456 ok", &values);
        assert_eq!(out, "key is [REDACTED:API_KEY] ok");
        assert_eq!(n, 1);
        // Short values are skipped (would mangle ordinary text).
        let (out2, n2) = scrub_exact_values("abc abc", &values);
        assert_eq!(out2, "abc abc");
        assert_eq!(n2, 0);
        // Percent-encoded form.
        let vals = vec![("DB".to_string(), "p@ss word!".to_string())];
        let (out3, _) = scrub_exact_values("u=p%40ss%20word%21", &vals);
        assert_eq!(out3, "u=[REDACTED:DB]");
        // Base64 form.
        let (out4, _) = scrub_exact_values("dGVzdF92YWx1ZV8xMjM0NTY=", &values);
        assert_eq!(out4, "[REDACTED:API_KEY]");
    }
}
