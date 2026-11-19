//! Canonical text encodings shared by the C2SP formats.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// Standard base64 (RFC 4648 §4) with `=` padding.
pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decodes standard padded base64, rejecting non-canonical encodings
/// (RFC 4648 §3.5) as the C2SP specs require.
pub(crate) fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = STANDARD.decode(text).ok()?;
    // The engine already rejects non-zero trailing bits and bad padding;
    // re-encoding makes the canonical-form guarantee independent of its
    // configuration.
    (STANDARD.encode(&bytes) == text).then_some(bytes)
}

/// Parses an ASCII decimal with no sign and no extra leading zeros.
pub(crate) fn parse_decimal_u64(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

/// Whether `c` is an ASCII control character other than newline: the
/// characters signed notes may not contain.
pub(crate) fn is_forbidden_control(c: char) -> bool {
    c < '\u{20}' && c != '\n'
}

/// A signed-note key name: non-empty, with no Unicode space, no `+` and no
/// control character.
pub(crate) fn is_valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| !c.is_whitespace() && c != '+' && c >= '\u{20}')
}

/// The most bytes a cosigner name or log origin may have.
pub(crate) const MAX_COSIGNER_NAME_LEN: usize = 255;

/// A cosigner name or log origin (c2sp.org/tlog-cosignature): a valid key
/// name of at most 255 bytes.
pub(crate) fn is_valid_cosigner_name(name: &str) -> bool {
    name.len() <= MAX_COSIGNER_NAME_LEN && is_valid_key_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_must_be_canonical() {
        assert_eq!(b64_decode("AA=="), Some(vec![0]));
        assert_eq!(b64_decode("AB=="), None, "non-zero trailing bits");
        assert_eq!(b64_decode("AA"), None, "missing padding");
        assert_eq!(b64_decode("AA=\n"), None);
        assert_eq!(b64_decode(" AA=="), None);
        assert_eq!(b64_decode("A-=="), None, "URL alphabet");
        assert_eq!(b64_decode(""), Some(vec![]));
    }

    #[test]
    fn decimals_must_be_canonical() {
        assert_eq!(parse_decimal_u64("0"), Some(0));
        assert_eq!(parse_decimal_u64("20852163"), Some(20_852_163));
        assert_eq!(parse_decimal_u64("18446744073709551615"), Some(u64::MAX));
        for bad in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1e3",
            "18446744073709551616",
            "١",
        ] {
            assert_eq!(parse_decimal_u64(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn names() {
        assert!(is_valid_key_name("example.com/log"));
        assert!(is_valid_key_name("oid/1.3.6.1.4.1"));
        for bad in [
            "",
            "a b",
            "a+b",
            "a\tb",
            "a\u{a0}b",
            "a\u{2003}b",
            "a\u{1}b",
            "a\nb",
        ] {
            assert!(!is_valid_key_name(bad), "{bad:?}");
        }
        assert!(is_valid_cosigner_name(&"a".repeat(255)));
        assert!(!is_valid_cosigner_name(&"a".repeat(256)));
    }
}
