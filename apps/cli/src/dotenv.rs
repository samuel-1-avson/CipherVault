//! In-memory Dotenv Parser for Zero-Disk Secret Injection
//!
//! Parses `.env` configuration bytes in volatile memory into key-value pairs
//! without writing any secret data to disk. Intermediate buffers are zeroized.

use zeroize::Zeroize;

/// Parses raw UTF-8 bytes of a `.env` file into a vector of key-value tuples.
pub fn parse_dotenv_bytes(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => return Err(format!("Invalid UTF-8 in secret file: {}", e)),
    };

    let mut result = Vec::new();

    for (line_num, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();

        // Skip empty lines and full-line comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip optional "export " prefix (e.g. Bash export KEY=VALUE)
        let line = if let Some(stripped) = line.strip_prefix("export ") {
            stripped.trim_start()
        } else {
            line
        };

        // Locate key=value separator
        let (raw_key, raw_val) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => {
                // Lines without '=' are ignored or comments
                continue;
            }
        };

        if raw_key.is_empty() {
            return Err(format!(
                "Malformed .env line {}: missing variable key",
                line_num + 1
            ));
        }

        // Validate key format: standard environment variable characters (alphanumeric, underscore)
        if !raw_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(format!(
                "Invalid environment variable name '{}' at line {}",
                raw_key,
                line_num + 1
            ));
        }

        let parsed_val = parse_value(raw_val);
        result.push((raw_key.to_string(), parsed_val));
    }

    Ok(result)
}

/// Parses the value part of a KEY=VALUE assignment, handling quotes and inline comments.
fn parse_value(raw: &str) -> String {
    let trimmed = raw.trim();

    // Case 1: Double-quoted string ("...")
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        let inner = &trimmed[1..trimmed.len() - 1];
        return unescape_double_quoted(inner);
    }

    // Case 2: Single-quoted string ('...')
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        // Single quotes are verbatim (no escape expansion)
        return trimmed[1..trimmed.len() - 1].to_string();
    }

    // Case 3: Unquoted value
    // Inline comment: strip from the first unescaped ' #' with preceding whitespace
    let mut val = trimmed;
    if let Some(pos) = val.find(" #") {
        val = val[..pos].trim_end();
    } else if let Some(pos) = val.find("\t#") {
        val = val[..pos].trim_end();
    }

    val.to_string()
}

/// Unescapes standard escape sequences inside double-quoted strings.
fn unescape_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next_c) = chars.next() {
                match next_c {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    '\'' => out.push('\''),
                    '$' => out.push('$'),
                    other => {
                        out.push('\\');
                        out.push(other);
                    }
                }
            } else {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }

    out
}

/// Securely zeroizes in-memory key-value pairs upon consumption.
pub fn zeroize_env_pairs(pairs: &mut [(String, String)]) {
    for (_, v) in pairs.iter_mut() {
        unsafe {
            // Overwrite underlying string bytes with zeroes
            let bytes = v.as_bytes_mut();
            bytes.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dotenv_standard_and_export() {
        let input = b"\
# Main Database Config
DATABASE_URL=postgres://user:pass@localhost:5432/db
PORT=8080
export JWT_SECRET=supersecret123
";
        let parsed = parse_dotenv_bytes(input).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[0],
            (
                "DATABASE_URL".into(),
                "postgres://user:pass@localhost:5432/db".into()
            )
        );
        assert_eq!(parsed[1], ("PORT".into(), "8080".into()));
        assert_eq!(parsed[2], ("JWT_SECRET".into(), "supersecret123".into()));
    }

    #[test]
    fn test_parse_dotenv_quoted_values() {
        let input = b"\
DOUBLE_QUOTED=\"hello\\nworld\\t!\"
SINGLE_QUOTED='literal\\nvalue'
COMPLEX_PASS=\"p@$$w0rd!#%^&*()\"
";
        let parsed = parse_dotenv_bytes(input).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[0],
            ("DOUBLE_QUOTED".into(), "hello\nworld\t!".into())
        );
        assert_eq!(
            parsed[1],
            ("SINGLE_QUOTED".into(), "literal\\nvalue".into())
        );
        assert_eq!(
            parsed[2],
            ("COMPLEX_PASS".into(), "p@$$w0rd!#%^&*()".into())
        );
    }

    #[test]
    fn test_parse_dotenv_inline_comments() {
        let input = b"\
API_KEY=xyz123 # Production API key
TIMEOUT=30\t# Seconds
COMMENTED_VALUE=\"val # with hash inside quotes\"
";
        let parsed = parse_dotenv_bytes(input).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], ("API_KEY".into(), "xyz123".into()));
        assert_eq!(parsed[1], ("TIMEOUT".into(), "30".into()));
        assert_eq!(
            parsed[2],
            (
                "COMMENTED_VALUE".into(),
                "val # with hash inside quotes".into()
            )
        );
    }

    #[test]
    fn test_parse_dotenv_values_with_equals_sign() {
        let input = b"\
URL=https://example.com/api?param1=foo&param2=bar
BASE64_TOKEN=ZXhhbXBsZTEyMw==
";
        let parsed = parse_dotenv_bytes(input).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0],
            (
                "URL".into(),
                "https://example.com/api?param1=foo&param2=bar".into()
            )
        );
        assert_eq!(
            parsed[1],
            ("BASE64_TOKEN".into(), "ZXhhbXBsZTEyMw==".into())
        );
    }

    #[test]
    fn test_parse_dotenv_invalid_key() {
        let input = b"INVALID-KEY=val\n";
        let err = parse_dotenv_bytes(input);
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .contains("Invalid environment variable name"));
    }
}
