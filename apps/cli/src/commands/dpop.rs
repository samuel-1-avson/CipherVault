//! DPoP-lite proof generation for key-bound scope tokens (T-902 follow-up).
//!
//! When `CIPHERVAULT_DPOP_KEY` is set, every account-API request carries a
//! `DPoP` proof: `<base64url(sig)>.<unix_secs>.<base64url(nonce)>`, where
//! `sig` covers `timestamp_be ‖ nonce ‖ jti ‖ tenant_id` under domain
//! `dpop-v1` — byte-identical to the server's expectation
//! (`services/account/src/dpop.rs`). The server ignores the header for
//! unbound tokens, so setting the key is safe with mixed fleets.
//!
//! Key material comes from the environment only — never a CLI flag — so
//! seeds cannot leak through shell history or process listings:
//!
//! * `CIPHERVAULT_DPOP_KEY=<64-hex-seed>`, or
//! * `CIPHERVAULT_DPOP_KEY=@/path/to/file` (first line, trimmed).
//!
//! A set-but-unreadable key fails closed (requests abort rather than go
//! out unproven). Tokens that are not `cvst1.*` scope tokens (e.g. session
//! tokens) skip proofs: there is no `jti` to bind, and the server would
//! ignore the header anyway.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;

/// Environment variable carrying the DPoP seed (hex or `@path`).
pub(crate) const DPOP_KEY_ENV: &str = "CIPHERVAULT_DPOP_KEY";

/// Must match the server's `DPOP_CONTEXT` byte-for-byte.
const DPOP_CONTEXT: &[u8] = b"dpop-v1";

/// Ed25519 seed rerived per call (no caching: tests and key rotation must
/// see fresh reads; the material is small).
pub(crate) struct DpopSigner {
    key: ed25519_dalek::SigningKey,
}

impl DpopSigner {
    /// Loads the signer from `CIPHERVAULT_DPOP_KEY`. `Ok(None)` when unset;
    /// `Err` when set but malformed (fail closed).
    pub(crate) fn from_env() -> Result<Option<Self>> {
        let raw = match std::env::var(DPOP_KEY_ENV) {
            Ok(raw) if !raw.trim().is_empty() => raw,
            _ => return Ok(None),
        };
        let trimmed = raw.trim();
        let hex_seed = if let Some(path) = trimmed.strip_prefix('@') {
            std::fs::read_to_string(path)
                .with_context(|| format!("reading DPoP key file {path}"))?
        } else {
            trimmed.to_string()
        };
        let bytes = hex::decode(hex_seed.trim())
            .context("CIPHERVAULT_DPOP_KEY must be 64 hex characters or @path")?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("CIPHERVAULT_DPOP_KEY must decode to 32 bytes"))?;
        Ok(Some(Self {
            key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }))
    }

    /// Builds a fresh proof for `token`, or `None` when the token is not a
    /// parseable `cvst1.*` scope token (nothing to bind). The payload is
    /// read, never trusted — the server verifies MAC then proof.
    pub(crate) fn proof_for_token(&self, token: &str) -> Result<Option<String>> {
        let Some((jti, tenant_id)) = scope_token_ids(token) else {
            return Ok(None);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock before epoch")?
            .as_secs();
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut message = Vec::with_capacity(8 + nonce.len() + jti.len() + tenant_id.len());
        message.extend_from_slice(&now.to_be_bytes());
        message.extend_from_slice(&nonce);
        message.extend_from_slice(jti.as_bytes());
        message.extend_from_slice(tenant_id.as_bytes());
        let signature =
            ciphervault_crypto::signatures::sign_with_domain(&self.key, DPOP_CONTEXT, &message);
        Ok(Some(format!(
            "{}.{now}.{}",
            URL_SAFE_NO_PAD.encode(signature),
            URL_SAFE_NO_PAD.encode(nonce),
        )))
    }
}

/// Extracts `(jti, tenant_id)` from a `cvst1.<payload>.<mac>` token's
/// base64url claims JSON. `None` for anything else (session tokens,
/// garbage) — the caller then sends no proof.
pub(crate) fn scope_token_ids(token: &str) -> Option<(String, String)> {
    let mut parts = token.trim().split('.');
    let (prefix, payload, mac, rest) = (parts.next()?, parts.next()?, parts.next()?, parts.next());
    if prefix != "cvst1" || rest.is_some() || payload.is_empty() || mac.is_empty() {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    Some((
        claims.get("jti")?.as_str()?.to_string(),
        claims.get("tenant_id")?.as_str()?.to_string(),
    ))
}

/// Attaches `Authorization` semantics plus an optional DPoP proof to a
/// request builder. One-line wrapper so every call site stays uniform:
/// `maybe_dpop(client.get(url), token)?.bearer_auth(token)`.
pub(crate) fn maybe_dpop(
    builder: reqwest::RequestBuilder,
    token: &str,
) -> Result<reqwest::RequestBuilder> {
    let proof = match DpopSigner::from_env()? {
        Some(signer) => signer.proof_for_token(token)?,
        None => None,
    };
    match proof {
        Some(proof) => Ok(builder.header("dpop", proof)),
        None => Ok(builder),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    const SEED_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn seed_key() -> ed25519_dalek::SigningKey {
        let bytes: [u8; 32] = hex::decode(SEED_HEX).unwrap().try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    }

    /// Fake `cvst1` token with caller-chosen claims (server never sees it;
    /// the payload shape is what the client parses).
    fn fake_token(jti: &str, tenant_id: &str) -> String {
        let payload = serde_json::json!({"jti": jti, "tenant_id": tenant_id}).to_string();
        format!("cvst1.{}.{}", URL_SAFE_NO_PAD.encode(payload), "bWFj")
    }

    #[test]
    fn token_ids_parse_scope_tokens_only() {
        let (jti, tenant) = scope_token_ids(&fake_token("j1", "t1")).unwrap();
        assert_eq!((jti.as_str(), tenant.as_str()), ("j1", "t1"));
        for bad in [
            "",
            "session-token-alice",
            "cvst1.only",
            "cvst1.a.b.c",
            "cvst1.!!!.bWFj",
            "cvst1.bWFj.bWFj", // "mac" is not JSON
        ] {
            assert!(scope_token_ids(bad).is_none(), "{bad}");
        }
        // Valid JSON but missing claims.
        let payload = URL_SAFE_NO_PAD.encode(r#"{"jti":"x"}"#);
        assert!(scope_token_ids(&format!("cvst1.{payload}.bWFj")).is_none());
    }

    #[test]
    fn proof_verifies_against_server_construction() {
        // Independent re-verification with the server's domain separation:
        // catches message-layout drift between the crates.
        let signer = DpopSigner { key: seed_key() };
        let token = fake_token("j-test-1", "tenant-test-1");
        let proof = signer.proof_for_token(&token).unwrap().unwrap();
        let mut parts = proof.split('.');
        let (sig_b64, ts_raw, nonce_b64) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        assert!(parts.next().is_none());
        let signature: [u8; 64] = URL_SAFE_NO_PAD.decode(sig_b64).unwrap().try_into().unwrap();
        let nonce = URL_SAFE_NO_PAD.decode(nonce_b64).unwrap();
        assert_eq!(nonce.len(), 16);
        let timestamp: u64 = ts_raw.parse().unwrap();
        let mut message = Vec::new();
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(&nonce);
        message.extend_from_slice(b"j-test-1");
        message.extend_from_slice(b"tenant-test-1");
        // Domain separation must match sign_with_domain("dpop-v1"):
        // SIGNATURE_DOMAIN_PREFIX + context + ':' + message.
        let mut domain_prefixed = Vec::new();
        domain_prefixed.extend_from_slice(b"CipherVault-Ed25519-v1:dpop-v1:");
        domain_prefixed.extend_from_slice(&message);
        seed_key()
            .verifying_key()
            .verify(
                &domain_prefixed,
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .unwrap();
        // Fresh proofs differ (random nonce) and stay in-window.
        let proof2 = signer.proof_for_token(&token).unwrap().unwrap();
        assert_ne!(proof, proof2);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now.abs_diff(timestamp) <= 5);
    }

    static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Sets `DPOP_KEY_ENV` for `f`, then restores the prior value.
    /// Serialized: parallel tests share one process environment.
    fn with_dpop_key<T>(value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _lock = ENV_GUARD.lock().unwrap();
        let prior = std::env::var(DPOP_KEY_ENV).ok();
        match value {
            Some(set) => std::env::set_var(DPOP_KEY_ENV, set),
            None => std::env::remove_var(DPOP_KEY_ENV),
        }
        let out = f();
        match prior {
            Some(set) => std::env::set_var(DPOP_KEY_ENV, set),
            None => std::env::remove_var(DPOP_KEY_ENV),
        }
        out
    }

    #[test]
    fn env_loading_rules() {
        with_dpop_key(None, || {
            assert!(DpopSigner::from_env().unwrap().is_none());
        });
        with_dpop_key(Some(""), || {
            assert!(DpopSigner::from_env().unwrap().is_none());
        });
        with_dpop_key(Some("zz"), || {
            assert!(DpopSigner::from_env().is_err());
        });
        with_dpop_key(Some(SEED_HEX), || {
            let signer = DpopSigner::from_env().unwrap().unwrap();
            assert!(signer.proof_for_token("session-token-x").unwrap().is_none());
            assert!(signer
                .proof_for_token(&fake_token("j", "t"))
                .unwrap()
                .is_some());
        });
    }

    #[test]
    fn file_keys_load() {
        let dir = std::env::temp_dir().join(format!("dpop-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seed.hex");
        std::fs::write(&path, format!("{SEED_HEX}\n")).unwrap();
        with_dpop_key(Some(&format!("@{}", path.display())), || {
            assert!(DpopSigner::from_env().unwrap().is_some());
        });
        with_dpop_key(Some("@/nonexistent-dpop-key"), || {
            assert!(DpopSigner::from_env().is_err());
        });
        std::fs::remove_dir_all(&dir).ok();
    }
}
