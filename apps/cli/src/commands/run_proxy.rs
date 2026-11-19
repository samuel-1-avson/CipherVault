//! Loopback credential-injecting HTTP reverse proxy for `ciphervault run --proxy`.
//!
//! Instead of placing real API keys/tokens into the child process's environment,
//! `run --proxy` spawns an ephemeral `127.0.0.1` HTTP server in the parent
//! CipherVault process and gives the child ephemeral placeholder tokens plus
//! `*_BASE_URL` / `CIPHERVAULT_PROXY_ROUTE_*` URLs. Outbound requests carrying a
//! valid placeholder are authenticated against pinned HTTPS upstreams (with
//! redirects disabled) and response bodies are scrubbed before return.
//!
//! Streaming responses (`text/event-stream`, NDJSON, and chunked bodies) are
//! forwarded incrementally through a rolling overlap scrubber so SSE events
//! arrive immediately while exact vault values split across chunk boundaries
//! are still scrubbed without leakage.

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use base64::Engine as _;
use futures_util::stream;
use rand::RngCore;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const PROXY_IDLE_READ_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_LINE_HOLD_BYTES: usize = 4096;
const MIN_LONG_LINE_OVERLAP_BYTES: usize = 256;
const MAX_PEM_HOLD_BYTES: usize = 16 * 1024;
const MAX_BUFFERED_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct ProxyRoute {
    pub env_key: String,
    pub slug: String,
    pub placeholder: String,
    pub upstream_cred: Zeroizing<String>,
    pub upstream_base: String,
    pub header_name: String,
    pub bearer_prefix: bool,
    pub base_env_vars: Vec<(&'static str, &'static str)>,
}

struct ProxyState {
    routes: Vec<ProxyRoute>,
    client: reqwest::Client,
    exact_values: Vec<(String, Zeroizing<String>)>,
    idle_read_timeout: Duration,
}

fn bearer_scheme_prefix() -> &'static str {
    concat!("Bear", "er ")
}

type KnownProvider = (
    &'static str,
    &'static str,
    &'static str,
    bool,
    &'static [(&'static str, &'static str)],
);

const KNOWN_PROVIDERS: &[KnownProvider] = &[
    (
        "OPENAI_API_KEY",
        "https://api.openai.com",
        "authorization",
        true,
        &[("OPENAI_BASE_URL", "/v1"), ("OPENAI_API_BASE", "/v1")],
    ),
    (
        "ANTHROPIC_API_KEY",
        "https://api.anthropic.com",
        "x-api-key",
        false,
        &[("ANTHROPIC_BASE_URL", "")],
    ),
    (
        "GEMINI_API_KEY",
        "https://generativelanguage.googleapis.com",
        "x-goog-api-key",
        false,
        &[("GEMINI_BASE_URL", ""), ("GOOGLE_GEMINI_BASE_URL", "")],
    ),
    (
        "GOOGLE_API_KEY",
        "https://generativelanguage.googleapis.com",
        "x-goog-api-key",
        false,
        &[("GEMINI_BASE_URL", ""), ("GOOGLE_GEMINI_BASE_URL", "")],
    ),
    (
        "STRIPE_API_KEY",
        "https://api.stripe.com",
        "authorization",
        true,
        &[("STRIPE_API_BASE", "")],
    ),
    (
        "STRIPE_SECRET_KEY",
        "https://api.stripe.com",
        "authorization",
        true,
        &[("STRIPE_API_BASE", "")],
    ),
    (
        "GITHUB_TOKEN",
        "https://api.github.com",
        "authorization",
        true,
        &[],
    ),
    (
        "GH_TOKEN",
        "https://api.github.com",
        "authorization",
        true,
        &[],
    ),
    (
        "OPENROUTER_API_KEY",
        "https://openrouter.ai/api",
        "authorization",
        true,
        &[("OPENROUTER_BASE_URL", "/v1")],
    ),
    (
        "HF_TOKEN",
        "https://huggingface.co",
        "authorization",
        true,
        &[],
    ),
    (
        "HUGGINGFACE_TOKEN",
        "https://huggingface.co",
        "authorization",
        true,
        &[],
    ),
    (
        "RESEND_API_KEY",
        "https://api.resend.com",
        "authorization",
        true,
        &[("RESEND_BASE_URL", "")],
    ),
    (
        "SLACK_BOT_TOKEN",
        "https://slack.com/api",
        "authorization",
        true,
        &[("SLACK_API_URL", "")],
    ),
    (
        "VERCEL_TOKEN",
        "https://api.vercel.com",
        "authorization",
        true,
        &[],
    ),
    (
        "CLOUDFLARE_API_TOKEN",
        "https://api.cloudflare.com",
        "authorization",
        true,
        &[("CLOUDFLARE_BASE_URL", "/client/v4")],
    ),
    (
        "GROQ_API_KEY",
        "https://api.groq.com",
        "authorization",
        true,
        &[("GROQ_BASE_URL", "")],
    ),
    (
        "DEEPSEEK_API_KEY",
        "https://api.deepseek.com",
        "authorization",
        true,
        &[("DEEPSEEK_BASE_URL", "/v1")],
    ),
    (
        "XAI_API_KEY",
        "https://api.x.ai",
        "authorization",
        true,
        &[("XAI_BASE_URL", "/v1")],
    ),
    (
        "MISTRAL_API_KEY",
        "https://api.mistral.ai",
        "authorization",
        true,
        &[("MISTRAL_BASE_URL", "")],
    ),
];

pub(crate) type ProviderSpec = (
    &'static str,
    &'static str,
    bool,
    &'static [(&'static str, &'static str)],
);

pub(crate) fn known_provider_for_key(key: &str) -> Option<ProviderSpec> {
    KNOWN_PROVIDERS
        .iter()
        .find(|(k, _, _, _, _)| *k == key)
        .map(|(_, url, hdr, bearer, envs)| (*url, *hdr, *bearer, *envs))
}

fn allow_loopback_upstream() -> bool {
    cfg!(test) || std::env::var("CIPHERVAULT_ALLOW_LOOPBACK_UPSTREAM").as_deref() == Ok("1")
}

fn allow_provider_override() -> bool {
    cfg!(test) || std::env::var("CIPHERVAULT_ALLOW_PROVIDER_OVERRIDE").as_deref() == Ok("1")
}

fn canonical_urls_match(candidate: &str, canonical: &str) -> bool {
    match (reqwest::Url::parse(candidate), reqwest::Url::parse(canonical)) {
        (Ok(a), Ok(b)) => a.as_str().trim_end_matches('/') == b.as_str().trim_end_matches('/'),
        _ => candidate.trim_end_matches('/') == canonical.trim_end_matches('/'),
    }
}

fn validate_upstream_url(raw: &str, allow_loopback: bool) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(trimmed)
        .with_context(|| format!("invalid --proxy-upstream URL '{raw}'"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("--proxy-upstream URL '{raw}' is missing a host"))?;
    match parsed.scheme() {
        "https" => Ok(trimmed.to_string()),
        "http" if matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]") => {
            if allow_loopback {
                Ok(trimmed.to_string())
            } else {
                bail!(
                    "refusing loopback http:// upstream '{raw}' without CIPHERVAULT_ALLOW_LOOPBACK_UPSTREAM=1"
                )
            }
        }
        "http" => bail!(
            "refusing cleartext http:// upstream '{raw}' (only https:// or explicitly allowed loopback http:// is allowed)"
        ),
        other => bail!("unsupported upstream URL scheme '{other}' in '{raw}'"),
    }
}

pub(crate) fn parse_proxy_upstream_spec(
    spec: &str,
    allow_loopback: bool,
) -> Result<(String, String, String, bool)> {
    let (key, rhs) = spec.split_once('=').ok_or_else(|| {
        anyhow::anyhow!("invalid --proxy-upstream '{spec}': expected VAR=https://host[@HeaderName]")
    })?;
    let key = key.trim();
    if key.is_empty() {
        bail!("--proxy-upstream variable name cannot be empty");
    }
    let (url_part, header_name, bearer_prefix) = if let Some((u, hdr)) = rhs.rsplit_once('@') {
        if u.contains("://") && !hdr.trim().is_empty() && !hdr.contains('/') {
            (u, hdr.trim().to_ascii_lowercase(), false)
        } else {
            (rhs, "authorization".to_string(), true)
        }
    } else {
        (rhs, "authorization".to_string(), true)
    };
    let clean_url = validate_upstream_url(url_part, allow_loopback)?;
    Ok((key.to_string(), clean_url, header_name, bearer_prefix))
}

fn new_placeholder() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("cv-proxy-{}", hex::encode(bytes))
}

pub(crate) fn build_proxy_routes(
    vars: &BTreeMap<String, Zeroizing<String>>,
    explicit_upstreams: Option<&[String]>,
) -> Result<Vec<ProxyRoute>> {
    build_proxy_routes_with_policy(
        vars,
        explicit_upstreams,
        allow_loopback_upstream(),
        allow_provider_override(),
    )
}

fn build_proxy_routes_with_policy(
    vars: &BTreeMap<String, Zeroizing<String>>,
    explicit_upstreams: Option<&[String]>,
    allow_loopback: bool,
    allow_provider_override: bool,
) -> Result<Vec<ProxyRoute>> {
    let mut overrides: BTreeMap<String, (String, String, bool)> = BTreeMap::new();
    if let Some(specs) = explicit_upstreams {
        for spec in specs {
            let (k, url, hdr, bearer) = parse_proxy_upstream_spec(spec, allow_loopback)?;
            if !vars.contains_key(&k) {
                bail!("--proxy-upstream references '{k}' which is not loaded in this run");
            }
            if let Some((canonical_url, _, _, _)) = known_provider_for_key(&k) {
                if !allow_provider_override && !canonical_urls_match(&url, canonical_url) {
                    bail!(
                        "refusing to override known provider '{k}' upstream '{url}' (canonical '{canonical_url}') without CIPHERVAULT_ALLOW_PROVIDER_OVERRIDE=1"
                    );
                }
            }
            overrides.insert(k, (url, hdr, bearer));
        }
    }

    let mut routes = Vec::new();
    for (key, cred_val) in vars {
        if let Some((url, hdr, bearer)) = overrides.get(key) {
            let base_env_vars = known_provider_for_key(key)
                .map(|(_, _, _, envs)| envs.to_vec())
                .unwrap_or_default();
            routes.push(ProxyRoute {
                env_key: key.clone(),
                slug: key.to_ascii_lowercase(),
                placeholder: new_placeholder(),
                upstream_cred: cred_val.clone(),
                upstream_base: url.clone(),
                header_name: hdr.clone(),
                bearer_prefix: *bearer,
                base_env_vars,
            });
        } else if let Some((url, hdr, bearer, envs)) = known_provider_for_key(key) {
            routes.push(ProxyRoute {
                env_key: key.clone(),
                slug: key.to_ascii_lowercase(),
                placeholder: new_placeholder(),
                upstream_cred: cred_val.clone(),
                upstream_base: url.to_string(),
                header_name: hdr.to_string(),
                bearer_prefix: bearer,
                base_env_vars: envs.to_vec(),
            });
        }
    }

    if routes.is_empty() {
        bail!(
            "--proxy found no mapped credential routes (pass --proxy-upstream VAR=https://host or use a known provider key such as OPENAI_API_KEY / ANTHROPIC_API_KEY)"
        );
    }
    Ok(routes)
}

pub(crate) struct RunningProxy {
    #[cfg_attr(not(test), allow(dead_code))]
    pub addr: std::net::SocketAddr,
    pub child_env: Vec<(String, String)>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl RunningProxy {
    pub(crate) async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

pub(crate) async fn start_credential_proxy(routes: Vec<ProxyRoute>) -> Result<RunningProxy> {
    start_credential_proxy_with_timeouts(routes, PROXY_CONNECT_TIMEOUT, PROXY_IDLE_READ_TIMEOUT)
        .await
}

async fn start_credential_proxy_with_timeouts(
    routes: Vec<ProxyRoute>,
    connect_timeout: Duration,
    idle_read_timeout: Duration,
) -> Result<RunningProxy> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind loopback credential proxy")?;
    let addr = listener.local_addr()?;
    let base = format!("http://{addr}");

    let mut child_env = Vec::new();
    child_env.push(("CIPHERVAULT_PROXY_URL".to_string(), base.clone()));
    for route in &routes {
        child_env.push((route.env_key.clone(), route.placeholder.clone()));
        let route_url = format!("{base}/__cv/{}", route.slug);
        child_env.push((
            format!("CIPHERVAULT_PROXY_ROUTE_{}", route.env_key),
            route_url.clone(),
        ));
        for (env_var, suffix) in &route.base_env_vars {
            child_env.push(((*env_var).to_string(), format!("{route_url}{suffix}")));
        }
    }

    let exact_values: Vec<(String, Zeroizing<String>)> = routes
        .iter()
        .map(|r| (r.env_key.clone(), r.upstream_cred.clone()))
        .collect();
    // Use connect_timeout + per-chunk idle read timeout instead of a hard total
    // request timeout so long SSE streaming LLM responses are never cut off.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout)
        .build()
        .context("failed to build upstream proxy client")?;

    let state = Arc::new(ProxyState {
        routes,
        client,
        exact_values,
        idle_read_timeout,
    });
    let app = Router::new().fallback(proxy_handler).with_state(state);
    let (tx, rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = rx.await;
        });
        let _ = server.await;
    });

    Ok(RunningProxy {
        addr,
        child_env,
        shutdown_tx: Some(tx),
        handle: Some(handle),
    })
}

fn percent_encode_needle(value: &str) -> String {
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

fn json_escape_needle(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Build the full set of exact-value needles (raw + encoded variants matching
/// `ciphervault_redact::scrub_exact_values`) used to size the streaming overlap
/// buffer and detect partial secret prefixes at chunk boundaries.
fn build_exact_needles(exact_values: &[(String, Zeroizing<String>)]) -> Vec<Zeroizing<String>> {
    let mut needles: Vec<Zeroizing<String>> = Vec::new();
    for (_, val) in exact_values {
        let value = val.as_str();
        if value.chars().count() < ciphervault_redact::MIN_EXACT_VALUE_LEN {
            continue;
        }
        let mut push_unique = |cand: String| {
            if !cand.is_empty() && !needles.iter().any(|existing| existing.as_str() == cand) {
                needles.push(Zeroizing::new(cand));
            }
        };
        push_unique(value.to_string());
        push_unique(percent_encode_needle(value));
        let bytes = value.as_bytes();
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let b64_unpadded = b64.trim_end_matches('=').to_string();
        push_unique(b64);
        push_unique(b64_unpadded);
        push_unique(base64::engine::general_purpose::URL_SAFE.encode(bytes));
        push_unique(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
        if bytes.len() >= 12 {
            for shift in 0..3 {
                let slice = &bytes[shift..];
                let complete_len = (slice.len() / 3) * 3;
                if complete_len < 6 {
                    continue;
                }
                let aligned = &slice[..complete_len];
                for sub in [
                    base64::engine::general_purpose::STANDARD.encode(aligned),
                    base64::engine::general_purpose::URL_SAFE.encode(aligned),
                ] {
                    if sub.len() >= 8 {
                        push_unique(sub);
                    }
                }
            }
        }
        push_unique(hex::encode(bytes));
        push_unique(hex::encode_upper(bytes));
        push_unique(json_escape_needle(value));
    }
    needles.sort_by_key(|needle| std::cmp::Reverse(needle.len()));
    needles
}

fn longest_needle_prefix_suffix(pending: &str, needles: &[Zeroizing<String>]) -> usize {
    let p_bytes = pending.as_bytes();
    let mut best = 0usize;
    for needle in needles {
        let n_bytes = needle.as_bytes();
        if n_bytes.len() <= 1 {
            continue;
        }
        let max_check = p_bytes.len().min(n_bytes.len() - 1);
        if max_check <= best {
            continue;
        }
        for len in (best + 1..=max_check).rev() {
            if p_bytes.ends_with(&n_bytes[..len]) {
                best = len;
                break;
            }
        }
    }
    best
}

fn pem_overlap_hold(pending: &str) -> usize {
    const BEGIN: &str = "-----BEGIN ";
    const END_MARK: &str = "-----END ";
    let mut hold = 0usize;

    if let Some(pos) = pending.rfind(BEGIN) {
        let tail = &pending[pos..];
        let closed = tail.find(END_MARK).is_some_and(|end_rel| {
            tail[end_rel + END_MARK.len()..].contains("-----")
        });
        if !closed {
            let after_begin = &tail[BEGIN.len()..];
            let header_maybe_private = match after_begin.find("-----") {
                None => !after_begin.contains('\n'),
                Some(h_end) => after_begin[..h_end]
                    .to_ascii_uppercase()
                    .contains("PRIVATE"),
            };
            if header_maybe_private && tail.len() <= MAX_PEM_HOLD_BYTES {
                hold = tail.len();
            }
        }
    }

    let p_bytes = pending.as_bytes();
    let b_bytes = BEGIN.as_bytes();
    let max_prefix = p_bytes.len().min(b_bytes.len() - 1);
    for len in (hold + 1..=max_prefix).rev() {
        if p_bytes.ends_with(&b_bytes[..len]) {
            hold = len;
            break;
        }
    }
    hold
}

/// Incremental UTF-8 stream scrubber with a rolling overlap buffer sized to
/// the maximum exact-value needle length so secrets split across HTTP/SSE chunk
/// boundaries are held and scrubbed while complete SSE events flush immediately.
struct StreamScrubber {
    exact_values: Vec<(String, Zeroizing<String>)>,
    needles: Vec<Zeroizing<String>>,
    max_needle_len: usize,
    pending: String,
    utf8_tail: Vec<u8>,
    is_binary: bool,
}

impl StreamScrubber {
    fn new(exact_values: Vec<(String, Zeroizing<String>)>) -> Self {
        let needles = build_exact_needles(&exact_values);
        let max_needle_len = needles.iter().map(|n| n.len()).max().unwrap_or(0);
        Self {
            exact_values,
            needles,
            max_needle_len,
            pending: String::new(),
            utf8_tail: Vec::new(),
            is_binary: false,
        }
    }

    fn push_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        if chunk.is_empty() {
            return Vec::new();
        }
        if self.is_binary {
            return chunk.to_vec();
        }

        let mut combined = Vec::with_capacity(self.utf8_tail.len() + chunk.len());
        combined.extend_from_slice(&self.utf8_tail);
        combined.extend_from_slice(chunk);
        self.utf8_tail.clear();

        let valid_text = match std::str::from_utf8(&combined) {
            Ok(s) => s,
            Err(err) => {
                if err.error_len().is_none() {
                    let valid_up_to = err.valid_up_to();
                    self.utf8_tail.extend_from_slice(&combined[valid_up_to..]);
                    // SAFETY: std::str::from_utf8 guaranteed `..valid_up_to` is valid UTF-8.
                    std::str::from_utf8(&combined[..valid_up_to]).unwrap_or("")
                } else {
                    self.is_binary = true;
                    let mut out = self.flush_pending_scrubbed();
                    out.extend_from_slice(&combined);
                    combined.zeroize();
                    return out;
                }
            }
        };

        self.pending.push_str(valid_text);
        combined.zeroize();

        // Compute holdback BEFORE exact-value replacement so that a shorter
        // secret which is a prefix of a longer secret (e.g. `abc123` vs
        // `abc123456`) is not prematurely rewritten before the remaining bytes
        // arrive in the next chunk.
        let exact_hold = longest_needle_prefix_suffix(&self.pending, &self.needles);
        let pem_hold = pem_overlap_hold(&self.pending);
        let max_line_hold = MAX_LINE_HOLD_BYTES.max(self.max_needle_len);
        let tail_after_nl = match self.pending.rfind('\n') {
            Some(nl_pos) => self.pending.len().saturating_sub(nl_pos + 1),
            None => self.pending.len(),
        };
        let line_hold = if tail_after_nl <= max_line_hold {
            tail_after_nl
        } else {
            MIN_LONG_LINE_OVERLAP_BYTES.max(exact_hold)
        };

        let hold = exact_hold.max(pem_hold).max(line_hold);
        let mut emit_end = self.pending.len().saturating_sub(hold);
        while emit_end > 0 && !self.pending.is_char_boundary(emit_end) {
            emit_end -= 1;
        }
        // Guarantee the cut point `emit_end` never bisects an exact-value needle
        // (e.g. a multiline secret straddling a newline when `line_hold > 0`).
        while emit_end > 0 && emit_end < self.pending.len() {
            let seam_overlap =
                longest_needle_prefix_suffix(&self.pending[..emit_end], &self.needles);
            if seam_overlap == 0 {
                break;
            }
            emit_end = emit_end.saturating_sub(seam_overlap);
            while emit_end > 0 && !self.pending.is_char_boundary(emit_end) {
                emit_end -= 1;
            }
        }
        if emit_end == 0 {
            return Vec::new();
        }

        let (scrubbed_exact, _) =
            ciphervault_redact::scrub_exact_values(&self.pending[..emit_end], &self.exact_values);
        let redacted = ciphervault_redact::redact_text(&scrubbed_exact);
        let rest = self.pending[emit_end..].to_string();
        self.pending.zeroize();
        self.pending = rest;
        redacted.into_bytes()
    }

    fn flush_pending_scrubbed(&mut self) -> Vec<u8> {
        if self.pending.is_empty() {
            return Vec::new();
        }
        let (exact, _) = ciphervault_redact::scrub_exact_values(&self.pending, &self.exact_values);
        self.pending.zeroize();
        self.pending.clear();
        ciphervault_redact::redact_text(&exact).into_bytes()
    }

    fn finish(&mut self) -> Vec<u8> {
        let mut out = self.flush_pending_scrubbed();
        if !self.utf8_tail.is_empty() {
            out.extend_from_slice(&self.utf8_tail);
            self.utf8_tail.zeroize();
            self.utf8_tail.clear();
        }
        out
    }
}

impl Drop for StreamScrubber {
    fn drop(&mut self) {
        self.pending.zeroize();
        self.utf8_tail.zeroize();
    }
}

fn is_streaming_response(headers: &reqwest::header::HeaderMap) -> bool {
    let ct_lower = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if ct_lower.starts_with("text/event-stream")
        || ct_lower.starts_with("application/x-ndjson")
        || ct_lower.starts_with("application/ndjson")
        || ct_lower.starts_with("application/stream+json")
    {
        return true;
    }
    let is_chunked = headers
        .get_all(reqwest::header::TRANSFER_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("chunked"));
    let has_content_length = headers.contains_key(reqwest::header::CONTENT_LENGTH);
    is_chunked && !has_content_length
}

fn extract_presented_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let trimmed = auth.trim();
        let lower_prefix = bearer_scheme_prefix().to_ascii_lowercase();
        if trimmed.to_ascii_lowercase().starts_with(&lower_prefix) {
            tokens.push(trimmed[lower_prefix.len()..].trim().to_string());
        } else {
            tokens.push(trimmed.to_string());
        }
    }
    for h in ["x-api-key", "x-goog-api-key", "x-ciphervault-proxy-token"] {
        if let Some(val) = headers.get(h).and_then(|v| v.to_str().ok()) {
            tokens.push(val.trim().to_string());
        }
    }
    tokens
}

fn is_hop_by_hop_or_auth(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "accept-encoding"
            | "authorization"
            | "x-api-key"
            | "x-goog-api-key"
            | "x-ciphervault-proxy-token"
    )
}

fn scrub_error_message(raw: &str, exact_values: &[(String, Zeroizing<String>)]) -> String {
    let (exact, _) = ciphervault_redact::scrub_exact_values(raw, exact_values);
    ciphervault_redact::redact_text(&exact)
}

fn build_response_headers(
    status: StatusCode,
    resp_headers: &reqwest::header::HeaderMap,
) -> axum::http::response::Builder {
    let mut out_resp = Response::builder().status(status);
    for (k, v) in resp_headers {
        let k_lower = k.as_str().to_ascii_lowercase();
        if matches!(
            k_lower.as_str(),
            "connection" | "transfer-encoding" | "content-length" | "keep-alive"
        ) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(k.as_str().as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out_resp = out_resp.header(hn, hv);
        }
    }
    out_resp
}

async fn proxy_handler(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response {
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let presented = extract_presented_tokens(&parts.headers);

    let (route, forward_path) = if let Some(rest) = path_and_query.strip_prefix("/__cv/") {
        let (slug, tail) = match rest.split_once('/') {
            Some((s, t)) => (s, format!("/{t}")),
            None => (rest, String::new()),
        };
        let Some(r) = state.routes.iter().find(|r| r.slug == slug) else {
            return (StatusCode::NOT_FOUND, "unknown CipherVault proxy route").into_response();
        };
        if !presented.iter().any(|t| t == &r.placeholder) {
            return (
                StatusCode::FORBIDDEN,
                "missing or invalid CipherVault proxy placeholder token",
            )
                .into_response();
        }
        (r, tail)
    } else {
        let Some(r) = state
            .routes
            .iter()
            .find(|r| presented.iter().any(|t| t == &r.placeholder))
        else {
            return (
                StatusCode::FORBIDDEN,
                "missing or invalid CipherVault proxy placeholder token",
            )
                .into_response();
        };
        (r, path_and_query.to_string())
    };

    let target_url = format!("{}{}", route.upstream_base, forward_path);
    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(m) => m,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid HTTP method").into_response(),
    };

    let body_bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body exceeds 16 MiB").into_response()
        }
    };

    let mut out_req = state.client.request(method, &target_url);
    for (k, v) in &parts.headers {
        let k_str = k.as_str();
        if is_hop_by_hop_or_auth(k_str) {
            continue;
        }
        if let Ok(val) = v.to_str() {
            out_req = out_req.header(k_str, val);
        }
    }

    let injected_value = if route.bearer_prefix {
        Zeroizing::new(format!(
            "{}{}",
            bearer_scheme_prefix(),
            route.upstream_cred.as_str()
        ))
    } else {
        route.upstream_cred.clone()
    };
    out_req = out_req.header(route.header_name.as_str(), injected_value.as_str());
    if !body_bytes.is_empty() && parts.method != Method::GET && parts.method != Method::HEAD {
        out_req = out_req.body(body_bytes.to_vec());
    }

    let mut resp = match tokio::time::timeout(state.idle_read_timeout, out_req.send()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let scrubbed_err = scrub_error_message(&e.to_string(), &state.exact_values);
            return (
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {scrubbed_err}"),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::GATEWAY_TIMEOUT,
                "upstream request timed out waiting for response headers",
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let resp_headers = resp.headers().clone();

    if is_streaming_response(&resp_headers) {
        let scrubber = StreamScrubber::new(state.exact_values.clone());
        let idle_timeout = state.idle_read_timeout;
        let body_stream = stream::unfold(
            (resp, scrubber, idle_timeout, false),
            |(mut resp, mut scrubber, idle_timeout, mut done)| async move {
                if done {
                    return None;
                }
                loop {
                    match tokio::time::timeout(idle_timeout, resp.chunk()).await {
                        Ok(Ok(Some(chunk))) => {
                            let emitted = scrubber.push_chunk(&chunk);
                            if !emitted.is_empty() {
                                return Some((
                                    Ok::<Vec<u8>, std::io::Error>(emitted),
                                    (resp, scrubber, idle_timeout, false),
                                ));
                            }
                        }
                        Ok(Ok(None)) => {
                            done = true;
                            let tail = scrubber.finish();
                            if tail.is_empty() {
                                return None;
                            }
                            return Some((
                                Ok::<Vec<u8>, std::io::Error>(tail),
                                (resp, scrubber, idle_timeout, done),
                            ));
                        }
                        Ok(Err(e)) => {
                            let scrubbed_err =
                                scrub_error_message(&e.to_string(), &scrubber.exact_values);
                            return Some((
                                Err(std::io::Error::other(format!(
                                    "upstream stream read failed: {scrubbed_err}"
                                ))),
                                (resp, scrubber, idle_timeout, true),
                            ));
                        }
                        Err(_) => {
                            return Some((
                                Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "upstream stream idle read timeout",
                                )),
                                (resp, scrubber, idle_timeout, true),
                            ));
                        }
                    }
                }
            },
        );

        let out_resp = build_response_headers(status, &resp_headers);
        return out_resp
            .body(Body::from_stream(body_stream))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let mut resp_bytes = Vec::new();
    loop {
        match tokio::time::timeout(state.idle_read_timeout, resp.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                if resp_bytes.len().saturating_add(chunk.len()) > MAX_BUFFERED_RESPONSE_BYTES {
                    resp_bytes.zeroize();
                    return (
                        StatusCode::BAD_GATEWAY,
                        "upstream response read failed: buffered response exceeds 64 MiB limit",
                    )
                        .into_response();
                }
                resp_bytes.extend_from_slice(&chunk);
            }
            Ok(Ok(None)) => break,
            Ok(Err(e)) => {
                resp_bytes.zeroize();
                let scrubbed_err = scrub_error_message(&e.to_string(), &state.exact_values);
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("upstream response read failed: {scrubbed_err}"),
                )
                    .into_response();
            }
            Err(_) => {
                resp_bytes.zeroize();
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream response read failed: idle read timeout",
                )
                    .into_response();
            }
        }
    }

    let final_body: Vec<u8> = match std::str::from_utf8(&resp_bytes) {
        Ok(text) => {
            let (exact, _) = ciphervault_redact::scrub_exact_values(text, &state.exact_values);
            let out = ciphervault_redact::redact_text(&exact).into_bytes();
            resp_bytes.zeroize();
            out
        }
        Err(_) => resp_bytes,
    };

    let out_resp = build_response_headers(status, &resp_headers);
    out_resp
        .body(Body::from(final_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    #[test]
    fn validates_upstream_urls_and_rejects_cleartext_remote() {
        let allow_loopback = allow_loopback_upstream();
        assert!(
            parse_proxy_upstream_spec("MY_VAR=https://api.example.com", allow_loopback).is_ok()
        );
        assert!(parse_proxy_upstream_spec("MY_VAR=http://127.0.0.1:8080", allow_loopback).is_ok());
        assert!(parse_proxy_upstream_spec("MY_VAR=http://evil.example.com", allow_loopback).is_err());

        let (k, u, h, bearer) =
            parse_proxy_upstream_spec("MY_VAR=https://api.example.com@X-Api-Key", allow_loopback)
                .unwrap();
        assert_eq!(k, "MY_VAR");
        assert_eq!(u, "https://api.example.com");
        assert_eq!(h, "x-api-key");
        assert!(!bearer);
    }

    #[test]
    fn known_providers_cover_expanded_developer_apis() {
        let expected = [
            ("RESEND_API_KEY", "https://api.resend.com", "RESEND_BASE_URL"),
            ("SLACK_BOT_TOKEN", "https://slack.com/api", "SLACK_API_URL"),
            ("VERCEL_TOKEN", "https://api.vercel.com", ""),
            (
                "CLOUDFLARE_API_TOKEN",
                "https://api.cloudflare.com",
                "CLOUDFLARE_BASE_URL",
            ),
            ("GROQ_API_KEY", "https://api.groq.com", "GROQ_BASE_URL"),
            (
                "DEEPSEEK_API_KEY",
                "https://api.deepseek.com",
                "DEEPSEEK_BASE_URL",
            ),
            ("XAI_API_KEY", "https://api.x.ai", "XAI_BASE_URL"),
            (
                "MISTRAL_API_KEY",
                "https://api.mistral.ai",
                "MISTRAL_BASE_URL",
            ),
        ];
        for (key, url, base_env) in expected {
            let (got_url, hdr, bearer, envs) =
                known_provider_for_key(key).unwrap_or_else(|| panic!("missing provider {key}"));
            assert_eq!(got_url, url);
            assert_eq!(hdr, "authorization");
            assert!(bearer);
            if !base_env.is_empty() {
                assert!(
                    envs.iter().any(|(e, _)| *e == base_env),
                    "{key} missing expected base env {base_env}"
                );
            }
            // Non-canonical override must be rejected when allow_provider_override=false.
            let mut vars = BTreeMap::new();
            vars.insert(
                key.to_string(),
                Zeroizing::new("synthetic_provider_val_998877".to_string()),
            );
            assert!(build_proxy_routes_with_policy(
                &vars,
                Some(&[format!("{key}=https://attacker.example.com")]),
                false,
                false,
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn proxy_injects_real_cred_blocks_wrong_token_and_scrubs_echoed_value() {
        let real_val = concat!("real_proxy_", "tok_", "77889900aabb");

        let mock_app = Router::new().route(
            "/v1/echo",
            get(|headers: HeaderMap| async move {
                let hdr = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                format!("got_hdr {hdr}")
            }),
        );
        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap();
        let mock_handle = tokio::spawn(async move {
            let _ = axum::serve(mock_listener, mock_app).await;
        });

        let mut vars = BTreeMap::new();
        vars.insert(
            "OPENAI_API_KEY".to_string(),
            Zeroizing::new(real_val.to_string()),
        );
        let upstream_arg = format!("{}={}://{mock_addr}", "OPENAI_API_KEY", "http");
        let routes = build_proxy_routes(&vars, Some(&[upstream_arg])).unwrap();
        let placeholder = routes[0].placeholder.clone();
        assert_ne!(placeholder, real_val);

        let proxy = start_credential_proxy(routes).await.unwrap();
        let proxy_base = format!("http://{}", proxy.addr);
        let client = reqwest::Client::new();
        let scheme = bearer_scheme_prefix();

        let bad = client
            .get(format!("{proxy_base}/__cv/openai_api_key/v1/echo"))
            .header("authorization", format!("{scheme}wrong-token"))
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), reqwest::StatusCode::FORBIDDEN);

        let ok = client
            .get(format!("{proxy_base}/__cv/openai_api_key/v1/echo"))
            .header("authorization", format!("{scheme}{placeholder}"))
            .header("host", "attacker.example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), reqwest::StatusCode::OK);
        let body = ok.text().await.unwrap();
        assert!(!body.contains(real_val), "value leaked in body: {body}");
        assert!(body.contains("[REDACTED"), "expected redaction in {body}");

        proxy.shutdown().await;
        mock_handle.abort();
    }

    #[tokio::test]
    async fn proxy_streams_sse_incrementally_and_scrubs_secret_split_across_chunks() {
        let real_val = concat!("real_sse_", "stream_", "secret_55667788");
        let hex_val = hex::encode(real_val.as_bytes());
        let gate = Arc::new(tokio::sync::Notify::new());
        let gate_server = gate.clone();

        let mock_app = Router::new().route(
            "/v1/chat/completions",
            get(move |headers: HeaderMap| {
                let gate_inner = gate_server.clone();
                let hex_copy = hex_val.clone();
                async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let raw_secret = auth
                        .strip_prefix(bearer_scheme_prefix())
                        .unwrap_or(&auth)
                        .to_string();
                    let split_raw = raw_secret.len() / 2;
                    let raw_a = raw_secret[..split_raw].to_string();
                    let raw_b = raw_secret[split_raw..].to_string();
                    let split_hex = hex_copy.len() / 2;
                    let hex_a = hex_copy[..split_hex].to_string();
                    let hex_b = hex_copy[split_hex..].to_string();

                    let (tx, rx) =
                        tokio::sync::mpsc::channel::<std::result::Result<Vec<u8>, std::io::Error>>(
                            8,
                        );
                    tokio::spawn(async move {
                        let _ = tx
                            .send(Ok(b"data: {\"delta\":\"hello\"}\n\n".to_vec()))
                            .await;
                        // Hold sending chunk 2 until the client proves it received chunk 1
                        // incrementally while the upstream stream is still open.
                        gate_inner.notified().await;
                        let _ = tx
                            .send(Ok(format!("data: {{\"raw\":\"{raw_a}").into_bytes()))
                            .await;
                        let _ = tx
                            .send(Ok(format!("{raw_b}\",\"hex\":\"{hex_a}").into_bytes()))
                            .await;
                        let _ = tx
                            .send(Ok(format!("{hex_b}\"}}\n\n").into_bytes()))
                            .await;
                        let _ = tx.send(Ok(b"data: [DONE]\n\n".to_vec())).await;
                    });

                    let body_stream = stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|item| (item, rx))
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/event-stream")
                        .header("cache-control", "no-cache")
                        .body(Body::from_stream(body_stream))
                        .unwrap()
                }
            }),
        );

        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap();
        let mock_handle = tokio::spawn(async move {
            let _ = axum::serve(mock_listener, mock_app).await;
        });

        let mut vars = BTreeMap::new();
        vars.insert(
            "OPENAI_API_KEY".to_string(),
            Zeroizing::new(real_val.to_string()),
        );
        let upstream_arg = format!("OPENAI_API_KEY=http://{mock_addr}");
        let routes = build_proxy_routes(&vars, Some(&[upstream_arg])).unwrap();
        let placeholder = routes[0].placeholder.clone();

        let proxy = start_credential_proxy(routes).await.unwrap();
        let client = reqwest::Client::new();
        let scheme = bearer_scheme_prefix();

        let mut resp = client
            .get(format!(
                "http://{}/__cv/openai_api_key/v1/chat/completions",
                proxy.addr
            ))
            .header("authorization", format!("{scheme}{placeholder}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );

        // Chunk 1 must arrive BEFORE we notify the mock upstream to send chunks 2..5.
        let first_chunk = tokio::time::timeout(Duration::from_secs(3), resp.chunk())
            .await
            .expect("SSE chunk 1 stalled (response was buffered instead of streamed)")
            .unwrap()
            .expect("expected SSE chunk 1 bytes");
        let first_text = String::from_utf8(first_chunk.to_vec()).unwrap();
        assert!(
            first_text.contains("\"delta\":\"hello\""),
            "unexpected first SSE chunk: {first_text}"
        );

        // Release remaining chunks containing secrets split across chunk boundaries.
        gate.notify_one();

        let mut full = first_text;
        while let Some(chunk) = tokio::time::timeout(Duration::from_secs(3), resp.chunk())
            .await
            .expect("timed out reading remaining SSE chunks")
            .unwrap()
        {
            full.push_str(&String::from_utf8_lossy(&chunk));
        }

        let hex_needle = hex::encode(real_val.as_bytes());
        assert!(!full.contains(real_val), "raw secret leaked in SSE: {full}");
        assert!(
            !full.contains(&hex_needle),
            "hex-encoded secret leaked in SSE: {full}"
        );
        assert_eq!(
            full.matches("[REDACTED:OPENAI_API_KEY]").count(),
            2,
            "expected both split raw and split hex values to redact cleanly: {full}"
        );
        assert!(full.contains("data: [DONE]\n\n"));

        proxy.shutdown().await;
        mock_handle.abort();
    }

    #[test]
    fn stream_scrubber_handles_single_byte_chunks_utf8_and_multiline_secrets() {
        let secret = concat!("line1_secret_", "abc\nline2_", "xyz987");
        let mut scrubber = StreamScrubber::new(vec![(
            "MULTI_KEY".to_string(),
            Zeroizing::new(secret.to_string()),
        )]);

        // Complete non-secret SSE frame flushes immediately in a single push.
        let immediate = scrubber.push_chunk(b"data: ok \xF0\x9F\x94\x92\n\n");
        assert_eq!(
            String::from_utf8(immediate).unwrap(),
            "data: ok \u{1F512}\n\n"
        );

        // Feed a payload with multi-byte UTF-8 + multiline secret split 1 byte at a time.
        let payload = format!("prefix \u{2713} {secret} suffix\n");
        let mut collected = Vec::new();
        for b in payload.as_bytes() {
            collected.extend_from_slice(&scrubber.push_chunk(&[*b]));
        }
        collected.extend_from_slice(&scrubber.finish());
        let out = String::from_utf8(collected).unwrap();
        assert!(!out.contains("line1_secret_abc"), "part 1 leaked: {out}");
        assert!(!out.contains("line2_xyz987"), "part 2 leaked: {out}");
        assert_eq!(out, "prefix \u{2713} [REDACTED:MULTI_KEY] suffix\n");

        // Seam safety: multiline secret straddling newline with trailing incomplete line
        // AND shorter secret that is a prefix of a longer secret across chunk boundaries.
        let mut scrubber2 = StreamScrubber::new(vec![
            (
                "SHORT_KEY".to_string(),
                Zeroizing::new("overlap_tok_1234".to_string()),
            ),
            (
                "LONG_KEY".to_string(),
                Zeroizing::new("overlap_tok_1234_extended".to_string()),
            ),
            (
                "ML_KEY".to_string(),
                Zeroizing::new("alpha_line\nbeta_line".to_string()),
            ),
        ]);
        let mut out2 = Vec::new();
        out2.extend_from_slice(&scrubber2.push_chunk(b"a=overlap_tok_1234"));
        out2.extend_from_slice(&scrubber2.push_chunk(b"_extended\nb=alpha_line\nbeta_line tail"));
        out2.extend_from_slice(&scrubber2.push_chunk(b"\n"));
        out2.extend_from_slice(&scrubber2.finish());
        let text2 = String::from_utf8(out2).unwrap();
        assert!(!text2.contains("_extended"), "longer secret suffix leaked: {text2}");
        assert!(!text2.contains("alpha_line"), "multiline secret leaked: {text2}");
        assert!(!text2.contains("beta_line"), "multiline secret leaked: {text2}");
        assert_eq!(
            text2,
            "a=[REDACTED:LONG_KEY]\nb=[REDACTED:ML_KEY] tail\n"
        );
    }

    #[tokio::test]
    async fn proxy_uses_per_chunk_idle_timeout_without_killing_long_streams() {
        let mock_app = Router::new()
            .route(
                "/slow-steady",
                get(|| async {
                    let (tx, rx) =
                        tokio::sync::mpsc::channel::<std::result::Result<Vec<u8>, std::io::Error>>(
                            8,
                        );
                    tokio::spawn(async move {
                        for idx in 0..5 {
                            tokio::time::sleep(Duration::from_millis(70)).await;
                            let _ = tx
                                .send(Ok(format!("data: tick-{idx}\n\n").into_bytes()))
                                .await;
                        }
                    });
                    let body_stream = stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|item| (item, rx))
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/event-stream")
                        .body(Body::from_stream(body_stream))
                        .unwrap()
                }),
            )
            .route(
                "/stalled",
                get(|| async {
                    let (tx, rx) =
                        tokio::sync::mpsc::channel::<std::result::Result<Vec<u8>, std::io::Error>>(
                            4,
                        );
                    tokio::spawn(async move {
                        let _ = tx.send(Ok(b"data: first\n\n".to_vec())).await;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        let _ = tx.send(Ok(b"data: too-late\n\n".to_vec())).await;
                    });
                    let body_stream = stream::unfold(rx, |mut rx| async move {
                        rx.recv().await.map(|item| (item, rx))
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/event-stream")
                        .body(Body::from_stream(body_stream))
                        .unwrap()
                }),
            );

        let mock_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap();
        let mock_handle = tokio::spawn(async move {
            let _ = axum::serve(mock_listener, mock_app).await;
        });

        let mut vars = BTreeMap::new();
        vars.insert(
            "CUSTOM_KEY".to_string(),
            Zeroizing::new("custom_stream_tok_12345".to_string()),
        );
        let routes =
            build_proxy_routes(&vars, Some(&[format!("CUSTOM_KEY=http://{mock_addr}")])).unwrap();
        let placeholder = routes[0].placeholder.clone();

        // Idle timeout is 220ms, while 5 ticks * 70ms = 350ms total (> 220ms).
        // A total timeout would kill /slow-steady; a per-chunk idle timeout lets it finish!
        let proxy = start_credential_proxy_with_timeouts(
            routes,
            Duration::from_secs(5),
            Duration::from_millis(220),
        )
        .await
        .unwrap();
        let client = reqwest::Client::new();
        let scheme = bearer_scheme_prefix();

        let ok = client
            .get(format!("http://{}/__cv/custom_key/slow-steady", proxy.addr))
            .header("authorization", format!("{scheme}{placeholder}"))
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), reqwest::StatusCode::OK);
        let body = ok.text().await.unwrap();
        assert!(body.contains("data: tick-4\n\n"), "stream truncated: {body}");

        // A genuinely stalled stream must fail once idle_read_timeout expires.
        let mut stalled = client
            .get(format!("http://{}/__cv/custom_key/stalled", proxy.addr))
            .header("authorization", format!("{scheme}{placeholder}"))
            .send()
            .await
            .unwrap();
        assert_eq!(stalled.status(), reqwest::StatusCode::OK);
        let first = stalled.chunk().await.unwrap().unwrap();
        assert_eq!(&first[..], b"data: first\n\n");
        let second = tokio::time::timeout(Duration::from_secs(2), stalled.chunk())
            .await
            .expect("stalled stream did not time out promptly");
        assert!(
            second.is_err(),
            "expected stream read error after idle timeout, got {second:?}"
        );

        proxy.shutdown().await;
        mock_handle.abort();
    }

    #[test]
    fn rejects_loopback_http_upstream_unless_allowed() {
        for url in [
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            let err = validate_upstream_url(url, false).unwrap_err();
            assert!(
                err.to_string()
                    .contains("CIPHERVAULT_ALLOW_LOOPBACK_UPSTREAM=1"),
                "unexpected error for {url}: {err}"
            );
            assert!(
                validate_upstream_url(url, true).is_ok(),
                "expected {url} to be allowed when allow_loopback=true"
            );
        }

        // Non-loopback cleartext HTTP is always refused even with allow_loopback=true.
        assert!(validate_upstream_url("http://evil.example.com", true).is_err());
    }

    #[test]
    fn rejects_known_provider_override_unless_allowed() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "OPENAI_API_KEY".to_string(),
            Zeroizing::new("sk-test-1234567890".to_string()),
        );
        vars.insert(
            "OPENROUTER_API_KEY".to_string(),
            Zeroizing::new("sk-or-test-1234567890".to_string()),
        );
        vars.insert(
            "CUSTOM_API_KEY".to_string(),
            Zeroizing::new("custom-1234567890".to_string()),
        );

        // Overriding a known provider to a non-canonical HTTPS host fails when disallowed.
        let err = build_proxy_routes_with_policy(
            &vars,
            Some(&["OPENAI_API_KEY=https://attacker.example.com".to_string()]),
            false,
            false,
        )
        .err()
        .expect("expected provider override to fail");
        assert!(
            err.to_string()
                .contains("CIPHERVAULT_ALLOW_PROVIDER_OVERRIDE=1"),
            "unexpected error: {err}"
        );

        // Overriding a known provider to a loopback HTTP endpoint also fails without provider override.
        assert!(build_proxy_routes_with_policy(
            &vars,
            Some(&["OPENAI_API_KEY=http://127.0.0.1:9999".to_string()]),
            true,
            false,
        )
        .is_err());

        // Allowed when CIPHERVAULT_ALLOW_PROVIDER_OVERRIDE=1 policy is enabled.
        let allowed_routes = build_proxy_routes_with_policy(
            &vars,
            Some(&["OPENAI_API_KEY=https://attacker.example.com".to_string()]),
            false,
            true,
        )
        .unwrap();
        let openai = allowed_routes
            .iter()
            .find(|r| r.env_key == "OPENAI_API_KEY")
            .unwrap();
        assert_eq!(openai.upstream_base, "https://attacker.example.com");

        // Canonical URL (even with trailing slash or uppercase host) succeeds without override flag.
        assert!(build_proxy_routes_with_policy(
            &vars,
            Some(&[
                "OPENAI_API_KEY=HTTPS://API.OPENAI.COM/".to_string(),
                "OPENROUTER_API_KEY=https://openrouter.ai/api/".to_string(),
            ]),
            false,
            false,
        )
        .is_ok());

        // Non-known custom keys can bind to arbitrary HTTPS upstreams without override flag.
        assert!(build_proxy_routes_with_policy(
            &vars,
            Some(&["CUSTOM_API_KEY=https://gateway.example.com".to_string()]),
            false,
            false,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn proxy_scrubs_upstream_response_read_errors() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let real_val = concat!("real_read_err_", "tok_", "aabbccddeeff");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = listener.local_addr().unwrap();
        let mock_handle = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Consume the request first: closing with unread request
                // bytes can RST the connection, which newer hyper surfaces
                // as a send error instead of the intended body-read error.
                let mut req_buf = [0u8; 4096];
                let _ = sock.read(&mut req_buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\npartial")
                    .await;
                let _ = sock.shutdown().await;
            }
        });

        let mut vars = BTreeMap::new();
        vars.insert(
            "CUSTOM_KEY".to_string(),
            Zeroizing::new(real_val.to_string()),
        );
        let upstream_arg = format!("CUSTOM_KEY=http://{mock_addr}");
        let routes = build_proxy_routes(&vars, Some(&[upstream_arg])).unwrap();
        let placeholder = routes[0].placeholder.clone();

        let proxy = start_credential_proxy(routes).await.unwrap();
        let client = reqwest::Client::new();
        let scheme = bearer_scheme_prefix();
        let resp = client
            .get(format!("http://{}/__cv/custom_key/data", proxy.addr))
            .header("authorization", format!("{scheme}{placeholder}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
        let body = resp.text().await.unwrap();
        assert!(
            body.starts_with("upstream response read failed:"),
            "unexpected body: {body}"
        );
        assert!(!body.contains(real_val));

        proxy.shutdown().await;
        mock_handle.abort();
    }
}
