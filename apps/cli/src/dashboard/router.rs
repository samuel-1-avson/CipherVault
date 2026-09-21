//! Dashboard HTTP routers (private, public, shell, and mode dispatch).

use super::session::UiServerMode;
use crate::{
    api_account_capabilities_handler, api_account_device_challenge_handler,
    api_account_device_enrollment_handler, api_account_invitation_accept_handler,
    api_account_invitations_get_handler, api_account_invitations_post_handler,
    api_account_login_handler, api_account_logout_handler, api_account_membership_revoke_handler,
    api_account_memberships_get_handler, api_account_recovery_codes_handler,
    api_account_register_handler, api_account_resource_get_handler,
    api_account_session_challenge_handler, api_account_session_handler,
    api_account_session_handoff_consume_handler, api_account_session_handoff_handler,
    api_account_session_login_handler, api_account_status_handler,
    api_account_totp_enrollment_handler, api_account_totp_enrollment_verify_handler,
    api_account_totp_options_handler, api_account_totp_revoke_handler,
    api_account_totp_verify_handler, api_account_vaults_post_handler,
    api_account_webauthn_options_handler, api_account_webauthn_registration_options_handler,
    api_account_webauthn_registration_verify_handler, api_account_webauthn_verify_handler,
    api_activity_handler, api_anchors_handler, api_approvals_handler, api_audit_handler,
    api_create_anchor_handler, api_create_snapshot_handler, api_diff_handler,
    api_explorer_object_handler, api_explorer_overview_handler, api_fastcdc_inspect_handler,
    api_fastcdc_vault_files_handler, api_files_track_handler, api_files_untrack_handler,
    api_fleet_audit_handler, api_fleet_handler, api_guardians_handler, api_operators_handler,
    api_private_context_handler, api_private_fallback_handler, api_private_session_revoke_handler,
    api_public_anchors_handler, api_public_context_handler, api_public_fallback_handler,
    api_public_fleet_handler, api_public_operators_handler, api_public_operators_history_handler,
    api_public_operators_jobs_handler, api_public_relayer_checkpoints_handler,
    api_public_stream_handler, api_public_vault_handler, api_relayer_anchor_handler,
    api_relayer_checkpoints_handler, api_snapshot_manifest_handler, api_snapshots_handler,
    api_snapshots_restore_handler, api_stream_handler, api_token_handler, api_vault_handler,
    api_workspaces_handler, api_workspaces_scan_handler, api_workspaces_switch_handler,
    private_ui_request_guard, UI_APP_JS, UI_INDEX_HTML, UI_STYLES_CSS,
};

/// Content-Security-Policy for the UI shell document. The bundle is a
/// separate same-origin file with no inline scripts, styles, or event
/// handlers, and the app never injects script/style/iframe elements or
/// uses string-compiled timers — so a strict same-origin policy holds.
const UI_SHELL_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

/// Cap on buffered request bodies for every dashboard route, private and
/// public. Axum 0.7 defaults buffering extractors to 2 MiB, which already
/// covers the account proxy's raw-`Bytes` handlers — this layer pins that
/// behavior explicitly so it cannot silently change (or be disabled) later.
/// Every dashboard POST is small control JSON, so nothing legitimate comes
/// close; oversized bodies fail with 413 before any upstream contact.
const UI_REQUEST_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

pub(crate) fn ui_shell_router() -> axum::Router {
    use axum::{
        http::header,
        response::{Html, IntoResponse},
        routing::get,
        Router,
    };

    Router::new()
        .route(
            "/",
            get(|| async {
                let mut response = Html(UI_INDEX_HTML).into_response();
                response.headers_mut().insert(
                    header::CONTENT_SECURITY_POLICY,
                    axum::http::HeaderValue::from_static(UI_SHELL_CSP),
                );
                response
            }),
        )
        .route(
            "/styles.css",
            get(|| async { ([(header::CONTENT_TYPE, "text/css")], UI_STYLES_CSS) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/javascript")],
                    UI_APP_JS,
                )
            }),
        )
}

pub(crate) fn private_ui_router() -> axum::Router {
    use axum::routing::get;

    ui_shell_router()
        .route("/api/context", get(api_private_context_handler))
        .route("/api/account/status", get(api_account_status_handler))
        .route(
            "/api/account/capabilities",
            get(api_account_capabilities_handler),
        )
        .route(
            "/api/account/register",
            axum::routing::post(api_account_register_handler),
        )
        .route("/api/account/session", get(api_account_session_handler))
        .route(
            "/api/account/sessions/challenge",
            axum::routing::post(api_account_session_challenge_handler),
        )
        .route(
            "/api/account/sessions/login",
            axum::routing::post(api_account_session_login_handler),
        )
        .route(
            "/api/account/sessions/handoff",
            axum::routing::post(api_account_session_handoff_handler),
        )
        .route(
            "/api/account/session/handoff",
            axum::routing::post(api_account_session_handoff_consume_handler),
        )
        .route(
            "/api/account/:account_id",
            get(api_account_resource_get_handler),
        )
        .route(
            "/api/account/:account_id/invitations",
            get(api_account_invitations_get_handler).post(api_account_invitations_post_handler),
        )
        .route(
            "/api/account/:account_id/vaults",
            axum::routing::post(api_account_vaults_post_handler),
        )
        .route(
            "/api/account/:account_id/memberships",
            get(api_account_memberships_get_handler),
        )
        .route(
            "/api/account/:account_id/memberships/:member_account_id/revoke",
            axum::routing::post(api_account_membership_revoke_handler),
        )
        .route(
            "/api/account/:account_id/recovery/codes",
            axum::routing::post(api_account_recovery_codes_handler),
        )
        .route(
            "/api/account/invitations/accept",
            axum::routing::post(api_account_invitation_accept_handler),
        )
        .route(
            "/api/account/login",
            axum::routing::post(api_account_login_handler),
        )
        .route(
            "/api/account/logout",
            axum::routing::post(api_account_logout_handler),
        )
        .route(
            "/api/account/webauthn/authentication/options",
            axum::routing::post(api_account_webauthn_options_handler),
        )
        .route(
            "/api/account/webauthn/authentication/verify",
            axum::routing::post(api_account_webauthn_verify_handler),
        )
        .route(
            "/api/account/:account_id/webauthn/registration/options",
            axum::routing::post(api_account_webauthn_registration_options_handler),
        )
        .route(
            "/api/account/:account_id/devices/challenge",
            axum::routing::post(api_account_device_challenge_handler),
        )
        .route(
            "/api/account/:account_id/devices",
            axum::routing::post(api_account_device_enrollment_handler),
        )
        .route(
            "/api/account/:account_id/webauthn/registration/verify",
            axum::routing::post(api_account_webauthn_registration_verify_handler),
        )
        .route(
            "/api/account/totp/authentication/options",
            axum::routing::post(api_account_totp_options_handler),
        )
        .route(
            "/api/account/totp/authentication/verify",
            axum::routing::post(api_account_totp_verify_handler),
        )
        .route(
            "/api/account/:account_id/totp/enrollment",
            axum::routing::post(api_account_totp_enrollment_handler),
        )
        .route(
            "/api/account/:account_id/totp/enrollment/verify",
            axum::routing::post(api_account_totp_enrollment_verify_handler),
        )
        .route(
            "/api/account/:account_id/totp/revoke",
            axum::routing::post(api_account_totp_revoke_handler),
        )
        .route(
            "/api/session/revoke",
            axum::routing::post(api_private_session_revoke_handler),
        )
        .route("/api/vault", get(api_vault_handler))
        .route("/api/operators", get(api_operators_handler))
        .route("/api/approvals", get(api_approvals_handler))
        .route(
            "/api/snapshots",
            get(api_snapshots_handler).post(api_create_snapshot_handler),
        )
        .route(
            "/api/snapshots/:id/manifest",
            get(api_snapshot_manifest_handler),
        )
        .route("/api/activity", get(api_activity_handler))
        .route(
            "/api/anchors",
            get(api_anchors_handler).post(api_create_anchor_handler),
        )
        .route("/api/audit", axum::routing::post(api_audit_handler))
        .route("/api/guardians", get(api_guardians_handler))
        .route(
            "/api/relayer/checkpoints",
            get(api_relayer_checkpoints_handler),
        )
        .route(
            "/api/relayer/anchor",
            axum::routing::post(api_relayer_anchor_handler),
        )
        .route("/api/fleet", get(api_fleet_handler))
        .route(
            "/api/fleet/audit",
            axum::routing::post(api_fleet_audit_handler),
        )
        .route("/api/token", get(api_token_handler))
        .route("/api/stream", get(api_stream_handler))
        .route(
            "/api/fastcdc/inspect",
            axum::routing::post(api_fastcdc_inspect_handler),
        )
        .route(
            "/api/fastcdc/vault-files",
            get(api_fastcdc_vault_files_handler),
        )
        .route("/api/diff", get(api_diff_handler))
        .route(
            "/api/files/track",
            axum::routing::post(api_files_track_handler),
        )
        .route(
            "/api/files/untrack",
            axum::routing::post(api_files_untrack_handler),
        )
        .route(
            "/api/snapshots/restore",
            axum::routing::post(api_snapshots_restore_handler),
        )
        .route("/api/workspaces", get(api_workspaces_handler))
        .route(
            "/api/workspaces/switch",
            axum::routing::post(api_workspaces_switch_handler),
        )
        .route(
            "/api/workspaces/scan",
            axum::routing::post(api_workspaces_scan_handler),
        )
        .fallback(api_private_fallback_handler)
        .layer(axum::middleware::from_fn(private_ui_request_guard))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            UI_REQUEST_BODY_LIMIT_BYTES,
        ))
}

/// Hardening headers for every public response: MIME-sniffing off.
/// (Caching is per-endpoint: telemetry opts into `public, max-age=30`.)
async fn public_api_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}

/// Per-IP rate budgets for the public explorer, requests per minute.
/// Object lookups fan out to every operator, so they get the tight budget;
/// everything else shares the general budget (covers 30 s UI polling).
const EXPLORER_OBJECT_BUDGET_PER_MIN: u32 = 30;
const EXPLORER_GENERAL_BUDGET_PER_MIN: u32 = 600;
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Upper bound on tracked (client, budget) windows. Past this the limiter
/// prunes expired windows and fails open for new clients rather than
/// growing without bound under a distributed flood.
const RATE_LIMIT_MAX_TRACKED_CLIENTS: usize = 10_000;

#[derive(Clone)]
pub(crate) struct RateLimiter {
    object_budget: u32,
    general_budget: u32,
    window: std::time::Duration,
    trust_xff: bool,
    windows: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<(bool, std::net::IpAddr), RateWindow>>,
    >,
}

struct RateWindow {
    start: std::time::Instant,
    count: u32,
}

impl RateLimiter {
    fn production() -> Self {
        let trust_xff = std::env::var("CIPHERVAULT_TRUST_XFF")
            .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
        Self::new(
            EXPLORER_OBJECT_BUDGET_PER_MIN,
            EXPLORER_GENERAL_BUDGET_PER_MIN,
            std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS),
            trust_xff,
        )
    }

    fn new(
        object_budget: u32,
        general_budget: u32,
        window: std::time::Duration,
        trust_xff: bool,
    ) -> Self {
        Self {
            object_budget,
            general_budget,
            window,
            trust_xff,
            windows: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Records one request; `Err(retry_after_secs)` when the budget is spent.
    /// Fails open (allows) when the lock is poisoned or the tracker is full,
    /// so limiter trouble never becomes an outage.
    fn check(&self, ip: std::net::IpAddr, is_object_lookup: bool) -> Result<(), u64> {
        let budget = if is_object_lookup {
            self.object_budget
        } else {
            self.general_budget
        };
        let now = std::time::Instant::now();
        let mut windows = match self.windows.lock() {
            Ok(guard) => guard,
            Err(_) => return Ok(()),
        };
        if windows.len() >= RATE_LIMIT_MAX_TRACKED_CLIENTS {
            windows.retain(|_, window| now.duration_since(window.start) < self.window);
            if windows.len() >= RATE_LIMIT_MAX_TRACKED_CLIENTS {
                return Ok(());
            }
        }
        let window = windows.entry((is_object_lookup, ip)).or_insert(RateWindow {
            start: now,
            count: 0,
        });
        if now.duration_since(window.start) >= self.window {
            window.start = now;
            window.count = 0;
        }
        if window.count >= budget {
            let retry_after = self
                .window
                .saturating_sub(now.duration_since(window.start))
                .as_secs()
                .max(1);
            return Err(retry_after);
        }
        window.count += 1;
        Ok(())
    }
}

/// Best-effort client identity for rate limiting. Behind the cloud edge
/// (`CIPHERVAULT_TRUST_XFF=1`) the rightmost X-Forwarded-For entry is the
/// address our own proxy appended — entries left of it are
/// client-controlled. Direct `--serve` ignores XFF entirely (any client can
/// spoof it) and keys on the TCP peer. `None` (fail open) only when neither
/// source exists, which is just unit tests without connect info.
fn rate_limit_client_ip(
    request: &axum::extract::Request,
    trust_xff: bool,
) -> Option<std::net::IpAddr> {
    if trust_xff {
        if let Some(forwarded) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        {
            if let Some(ip) = forwarded
                .rsplit(',')
                .next()
                .and_then(|part| part.trim().parse::<std::net::IpAddr>().ok())
            {
                return Some(ip);
            }
        }
    }
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip())
}

async fn public_rate_limit(
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let is_object_lookup = request.uri().path().starts_with("/api/explorer/object/");
    let limited = rate_limit_client_ip(&request, limiter.trust_xff)
        .and_then(|ip| limiter.check(ip, is_object_lookup).err());
    if let Some(retry_after) = limited {
        let retry_after = axum::http::HeaderValue::from_str(&retry_after.to_string())
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("60"));
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry_after)],
            "rate limit exceeded for this client; retry later",
        )
            .into_response();
    }
    next.run(request).await
}

pub(crate) fn public_ui_router() -> axum::Router {
    public_ui_router_with_limiter(RateLimiter::production())
}

/// Test seam: identical public routes with an explicit limiter.
pub(crate) fn public_ui_router_with_limiter(limiter: RateLimiter) -> axum::Router {
    use axum::routing::get;

    ui_shell_router()
        .route("/api/context", get(api_public_context_handler))
        .route("/api/account/status", get(api_account_status_handler))
        .route(
            "/api/account/capabilities",
            get(api_account_capabilities_handler),
        )
        .route(
            "/api/account/register",
            axum::routing::post(api_account_register_handler),
        )
        .route("/api/account/session", get(api_account_session_handler))
        .route(
            "/api/account/sessions/challenge",
            axum::routing::post(api_account_session_challenge_handler),
        )
        .route(
            "/api/account/sessions/login",
            axum::routing::post(api_account_session_login_handler),
        )
        .route(
            "/api/account/sessions/handoff",
            axum::routing::post(api_account_session_handoff_handler),
        )
        .route(
            "/api/account/session/handoff",
            axum::routing::post(api_account_session_handoff_consume_handler),
        )
        .route(
            "/api/account/:account_id",
            get(api_account_resource_get_handler),
        )
        .route(
            "/api/account/:account_id/invitations",
            get(api_account_invitations_get_handler).post(api_account_invitations_post_handler),
        )
        .route(
            "/api/account/:account_id/vaults",
            axum::routing::post(api_account_vaults_post_handler),
        )
        .route(
            "/api/account/:account_id/memberships",
            get(api_account_memberships_get_handler),
        )
        .route(
            "/api/account/:account_id/memberships/:member_account_id/revoke",
            axum::routing::post(api_account_membership_revoke_handler),
        )
        .route(
            "/api/account/:account_id/recovery/codes",
            axum::routing::post(api_account_recovery_codes_handler),
        )
        .route(
            "/api/account/invitations/accept",
            axum::routing::post(api_account_invitation_accept_handler),
        )
        .route(
            "/api/account/logout",
            axum::routing::post(api_account_logout_handler),
        )
        .route(
            "/api/account/webauthn/authentication/options",
            axum::routing::post(api_account_webauthn_options_handler),
        )
        .route(
            "/api/account/webauthn/authentication/verify",
            axum::routing::post(api_account_webauthn_verify_handler),
        )
        .route(
            "/api/account/:account_id/webauthn/registration/options",
            axum::routing::post(api_account_webauthn_registration_options_handler),
        )
        .route(
            "/api/account/:account_id/devices/challenge",
            axum::routing::post(api_account_device_challenge_handler),
        )
        .route(
            "/api/account/:account_id/devices",
            axum::routing::post(api_account_device_enrollment_handler),
        )
        .route(
            "/api/account/:account_id/webauthn/registration/verify",
            axum::routing::post(api_account_webauthn_registration_verify_handler),
        )
        .route(
            "/api/account/totp/authentication/options",
            axum::routing::post(api_account_totp_options_handler),
        )
        .route(
            "/api/account/totp/authentication/verify",
            axum::routing::post(api_account_totp_verify_handler),
        )
        .route("/api/vault", get(api_public_vault_handler))
        .route("/api/operators", get(api_public_operators_handler))
        .route(
            "/api/operators/history",
            get(api_public_operators_history_handler),
        )
        .route(
            "/api/operators/jobs",
            get(api_public_operators_jobs_handler),
        )
        .route("/api/anchors", get(api_public_anchors_handler))
        .route(
            "/api/relayer/checkpoints",
            get(api_public_relayer_checkpoints_handler),
        )
        .route("/api/fleet", get(api_public_fleet_handler))
        .route("/api/stream", get(api_public_stream_handler))
        .route("/api/explorer/overview", get(api_explorer_overview_handler))
        .route(
            "/api/explorer/object/:cid",
            get(api_explorer_object_handler),
        )
        .fallback(api_public_fallback_handler)
        // Innermost so 429s still pass through the hardening headers below.
        .layer(axum::middleware::from_fn_with_state(
            limiter,
            public_rate_limit,
        ))
        .layer(axum::middleware::from_fn(public_api_headers))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            UI_REQUEST_BODY_LIMIT_BYTES,
        ))
}

pub(crate) fn ui_router(mode: UiServerMode) -> axum::Router {
    match mode {
        UiServerMode::LocalPrivate => private_ui_router(),
        UiServerMode::PublicExplorer => public_ui_router(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_ui_session_snapshot;
    use axum::http::StatusCode;

    /// Panic-safe `CIPHERVAULT_ACCOUNT_PATH` override. The private guard also
    /// validates the ambient hosted account session when a store exists, so
    /// guard tests must not inherit the developer's real account state.
    struct AccountPathGuard {
        prior: Option<std::ffi::OsString>,
    }

    impl AccountPathGuard {
        fn isolate() -> Self {
            let prior = std::env::var_os("CIPHERVAULT_ACCOUNT_PATH");
            std::env::set_var(
                "CIPHERVAULT_ACCOUNT_PATH",
                std::env::temp_dir().join(format!("cv-no-account-{}", std::process::id())),
            );
            Self { prior }
        }
    }

    impl Drop for AccountPathGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(value) => std::env::set_var("CIPHERVAULT_ACCOUNT_PATH", value),
                None => std::env::remove_var("CIPHERVAULT_ACCOUNT_PATH"),
            }
        }
    }

    async fn start_public_test_server() -> (tokio::task::JoinHandle<()>, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                public_ui_router().into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (server, format!("http://{}", address))
    }

    async fn start_public_test_server_with_limiter(
        limiter: RateLimiter,
    ) -> (tokio::task::JoinHandle<()>, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                public_ui_router_with_limiter(limiter)
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (server, format!("http://{}", address))
    }

    fn test_limiter(object_budget: u32, general_budget: u32, trust_xff: bool) -> RateLimiter {
        RateLimiter::new(
            object_budget,
            general_budget,
            std::time::Duration::from_secs(60),
            trust_xff,
        )
    }

    /// Serializes tests that share process-global dashboard state: the
    /// private UI session (`private_ui_session_snapshot` rotates it) and the
    /// `CIPHERVAULT_ACCOUNT_*` env the handlers and guards read per request.
    /// Any test that starts the private router or mutates that env must hold
    /// this guard for its whole body; pure-public tests need not bother. A
    /// tokio mutex (not std) so holding it across awaits is executor-safe.
    static ROUTER_TEST_SERIALIZER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn serialized_router_test() -> tokio::sync::MutexGuard<'static, ()> {
        ROUTER_TEST_SERIALIZER.lock().await
    }

    async fn start_private_test_server() -> (
        tokio::task::JoinHandle<()>,
        String,
        tokio::sync::MutexGuard<'static, ()>,
    ) {
        // Acquired first and returned so callers hold it for the whole test:
        // every private-router test is serialized, present and future.
        let guard = serialized_router_test().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, private_ui_router()).await.unwrap();
        });
        (server, format!("http://{}", address), guard)
    }

    #[tokio::test]
    async fn public_router_allows_only_explicit_public_api_routes() {
        let (server, base_url) = start_public_test_server().await;
        let client = reqwest::Client::new();

        let context = client
            .get(format!("{base_url}/api/context"))
            .send()
            .await
            .unwrap();
        assert_eq!(context.status(), StatusCode::OK);

        let context: serde_json::Value = context.json().await.unwrap();
        assert_eq!(context["mode"], "public_explorer");
        assert_eq!(context["access_mode"], "public");
        assert_eq!(context["build_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(context["capabilities"]["vault_workspace"], false);
        assert_eq!(context["capabilities"]["plaintext_inspection"], false);

        let public_vault: serde_json::Value = client
            .get(format!("{base_url}/api/vault"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(public_vault.get("vault_id_hex").is_none());
        assert_eq!(public_vault["private_vault_access"], false);

        let anchors: serde_json::Value = client
            .get(format!("{base_url}/api/anchors"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(anchors.as_array().is_some_and(Vec::is_empty));

        let checkpoints: serde_json::Value = client
            .get(format!("{base_url}/api/relayer/checkpoints"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            checkpoints["relayer_status"]["verification_status"],
            "unavailable"
        );
        assert!(checkpoints["message"]
            .as_str()
            .is_some_and(|message| message.contains("signed public checkpoint feed")));

        for uri in [
            "/api/guardians",
            "/api/fastcdc/vault-files",
            "/api/snapshots/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/manifest",
            "/api/workspaces",
        ] {
            let response = client
                .get(format!("{base_url}{uri}"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "public explorer unexpectedly exposed {uri}"
            );
        }

        let mutation = client
            .post(format!("{base_url}/api/snapshots"))
            .json(&serde_json::json!({ "message": "must not be accepted" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            mutation.status(),
            StatusCode::FORBIDDEN,
            "public explorer unexpectedly accepted a snapshot mutation"
        );

        for uri in [
            "/api/fastcdc/inspect",
            "/api/files/track",
            "/api/files/untrack",
            "/api/snapshots/restore",
        ] {
            let response = client
                .post(format!("{base_url}{uri}"))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "public explorer unexpectedly exposed private mutation {uri}"
            );
        }

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn explorer_object_rejects_malformed_cid_without_probing() {
        let (server, base_url) = start_public_test_server().await;
        let client = reqwest::Client::new();
        for bad in ["not-a-cid", "ab12", &"zz".repeat(32)] {
            let response = client
                .get(format!("{base_url}/api/explorer/object/{bad}"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "explorer accepted malformed CID {bad}"
            );
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["code"], "INVALID_CID");
        }
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn explorer_overview_reports_operator_and_anchor_shape() {
        let (server, base_url) = start_public_test_server().await;
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{base_url}/api/explorer/overview"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["observed_at_utc"].is_string());
        assert!(body["operators"]["total"].is_number());
        assert!(body["operators"]["reachable"].is_number());
        assert!(body["anchors"]["count"].is_number());
        server.abort();
        let _ = server.await;
    }

    /// Regression: the per-resource account handlers extract a single
    /// `:account_id` segment. A generic `Path<(String, String)>` handler on
    /// these single-param routes 500s instead of reaching the proxy.
    #[tokio::test]
    async fn account_resource_routes_reach_the_proxy_handler() {
        struct EndpointGuard {
            prior: Option<std::ffi::OsString>,
        }

        impl EndpointGuard {
            fn clear() -> Self {
                let prior = std::env::var_os("CIPHERVAULT_ACCOUNT_ENDPOINT");
                std::env::remove_var("CIPHERVAULT_ACCOUNT_ENDPOINT");
                Self { prior }
            }
        }

        impl Drop for EndpointGuard {
            fn drop(&mut self) {
                match self.prior.take() {
                    Some(value) => std::env::set_var("CIPHERVAULT_ACCOUNT_ENDPOINT", value),
                    None => std::env::remove_var("CIPHERVAULT_ACCOUNT_ENDPOINT"),
                }
            }
        }

        // Serialize before mutating shared env: the private guard and the
        // context handlers read this per request.
        let _serialized = serialized_router_test().await;
        let _no_endpoint = EndpointGuard::clear();
        let (server, base_url) = start_public_test_server().await;
        let client = reqwest::Client::new();
        // Valid-format ID so ID validation never masks an extraction failure.
        let account_id = format!("cvacct_{}", "ab".repeat(16));

        for uri in [
            format!("/api/account/{account_id}/invitations"),
            format!("/api/account/{account_id}/memberships"),
        ] {
            let response = client.get(format!("{base_url}{uri}")).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["code"], "ACCOUNT_SERVICE_NOT_CONFIGURED");
        }
        for uri in [
            format!("/api/account/{account_id}/invitations"),
            format!("/api/account/{account_id}/vaults"),
        ] {
            let response = client
                .post(format!("{base_url}{uri}"))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["code"], "ACCOUNT_SERVICE_NOT_CONFIGURED");
        }

        server.abort();
        let _ = server.await;
    }

    /// Malformed account IDs are rejected before any upstream URL is built,
    /// so a routed segment can never smuggle extra upstream path segments.
    /// Validation precedes proxying, hence no endpoint isolation is needed.
    #[tokio::test]
    async fn account_proxy_rejects_malformed_account_ids() {
        let (server, base_url) = start_public_test_server().await;
        let client = reqwest::Client::new();
        let valid = format!("cvacct_{}", "ab".repeat(16));

        for uri in [
            "/api/account/not-an-id/invitations".to_string(),
            "/api/account/ABC/memberships".to_string(),
            format!("/api/account/cvacct_{}/invitations", "ab".repeat(15)),
            format!("/api/account/{}/memberships", "zz".repeat(32)),
            "/api/account/abc%2Fdef/invitations".to_string(),
        ] {
            let response = client.get(format!("{base_url}{uri}")).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {uri}");
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["code"], "INVALID_ACCOUNT_ID");
        }

        // Both IDs on the membership-revoke route are validated.
        for uri in [
            format!("/api/account/bad-id/memberships/{valid}/revoke"),
            format!("/api/account/{valid}/memberships/bad-id/revoke"),
        ] {
            let response = client
                .post(format!("{base_url}{uri}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "for {uri}");
            let body: serde_json::Value = response.json().await.unwrap();
            assert_eq!(body["code"], "INVALID_ACCOUNT_ID");
        }

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn public_responses_carry_hardening_headers_and_shell_has_csp() {
        let (server, base_url) = start_public_test_server().await;
        let client = reqwest::Client::new();

        let shell = client.get(format!("{base_url}/")).send().await.unwrap();
        assert_eq!(shell.status(), StatusCode::OK);
        let csp = shell
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"),
            "unexpected shell CSP: {csp}"
        );
        assert_eq!(
            shell.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );

        for path in ["/api/operators", "/api/explorer/overview"] {
            let telemetry = client
                .get(format!("{base_url}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(telemetry.status(), StatusCode::OK);
            assert_eq!(
                telemetry.headers().get("x-content-type-options").unwrap(),
                "nosniff",
                "{path} must disable sniffing"
            );
            assert_eq!(
                telemetry.headers().get("cache-control").unwrap(),
                "public, max-age=30",
                "{path} must opt into shared caching"
            );
        }

        // Non-telemetry public endpoints: sniffing off, no shared caching.
        let fleet = client
            .get(format!("{base_url}/api/fleet"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            fleet.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert!(fleet.headers().get("cache-control").is_none());

        let missing = client
            .get(format!("{base_url}/api/nope"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            missing.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );

        server.abort();
    }

    #[tokio::test]
    async fn account_proxy_rejects_oversized_bodies_before_upstream() {
        struct EndpointGuard {
            prior: Option<std::ffi::OsString>,
        }

        impl EndpointGuard {
            fn point_at_closed_port() -> Self {
                let prior = std::env::var_os("CIPHERVAULT_ACCOUNT_ENDPOINT");
                std::env::set_var("CIPHERVAULT_ACCOUNT_ENDPOINT", "http://127.0.0.1:9");
                Self { prior }
            }
        }

        impl Drop for EndpointGuard {
            fn drop(&mut self) {
                match self.prior.take() {
                    Some(value) => std::env::set_var("CIPHERVAULT_ACCOUNT_ENDPOINT", value),
                    None => std::env::remove_var("CIPHERVAULT_ACCOUNT_ENDPOINT"),
                }
            }
        }

        let _serialized = serialized_router_test().await;
        let _endpoint = EndpointGuard::point_at_closed_port();
        let (server, base_url) = start_public_test_server().await;
        let client = reqwest::Client::new();

        // Small body reaches the (unreachable) upstream: 502 proves the
        // proxy path is exercised, so the 413 below is meaningful.
        let small = client
            .post(format!("{base_url}/api/account/register"))
            .json(&serde_json::json!({"public_key_hex": "ab"}))
            .send()
            .await
            .unwrap();
        assert_eq!(small.status(), StatusCode::BAD_GATEWAY);

        // 3 MiB exceeds the dashboard cap: rejected while buffering,
        // before any upstream contact. The server may answer 413 mid-upload
        // (client sees the status) or hang up first (client sees a send
        // error, with no response to assert on); both prove the limit
        // engaged. What must NOT happen is a 502, which would mean the body
        // reached the upstream — and the 502 control above proves the server
        // is alive and proxying, so a hangup here cannot mask a dead server.
        if let Ok(response) = client
            .post(format!("{base_url}/api/account/register"))
            .body(vec![b'x'; 3 * 1024 * 1024])
            .send()
            .await
        {
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        }

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn private_router_requires_loopback_origin_for_mutations() {
        // The serializer arrives with the server and is held for the whole
        // body; env isolation nests inside it (drops first, restores while
        // still serialized).
        let (server, base_url, _serialized) = start_private_test_server().await;
        let _account_isolation = AccountPathGuard::isolate();
        let client = reqwest::Client::new();

        let read = client
            .get(format!("{base_url}/api/context"))
            .send()
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        let set_cookie = read
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(set_cookie.starts_with("ciphervault_private_session="));
        assert!(set_cookie.contains("Max-Age=1800"));
        let private_context: serde_json::Value = read.json().await.unwrap();
        assert_eq!(private_context["mode"], "local_private");
        assert_eq!(private_context["build_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(private_context["session"]["scheme"], "http_only_cookie");
        assert_eq!(private_context["session"]["ttl_seconds"], 1800);
        assert_eq!(
            private_context["session"]["revocation_endpoint"],
            "/api/session/revoke"
        );

        let cross_origin_read = client
            .get(format!("{base_url}/api/context"))
            .header("Origin", "http://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(cross_origin_read.status(), StatusCode::FORBIDDEN);

        let missing_origin_mutation = client
            .post(format!("{base_url}/api/unknown"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing_origin_mutation.status(), StatusCode::FORBIDDEN);

        let missing_session = client
            .get(format!("{base_url}/api/unknown"))
            .header("Origin", &base_url)
            .send()
            .await
            .unwrap();
        assert_eq!(missing_session.status(), StatusCode::UNAUTHORIZED);

        let session_token = private_ui_session_snapshot().token;
        let same_origin_mutation = client
            .post(format!("{base_url}/api/unknown"))
            .header("Origin", &base_url)
            .header(
                "Cookie",
                format!("ciphervault_private_session={session_token}"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(same_origin_mutation.status(), StatusCode::NOT_FOUND);
        // Unknown private API paths keep the JSON error envelope.
        let fallback_body: serde_json::Value = same_origin_mutation.json().await.unwrap();
        assert_eq!(fallback_body["code"], "PRIVATE_API_NOT_FOUND");

        let revoke = client
            .post(format!("{base_url}/api/session/revoke"))
            .header("Origin", &base_url)
            .header(
                "Cookie",
                format!("ciphervault_private_session={session_token}"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);
        assert_eq!(
            revoke
                .headers()
                .get(axum::http::header::SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("ciphervault_private_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
        );

        let revoked_session = client
            .get(format!("{base_url}/api/unknown"))
            .header("Origin", &base_url)
            .header(
                "Cookie",
                format!("ciphervault_private_session={session_token}"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(revoked_session.status(), StatusCode::UNAUTHORIZED);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn public_rate_limit_trips_429_with_retry_after() {
        let (server, base_url) =
            start_public_test_server_with_limiter(test_limiter(1000, 2, true)).await;
        let client = reqwest::Client::new();
        for _ in 0..2 {
            let ok = client
                .get(format!("{base_url}/api/context"))
                .send()
                .await
                .unwrap();
            assert_eq!(ok.status(), StatusCode::OK);
        }
        let limited = client
            .get(format!("{base_url}/api/context"))
            .send()
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = limited
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let seconds: u64 = retry_after.parse().unwrap();
        assert!((1..=60).contains(&seconds));
        // The rejection still carries the public hardening headers.
        assert_eq!(
            limited
                .headers()
                .get(axum::http::header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|value| value.to_str().ok()),
            Some("nosniff"),
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn public_rate_limit_object_path_uses_object_budget() {
        // An invalid CID 400s without touching operators, so this proves
        // path classification with no fleet contact: object budget 1.
        let (server, base_url) =
            start_public_test_server_with_limiter(test_limiter(1, 1000, true)).await;
        let client = reqwest::Client::new();
        let first = client
            .get(format!("{base_url}/api/explorer/object/not-a-cid"))
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::BAD_REQUEST);
        let limited = client
            .get(format!("{base_url}/api/explorer/object/not-a-cid"))
            .send()
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        // The general budget is untouched: context still answers.
        let context = client
            .get(format!("{base_url}/api/context"))
            .send()
            .await
            .unwrap();
        assert_eq!(context.status(), StatusCode::OK);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn public_rate_limit_is_per_client() {
        let (server, base_url) =
            start_public_test_server_with_limiter(test_limiter(1000, 1, true)).await;
        let client = reqwest::Client::new();
        let first = client
            .get(format!("{base_url}/api/context"))
            .header("x-forwarded-for", "203.0.113.7")
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let tripped = client
            .get(format!("{base_url}/api/context"))
            .header("x-forwarded-for", "203.0.113.7")
            .send()
            .await
            .unwrap();
        assert_eq!(tripped.status(), StatusCode::TOO_MANY_REQUESTS);
        let other = client
            .get(format!("{base_url}/api/context"))
            .header("x-forwarded-for", "198.51.100.9")
            .send()
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn public_rate_limit_trusts_rightmost_xff_entry() {
        // Through the edge proxy Caddy appends the real peer rightmost, so
        // spoofed entries left of it must not dodge the budget.
        let (server, base_url) =
            start_public_test_server_with_limiter(test_limiter(1000, 1, true)).await;
        let client = reqwest::Client::new();
        let first = client
            .get(format!("{base_url}/api/context"))
            .header("x-forwarded-for", "203.0.113.7")
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let spoofed = client
            .get(format!("{base_url}/api/context"))
            .header("x-forwarded-for", "192.0.2.1, 203.0.113.7")
            .send()
            .await
            .unwrap();
        assert_eq!(spoofed.status(), StatusCode::TOO_MANY_REQUESTS);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn public_rate_limit_ignores_xff_when_direct() {
        // Direct `--serve` keys on the TCP peer: rotating XFF values from
        // the same peer share one bucket and still trip.
        let (server, base_url) =
            start_public_test_server_with_limiter(test_limiter(1000, 2, false)).await;
        let client = reqwest::Client::new();
        for (index, spoof) in ["10.1.0.1", "10.2.0.2", "10.3.0.3"].into_iter().enumerate() {
            let response = client
                .get(format!("{base_url}/api/context"))
                .header("x-forwarded-for", spoof)
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if index < 2 {
                    StatusCode::OK
                } else {
                    StatusCode::TOO_MANY_REQUESTS
                },
            );
        }

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn rate_limiter_window_resets() {
        let limiter = RateLimiter::new(1000, 1, std::time::Duration::from_millis(50), true);
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.check(ip, false).is_ok());
        assert!(limiter.check(ip, false).is_err());
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        assert!(limiter.check(ip, false).is_ok());
    }

    fn test_request(
        xff: Option<&str>,
        peer: Option<std::net::SocketAddr>,
    ) -> axum::extract::Request {
        let mut builder = axum::extract::Request::builder().uri("http://localhost/api/context");
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut request = builder.body(axum::body::Body::empty()).unwrap();
        if let Some(peer) = peer {
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
        }
        request
    }

    #[test]
    fn rate_limit_client_ip_selection() {
        let peer: std::net::SocketAddr = "192.0.2.44:1234".parse().unwrap();
        // Trusted proxy: rightmost entry wins, even with spoofed prefixes.
        let request = test_request(Some("203.0.113.7, 198.51.100.9"), Some(peer));
        assert_eq!(
            rate_limit_client_ip(&request, true),
            Some("198.51.100.9".parse().unwrap()),
        );
        // Trusted proxy with garbage XFF falls back to the peer.
        let request = test_request(Some("not-an-ip"), Some(peer));
        assert_eq!(
            rate_limit_client_ip(&request, true),
            Some("192.0.2.44".parse().unwrap()),
        );
        // Direct serve ignores XFF entirely.
        let request = test_request(Some("203.0.113.7"), Some(peer));
        assert_eq!(
            rate_limit_client_ip(&request, false),
            Some("192.0.2.44".parse().unwrap()),
        );
        // Nothing known: fail open.
        let request = test_request(None, None);
        assert_eq!(rate_limit_client_ip(&request, true), None);
    }
}
