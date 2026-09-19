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
    api_private_context_handler, api_private_session_revoke_handler, api_public_anchors_handler,
    api_public_context_handler, api_public_fallback_handler, api_public_fleet_handler,
    api_public_operators_handler, api_public_operators_history_handler,
    api_public_operators_jobs_handler, api_public_relayer_checkpoints_handler,
    api_public_stream_handler, api_public_vault_handler, api_relayer_anchor_handler,
    api_relayer_checkpoints_handler, api_snapshot_manifest_handler, api_snapshots_handler,
    api_snapshots_restore_handler, api_stream_handler, api_token_handler, api_vault_handler,
    api_workspaces_handler, api_workspaces_scan_handler, api_workspaces_switch_handler,
    private_ui_request_guard, UI_APP_JS, UI_INDEX_HTML, UI_STYLES_CSS,
};

pub(crate) fn ui_shell_router() -> axum::Router {
    use axum::{http::header, response::Html, routing::get, Router};

    Router::new()
        .route("/", get(|| async { Html(UI_INDEX_HTML) }))
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
        .layer(axum::middleware::from_fn(private_ui_request_guard))
}

pub(crate) fn public_ui_router() -> axum::Router {
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
            axum::serve(listener, public_ui_router()).await.unwrap();
        });
        (server, format!("http://{}", address))
    }

    async fn start_private_test_server() -> (tokio::task::JoinHandle<()>, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, private_ui_router()).await.unwrap();
        });
        (server, format!("http://{}", address))
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
            "/api/secrets/inspect",
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
            "/api/guardians/split",
            "/api/guardians/reconstruct",
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

    #[tokio::test]
    async fn private_router_requires_loopback_origin_for_mutations() {
        let _account_isolation = AccountPathGuard::isolate();
        let (server, base_url) = start_private_test_server().await;
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
}
