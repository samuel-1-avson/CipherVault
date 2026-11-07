use axum::{
    http::{HeaderMap, StatusCode},
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use ciphervault_storage::OperatorClient;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (endpoint, task)
}

/// Minimal no-redirect checkpoint fetch mirroring the removed EVM
/// `AnchorRelayerClient`: attaches the service token only for independently
/// allowlisted endpoints and never follows redirects.
async fn fetch_checkpoint_no_redirect(base: &str, commitment: &[u8; 32]) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = client.get(format!("{base}/v1/checkpoints/{}", hex::encode(commitment)));
    let allowlisted = std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN_ENDPOINTS")
        .unwrap_or_default()
        .split(',')
        .any(|endpoint| endpoint.trim().trim_end_matches('/') == base);
    if allowlisted {
        if let Ok(token) = std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
            if !token.is_empty() {
                request = request.header("x-ciphervault-service-token", token);
            }
        }
    }
    let response = request.send().await.map_err(|e| e.to_string())?;
    if !response.status().is_success() {
        return Err(format!("unexpected status {}", response.status()));
    }
    response.text().await.map_err(|e| e.to_string())
}

/// One test owns these process-wide environment settings. Every endpoint and
/// token is synthetic; no configured or production operator is contacted.
#[tokio::test]
async fn operator_tokens_require_allowlists_and_never_follow_redirects() {
    let redirected_hits = Arc::new(AtomicUsize::new(0));
    let (target, target_task) = serve(Router::new().fallback({
        let hits = redirected_hits.clone();
        move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }
    }))
    .await;
    let observed_token = Arc::new(AtomicBool::new(false));
    let redirect = {
        let target = target.clone();
        let observed = observed_token.clone();
        move |headers: HeaderMap| {
            let target = target.clone();
            let observed = observed.clone();
            async move {
                observed.store(
                    headers.get("x-ciphervault-service-token").is_some(),
                    Ordering::SeqCst,
                );
                Redirect::temporary(&target)
            }
        }
    };
    let (trusted, trusted_task) = serve(
        Router::new()
            .route("/v1/peers", get(redirect.clone()))
            .route("/v1/vouchers", post(redirect.clone()))
            .route("/v1/checkpoints/:commitment", get(redirect)),
    )
    .await;
    std::env::set_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", "synthetic-token");
    std::env::set_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN_ENDPOINTS", &trusted);

    // Even a caller-owned client that follows redirects cannot make control
    // operations forward the token beyond the independently authorized URL.
    let client = OperatorClient::with_http_client(trusted.clone(), reqwest::Client::new());
    assert!(client.get_peers().await.is_err());
    assert!(observed_token.load(Ordering::SeqCst));
    assert_eq!(redirected_hits.load(Ordering::SeqCst), 0);
    assert!(client
        .issue_voucher(&hex::encode([1; 32]), 1, 60)
        .await
        .is_err());
    assert_eq!(redirected_hits.load(Ordering::SeqCst), 0);
    assert!(fetch_checkpoint_no_redirect(&trusted, &[1; 32])
        .await
        .is_err());
    assert_eq!(redirected_hits.load(Ordering::SeqCst), 0);

    let untrusted_received_token = Arc::new(AtomicBool::new(false));
    let capture = {
        let observed = untrusted_received_token.clone();
        move |headers: HeaderMap| {
            let observed = observed.clone();
            async move {
                observed.store(
                    headers.get("x-ciphervault-service-token").is_some(),
                    Ordering::SeqCst,
                );
                Json(Vec::<ciphervault_storage::PeerDescriptor>::new())
            }
        }
    };
    let (untrusted, untrusted_task) = serve(
        Router::new()
            .route("/v1/peers", get(capture.clone()))
            .route("/v1/checkpoints/:commitment", get(capture)),
    )
    .await;
    OperatorClient::new(untrusted.clone())
        .get_peers()
        .await
        .unwrap();
    assert!(!untrusted_received_token.load(Ordering::SeqCst));
    // The mock returns a deliberately invalid receipt, but records headers.
    let body = fetch_checkpoint_no_redirect(&untrusted, &[1; 32])
        .await
        .unwrap();
    assert!(!body.contains("commitment_hex"));
    assert!(!untrusted_received_token.load(Ordering::SeqCst));

    std::env::remove_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN");
    std::env::remove_var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN_ENDPOINTS");
    target_task.abort();
    trusted_task.abort();
    untrusted_task.abort();
    let _ = tokio::join!(target_task, trusted_task, untrusted_task);
}
