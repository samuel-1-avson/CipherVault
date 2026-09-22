//! Operator wire transports (DON Phase 1).
//!
//! [`OperatorTransport`] abstracts the byte transport beneath [`OperatorClient`]
//! (see `client.rs`): HTTP today, libp2p streams tomorrow. The replication
//! pipeline in `pool.rs` is untouched — every quorum, lease, recovery-log, and
//! readback rule runs identically above any transport, and verification that
//! used to live beside the HTTP calls (identity signatures, object digests,
//! challenge signing) stays in the client so all transports inherit it.
//!
//! [`MemoryTransport`] is an in-memory operator for conformance tests: it speaks
//! the same request/response pairs with real cryptography (ed25519 receipts,
//! domain-separated PoS proofs) plus fault-injection hooks, so pool scenarios
//! run without sockets. Documented divergences from a real operator: recovery
//! records skip CBOR authorization (any bytes append), challenge nonces never
//! expire, and the approval queue is always empty.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use reqwest::{header, Client};

use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::compute_digest;

use crate::compute_pos_proof;
use crate::error::StorageError;
use crate::invites::{JoinInvite, JoinRefreshResponse, JoinRequest, JoinResponse};
use crate::types::{
    ApiErrorBody, AppendRecordResponse, ChallengeRequest, ChallengeResponse, LeaseListResponse,
    LeaseReceipt, LeaseRenewRequest, LeaseRequest, OperatorInfo, PeerDescriptor,
    PendingApprovalChallenge, PosChallengeRequest, ProofOfStorageReceipt, RecoveryRecordsResponse,
    SessionRequest, SessionResponse, VoucherIssueRequest,
};
use crate::vouchers::{VoucherLedger, WriteVoucher};

/// Boxed-future alias keeping the object-safe trait readable without new
/// dependencies (`Arc<dyn OperatorTransport>` shares clients across pool tasks).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Raw operator wire operations as transport-agnostic request/response pairs.
///
/// Every method moves bytes and maps transport failures to [`StorageError`];
/// cryptographic verification of responses (identity signatures, object
/// digests, receipt signatures) is the caller's job — [`OperatorClient`]
/// performs it identically for all transports.
pub trait OperatorTransport: Send + Sync {
    fn request_challenge<'a>(
        &'a self,
        req: ChallengeRequest,
    ) -> BoxFuture<'a, Result<ChallengeResponse, StorageError>>;
    fn redeem_session<'a>(
        &'a self,
        req: SessionRequest,
    ) -> BoxFuture<'a, Result<SessionResponse, StorageError>>;
    fn revoke_session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), StorageError>>;
    fn fetch_info<'a>(&'a self) -> BoxFuture<'a, Result<OperatorInfo, StorageError>>;
    fn put_object<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
        data: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), StorageError>>;
    fn fetch_object_bytes<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<Vec<u8>, StorageError>>;
    fn challenge_object_pos<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
        nonce: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<ProofOfStorageReceipt, StorageError>>;
    fn commit_lease<'a>(
        &'a self,
        token: &'a str,
        closure_digest: &'a [u8; 32],
        byte_count: u64,
        term_days: u32,
    ) -> BoxFuture<'a, Result<LeaseReceipt, StorageError>>;
    fn renew_lease<'a>(
        &'a self,
        token: &'a str,
        lease_id: &'a str,
        additional_days: u32,
        byte_count: u64,
    ) -> BoxFuture<'a, Result<LeaseReceipt, StorageError>>;
    fn list_leases<'a>(
        &'a self,
        token: &'a str,
        limit: u32,
    ) -> BoxFuture<'a, Result<LeaseListResponse, StorageError>>;
    fn append_recovery_record<'a>(
        &'a self,
        token: &'a str,
        locator: &'a [u8; 32],
        record_bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<u64, StorageError>>;
    fn get_recovery_records<'a>(
        &'a self,
        locator: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>, StorageError>>;
    fn announce_peer<'a>(
        &'a self,
        descriptor: &'a PeerDescriptor,
    ) -> BoxFuture<'a, Result<(), StorageError>>;
    fn get_peers<'a>(&'a self) -> BoxFuture<'a, Result<Vec<PeerDescriptor>, StorageError>>;
    /// Presents a verified-join ticket (fleet-signed invite + fresh
    /// self-signed descriptor) to a fleet node. Public route: the ticket
    /// is the authorization, so no service token is attached. HTTP only;
    /// non-HTTP transports report 501.
    fn join_with_invite<'a>(
        &'a self,
        descriptor: &'a PeerDescriptor,
        invite: &'a JoinInvite,
    ) -> BoxFuture<'a, Result<JoinResponse, StorageError>>;
    /// Re-presents a fresh self-signed descriptor to prove liveness of an
    /// already-joined node key. Public route, HTTP only like the join.
    /// Returns the joiner's standing (`"probation"` or `"full"`).
    fn refresh_join<'a>(
        &'a self,
        descriptor: &'a PeerDescriptor,
    ) -> BoxFuture<'a, Result<JoinRefreshResponse, StorageError>>;
    fn get_pending_approvals<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<PendingApprovalChallenge>, StorageError>>;
    /// Issues a self-signed write voucher (D4 barter model). Operator-local
    /// administration: service-token auth, HTTP only. Non-HTTP transports
    /// report 501.
    fn issue_voucher<'a>(
        &'a self,
        holder_pk_hex: &'a str,
        quota_bytes: u64,
        ttl_secs: u64,
    ) -> BoxFuture<'a, Result<WriteVoucher, StorageError>>;
    /// Stages the write voucher attached to subsequent requests (`None`
    /// clears it). Operators with voucher policy on reject writes without
    /// one; policy-off operators ignore it.
    fn set_write_voucher(&self, voucher: Option<WriteVoucher>);
}

/// Shared header state, cloned between a client and its HTTP transport so
/// identity/trace setters keep working after the port.
pub type SharedScope = Arc<Mutex<Option<String>>>;
/// Shared optional account/device identity binding.
pub type SharedIdentity = Arc<Mutex<Option<(String, String)>>>;

/// Shared staged write voucher (D4): attached as `X-CipherVault-Voucher`.
pub type SharedVoucher = Arc<Mutex<Option<WriteVoucher>>>;

/// HTTP operator transport: the original `OperatorClient` wire logic, moved
/// verbatim behind [`OperatorTransport`].
#[derive(Clone)]
pub struct HttpTransport {
    endpoint: String,
    http: Client,
    vault_scope: SharedScope,
    account_identity: SharedIdentity,
    trace_id: SharedScope,
    write_voucher: SharedVoucher,
}

impl HttpTransport {
    pub fn new(endpoint: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self::with_shared(
            endpoint,
            http,
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(None)),
        )
    }

    /// Builds a transport over a caller-owned HTTP pool with-supplied shared
    /// header state. Cloning `reqwest::Client` shares its connection pool.
    pub fn with_shared(
        endpoint: String,
        http: Client,
        vault_scope: SharedScope,
        account_identity: SharedIdentity,
        trace_id: SharedScope,
    ) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
            vault_scope,
            account_identity,
            trace_id,
            write_voucher: Arc::new(Mutex::new(None)),
        }
    }

    fn account_identity(&self) -> Option<(String, String)> {
        self.account_identity
            .lock()
            .ok()
            .and_then(|identity| identity.clone())
    }

    fn with_identity_binding(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.account_identity() {
            Some((account_id, device_id_hex)) => request
                .header("X-CipherVault-Account-Id", account_id)
                .header("X-CipherVault-Device-Id", device_id_hex),
            None => request,
        }
    }

    fn with_vault_scope(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let request = match self.vault_scope.lock().ok().and_then(|scope| scope.clone()) {
            Some(scope) => request.header("X-CipherVault-Id", scope),
            None => request,
        };
        let request = match self.trace_id.lock().ok().and_then(|id| id.clone()) {
            Some(trace_id) => request.header("X-CipherVault-Trace-Id", trace_id),
            None => request,
        };
        let request = match self
            .write_voucher
            .lock()
            .ok()
            .and_then(|voucher| voucher.clone())
            .and_then(|voucher| serde_json::to_string(&voucher).ok())
        {
            Some(encoded) => request.header("X-CipherVault-Voucher", encoded),
            None => request,
        };
        self.with_identity_binding(request)
    }

    fn with_service_token(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
            Ok(token) if !token.is_empty() => request.header("X-CipherVault-Service-Token", token),
            _ => request,
        }
    }

    fn server_error(status: u16, message: String) -> StorageError {
        StorageError::ServerError { status, message }
    }

    async fn check_ok(resp: reqwest::Response) -> Result<reqwest::Response, StorageError> {
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::server_error(status, Self::error_message(&body)));
        }
        Ok(resp)
    }

    /// Extracts the human message from an error body: prefers the JSON
    /// [`ApiErrorBody`] envelope, falls back to raw text for proxies and
    /// middleboxes that never heard of it.
    fn error_message(body: &str) -> String {
        if let Ok(envelope) = serde_json::from_str::<ApiErrorBody>(body) {
            return envelope.error;
        }
        body.to_string()
    }

    /// Sends one idempotent GET with bounded retry: transport failures and
    /// retryable statuses (408/429/502/503/504) retry up to three attempts
    /// with linear backoff. Writes are never retried here — POST/PUT rely
    /// on pool failover, since a replayed non-idempotent write could
    /// double-apply.
    async fn get_with_retry(
        &self,
        url: &str,
        auth: GetAuth<'_>,
    ) -> Result<reqwest::Response, StorageError> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let request = match auth {
                GetAuth::None => self.http.get(url),
                GetAuth::Bearer(token) => self
                    .with_vault_scope(self.http.get(url))
                    .header(header::AUTHORIZATION, format!("Bearer {token}")),
                GetAuth::ServiceToken => self.with_service_token(self.http.get(url)),
            };
            match request.send().await {
                Ok(resp)
                    if !is_retryable_status(resp.status()) || attempt >= GET_RETRY_ATTEMPTS =>
                {
                    return Ok(resp)
                }
                Ok(_) => {}
                Err(e) if attempt >= GET_RETRY_ATTEMPTS => return Err(StorageError::HttpError(e)),
                Err(_) => {}
            }
            tokio::time::sleep(Duration::from_millis(100 * u64::from(attempt))).await;
        }
    }
}

/// Auth flavor for a retried GET.
#[derive(Clone, Copy)]
enum GetAuth<'a> {
    /// Public route: no auth headers.
    None,
    /// Device session bearer + vault scope.
    Bearer(&'a str),
    /// Operator service token from the environment.
    ServiceToken,
}

/// Total attempts per idempotent read (1 initial + 2 retries).
const GET_RETRY_ATTEMPTS: u32 = 3;

fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
}

impl OperatorTransport for HttpTransport {
    fn request_challenge<'a>(
        &'a self,
        req: ChallengeRequest,
    ) -> BoxFuture<'a, Result<ChallengeResponse, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/challenges", self.endpoint);
            let resp = Self::check_ok(
                self.with_identity_binding(self.http.post(&url))
                    .json(&req)
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<ChallengeResponse>().await?)
        })
    }

    fn redeem_session<'a>(
        &'a self,
        req: SessionRequest,
    ) -> BoxFuture<'a, Result<SessionResponse, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/sessions", self.endpoint);
            let resp = Self::check_ok(
                self.with_identity_binding(self.http.post(&url))
                    .json(&req)
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<SessionResponse>().await?)
        })
    }

    fn revoke_session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/sessions/revoke", self.endpoint);
            Self::check_ok(
                self.with_vault_scope(self.http.post(&url))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .send()
                    .await?,
            )
            .await?;
            Ok(())
        })
    }

    fn fetch_info<'a>(&'a self) -> BoxFuture<'a, Result<OperatorInfo, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/info", self.endpoint);
            let resp = Self::check_ok(self.get_with_retry(&url, GetAuth::None).await?).await?;
            Ok(resp.json::<OperatorInfo>().await?)
        })
    }

    fn put_object<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
        data: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let cid_hex = hex::encode(cid);
            let url = format!("{}/v1/objects/{}", self.endpoint, cid_hex);
            Self::check_ok(
                self.with_vault_scope(self.http.put(&url))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(data)
                    .send()
                    .await?,
            )
            .await?;
            Ok(())
        })
    }

    fn fetch_object_bytes<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<Vec<u8>, StorageError>> {
        Box::pin(async move {
            let cid_hex = hex::encode(cid);
            let url = format!("{}/v1/objects/{}", self.endpoint, cid_hex);
            let resp =
                Self::check_ok(self.get_with_retry(&url, GetAuth::Bearer(token)).await?).await?;
            Ok(resp.bytes().await?.to_vec())
        })
    }

    fn challenge_object_pos<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
        nonce: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<ProofOfStorageReceipt, StorageError>> {
        Box::pin(async move {
            let cid_hex = hex::encode(cid);
            let url = format!("{}/v1/objects/{}/challenge", self.endpoint, cid_hex);
            let resp = Self::check_ok(
                self.with_vault_scope(self.http.post(&url))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .json(&PosChallengeRequest {
                        nonce_hex: hex::encode(nonce),
                    })
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<ProofOfStorageReceipt>().await?)
        })
    }

    fn commit_lease<'a>(
        &'a self,
        token: &'a str,
        closure_digest: &'a [u8; 32],
        byte_count: u64,
        term_days: u32,
    ) -> BoxFuture<'a, Result<LeaseReceipt, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/leases", self.endpoint);
            let resp = Self::check_ok(
                self.with_vault_scope(self.http.post(&url))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .json(&LeaseRequest {
                        closure_digest_hex: hex::encode(closure_digest),
                        byte_count,
                        term_days,
                    })
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<LeaseReceipt>().await?)
        })
    }

    fn renew_lease<'a>(
        &'a self,
        token: &'a str,
        lease_id: &'a str,
        additional_days: u32,
        byte_count: u64,
    ) -> BoxFuture<'a, Result<LeaseReceipt, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/leases/{}/renew", self.endpoint, lease_id);
            let resp = Self::check_ok(
                self.with_vault_scope(self.http.post(&url))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .json(&LeaseRenewRequest {
                        additional_days,
                        byte_count,
                    })
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<LeaseReceipt>().await?)
        })
    }

    fn list_leases<'a>(
        &'a self,
        token: &'a str,
        limit: u32,
    ) -> BoxFuture<'a, Result<LeaseListResponse, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/leases?limit={}", self.endpoint, limit);
            let resp = Self::check_ok(
                self.with_vault_scope(self.http.get(&url))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<LeaseListResponse>().await?)
        })
    }

    fn append_recovery_record<'a>(
        &'a self,
        token: &'a str,
        locator: &'a [u8; 32],
        record_bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<u64, StorageError>> {
        Box::pin(async move {
            let locator_hex = hex::encode(locator);
            let url = format!("{}/v1/recovery/{}/records", self.endpoint, locator_hex);
            let resp = Self::check_ok(
                self.with_vault_scope(self.http.post(&url))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(record_bytes)
                    .send()
                    .await?,
            )
            .await?;
            let result = resp.json::<AppendRecordResponse>().await?;
            Ok(result.sequence)
        })
    }

    fn get_recovery_records<'a>(
        &'a self,
        locator: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>, StorageError>> {
        Box::pin(async move {
            let locator_hex = hex::encode(locator);
            let url = format!("{}/v1/recovery/{}/records", self.endpoint, locator_hex);
            let resp = Self::check_ok(self.get_with_retry(&url, GetAuth::None).await?).await?;
            let body = resp.json::<RecoveryRecordsResponse>().await?;
            let mut out = Vec::new();
            for r_hex in body.records_hex {
                let b = hex::decode(r_hex).map_err(|e| StorageError::ServerError {
                    status: 500,
                    message: e.to_string(),
                })?;
                out.push(b);
            }
            Ok(out)
        })
    }

    fn announce_peer<'a>(
        &'a self,
        descriptor: &'a PeerDescriptor,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/peers/announce", self.endpoint);
            Self::check_ok(
                self.with_service_token(self.http.post(&url))
                    .json(descriptor)
                    .send()
                    .await?,
            )
            .await?;
            Ok(())
        })
    }

    fn get_peers<'a>(&'a self) -> BoxFuture<'a, Result<Vec<PeerDescriptor>, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/peers", self.endpoint);
            let resp =
                Self::check_ok(self.get_with_retry(&url, GetAuth::ServiceToken).await?).await?;
            Ok(resp.json::<Vec<PeerDescriptor>>().await?)
        })
    }

    fn join_with_invite<'a>(
        &'a self,
        descriptor: &'a PeerDescriptor,
        invite: &'a JoinInvite,
    ) -> BoxFuture<'a, Result<JoinResponse, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/peers/join", self.endpoint);
            let resp = Self::check_ok(
                self.http
                    .post(&url)
                    .json(&JoinRequest {
                        descriptor: descriptor.clone(),
                        invite: invite.clone(),
                    })
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<JoinResponse>().await?)
        })
    }

    fn refresh_join<'a>(
        &'a self,
        descriptor: &'a PeerDescriptor,
    ) -> BoxFuture<'a, Result<JoinRefreshResponse, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/peers/join/refresh", self.endpoint);
            let resp = Self::check_ok(
                self.http
                    .post(&url)
                    .json(&crate::invites::JoinRefreshRequest {
                        descriptor: descriptor.clone(),
                    })
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<JoinRefreshResponse>().await?)
        })
    }

    fn get_pending_approvals<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<PendingApprovalChallenge>, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/auth/challenges/pending", self.endpoint);
            let resp =
                Self::check_ok(self.get_with_retry(&url, GetAuth::ServiceToken).await?).await?;
            Ok(resp.json::<Vec<PendingApprovalChallenge>>().await?)
        })
    }

    fn issue_voucher<'a>(
        &'a self,
        holder_pk_hex: &'a str,
        quota_bytes: u64,
        ttl_secs: u64,
    ) -> BoxFuture<'a, Result<WriteVoucher, StorageError>> {
        Box::pin(async move {
            let url = format!("{}/v1/vouchers", self.endpoint);
            let resp = Self::check_ok(
                self.with_service_token(self.http.post(&url))
                    .json(&VoucherIssueRequest {
                        holder_pk_hex: holder_pk_hex.to_string(),
                        quota_bytes,
                        ttl_secs,
                    })
                    .send()
                    .await?,
            )
            .await?;
            Ok(resp.json::<WriteVoucher>().await?)
        })
    }

    fn set_write_voucher(&self, voucher: Option<WriteVoucher>) {
        if let Ok(mut staged) = self.write_voucher.lock() {
            *staged = voucher;
        }
    }
}

/// Size caps mirrored from the real operator (`MAX_OBJECT_SIZE`,
/// `MAX_RECOVERY_RECORD_SIZE` in `services/operator`).
const MEMORY_MAX_OBJECT_SIZE: usize = 4 * 1024 * 1024;
const MEMORY_MAX_RECOVERY_RECORD_SIZE: usize = 64 * 1024;

/// Counters for conformance assertions (e.g. proving PoS dedup skipped an
/// upload). Read via [`MemoryTransport::stats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryStats {
    pub puts: u64,
    pub challenges: u64,
}

struct PendingChallenge {
    nonce: [u8; 32],
    public_key_hex: String,
    used: bool,
}

#[derive(Default)]
struct MemoryFaults {
    offline: bool,
    fail_put: bool,
    fail_append: bool,
}

struct MemoryOperator {
    operator_id: String,
    signing_key: SigningKey,
    objects: HashMap<[u8; 32], Vec<u8>>,
    challenges: HashMap<String, PendingChallenge>,
    sessions: HashSet<String>,
    leases: HashMap<String, LeaseReceipt>,
    recovery: HashMap<[u8; 32], Vec<Vec<u8>>>,
    peers: Vec<PeerDescriptor>,
    next_id: u64,
    faults: MemoryFaults,
    stats: MemoryStats,
    /// Client side: voucher staged by `set_write_voucher`, mirroring the
    /// HTTP header / P2P envelope the real transports carry.
    presented_voucher: Option<WriteVoucher>,
    /// Server side: voucher policy + spend ledger, mirroring `OperatorState`.
    vouchers_required: bool,
    voucher_ledger: VoucherLedger,
}

/// In-memory operator speaking [`OperatorTransport`] with real cryptography:
/// ed25519-signed receipts, domain-separated PoS proofs, and verified
/// challenge signatures. Drives the dual-transport conformance suite without
/// sockets; fault flags simulate downed and flaky operators.
///
/// Documented divergences from a real operator: recovery records skip CBOR
/// authorization (any bytes append), challenge nonces and sessions never
/// expire, the approval queue is always empty, challenge input hex is not
/// validated, recovery append sequences are 0-based positions (the real
/// operator always returns `1`; the pool ignores the value), peer endpoint
/// schemes are not restricted to HTTP(S), and transport errors surface as
/// [`StorageError::ServerError`] (there is no TCP layer to fail). A lease
/// commit with `term_days == 0` is rejected with 400 here while the real
/// handler maps it to 500; both are errors.
#[derive(Clone)]
pub struct MemoryTransport {
    state: Arc<Mutex<MemoryOperator>>,
}

impl MemoryTransport {
    pub fn new(operator_id: impl Into<String>) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryOperator {
                operator_id: operator_id.into(),
                signing_key: ciphervault_crypto::generate_signing_key(),
                objects: HashMap::new(),
                challenges: HashMap::new(),
                sessions: HashSet::new(),
                leases: HashMap::new(),
                recovery: HashMap::new(),
                peers: Vec::new(),
                next_id: 1,
                faults: MemoryFaults::default(),
                stats: MemoryStats::default(),
                presented_voucher: None,
                vouchers_required: false,
                voucher_ledger: VoucherLedger::new(u64::MAX),
            })),
        }
    }

    pub fn operator_id(&self) -> String {
        self.lock().operator_id.clone()
    }

    pub fn stats(&self) -> MemoryStats {
        self.lock().stats
    }

    /// Simulates a downed operator: every operation fails until cleared.
    pub fn set_offline(&self, offline: bool) {
        self.lock().faults.offline = offline;
    }

    /// Simulates failing object writes (500) while everything else works.
    pub fn set_failing_put(&self, failing: bool) {
        self.lock().faults.fail_put = failing;
    }

    /// Simulates failing recovery appends (500) while everything else works.
    pub fn set_failing_append(&self, failing: bool) {
        self.lock().faults.fail_append = failing;
    }

    /// Mirrors the real operator's voucher policy switch.
    pub fn set_vouchers_required(&self, required: bool) {
        self.lock().vouchers_required = required;
    }

    /// Mirrors the real operator's per-grant maximum.
    pub fn set_voucher_max_quota(&self, max_quota_bytes: u64) {
        self.lock().voucher_ledger.set_max_quota(max_quota_bytes);
    }

    /// Issues a voucher against this operator's own key (test + drill use).
    pub fn issue_voucher(
        &self,
        holder_pk_hex: String,
        quota_bytes: u64,
        ttl_secs: u64,
    ) -> Result<WriteVoucher, StorageError> {
        let state = self.lock();
        WriteVoucher::issue(&state.signing_key, holder_pk_hex, quota_bytes, ttl_secs)
    }

    /// Server-side voucher gate, mirroring `OperatorState::authorize_write`:
    /// verifies the presented voucher and charges `bytes`, or rejects
    /// voucherless writes when policy requires vouchers. Returns the charge
    /// to release if persistence fails or stores no new bytes.
    fn check_voucher(
        state: &mut MemoryOperator,
        bytes: u64,
    ) -> Result<Option<(String, u64)>, StorageError> {
        match state.presented_voucher.clone() {
            Some(voucher) => {
                let issuer = hex::encode(state.signing_key.verifying_key().to_bytes());
                state
                    .voucher_ledger
                    .try_consume(&voucher, &issuer, now_utc_secs(), bytes)?;
                Ok(Some((voucher.nonce_hex.clone(), bytes)))
            }
            None if state.vouchers_required => Err(StorageError::ServerError {
                status: 403,
                message: "write voucher required".into(),
            }),
            None => Ok(None),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryOperator> {
        self.state.lock().expect("memory operator state lock")
    }

    fn check_online(state: &MemoryOperator) -> Result<(), StorageError> {
        if state.faults.offline {
            return Err(StorageError::ServerError {
                status: 503,
                message: "operator offline".into(),
            });
        }
        Ok(())
    }

    fn check_session(state: &MemoryOperator, token: &str) -> Result<(), StorageError> {
        Self::check_online(state)?;
        if !state.sessions.contains(token) {
            return Err(StorageError::ServerError {
                status: 401,
                message: "unknown or expired session".into(),
            });
        }
        Ok(())
    }

    /// Read-path sessions mirror the real operator: public recovery reads
    /// accept the anonymous token while writes always need a live session.
    fn check_session_read(state: &MemoryOperator, token: &str) -> Result<(), StorageError> {
        Self::check_online(state)?;
        if token != "recovery_anonymous" && !state.sessions.contains(token) {
            return Err(StorageError::ServerError {
                status: 401,
                message: "unknown or expired session".into(),
            });
        }
        Ok(())
    }

    fn mint_id(state: &mut MemoryOperator, prefix: &str) -> String {
        let id = format!("{prefix}-{}-{}", state.operator_id, state.next_id);
        state.next_id += 1;
        id
    }
}

fn now_utc_secs() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

impl OperatorTransport for MemoryTransport {
    fn request_challenge<'a>(
        &'a self,
        req: ChallengeRequest,
    ) -> BoxFuture<'a, Result<ChallengeResponse, StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            Self::check_online(&state)?;
            let nonce: [u8; 32] = rand::random();
            let challenge_id = Self::mint_id(&mut state, "mem-ch");
            state.challenges.insert(
                challenge_id.clone(),
                PendingChallenge {
                    nonce,
                    public_key_hex: req.public_key_hex,
                    used: false,
                },
            );
            Ok(ChallengeResponse {
                challenge_id,
                nonce_hex: hex::encode(nonce),
                expires_at_utc: now_utc_secs() + 600,
            })
        })
    }

    fn redeem_session<'a>(
        &'a self,
        req: SessionRequest,
    ) -> BoxFuture<'a, Result<SessionResponse, StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            Self::check_online(&state)?;
            let pending = state.challenges.get_mut(&req.challenge_id).ok_or_else(|| {
                StorageError::ServerError {
                    status: 404,
                    message: "unknown challenge".into(),
                }
            })?;
            if pending.used {
                return Err(StorageError::ServerError {
                    status: 400,
                    message: "challenge already redeemed".into(),
                });
            }
            if !pending
                .public_key_hex
                .eq_ignore_ascii_case(&req.public_key_hex)
            {
                return Err(StorageError::ServerError {
                    status: 401,
                    message: "challenge bound to a different key".into(),
                });
            }
            let pk = hex::decode(&req.public_key_hex).map_err(|e| StorageError::ServerError {
                status: 400,
                message: e.to_string(),
            });
            let sig = hex::decode(&req.signature_hex).map_err(|e| StorageError::ServerError {
                status: 400,
                message: e.to_string(),
            });
            let (pk, sig) = match (pk, sig) {
                (Ok(pk), Ok(sig)) if pk.len() == 32 && sig.len() == 64 => {
                    let mut pk_arr = [0u8; 32];
                    let mut sig_arr = [0u8; 64];
                    pk_arr.copy_from_slice(&pk);
                    sig_arr.copy_from_slice(&sig);
                    (pk_arr, sig_arr)
                }
                _ => {
                    return Err(StorageError::ServerError {
                        status: 401,
                        message: "malformed challenge credentials".into(),
                    })
                }
            };
            ciphervault_crypto::signatures::verify_with_domain(
                &pk,
                b"operator_challenge",
                &pending.nonce,
                &sig,
            )
            .map_err(|_| StorageError::ServerError {
                status: 401,
                message: "challenge signature invalid".into(),
            })?;
            pending.used = true;
            let token = Self::mint_id(&mut state, "mem-tok");
            state.sessions.insert(token.clone());
            Ok(SessionResponse {
                token,
                expires_at_utc: now_utc_secs() + 3600,
            })
        })
    }

    fn revoke_session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            // The real handler resolves the session before revoking, so an
            // unknown or already-revoked token fails 401 instead of Ok.
            Self::check_session(&state, token)?;
            state.sessions.remove(token);
            Ok(())
        })
    }

    fn fetch_info<'a>(&'a self) -> BoxFuture<'a, Result<OperatorInfo, StorageError>> {
        Box::pin(async move {
            let state = self.lock();
            Self::check_online(&state)?;
            let pk_hex = hex::encode(state.signing_key.verifying_key().as_bytes());
            let mut info = OperatorInfo {
                operator_id: state.operator_id.clone(),
                operator_signing_pk_hex: pk_hex,
                supported_version: 1,
                retention_terms: "memory".into(),
                identity_signature_hex: String::new(),
                // The real operator advertises a 24h identity descriptor.
                identity_expires_at_utc: now_utc_secs() + 86_400,
            };
            let sig = sign_with_domain(
                &state.signing_key,
                b"operator_identity",
                &info.identity_signing_bytes(),
            );
            info.identity_signature_hex = hex::encode(sig);
            Ok(info)
        })
    }

    fn put_object<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
        data: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            Self::check_session(&state, token)?;
            if state.faults.fail_put {
                return Err(StorageError::ServerError {
                    status: 500,
                    message: "injected put failure".into(),
                });
            }
            if data.len() > MEMORY_MAX_OBJECT_SIZE {
                return Err(StorageError::ServerError {
                    status: 400,
                    message: "object exceeds size limit".into(),
                });
            }
            if compute_digest(&data) != *cid {
                return Err(StorageError::ServerError {
                    status: 400,
                    message: "object digest does not match CID".into(),
                });
            }
            // Idempotent re-PUT of identical bytes stores nothing new, so it
            // is billed zero: retries stay free even with the quota fully
            // spent (mirrors the real operator's pre-check).
            let net_new = state.objects.get(cid) != Some(&data);
            let billable = if net_new { data.len() as u64 } else { 0 };
            Self::check_voucher(&mut state, billable)?;
            state.objects.insert(*cid, data);
            state.stats.puts += 1;
            Ok(())
        })
    }

    fn fetch_object_bytes<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<Vec<u8>, StorageError>> {
        Box::pin(async move {
            let state = self.lock();
            Self::check_session_read(&state, token)?;
            state
                .objects
                .get(cid)
                .cloned()
                .ok_or_else(|| StorageError::ServerError {
                    status: 404,
                    message: "object not found".into(),
                })
        })
    }

    fn challenge_object_pos<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
        nonce: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<ProofOfStorageReceipt, StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            Self::check_session_read(&state, token)?;
            let data =
                state
                    .objects
                    .get(cid)
                    .cloned()
                    .ok_or_else(|| StorageError::ServerError {
                        status: 404,
                        message: "object not found".into(),
                    })?;
            let proof = compute_pos_proof(cid, nonce, &data);
            let mut receipt = ProofOfStorageReceipt {
                operator_id: state.operator_id.clone(),
                cid_hex: hex::encode(cid),
                nonce_hex: hex::encode(nonce),
                proof_hex: hex::encode(proof),
                signature_hex: String::new(),
                size_bytes: data.len() as u64,
            };
            let sig = sign_with_domain(
                &state.signing_key,
                b"operator_pos",
                &receipt.signing_bytes(),
            );
            receipt.signature_hex = hex::encode(sig);
            state.stats.challenges += 1;
            Ok(receipt)
        })
    }

    fn commit_lease<'a>(
        &'a self,
        token: &'a str,
        closure_digest: &'a [u8; 32],
        byte_count: u64,
        term_days: u32,
    ) -> BoxFuture<'a, Result<LeaseReceipt, StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            Self::check_session(&state, token)?;
            if term_days == 0 {
                return Err(StorageError::ServerError {
                    status: 400,
                    message: "Invalid closure digest or retention term".into(),
                });
            }
            // Leases store no bytes: the voucher authorizes, nothing is charged.
            Self::check_voucher(&mut state, 0)?;
            let lease_id = Self::mint_id(&mut state, "mem-lease");
            let issued = now_utc_secs();
            let mut receipt = LeaseReceipt {
                lease_id: lease_id.clone(),
                operator_id: state.operator_id.clone(),
                closure_digest_hex: hex::encode(closure_digest),
                term_days,
                bytes: byte_count,
                issued_at_utc: issued,
                expires_at_utc: issued + u64::from(term_days) * 86400,
                signature_hex: String::new(),
            };
            let sig = sign_with_domain(
                &state.signing_key,
                b"operator_lease",
                &receipt.signing_bytes(),
            );
            receipt.signature_hex = hex::encode(sig);
            state.leases.insert(lease_id, receipt.clone());
            Ok(receipt)
        })
    }

    fn renew_lease<'a>(
        &'a self,
        token: &'a str,
        lease_id: &'a str,
        additional_days: u32,
        byte_count: u64,
    ) -> BoxFuture<'a, Result<LeaseReceipt, StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            Self::check_session(&state, token)?;
            if additional_days == 0 {
                return Err(StorageError::ServerError {
                    status: 400,
                    message: "Invalid lease ID or retention term".into(),
                });
            }
            // Renewals store no new bytes: authorize without charging.
            Self::check_voucher(&mut state, 0)?;
            let mut receipt =
                state
                    .leases
                    .get(lease_id)
                    .cloned()
                    .ok_or_else(|| StorageError::ServerError {
                        status: 404,
                        message: "lease not found".into(),
                    })?;
            if receipt.bytes != byte_count {
                return Err(StorageError::ServerError {
                    status: 400,
                    message: "Lease byte count mismatch".into(),
                });
            }
            receipt.term_days += additional_days;
            receipt.bytes = byte_count;
            receipt.expires_at_utc += u64::from(additional_days) * 86400;
            let sig = sign_with_domain(
                &state.signing_key,
                b"operator_lease",
                &receipt.signing_bytes(),
            );
            receipt.signature_hex = hex::encode(sig);
            state.leases.insert(lease_id.to_string(), receipt.clone());
            Ok(receipt)
        })
    }

    fn list_leases<'a>(
        &'a self,
        token: &'a str,
        limit: u32,
    ) -> BoxFuture<'a, Result<LeaseListResponse, StorageError>> {
        Box::pin(async move {
            let state = self.lock();
            Self::check_session(&state, token)?;
            let limit = usize::try_from(limit).unwrap_or(usize::MAX).max(1);
            let leases: Vec<LeaseReceipt> = state.leases.values().take(limit).cloned().collect();
            Ok(LeaseListResponse {
                total: state.leases.len(),
                leases,
            })
        })
    }

    fn append_recovery_record<'a>(
        &'a self,
        token: &'a str,
        locator: &'a [u8; 32],
        record_bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<u64, StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            Self::check_session(&state, token)?;
            if state.faults.fail_append {
                return Err(StorageError::ServerError {
                    status: 500,
                    message: "injected append failure".into(),
                });
            }
            if record_bytes.len() > MEMORY_MAX_RECOVERY_RECORD_SIZE {
                return Err(StorageError::ServerError {
                    status: 400,
                    message: "record exceeds size limit".into(),
                });
            }
            Self::check_voucher(&mut state, record_bytes.len() as u64)?;
            let log = state.recovery.entry(*locator).or_default();
            let sequence = log.len() as u64;
            log.push(record_bytes);
            Ok(sequence)
        })
    }

    fn get_recovery_records<'a>(
        &'a self,
        locator: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>, StorageError>> {
        Box::pin(async move {
            let state = self.lock();
            Self::check_online(&state)?;
            Ok(state.recovery.get(locator).cloned().unwrap_or_default())
        })
    }

    fn announce_peer<'a>(
        &'a self,
        descriptor: &'a PeerDescriptor,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let mut state = self.lock();
            Self::check_online(&state)?;
            descriptor.verify()?;
            state
                .peers
                .retain(|p| p.operator_id != descriptor.operator_id);
            state.peers.push(descriptor.clone());
            Ok(())
        })
    }

    fn get_peers<'a>(&'a self) -> BoxFuture<'a, Result<Vec<PeerDescriptor>, StorageError>> {
        Box::pin(async move {
            let state = self.lock();
            Self::check_online(&state)?;
            Ok(state.peers.clone())
        })
    }

    fn join_with_invite<'a>(
        &'a self,
        _descriptor: &'a PeerDescriptor,
        _invite: &'a JoinInvite,
    ) -> BoxFuture<'a, Result<JoinResponse, StorageError>> {
        Box::pin(async move {
            Err(StorageError::ServerError {
                status: 501,
                message: "verified join is fleet administration (HTTP only)".into(),
            })
        })
    }

    fn refresh_join<'a>(
        &'a self,
        _descriptor: &'a PeerDescriptor,
    ) -> BoxFuture<'a, Result<JoinRefreshResponse, StorageError>> {
        Box::pin(async move {
            Err(StorageError::ServerError {
                status: 501,
                message: "verified join is fleet administration (HTTP only)".into(),
            })
        })
    }

    fn get_pending_approvals<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<PendingApprovalChallenge>, StorageError>> {
        Box::pin(async move {
            let state = self.lock();
            Self::check_online(&state)?;
            Ok(Vec::new())
        })
    }

    fn issue_voucher<'a>(
        &'a self,
        _holder_pk_hex: &'a str,
        _quota_bytes: u64,
        _ttl_secs: u64,
    ) -> BoxFuture<'a, Result<WriteVoucher, StorageError>> {
        Box::pin(async move {
            Err(StorageError::ServerError {
                status: 501,
                message: "voucher issuance is operator-local administration (HTTP only)".into(),
            })
        })
    }

    fn set_write_voucher(&self, voucher: Option<WriteVoucher>) {
        self.lock().presented_voucher = voucher;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::OperatorClient;

    fn memory_client(operator_id: &str) -> (OperatorClient, MemoryTransport) {
        let transport = MemoryTransport::new(operator_id);
        let client = OperatorClient::with_transport(
            format!("memory://{operator_id}"),
            Arc::new(transport.clone()),
        );
        (client, transport)
    }

    fn operator_pk(info: &OperatorInfo) -> [u8; 32] {
        let bytes = hex::decode(&info.operator_signing_pk_hex).unwrap();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        pk
    }

    #[tokio::test]
    async fn memory_auth_roundtrip_with_real_signature() {
        let (client, _) = memory_client("mem-op-1");
        let vault_id = [7u8; 32];
        let key = ciphervault_crypto::generate_signing_key();
        let token = client.authenticate(&vault_id, &key).await.unwrap();
        assert!(!token.is_empty());
        // Unknown sessions are rejected.
        let data = b"hello-memory".to_vec();
        let cid = compute_digest(&data);
        let err = client
            .put_object("bogus-token", &cid, data)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::ServerError { status: 401, .. }));
    }

    #[tokio::test]
    async fn memory_object_roundtrip_with_pos_and_revoke() {
        let (client, transport) = memory_client("mem-op-1");
        let vault_id = [7u8; 32];
        let key = ciphervault_crypto::generate_signing_key();
        let token = client.authenticate(&vault_id, &key).await.unwrap();

        let data = b"roundtrip-bytes".to_vec();
        let cid = compute_digest(&data);
        client.put_object(&token, &cid, data.clone()).await.unwrap();

        let nonce = [9u8; 32];
        let receipt = client
            .challenge_object_pos(&token, &cid, &nonce)
            .await
            .unwrap();
        let info = client.get_info().await.unwrap();
        let expected = compute_pos_proof(&cid, &nonce, &data);
        receipt.verify(&operator_pk(&info), &expected).unwrap();

        assert_eq!(client.get_object(&token, &cid).await.unwrap(), data);
        assert_eq!(transport.stats().puts, 1);
        assert_eq!(transport.stats().challenges, 1);

        client.revoke_session(&token).await.unwrap();
        assert!(client.get_object(&token, &cid).await.is_err());
    }

    #[tokio::test]
    async fn memory_public_recovery_reads_accept_anonymous_token() {
        let (client, _) = memory_client("mem-op-1");
        let vault_id = [7u8; 32];
        let key = ciphervault_crypto::generate_signing_key();
        let token = client.authenticate(&vault_id, &key).await.unwrap();

        let data = b"public-bytes".to_vec();
        let cid = compute_digest(&data);
        client.put_object(&token, &cid, data.clone()).await.unwrap();

        // Reads accept the anonymous recovery token; writes do not.
        assert_eq!(
            client.get_object("recovery_anonymous", &cid).await.unwrap(),
            data
        );
        client
            .challenge_object_pos("recovery_anonymous", &cid, &[1u8; 32])
            .await
            .unwrap();
        let other = b"nope".to_vec();
        let other_cid = compute_digest(&other);
        assert!(client
            .put_object("recovery_anonymous", &other_cid, other)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn memory_rejects_bad_puts() {
        let (client, _) = memory_client("mem-op-1");
        let vault_id = [7u8; 32];
        let key = ciphervault_crypto::generate_signing_key();
        let token = client.authenticate(&vault_id, &key).await.unwrap();

        // Digest mismatch.
        let err = client
            .put_object(&token, &[1u8; 32], b"not-matching".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::ServerError { status: 400, .. }));
        // Oversize.
        let big = vec![0u8; MEMORY_MAX_OBJECT_SIZE + 1];
        let big_cid = compute_digest(&big);
        let err = client.put_object(&token, &big_cid, big).await.unwrap_err();
        assert!(matches!(err, StorageError::ServerError { status: 400, .. }));
        // Unknown object reads and challenges.
        assert!(client.get_object(&token, &[2u8; 32]).await.is_err());
        assert!(client
            .challenge_object_pos(&token, &[2u8; 32], &[3u8; 32])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn memory_lease_receipt_verifies_and_renews() {
        let (client, _) = memory_client("mem-op-1");
        let vault_id = [7u8; 32];
        let key = ciphervault_crypto::generate_signing_key();
        let token = client.authenticate(&vault_id, &key).await.unwrap();

        let closure = [11u8; 32];
        let receipt = client
            .commit_lease(&token, &closure, 1024, 90)
            .await
            .unwrap();
        let info = client.get_info().await.unwrap();
        receipt.verify(&operator_pk(&info)).unwrap();
        assert_eq!(receipt.closure_digest_hex, hex::encode(closure));

        // The real operator requires the byte count to match the commit.
        assert!(client
            .renew_lease(&token, &receipt.lease_id, 30, 2048)
            .await
            .is_err());
        assert!(client
            .renew_lease(&token, &receipt.lease_id, 0, 1024)
            .await
            .is_err());
        let renewed = client
            .renew_lease(&token, &receipt.lease_id, 30, 1024)
            .await
            .unwrap();
        assert_eq!(renewed.lease_id, receipt.lease_id);
        assert_eq!(renewed.term_days, 120);
        renewed.verify(&operator_pk(&info)).unwrap();
    }

    #[tokio::test]
    async fn memory_list_leases_reports_total_and_truncates() {
        let (client, _) = memory_client("mem-op-1");
        let vault_id = [7u8; 32];
        let key = ciphervault_crypto::generate_signing_key();
        let token = client.authenticate(&vault_id, &key).await.unwrap();

        let first = client
            .commit_lease(&token, &[11u8; 32], 1024, 90)
            .await
            .unwrap();
        let second = client
            .commit_lease(&token, &[12u8; 32], 2048, 30)
            .await
            .unwrap();

        let listing = client.list_leases(&token, 100).await.unwrap();
        assert_eq!(listing.total, 2);
        let ids: Vec<&str> = listing
            .leases
            .iter()
            .map(|receipt| receipt.lease_id.as_str())
            .collect();
        assert!(ids.contains(&first.lease_id.as_str()));
        assert!(ids.contains(&second.lease_id.as_str()));

        let page = client.list_leases(&token, 1).await.unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.leases.len(), 1);

        assert!(client.list_leases("bogus-token", 100).await.is_err());
    }

    #[tokio::test]
    async fn memory_recovery_log_roundtrip_is_monotonic() {
        let (client, _) = memory_client("mem-op-1");
        let vault_id = [7u8; 32];
        let key = ciphervault_crypto::generate_signing_key();
        let token = client.authenticate(&vault_id, &key).await.unwrap();

        let locator = [13u8; 32];
        assert!(client
            .get_recovery_records(&locator)
            .await
            .unwrap()
            .is_empty());
        let s0 = client
            .append_recovery_record(&token, &locator, b"r0".to_vec())
            .await
            .unwrap();
        let s1 = client
            .append_recovery_record(&token, &locator, b"r1".to_vec())
            .await
            .unwrap();
        assert!(s1 > s0);
        assert_eq!(
            client.get_recovery_records(&locator).await.unwrap(),
            vec![b"r0".to_vec(), b"r1".to_vec()]
        );
    }

    #[tokio::test]
    async fn memory_peer_gossip_verifies_and_roundtrips() {
        let (client, _) = memory_client("mem-op-1");
        assert!(client.get_peers().await.unwrap().is_empty());

        let key = ciphervault_crypto::generate_signing_key();
        let descriptor = PeerDescriptor::new("mem-op-9".into(), "memory://mem-op-9".into(), &key);
        client.announce_peer(&descriptor).await.unwrap();
        assert_eq!(client.get_peers().await.unwrap(), vec![descriptor]);

        // Tampered announcements are rejected.
        let mut bad = PeerDescriptor::new("mem-op-evil".into(), "memory://evil".into(), &key);
        bad.endpoint = "memory://tampered".into();
        assert!(client.announce_peer(&bad).await.is_err());
    }

    #[tokio::test]
    async fn memory_fault_flags_fail_and_recover() {
        let (client, transport) = memory_client("mem-op-1");
        let vault_id = [7u8; 32];
        let key = ciphervault_crypto::generate_signing_key();
        let token = client.authenticate(&vault_id, &key).await.unwrap();

        transport.set_offline(true);
        assert!(client.get_info().await.is_err());
        transport.set_offline(false);
        client.get_info().await.unwrap();

        transport.set_failing_put(true);
        let data = b"x".to_vec();
        let cid = compute_digest(&data);
        assert!(client.put_object(&token, &cid, data.clone()).await.is_err());
        transport.set_failing_put(false);
        client.put_object(&token, &cid, data).await.unwrap();

        transport.set_failing_append(true);
        assert!(client
            .append_recovery_record(&token, &[1u8; 32], b"r".to_vec())
            .await
            .is_err());
        transport.set_failing_append(false);
        client
            .append_recovery_record(&token, &[1u8; 32], b"r".to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn memory_challenge_is_bound_single_use_and_verified() {
        let transport = MemoryTransport::new("mem-op-1");
        let key = ciphervault_crypto::generate_signing_key();
        let pk_hex = hex::encode(key.verifying_key().as_bytes());
        let challenge = transport
            .request_challenge(ChallengeRequest {
                vault_id_hex: "ab".into(),
                public_key_hex: pk_hex.clone(),
                account_id: None,
                device_id_hex: None,
            })
            .await
            .unwrap();
        let nonce_bytes = hex::decode(&challenge.nonce_hex).unwrap();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);
        let sig = sign_with_domain(&key, b"operator_challenge", &nonce);
        let req = SessionRequest {
            challenge_id: challenge.challenge_id.clone(),
            public_key_hex: pk_hex,
            signature_hex: hex::encode(sig),
        };
        transport.redeem_session(req.clone()).await.unwrap();
        // Second redemption of the same challenge is rejected.
        let err = transport.redeem_session(req).await.unwrap_err();
        assert!(matches!(err, StorageError::ServerError { status: 400, .. }));
        // Unknown challenge ids fail closed.
        let other_key = ciphervault_crypto::generate_signing_key();
        let other_pk = hex::encode(other_key.verifying_key().as_bytes());
        let err = transport
            .redeem_session(SessionRequest {
                challenge_id: "mem-ch-mem-op-1-9999".into(),
                public_key_hex: other_pk,
                signature_hex: "00".repeat(64),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::ServerError { status: 404, .. }));
    }
}
