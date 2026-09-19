//! [`OperatorTransport`] over libp2p request-response (DON Phase 2).
//!
//! [`Libp2pTransport`] drives the operator RPC protocol through a client
//! [`SwarmHandle`] pointed at one operator [`PeerId`]. Auth envelopes mirror
//! the HTTP headers exactly (bearer + vault scope on data routes, service
//! token from the same env var on control routes), and server `Err` payloads
//! map 1:1 onto HTTP `StorageError::ServerError { status, message }` — the
//! three-leg conformance suite proves all three transports agree.
//!
//! [`OperatorTransport`]: ciphervault_storage::OperatorTransport

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciphervault_storage::transport::BoxFuture;
use ciphervault_storage::types::{
    ChallengeRequest, ChallengeResponse, LeaseReceipt, OperatorInfo, PeerDescriptor,
    PendingApprovalChallenge, ProofOfStorageReceipt, SessionRequest, SessionResponse,
};
use ciphervault_storage::{OperatorTransport, StorageError};
use libp2p::{Multiaddr, PeerId};

use super::behaviour::{OperatorRpcBody, OperatorRpcRequest, OperatorRpcResponse, P2pAuth};
use super::{SwarmError, SwarmHandle};

/// How long a transport waits for a (re)dial before reporting the operator
/// unreachable.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct Libp2pTransport {
    handle: SwarmHandle,
    peer: PeerId,
    addrs: Vec<Multiaddr>,
    vault_scope: Arc<Mutex<Option<String>>>,
    write_voucher: Arc<Mutex<Option<ciphervault_storage::vouchers::WriteVoucher>>>,
}

impl Libp2pTransport {
    /// Binds a client swarm handle to one operator peer. `addrs` are dial
    /// candidates used to (re)establish the connection on demand.
    pub fn new(handle: SwarmHandle, peer: PeerId, addrs: Vec<Multiaddr>) -> Self {
        Self {
            handle,
            peer,
            addrs,
            vault_scope: Arc::new(Mutex::new(None)),
            write_voucher: Arc::new(Mutex::new(None)),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer
    }

    fn endpoint_label(&self) -> String {
        format!("p2p://{}", self.peer)
    }

    fn unreachable(&self, details: impl Into<String>) -> StorageError {
        StorageError::OperatorUnreachable {
            endpoint: self.endpoint_label(),
            details: details.into(),
        }
    }

    fn vault_scope(&self) -> Option<String> {
        self.vault_scope.lock().ok().and_then(|scope| scope.clone())
    }

    fn set_vault_scope(&self, vault_id_hex: &str) {
        if let Ok(mut scope) = self.vault_scope.lock() {
            *scope = Some(vault_id_hex.trim().to_ascii_lowercase());
        }
    }

    fn write_voucher(&self) -> Option<ciphervault_storage::vouchers::WriteVoucher> {
        self.write_voucher.lock().ok().and_then(|v| v.clone())
    }

    fn service_token() -> Option<String> {
        match std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
            Ok(token) if !token.trim().is_empty() => Some(token),
            _ => None,
        }
    }

    fn scoped_auth(&self, token: &str) -> P2pAuth {
        P2pAuth {
            bearer_token: Some(token.to_string()),
            vault_id_hex: self.vault_scope(),
            service_token: None,
            voucher: self.write_voucher(),
        }
    }

    fn control_auth() -> P2pAuth {
        P2pAuth {
            bearer_token: None,
            vault_id_hex: None,
            service_token: Self::service_token(),
            voucher: None,
        }
    }

    async fn ensure_connected(&self) -> Result<(), StorageError> {
        if self
            .handle
            .is_connected(self.peer)
            .await
            .map_err(|e| self.unreachable(e.to_string()))?
        {
            return Ok(());
        }
        for addr in &self.addrs {
            let mut qualified = addr.clone();
            let has_peer = addr
                .iter()
                .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)));
            if !has_peer {
                qualified.push(libp2p::multiaddr::Protocol::P2p(self.peer));
            }
            let _ = self.handle.dial(qualified).await;
        }
        let deadline = tokio::time::Instant::now() + DIAL_TIMEOUT;
        loop {
            if self
                .handle
                .is_connected(self.peer)
                .await
                .map_err(|e| self.unreachable(e.to_string()))?
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(self.unreachable("dial timed out"));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn rpc(
        &self,
        auth: P2pAuth,
        body: OperatorRpcBody,
    ) -> Result<OperatorRpcResponse, StorageError> {
        self.ensure_connected().await?;
        self.handle
            .rpc_request(self.peer, OperatorRpcRequest { auth, body })
            .await
            .map_err(|e| match e {
                SwarmError::RequestFailed(details) => self.unreachable(details),
                other => self.unreachable(other.to_string()),
            })
    }

    fn unexpected(what: &str) -> StorageError {
        StorageError::ServerError {
            status: 500,
            message: format!("Unexpected P2P response for {what}"),
        }
    }
}

impl OperatorTransport for Libp2pTransport {
    fn request_challenge<'a>(
        &'a self,
        req: ChallengeRequest,
    ) -> BoxFuture<'a, Result<ChallengeResponse, StorageError>> {
        Box::pin(async move {
            // Like the HTTP shared vault scope: the challenge binds every
            // later scoped call to this vault.
            self.set_vault_scope(&req.vault_id_hex);
            match self
                .rpc(P2pAuth::default(), OperatorRpcBody::RequestChallenge(req))
                .await?
            {
                OperatorRpcResponse::Challenge(c) => Ok(c),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("request_challenge")),
            }
        })
    }

    fn redeem_session<'a>(
        &'a self,
        req: SessionRequest,
    ) -> BoxFuture<'a, Result<SessionResponse, StorageError>> {
        Box::pin(async move {
            match self
                .rpc(P2pAuth::default(), OperatorRpcBody::RedeemSession(req))
                .await?
            {
                OperatorRpcResponse::Session(s) => Ok(s),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("redeem_session")),
            }
        })
    }

    fn revoke_session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            match self
                .rpc(self.scoped_auth(token), OperatorRpcBody::RevokeSession)
                .await?
            {
                OperatorRpcResponse::Revoked => Ok(()),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("revoke_session")),
            }
        })
    }

    fn fetch_info<'a>(&'a self) -> BoxFuture<'a, Result<OperatorInfo, StorageError>> {
        Box::pin(async move {
            match self
                .rpc(P2pAuth::default(), OperatorRpcBody::GetInfo)
                .await?
            {
                OperatorRpcResponse::Info(info) => Ok(info),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("fetch_info")),
            }
        })
    }

    fn put_object<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
        data: Vec<u8>,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let body = OperatorRpcBody::PutObject { cid: *cid, data };
            match self.rpc(self.scoped_auth(token), body).await? {
                OperatorRpcResponse::PutDone => Ok(()),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("put_object")),
            }
        })
    }

    fn fetch_object_bytes<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<Vec<u8>, StorageError>> {
        Box::pin(async move {
            let body = OperatorRpcBody::GetObject { cid: *cid };
            match self.rpc(self.scoped_auth(token), body).await? {
                OperatorRpcResponse::Object { bytes } => Ok(bytes),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("fetch_object_bytes")),
            }
        })
    }

    fn challenge_object_pos<'a>(
        &'a self,
        token: &'a str,
        cid: &'a [u8; 32],
        nonce: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<ProofOfStorageReceipt, StorageError>> {
        Box::pin(async move {
            let body = OperatorRpcBody::ProveStorage {
                cid: *cid,
                nonce: *nonce,
            };
            match self.rpc(self.scoped_auth(token), body).await? {
                OperatorRpcResponse::Proof { receipt } => Ok(receipt),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("challenge_object_pos")),
            }
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
            let body = OperatorRpcBody::CommitLease {
                closure_digest: *closure_digest,
                byte_count,
                term_days,
            };
            match self.rpc(self.scoped_auth(token), body).await? {
                OperatorRpcResponse::Lease(receipt) => Ok(receipt),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("commit_lease")),
            }
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
            let body = OperatorRpcBody::RenewLease {
                lease_id: lease_id.to_string(),
                additional_days,
                byte_count,
            };
            match self.rpc(self.scoped_auth(token), body).await? {
                OperatorRpcResponse::Lease(receipt) => Ok(receipt),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("renew_lease")),
            }
        })
    }

    fn append_recovery_record<'a>(
        &'a self,
        token: &'a str,
        locator: &'a [u8; 32],
        record_bytes: Vec<u8>,
    ) -> BoxFuture<'a, Result<u64, StorageError>> {
        Box::pin(async move {
            let body = OperatorRpcBody::AppendRecovery {
                locator: *locator,
                record: record_bytes,
            };
            match self.rpc(self.scoped_auth(token), body).await? {
                OperatorRpcResponse::Appended { sequence } => Ok(sequence),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("append_recovery_record")),
            }
        })
    }

    fn get_recovery_records<'a>(
        &'a self,
        locator: &'a [u8; 32],
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>, StorageError>> {
        Box::pin(async move {
            let body = OperatorRpcBody::GetRecovery { locator: *locator };
            match self.rpc(P2pAuth::default(), body).await? {
                OperatorRpcResponse::RecoveryRecords { records } => Ok(records),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("get_recovery_records")),
            }
        })
    }

    fn announce_peer<'a>(
        &'a self,
        descriptor: &'a PeerDescriptor,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let body = OperatorRpcBody::AnnouncePeer {
                descriptor: descriptor.clone(),
            };
            match self.rpc(Self::control_auth(), body).await? {
                OperatorRpcResponse::PeerAnnounced => Ok(()),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("announce_peer")),
            }
        })
    }

    fn get_peers<'a>(&'a self) -> BoxFuture<'a, Result<Vec<PeerDescriptor>, StorageError>> {
        Box::pin(async move {
            match self
                .rpc(Self::control_auth(), OperatorRpcBody::GetPeers)
                .await?
            {
                OperatorRpcResponse::Peers { peers } => Ok(peers),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("get_peers")),
            }
        })
    }

    fn get_pending_approvals<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Vec<PendingApprovalChallenge>, StorageError>> {
        Box::pin(async move {
            match self
                .rpc(Self::control_auth(), OperatorRpcBody::GetPendingApprovals)
                .await?
            {
                OperatorRpcResponse::PendingApprovals { challenges } => Ok(challenges),
                OperatorRpcResponse::Err { status, message } => {
                    Err(StorageError::ServerError { status, message })
                }
                _ => Err(Self::unexpected("get_pending_approvals")),
            }
        })
    }

    fn issue_voucher<'a>(
        &'a self,
        _holder_pk_hex: &'a str,
        _quota_bytes: u64,
        _ttl_secs: u64,
    ) -> BoxFuture<'a, Result<ciphervault_storage::vouchers::WriteVoucher, StorageError>> {
        Box::pin(async move {
            Err(StorageError::ServerError {
                status: 501,
                message: "voucher issuance is operator-local administration (HTTP only)".into(),
            })
        })
    }

    fn set_write_voucher(&self, voucher: Option<ciphervault_storage::vouchers::WriteVoucher>) {
        if let Ok(mut staged) = self.write_voucher.lock() {
            *staged = voucher;
        }
    }
}
