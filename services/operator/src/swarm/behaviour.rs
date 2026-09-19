//! libp2p [`Behaviour`] for CipherVault operators (DON Phase 2, D2).
//!
//! The behaviour is additive: identify, ping, Kademlia provider records,
//! Gossipsub control topics, LAN mDNS, and a CBOR request-response operator
//! RPC covering the full [`OperatorTransport`] surface, plus relay client,
//! DCUtR, AutoNAT, rendezvous, and signed DHT peer records (D5) — each
//! covered by its own regression test.
//!
//! [`OperatorTransport`]: ciphervault_storage::OperatorTransport

use std::time::Duration;

use libp2p::identity::{Keypair, PeerId};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{
    autonat, connection_limits, dcutr, gossipsub, identify, kad, mdns, ping, relay, rendezvous,
    request_response, StreamProtocol,
};
use serde::{Deserialize, Serialize};

use ciphervault_storage::types::{
    ChallengeRequest, ChallengeResponse, LeaseReceipt, OperatorInfo, PeerDescriptor,
    PendingApprovalChallenge, ProofOfStorageReceipt, SessionRequest, SessionResponse,
};

use super::SwarmError;

/// Operator RPC request-response protocol version.
pub const OPERATOR_PROTOCOL: &str = "/ciphervault/operator/1.0.0";
/// Request size cap: 4 MiB objects plus envelope headroom.
pub const RPC_REQUEST_SIZE_MAXIMUM: u64 = 8 * 1024 * 1024;
/// Response size cap: 16 MiB recovery readbacks plus envelope headroom.
pub const RPC_RESPONSE_SIZE_MAXIMUM: u64 = 32 * 1024 * 1024;
/// Kademlia DHT protocol version (isolated from the IPFS DHT).
pub const KAD_PROTOCOL: &str = "/ciphervault/kad/1.0.0";
/// Gossipsub control topic for operator coordination.
pub const CONTROL_TOPIC: &str = "ciphervault/ctrl/1";
/// Rendezvous namespace operators register under for first contact.
pub const RENDEZVOUS_NAMESPACE: &str = "ciphervault/1";
/// Maximum gossipsub payload in bytes (Phase 3 slice 3 DoS posture).
/// Control messages are small descriptors; anything larger is rejected at
/// publish time (`PublishError::MessageTooLarge`) and never hits the mesh.
pub const GOSSIP_MAX_TRANSMIT_SIZE: usize = 64 * 1024;
/// The rendezvous namespace as a libp2p type (panics only if the constant
/// above stops being a valid namespace — covered by the rendezvous test).
pub fn rendezvous_namespace() -> rendezvous::Namespace {
    rendezvous::Namespace::from_static(RENDEZVOUS_NAMESPACE)
}
/// Identify agent version: `ciphervault/<operator-crate-version>`.
pub fn agent_version() -> String {
    format!("ciphervault/{}", env!("CARGO_PKG_VERSION"))
}

/// Auth envelope mirroring the HTTP headers (`Authorization: Bearer`,
/// `X-CipherVault-Id`, `X-CipherVault-Service-Token`, `X-CipherVault-Voucher`).
/// The server rebuilds a header map and runs the SAME `handlers` auth checks,
/// so P2P auth semantics are identical to HTTP by construction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct P2pAuth {
    pub bearer_token: Option<String>,
    pub vault_id_hex: Option<String>,
    pub service_token: Option<String>,
    pub voucher: Option<ciphervault_storage::vouchers::WriteVoucher>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRpcRequest {
    pub auth: P2pAuth,
    pub body: OperatorRpcBody,
}

/// One variant per [`OperatorTransport`] operation, reusing the exact HTTP
/// wire types so serialization semantics cannot drift.
///
/// [`OperatorTransport`]: ciphervault_storage::OperatorTransport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorRpcBody {
    RequestChallenge(ChallengeRequest),
    RedeemSession(SessionRequest),
    RevokeSession,
    GetInfo,
    PutObject {
        cid: [u8; 32],
        data: Vec<u8>,
    },
    GetObject {
        cid: [u8; 32],
    },
    ProveStorage {
        cid: [u8; 32],
        nonce: [u8; 32],
    },
    CommitLease {
        closure_digest: [u8; 32],
        byte_count: u64,
        term_days: u32,
    },
    RenewLease {
        lease_id: String,
        additional_days: u32,
        byte_count: u64,
    },
    AppendRecovery {
        locator: [u8; 32],
        record: Vec<u8>,
    },
    GetRecovery {
        locator: [u8; 32],
    },
    AnnouncePeer {
        descriptor: PeerDescriptor,
    },
    GetPeers,
    GetPendingApprovals,
    /// Mesh-internal repair backfill (Phase 4). Operator-signed, NOT
    /// session-authed: the receiver verifies the sender against its peer
    /// routing table, checks the ed25519 signature over
    /// [`crate::swarm::repair::repair_signing_bytes`], confirms the
    /// digest, and spends repair budget. P2P-only: no HTTP route and no
    /// `OperatorTransport` method — clients never repair.
    RepairPush {
        cid: [u8; 32],
        data: Vec<u8>,
        sender_operator_id: String,
        sender_pk_hex: String,
        recipient_operator_id: String,
        signature_hex: String,
    },
}

/// One success variant per operation plus a status-carrying error that maps
/// 1:1 onto HTTP failures (`StorageError::ServerError { status, message }`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorRpcResponse {
    Challenge(ChallengeResponse),
    Session(SessionResponse),
    Revoked,
    Info(OperatorInfo),
    PutDone,
    Object {
        bytes: Vec<u8>,
    },
    Proof {
        receipt: ProofOfStorageReceipt,
    },
    Lease(LeaseReceipt),
    Appended {
        sequence: u64,
    },
    RecoveryRecords {
        records: Vec<Vec<u8>>,
    },
    PeerAnnounced,
    Peers {
        peers: Vec<PeerDescriptor>,
    },
    PendingApprovals {
        challenges: Vec<PendingApprovalChallenge>,
    },
    RepairDone {
        /// False when the recipient already held identical bytes
        /// (idempotent re-push): still a success, still stops retry.
        stored: bool,
    },
    Err {
        status: u16,
        message: String,
    },
}

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct Behaviour {
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub rpc: request_response::cbor::Behaviour<OperatorRpcRequest, OperatorRpcResponse>,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: Toggle<relay::Behaviour>,
    pub dcutr: Toggle<dcutr::Behaviour>,
    pub autonat_client: autonat::v2::client::Behaviour,
    pub autonat_server: autonat::v2::server::Behaviour,
    pub rendezvous_client: rendezvous::client::Behaviour,
    pub rendezvous_server: Toggle<rendezvous::server::Behaviour>,
    pub connection_limits: connection_limits::Behaviour,
}

/// Every behaviour except the relay client, whose instance is minted by
/// `SwarmBuilder::with_relay_client` and attached inside its closure.
pub struct BehaviourParts {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
    rpc: request_response::cbor::Behaviour<OperatorRpcRequest, OperatorRpcResponse>,
    relay_server: Toggle<relay::Behaviour>,
    dcutr: Toggle<dcutr::Behaviour>,
    autonat_client: autonat::v2::client::Behaviour,
    autonat_server: autonat::v2::server::Behaviour,
    rendezvous_client: rendezvous::client::Behaviour,
    rendezvous_server: Toggle<rendezvous::server::Behaviour>,
    connection_limits: connection_limits::Behaviour,
}

impl BehaviourParts {
    pub fn attach(self, relay_client: relay::client::Behaviour) -> Behaviour {
        Behaviour {
            identify: self.identify,
            ping: self.ping,
            kademlia: self.kademlia,
            gossipsub: self.gossipsub,
            mdns: self.mdns,
            rpc: self.rpc,
            relay_client,
            relay_server: self.relay_server,
            dcutr: self.dcutr,
            autonat_client: self.autonat_client,
            autonat_server: self.autonat_server,
            rendezvous_client: self.rendezvous_client,
            rendezvous_server: self.rendezvous_server,
            connection_limits: self.connection_limits,
        }
    }
}

pub fn new_behaviour_parts(
    key: &Keypair,
    peer_id: PeerId,
    enable_mdns: bool,
    enable_relay_server: bool,
    enable_dcutr: bool,
    enable_rendezvous_server: bool,
    conn_limits: connection_limits::ConnectionLimits,
) -> Result<BehaviourParts, SwarmError> {
    let identify = identify::Behaviour::new(
        identify::Config::new("ciphervault/id/1.0.0".to_string(), key.public())
            .with_agent_version(agent_version()),
    );
    let ping = ping::Behaviour::default();

    let store_config = kad::store::MemoryStoreConfig {
        max_value_bytes: super::records::MAX_PEER_RECORD_BYTES,
        ..Default::default()
    };
    let mut kademlia = kad::Behaviour::with_config(
        peer_id,
        kad::store::MemoryStore::with_config(peer_id, store_config),
        kad::Config::new(StreamProtocol::new(KAD_PROTOCOL)),
    );
    // Permissioned operator mesh: every node is a DHT server. The
    // default auto mode pins loopback/NATed nodes to client mode —
    // refusing ALL inbound kad, including provider queries — until
    // AutoNAT confirms an external address, a race repair must not
    // depend on. Our peers are mutually dialed over a private
    // protocol, so serving records is always correct.
    kademlia.set_mode(Some(kad::Mode::Server));

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(GOSSIP_MAX_TRANSMIT_SIZE)
        .build()
        .map_err(|e| SwarmError::Config(format!("gossipsub config: {e}")))?;
    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
    )
    .map_err(|e| SwarmError::Config(format!("gossipsub behaviour: {e}")))?;
    gossipsub
        .subscribe(&gossipsub::IdentTopic::new(CONTROL_TOPIC))
        .map_err(|e| SwarmError::Config(format!("control topic: {e}")))?;

    let mdns = if enable_mdns {
        Toggle::from(Some(
            mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                .map_err(|e| SwarmError::Io(format!("mdns: {e}")))?,
        ))
    } else {
        Toggle::from(None)
    };

    // Raised codec limits: the 1 MiB / 10 MiB codec defaults cannot carry
    // 4 MiB object puts or large recovery readbacks.
    let codec = request_response::cbor::codec::Codec::default()
        .set_request_size_maximum(RPC_REQUEST_SIZE_MAXIMUM)
        .set_response_size_maximum(RPC_RESPONSE_SIZE_MAXIMUM);
    let rpc_config =
        request_response::Config::default().with_request_timeout(Duration::from_secs(30));
    let rpc = request_response::cbor::Behaviour::with_codec(
        codec,
        [(
            StreamProtocol::new(OPERATOR_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        rpc_config,
    );

    let relay_server = if enable_relay_server {
        Toggle::from(Some(relay::Behaviour::new(
            peer_id,
            relay::Config::default(),
        )))
    } else {
        Toggle::from(None)
    };

    let dcutr = if enable_dcutr {
        Toggle::from(Some(dcutr::Behaviour::new(peer_id)))
    } else {
        Toggle::from(None)
    };

    let connection_limits = connection_limits::Behaviour::new(conn_limits);

    let rendezvous_client = rendezvous::client::Behaviour::new(key.clone());
    let rendezvous_server = if enable_rendezvous_server {
        Toggle::from(Some(rendezvous::server::Behaviour::new(
            rendezvous::server::Config::default(),
        )))
    } else {
        Toggle::from(None)
    };

    Ok(BehaviourParts {
        identify,
        ping,
        kademlia,
        gossipsub,
        mdns,
        rpc,
        relay_server,
        dcutr,
        autonat_client: autonat::v2::client::Behaviour::default(),
        autonat_server: autonat::v2::server::Behaviour::default(),
        rendezvous_client,
        rendezvous_server,
        connection_limits,
    })
}
