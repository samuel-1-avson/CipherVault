//! libp2p swarm node for CipherVault operators (DON Phase 2, D2).
//!
//! Dual-stack QUIC+TCP with Noise/Yamux, identify, Kademlia provider
//! records, Gossipsub control topics, LAN mDNS, and CBOR chunk/PoS RPCs
//! served from the live [`OperatorState`]. The node runs alongside the HTTP
//! API (`--enable-p2p` dual mode) with relay client, DCUtR, AutoNAT, and
//! signed DHT peer records (D5).

pub mod behaviour;
pub mod bootstrap;
pub mod liveness;
pub mod records;
pub mod repair;
pub mod serve;
pub mod transport;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use behaviour::{
    new_behaviour_parts, Behaviour, OperatorRpcBody, OperatorRpcRequest, OperatorRpcResponse,
    P2pAuth, CONTROL_TOPIC,
};
use ciphervault_storage::types::PeerDescriptor;
use futures_util::StreamExt;
use libp2p::connection_limits::ConnectionLimits;
use libp2p::identity::Keypair;
use libp2p::kad::{QueryId, Quorum, Record as KadRecord, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::OutboundRequestId;
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use liveness::{HeartbeatConfig, LivenessTracker};
use repair::{RepairConfig, TokenBucket};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::OperatorState;

#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    #[error("swarm config: {0}")]
    Config(String),
    #[error("swarm io: {0}")]
    Io(String),
    #[error("swarm transport: {0}")]
    Transport(String),
    #[error("swarm dial: {0}")]
    Dial(String),
    #[error("swarm request failed: {0}")]
    RequestFailed(String),
    #[error("swarm node shut down")]
    Shutdown,
    #[error("swarm identity: {0}")]
    Key(String),
    #[error("swarm publish: {0}")]
    Publish(String),
}

/// Default cap on total established swarm connections when
/// [`SwarmNodeConfig::max_established_connections`] is `None`.
pub const DEFAULT_MAX_ESTABLISHED_CONNECTIONS: u32 = 512;
/// Default cap on established connections to a single peer when
/// [`SwarmNodeConfig::max_established_per_peer`] is `None`.
pub const DEFAULT_MAX_ESTABLISHED_PER_PEER: u32 = 8;
/// Default per-peer operator-RPC rate (requests per one-second window)
/// when [`SwarmNodeConfig::max_rpc_per_sec_per_peer`] is `None`.
pub const DEFAULT_MAX_RPC_PER_SEC_PER_PEER: u32 = 50;
/// Sliding window for the per-peer RPC rate limiter.
const RPC_RATE_WINDOW: Duration = Duration::from_secs(1);
/// Upper bound on tracked peers in the rate limiter. Past this, untracked
/// peers fail closed (429) so the tracker itself cannot be memory-DoSed.
const MAX_RATE_TRACKED_PEERS: usize = 4096;

pub struct SwarmNodeConfig {
    pub key_path: PathBuf,
    pub tcp_listen: Multiaddr,
    pub quic_listen: Multiaddr,
    pub bootstrap: Vec<Multiaddr>,
    pub enable_mdns: bool,
    /// Run a circuit-relay server (for dedicated relay/seed nodes only;
    /// every node is always a relay client and AutoNAT v2 client+server).
    pub enable_relay_server: bool,
    /// Run DCUtR direct-upgrade coordination (disable only to pin relayed
    /// paths in tests).
    pub enable_dcutr: bool,
    /// Signed JSON bootstrap list, verified against `bootstrap_signer_hex`
    /// before any dial. Both must be set together; anything unverifiable
    /// refuses to boot.
    pub bootstrap_list_path: Option<PathBuf>,
    pub bootstrap_signer_hex: Option<String>,
    /// Run a rendezvous server (dedicated seed nodes only; every node is
    /// always a rendezvous client).
    pub enable_rendezvous_server: bool,
    /// Operator-declared reachable addresses, added as swarm external
    /// addresses at boot. These are what rendezvous registration
    /// advertises; leave empty to rely on AutoNAT confirmation.
    pub advertise_addrs: Vec<Multiaddr>,
    /// Cap on total established connections (`None` =
    /// [`DEFAULT_MAX_ESTABLISHED_CONNECTIONS`]). Excess connections are
    /// denied by the connection-limits behaviour, never silently queued.
    pub max_established_connections: Option<u32>,
    /// Cap on established connections to one peer (`None` =
    /// [`DEFAULT_MAX_ESTABLISHED_PER_PEER`]).
    pub max_established_per_peer: Option<u32>,
    /// Peers refused at boot: never dialed, and any established
    /// connection (either direction) is closed immediately.
    pub blocked_peers: Vec<PeerId>,
    /// Per-peer operator-RPC rate in requests per one-second window
    /// (`None` = [`DEFAULT_MAX_RPC_PER_SEC_PER_PEER`]). Over-limit
    /// requests are rejected with 429 BEFORE auth/serve.
    pub max_rpc_per_sec_per_peer: Option<u32>,
    /// Interval between signed liveness heartbeats on the control topic
    /// (repair protocol §1). Use
    /// [`liveness::DEFAULT_HEARTBEAT_INTERVAL`] unless tests need faster
    /// convergence.
    pub heartbeat_interval: Duration,
    /// Liveness timeout: a peer silent longer than this reads as dead.
    /// Use [`liveness::DEFAULT_HEARTBEAT_TIMEOUT`]; must exceed the
    /// interval or live peers flap.
    pub heartbeat_timeout: Duration,
    /// Mesh repair knobs (target replicas, scan pacing, bandwidth
    /// budgets, cooldowns). [`RepairConfig::default`] suits a small
    /// fleet; chaos gates tune it down.
    pub repair: RepairConfig,
}

/// One peer discovered via rendezvous: dialable addresses from its signed
/// peer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousPeer {
    pub peer: PeerId,
    pub addrs: Vec<Multiaddr>,
}

/// One observed DCUtR hole-punch outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcutrUpgrade {
    pub peer: PeerId,
    pub success: bool,
}

enum Command {
    Dial {
        addr: Multiaddr,
    },
    IsConnected {
        peer: PeerId,
        respond_to: oneshot::Sender<bool>,
    },
    Listeners {
        respond_to: oneshot::Sender<Vec<Multiaddr>>,
    },
    RpcRequest {
        peer: PeerId,
        // Boxed: the request (auth envelope + body) dwarfs every other
        // variant, and commands cross an mpsc queue.
        request: Box<OperatorRpcRequest>,
        respond_to: oneshot::Sender<Result<OperatorRpcResponse, SwarmError>>,
    },
    ListenOn {
        addr: Multiaddr,
        respond_to: oneshot::Sender<Result<(), String>>,
    },
    ExternalAddrs {
        respond_to: oneshot::Sender<Vec<Multiaddr>>,
    },
    TakeDcutrUpgrades {
        respond_to: oneshot::Sender<Vec<DcutrUpgrade>>,
    },
    PublishPeer {
        descriptor: PeerDescriptor,
    },
    PutRawRecord {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    GetVerifiedPeers {
        signing_pk_hex: String,
        respond_to: oneshot::Sender<Vec<PeerDescriptor>>,
    },
    AddExternalAddr {
        addr: Multiaddr,
    },
    RendezvousRegister {
        server: PeerId,
    },
    RendezvousDiscover {
        server: PeerId,
        limit: Option<u64>,
    },
    TakeRendezvousDiscoveries {
        respond_to: oneshot::Sender<Vec<RendezvousPeer>>,
    },
    ProvideChunk {
        cid: [u8; 32],
    },
    GetProviders {
        cid: [u8; 32],
        respond_to: oneshot::Sender<Vec<PeerId>>,
    },
    BlockPeer {
        peer: PeerId,
    },
    UnblockPeer {
        peer: PeerId,
    },
    IsBlocked {
        peer: PeerId,
        respond_to: oneshot::Sender<bool>,
    },
    PublishControl {
        data: Vec<u8>,
        respond_to: oneshot::Sender<Result<String, String>>,
    },
    LivePeers {
        respond_to: oneshot::Sender<Vec<PeerId>>,
    },
    IsLive {
        peer: PeerId,
        respond_to: oneshot::Sender<bool>,
    },
    TriggerRepair {
        cid: [u8; 32],
    },
}

/// One in-flight DHT peer lookup: only verified records are collected, so
/// whatever is returned (even on query failure) is trusted by construction.
struct KadGetState {
    want_pk: String,
    found: Vec<PeerDescriptor>,
    respond_to: Option<oneshot::Sender<Vec<PeerDescriptor>>>,
}

/// One in-flight provider lookup: every announced provider is collected;
/// provider records are routing hints, and chunk bytes self-verify by CID
/// hash on fetch, so no per-record validation applies here.
struct ProviderGetState {
    found: HashSet<PeerId>,
    respond_to: Option<oneshot::Sender<Vec<PeerId>>>,
}

/// Event-loop boot parameters, bundled so `run_loop` keeps a stable
/// argument list as the swarm grows.
struct LoopConfig {
    blocked: HashSet<PeerId>,
    rpc_limit: u32,
    heartbeat: HeartbeatConfig,
    repair: RepairConfig,
}

/// In-flight repair provider query: the CID under assessment plus every
/// provider announced so far.
struct RepairQuery {
    cid: [u8; 32],
    found: HashSet<PeerId>,
}

/// Mutable repair-scanner state (see [`repair`] and the repair protocol
/// §2–§3). Cooldown/failure maps are pruned every scan tick; the query
/// and in-flight maps drain as DHT queries and RPCs complete.
struct RepairState {
    config: RepairConfig,
    bucket: TokenBucket,
    cooldowns: HashMap<[u8; 32], Instant>,
    fail_counts: HashMap<[u8; 32], u32>,
    pending_queries: HashMap<QueryId, RepairQuery>,
    inflight: HashMap<OutboundRequestId, [u8; 32]>,
    cursor: usize,
}

impl RepairState {
    fn new(config: RepairConfig) -> Self {
        Self {
            bucket: TokenBucket::new(config.max_bytes_per_sec),
            config,
            cooldowns: HashMap::new(),
            fail_counts: HashMap::new(),
            pending_queries: HashMap::new(),
            inflight: HashMap::new(),
            cursor: 0,
        }
    }
}

/// Cap on tracked per-CID cooldown/failure entries. Past this, new
/// entries are skipped (fail open on pacing — the sender bucket still
/// bounds bandwidth globally, so no storm).
const MAX_REPAIR_TRACKED_CIDS: usize = 4096;

/// Short cooldown when a repair round leaves recipients unpushed
/// (bucket/capacity), so the remainder goes soon without re-querying
/// the DHT every tick.
const REPAIR_REQUEUE_COOLDOWN: Duration = Duration::from_secs(5);

/// Mutable event-loop state, bundled so the swarm event handler stays under
/// the argument-count lint as behaviours keep landing.
struct LoopState {
    pending: HashMap<OutboundRequestId, oneshot::Sender<Result<OperatorRpcResponse, SwarmError>>>,
    pending_kad: HashMap<QueryId, KadGetState>,
    pending_providers: HashMap<QueryId, ProviderGetState>,
    dcutr_upgrades: Vec<DcutrUpgrade>,
    rendezvous_discoveries: Vec<RendezvousPeer>,
    blocked: HashSet<PeerId>,
    rpc_hits: HashMap<PeerId, VecDeque<Instant>>,
    rpc_limit: u32,
    liveness: LivenessTracker,
    heartbeat_seq: u64,
    heartbeat: HeartbeatConfig,
    repair: RepairState,
}

impl Default for LoopState {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            pending_kad: HashMap::new(),
            pending_providers: HashMap::new(),
            dcutr_upgrades: Vec::new(),
            rendezvous_discoveries: Vec::new(),
            blocked: HashSet::new(),
            rpc_hits: HashMap::new(),
            // Safe default: a zero limit would 429 every RPC, so fall back
            // to the documented default; `run_loop` overrides with config.
            rpc_limit: DEFAULT_MAX_RPC_PER_SEC_PER_PEER,
            liveness: LivenessTracker::new(),
            heartbeat_seq: 0,
            heartbeat: HeartbeatConfig {
                interval: liveness::DEFAULT_HEARTBEAT_INTERVAL,
                timeout: liveness::DEFAULT_HEARTBEAT_TIMEOUT,
            },
            repair: RepairState::new(RepairConfig::default()),
        }
    }
}

/// Handle to a running swarm node. Dropping the last handle shuts the node
/// down; the daemon holds one for its whole lifetime in dual mode.
#[derive(Clone)]
pub struct SwarmHandle {
    commands: mpsc::Sender<Command>,
    pub peer_id: PeerId,
}

impl SwarmHandle {
    async fn send(&self, command: Command) -> Result<(), SwarmError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| SwarmError::Shutdown)
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<(), SwarmError> {
        self.send(Command::Dial { addr }).await
    }

    pub async fn is_connected(&self, peer: PeerId) -> Result<bool, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::IsConnected {
            peer,
            respond_to: tx,
        })
        .await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    pub async fn listeners(&self) -> Result<Vec<Multiaddr>, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::Listeners { respond_to: tx }).await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    pub async fn rpc_request(
        &self,
        peer: PeerId,
        request: OperatorRpcRequest,
    ) -> Result<OperatorRpcResponse, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::RpcRequest {
            peer,
            request: Box::new(request),
            respond_to: tx,
        })
        .await?;
        rx.await.map_err(|_| SwarmError::Shutdown)?
    }

    /// Starts listening on `addr`. Used for circuit-relay reservations:
    /// pass `<relay-addr>/p2p/<relay-peer>/p2p-circuit` and the relayed
    /// address appears in [`Self::listeners`] once accepted.
    pub async fn listen_on(&self, addr: Multiaddr) -> Result<(), SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::ListenOn {
            addr,
            respond_to: tx,
        })
        .await?;
        rx.await
            .map_err(|_| SwarmError::Shutdown)?
            .map_err(SwarmError::Transport)
    }

    /// AutoNAT-confirmed external addresses (empty until a dial-back probe
    /// succeeds).
    pub async fn external_addrs(&self) -> Result<Vec<Multiaddr>, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::ExternalAddrs { respond_to: tx }).await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    /// Drains observed DCUtR hole-punch outcomes since the last call.
    pub async fn take_dcutr_upgrades(&self) -> Result<Vec<DcutrUpgrade>, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::TakeDcutrUpgrades { respond_to: tx })
            .await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    /// Publishes our signed peer descriptor to the DHT (D5). Fire-and-forget:
    /// the local store write is synchronous and replication proceeds in the
    /// background, so readers poll [`Self::get_verified_peers`].
    /// Live deployments must republish on a period well under
    /// [`records::MAX_PEER_RECORD_AGE_SECS`]: Kademlia republication is the
    /// only defense against same-key garbage blanking the record, and
    /// readers trust nothing older than that bound.
    pub async fn publish_peer(&self, descriptor: PeerDescriptor) -> Result<(), SwarmError> {
        self.send(Command::PublishPeer { descriptor }).await
    }

    /// Raw DHT write escape hatch for tests and future record kinds. Values
    /// written here are still filtered by client-side verification on read.
    pub async fn put_raw_record(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), SwarmError> {
        self.send(Command::PutRawRecord { key, value }).await
    }

    /// Looks up a peer's DHT record and returns ONLY descriptors that decode,
    /// match the queried key, carry a valid signature, and are fresh. An
    /// empty vec means "nothing trustworthy found", never an error, so
    /// callers poll with a deadline while the DHT converges.
    pub async fn get_verified_peers(
        &self,
        signing_pk_hex: String,
    ) -> Result<Vec<PeerDescriptor>, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::GetVerifiedPeers {
            signing_pk_hex,
            respond_to: tx,
        })
        .await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    /// Adds a swarm external address at runtime (e.g. the loopback listen
    /// addr in tests, or an operator-confirmed public addr). External
    /// addresses are what rendezvous registration advertises.
    pub async fn add_external_addr(&self, addr: Multiaddr) -> Result<(), SwarmError> {
        self.send(Command::AddExternalAddr { addr }).await
    }

    /// Registers our external addresses with a rendezvous server under the
    /// `ciphervault/1` namespace. Fire-and-forget: registration needs a
    /// connection to the server plus at least one external address, so
    /// callers retry until discovery succeeds elsewhere.
    pub async fn rendezvous_register(&self, server: PeerId) -> Result<(), SwarmError> {
        self.send(Command::RendezvousRegister { server }).await
    }

    /// Asks a rendezvous server for peers in the `ciphervault/1`
    /// namespace; results accumulate until drained with
    /// [`Self::take_rendezvous_discoveries`].
    pub async fn rendezvous_discover(
        &self,
        server: PeerId,
        limit: Option<u64>,
    ) -> Result<(), SwarmError> {
        self.send(Command::RendezvousDiscover { server, limit })
            .await
    }

    /// Drains peers discovered via rendezvous since the last call.
    pub async fn take_rendezvous_discoveries(&self) -> Result<Vec<RendezvousPeer>, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::TakeRendezvousDiscoveries { respond_to: tx })
            .await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    /// Advertises that this node holds chunk `cid` (Kademlia provider
    /// record, keyed by the raw 32-byte CID). Fire-and-forget: the local
    /// store write is synchronous and replication proceeds in the
    /// background, so readers poll [`Self::get_providers`].
    pub async fn provide_chunk(&self, cid: [u8; 32]) -> Result<(), SwarmError> {
        self.send(Command::ProvideChunk { cid }).await
    }

    /// Returns the peers currently advertising chunk `cid`, sorted.
    /// Provider records are routing hints, not trust: fetched bytes always
    /// self-verify against the CID hash. An empty vec means "no provider
    /// found yet" — callers poll with a deadline while the DHT converges.
    pub async fn get_providers(&self, cid: [u8; 32]) -> Result<Vec<PeerId>, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::GetProviders {
            cid,
            respond_to: tx,
        })
        .await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    /// Adds `peer` to the block-list and drops any live connection to it.
    /// Blocked peers are never dialed (direct or mDNS-triggered), and any
    /// connection they establish — either direction — is closed at once.
    pub async fn block_peer(&self, peer: PeerId) -> Result<(), SwarmError> {
        self.send(Command::BlockPeer { peer }).await
    }

    /// Removes `peer` from the block-list. Existing connections are NOT
    /// re-established; the peer must dial or be dialed again.
    pub async fn unblock_peer(&self, peer: PeerId) -> Result<(), SwarmError> {
        self.send(Command::UnblockPeer { peer }).await
    }

    /// Reports whether `peer` is currently block-listed.
    pub async fn is_blocked(&self, peer: PeerId) -> Result<bool, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::IsBlocked {
            peer,
            respond_to: tx,
        })
        .await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    /// Publishes `data` on the signed control topic. Payloads over
    /// [`behaviour::GOSSIP_MAX_TRANSMIT_SIZE`] are rejected with
    /// [`SwarmError::Publish`]; returns the gossipsub message id on success.
    pub async fn publish_control(&self, data: Vec<u8>) -> Result<String, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::PublishControl {
            data,
            respond_to: tx,
        })
        .await?;
        rx.await
            .map_err(|_| SwarmError::Shutdown)?
            .map_err(SwarmError::Publish)
    }

    /// Peers with a verified heartbeat inside the liveness timeout,
    /// sorted. Liveness is computed locally from gossip arrivals — there
    /// are no death claims, so this never reports a peer dead because
    /// someone else said so.
    pub async fn live_peers(&self) -> Result<Vec<PeerId>, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::LivePeers { respond_to: tx }).await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    /// Whether `peer` currently counts as live (see [`Self::live_peers`]).
    pub async fn is_live(&self, peer: PeerId) -> Result<bool, SwarmError> {
        let (tx, rx) = oneshot::channel();
        self.send(Command::IsLive {
            peer,
            respond_to: tx,
        })
        .await?;
        rx.await.map_err(|_| SwarmError::Shutdown)
    }

    /// Assesses `cid` for repair immediately, bypassing the scan cursor
    /// and any cooldown (explicit operator/drill action). No-op unless
    /// this node holds the object — only holders assess. Fire-and-forget:
    /// the provider query answers asynchronously, so callers poll the
    /// recipient's store (or repair metrics) with a deadline.
    pub async fn trigger_repair(&self, cid: [u8; 32]) -> Result<(), SwarmError> {
        self.send(Command::TriggerRepair { cid }).await
    }
}

/// Loads the persistent swarm identity, generating and storing a fresh
/// ed25519 keypair (0600, like `operator.key`) on first boot.
pub fn load_or_generate_key(path: &Path) -> Result<Keypair, SwarmError> {
    if let Ok(bytes) = fs::read(path) {
        return Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| SwarmError::Key(format!("invalid swarm key: {e}")));
    }
    let key = Keypair::generate_ed25519();
    let bytes = key
        .to_protobuf_encoding()
        .map_err(|e| SwarmError::Key(format!("encode swarm key: {e}")))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| SwarmError::Io(e.to_string()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|e| SwarmError::Io(e.to_string()))?;
    file.write_all(&bytes)
        .map_err(|e| SwarmError::Io(e.to_string()))?;
    file.sync_all().map_err(|e| SwarmError::Io(e.to_string()))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| SwarmError::Io(e.to_string()))?;
    Ok(key)
}

/// Boots a swarm node bound to `state` and spawns its event loop. Returns
/// the command handle plus the loop task; dropping the handle stops the node.
pub async fn boot_swarm(
    config: SwarmNodeConfig,
    state: Arc<OperatorState>,
) -> Result<(SwarmHandle, JoinHandle<()>), SwarmError> {
    // The bootstrap list is verified FIRST so a refusal leaves no
    // listeners, tasks, or partial state behind.
    let mut bootstrap_addrs = config.bootstrap.clone();
    match (&config.bootstrap_list_path, &config.bootstrap_signer_hex) {
        (None, None) => {}
        (Some(path), Some(signer)) => {
            let listed = bootstrap::BootstrapList::load_verified(path, signer)
                .map_err(|e| SwarmError::Config(e.to_string()))?;
            bootstrap_addrs.extend(listed);
        }
        _ => {
            return Err(SwarmError::Config(
                "bootstrap list path and signer key must be set together".to_string(),
            ))
        }
    }
    let key = load_or_generate_key(&config.key_path)?;
    let peer_id = key.public().to_peer_id();
    let blocked: HashSet<PeerId> = config.blocked_peers.iter().cloned().collect();
    // `with_behaviour` takes a ready behaviour, so fallible construction
    // happens before the key moves into the builder; the relay client is
    // minted by `with_relay_client` and attached inside its closure.
    let conn_limits = ConnectionLimits::default()
        .with_max_established(Some(
            config
                .max_established_connections
                .unwrap_or(DEFAULT_MAX_ESTABLISHED_CONNECTIONS),
        ))
        .with_max_established_per_peer(Some(
            config
                .max_established_per_peer
                .unwrap_or(DEFAULT_MAX_ESTABLISHED_PER_PEER),
        ));
    let parts = new_behaviour_parts(
        &key,
        peer_id,
        config.enable_mdns,
        config.enable_relay_server,
        config.enable_dcutr,
        config.enable_rendezvous_server,
        conn_limits,
    )?;

    let mut swarm = SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| SwarmError::Transport(format!("tcp: {e}")))?
        .with_quic()
        .with_dns()
        .map_err(|e| SwarmError::Transport(format!("dns: {e}")))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| SwarmError::Transport(format!("relay: {e}")))?
        .with_behaviour(|_, relay_client| parts.attach(relay_client))
        .map_err(|e| SwarmError::Config(e.to_string()))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();

    swarm
        .listen_on(config.tcp_listen)
        .map_err(|e| SwarmError::Transport(format!("tcp listen: {e}")))?;
    swarm
        .listen_on(config.quic_listen)
        .map_err(|e| SwarmError::Transport(format!("quic listen: {e}")))?;

    for addr in &config.advertise_addrs {
        swarm.add_external_address(addr.clone());
    }

    for addr in &bootstrap_addrs {
        // Boot-time block-list: never dial a listed peer, not even as a
        // configured bootstrap.
        if let Some(peer) = peer_from_multiaddr(addr) {
            if blocked.contains(&peer) {
                continue;
            }
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer, addr.clone());
        }
        swarm
            .dial(addr.clone())
            .map_err(|e| SwarmError::Dial(e.to_string()))?;
    }
    let _ = swarm.behaviour_mut().kademlia.bootstrap();

    let rpc_limit = config
        .max_rpc_per_sec_per_peer
        .unwrap_or(DEFAULT_MAX_RPC_PER_SEC_PER_PEER);
    let loop_config = LoopConfig {
        blocked,
        rpc_limit,
        heartbeat: HeartbeatConfig {
            interval: config.heartbeat_interval,
            timeout: config.heartbeat_timeout,
        },
        repair: config.repair,
    };
    let (tx, rx) = mpsc::channel(64);
    let task = tokio::spawn(run_loop(swarm, rx, state, loop_config));
    Ok((
        SwarmHandle {
            commands: tx,
            peer_id,
        },
        task,
    ))
}

fn peer_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|protocol| match protocol {
        Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

/// Classifies one inbound control-topic payload and applies its effect.
/// Returns the gossipsub verdict: Accept advances liveness, Reject
/// penalizes a faulty/Byzantine sender, Ignore passes over unknown
/// senders and unknown kinds without penalty (forward compatibility).
fn accept_control_message(
    state: &OperatorState,
    loop_state: &mut LoopState,
    data: &[u8],
) -> libp2p::gossipsub::MessageAcceptance {
    use libp2p::gossipsub::MessageAcceptance;
    use liveness::{ControlInput, HeartbeatReject};
    match liveness::classify_control_bytes(data) {
        ControlInput::BadEnvelope => {
            state.metrics.observe_heartbeat_dropped("bad_envelope");
            MessageAcceptance::Reject
        }
        ControlInput::UnknownKind => {
            state.metrics.observe_control_unknown_kind();
            MessageAcceptance::Ignore
        }
        ControlInput::Heartbeat(hb) => {
            // The sender's announced key is resolved FIRST: unknown
            // senders are ignored without touching crypto or the
            // tracker. (The routing-table lock recovers from poison, so
            // only genuinely unknown senders land in the drop below.)
            let table =
                crate::state::lock_or_recover(&state.peer_routing_table, "peer_routing_table");
            let announced = table
                .get(&hb.operator_id)
                .map(|desc| desc.signing_pk_hex.clone());
            let Some(expected_pk) = announced else {
                state.metrics.observe_heartbeat_dropped("unknown_sender");
                return MessageAcceptance::Ignore;
            };
            let Ok(peer) = hb.peer_id.parse::<PeerId>() else {
                state.metrics.observe_heartbeat_dropped("bad_envelope");
                return MessageAcceptance::Reject;
            };
            let last_seq = loop_state.liveness.last_seq(&peer);
            match liveness::verify_heartbeat(&hb, Some(&expected_pk), last_seq, liveness::now_ms())
            {
                Ok(()) => {
                    loop_state
                        .liveness
                        .note_heartbeat(peer, &hb.operator_id, hb.seq);
                    state.metrics.observe_heartbeat_received();
                    // A verified heartbeat is proof of life for probation:
                    // joiners graduate on time served plus recent liveness.
                    state.note_peer_heartbeat(&hb.operator_id);
                    MessageAcceptance::Accept
                }
                Err(reason) => {
                    let slug = match reason {
                        HeartbeatReject::BadVersion => "bad_version",
                        HeartbeatReject::ClockSkew => "clock_skew",
                        HeartbeatReject::BadSignature => "bad_signature",
                        HeartbeatReject::StaleSeq => "stale_seq",
                    };
                    state.metrics.observe_heartbeat_dropped(slug);
                    MessageAcceptance::Reject
                }
            }
        }
    }
}

/// One repair-scan tick: prune expired cooldowns (and their failure
/// counts), then assess up to `sample_size` local objects past the
/// rotating cursor.
fn repair_scan(swarm: &mut Swarm<Behaviour>, state: &OperatorState, loop_state: &mut LoopState) {
    let now = Instant::now();
    loop_state.repair.cooldowns.retain(|_, until| *until > now);
    let cooling: HashSet<[u8; 32]> = loop_state.repair.cooldowns.keys().cloned().collect();
    loop_state
        .repair
        .fail_counts
        .retain(|cid, _| cooling.contains(cid));
    let sample = loop_state.repair.config.sample_size;
    let cids = state.list_object_cids(loop_state.repair.cursor, sample);
    if cids.len() < sample {
        loop_state.repair.cursor = 0;
    } else {
        loop_state.repair.cursor += cids.len();
    }
    for cid in cids {
        start_repair_check(swarm, state, loop_state, cid, false);
    }
}

/// Starts one repair assessment: cooldown gate (unless `force`), holder
/// gate, query-cap gate, then a DHT provider query whose answer drives
/// [`finish_repair_check`]. Silent no-ops (not a holder, saturated)
/// stay metric-free — only assessed CIDs count.
fn start_repair_check(
    swarm: &mut Swarm<Behaviour>,
    state: &OperatorState,
    loop_state: &mut LoopState,
    cid: [u8; 32],
    force: bool,
) {
    if !force {
        if let Some(until) = loop_state.repair.cooldowns.get(&cid) {
            if Instant::now() < *until {
                state.metrics.observe_repair_cooldown_suppressed();
                return;
            }
        }
    }
    if !state.has_object(&hex::encode(cid)) {
        return;
    }
    if loop_state.repair.pending_queries.len() >= loop_state.repair.config.max_queries {
        return;
    }
    if loop_state
        .repair
        .pending_queries
        .values()
        .any(|query| query.cid == cid)
    {
        return;
    }
    let id = swarm
        .behaviour_mut()
        .kademlia
        .get_providers(RecordKey::new(&cid));
    loop_state.repair.pending_queries.insert(
        id,
        RepairQuery {
            cid,
            found: HashSet::new(),
        },
    );
}

/// Drops probationary joiners from repair-recipient candidates: new
/// replicas are entrusted only to proven members. (Probationers still
/// count as holders and may push — `plan_repair` uses the live set only
/// for candidates.) Self is always kept. Probation views can differ
/// across holders mid-propagation, so two holders may rarely elect
/// different recipients for one round — pushes are idempotent
/// (digest-verified) and budgeted, so the worst case is one duplicate
/// backfill.
fn retain_eligible_recipients(
    live: &mut Vec<PeerId>,
    liveness: &liveness::LivenessTracker,
    state: &OperatorState,
    self_peer: PeerId,
) {
    live.retain(|peer| {
        *peer == self_peer
            || !liveness
                .operator_for(peer)
                .is_some_and(|operator_id| state.is_probationary(&operator_id))
    });
}

/// Completes one repair assessment: intersects providers with the live
/// set, computes the deterministic plan, and pushes when this node is
/// the elected pusher. Every exit path (healthy, not-pusher, pushed)
/// cools the CID down so assessments never hot-loop.
fn finish_repair_check(
    swarm: &mut Swarm<Behaviour>,
    state: &OperatorState,
    loop_state: &mut LoopState,
    cid: [u8; 32],
    providers: HashSet<PeerId>,
) {
    state.metrics.observe_repair_check();
    note_repair_cooldown(loop_state, cid, loop_state.repair.config.cooldown);
    let self_peer = *swarm.local_peer_id();
    let mut live = loop_state.liveness.live_peers(loop_state.heartbeat.timeout);
    if !live.contains(&self_peer) {
        live.push(self_peer);
    }
    retain_eligible_recipients(&mut live, &loop_state.liveness, state, self_peer);
    let mut holders: Vec<PeerId> = providers.into_iter().filter(|p| live.contains(p)).collect();
    // Self holds the object (checks only start for held CIDs) but may be
    // missing from provider records (never announced) — always count it.
    if !holders.contains(&self_peer) {
        holders.push(self_peer);
    }
    let Some(plan) = repair::plan_repair(&cid, &holders, &live, loop_state.repair.config.target)
    else {
        // Healthy, hopeless, or target-less: a future regression starts
        // from base backoff, not from stale failure counts.
        loop_state.repair.fail_counts.remove(&cid);
        return;
    };
    if plan.pusher != self_peer {
        return;
    }
    let Some(bytes) = state.get_object(&hex::encode(cid)) else {
        return;
    };
    execute_repair_plan(swarm, state, loop_state, cid, &bytes, &plan);
}

/// Pushes one plan's recipients through the sender-side gates
/// (concurrency cap, token bucket, liveness race). Recipients skipped
/// for pacing reasons shorten the CID cooldown to the requeue horizon
/// so the remainder goes soon.
fn execute_repair_plan(
    swarm: &mut Swarm<Behaviour>,
    state: &OperatorState,
    loop_state: &mut LoopState,
    cid: [u8; 32],
    bytes: &[u8],
    plan: &repair::RepairPlan,
) {
    let mut deferred = false;
    for recipient in &plan.recipients {
        if loop_state.repair.inflight.len() >= loop_state.repair.config.max_concurrent_pushes {
            deferred = true;
            break;
        }
        let Some(recipient_operator) = loop_state.liveness.operator_for(recipient) else {
            // Liveness raced the plan (peer timed out mid-round): skip;
            // the next assessment recomputes without it.
            deferred = true;
            continue;
        };
        if !loop_state.repair.bucket.try_take(bytes.len() as u64) {
            state.metrics.observe_repair_bucket_deferred();
            deferred = true;
            continue;
        }
        let msg = repair::repair_signing_bytes(&recipient_operator, &cid, bytes);
        let sig = ciphervault_crypto::signatures::sign_with_domain(
            &state.signing_key,
            repair::REPAIR_PUSH_DOMAIN,
            &msg,
        );
        let request = OperatorRpcRequest {
            auth: P2pAuth::default(),
            body: OperatorRpcBody::RepairPush {
                cid,
                data: bytes.to_vec(),
                sender_operator_id: state.operator_id.clone(),
                sender_pk_hex: hex::encode(state.signing_key.verifying_key().as_bytes()),
                recipient_operator_id: recipient_operator,
                signature_hex: hex::encode(sig),
            },
        };
        let request_id = swarm.behaviour_mut().rpc.send_request(recipient, request);
        loop_state.repair.inflight.insert(request_id, cid);
        if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
            eprintln!("swarm: repair push {request_id:?} sent to {recipient}");
        }
        state.metrics.observe_repair_started();
        state.metrics.observe_repair_bytes(bytes.len() as u64);
    }
    if deferred {
        note_repair_cooldown(loop_state, cid, REPAIR_REQUEUE_COOLDOWN);
    }
}

/// Routes one repair-push RPC answer: success clears backoff state, 429
/// schedules paced retry, anything else fails terminally for the round
/// (the assessment cooldown already paces the next look).
fn handle_repair_response(
    state: &OperatorState,
    loop_state: &mut LoopState,
    cid: [u8; 32],
    response: &OperatorRpcResponse,
) {
    match response {
        OperatorRpcResponse::RepairDone { .. } => {
            state.metrics.observe_repair_completed();
            loop_state.repair.fail_counts.remove(&cid);
        }
        OperatorRpcResponse::Err { status: 429, .. } => {
            schedule_repair_backoff(state, loop_state, cid);
        }
        _ => {
            state.metrics.observe_repair_failed();
        }
    }
}

/// Exponential backoff with jitter after a 429 or transport failure,
/// overwriting the CID cooldown (failures pace out; successes reset).
fn schedule_repair_backoff(state: &OperatorState, loop_state: &mut LoopState, cid: [u8; 32]) {
    let fails = loop_state.repair.fail_counts.entry(cid).or_insert(0);
    *fails = fails.saturating_add(1);
    let wait = repair::backoff_for(
        *fails,
        loop_state.repair.config.cooldown,
        loop_state.repair.config.max_backoff,
    );
    note_repair_cooldown_at(loop_state, cid, Instant::now() + wait);
    state.metrics.observe_repair_backoff();
}

fn note_repair_cooldown(loop_state: &mut LoopState, cid: [u8; 32], after: Duration) {
    note_repair_cooldown_at(loop_state, cid, Instant::now() + after);
}

fn note_repair_cooldown_at(loop_state: &mut LoopState, cid: [u8; 32], at: Instant) {
    if loop_state.repair.cooldowns.len() < MAX_REPAIR_TRACKED_CIDS
        || loop_state.repair.cooldowns.contains_key(&cid)
    {
        loop_state.repair.cooldowns.insert(cid, at);
    }
}

/// Sliding-window per-peer RPC admission: records `now` for `peer` and
/// returns true when the request fits under `limit` hits per
/// [`RPC_RATE_WINDOW`]. A zero limit rejects everything (fail closed).
/// Expired entries are pruned on the admitting path, and the tracker is
/// bounded at [`MAX_RATE_TRACKED_PEERS`] — past that, untracked peers
/// fail closed so the tracker itself cannot be memory-DoSed.
fn rpc_allowed(hits: &mut HashMap<PeerId, VecDeque<Instant>>, peer: PeerId, limit: u32) -> bool {
    rpc_allowed_at(hits, peer, limit, Instant::now())
}

fn rpc_allowed_at(
    hits: &mut HashMap<PeerId, VecDeque<Instant>>,
    peer: PeerId,
    limit: u32,
    now: Instant,
) -> bool {
    let window_start = now.checked_sub(RPC_RATE_WINDOW);
    // Opportunistic hygiene past half capacity: evict peers with no
    // in-window hits so tracker growth stays proportional to ACTUAL
    // recent requesters, not to every peer ever seen.
    if hits.len() > MAX_RATE_TRACKED_PEERS / 2 {
        hits.retain(|_, times| {
            while window_start.is_some_and(|start| times.front().is_some_and(|t| *t <= start)) {
                times.pop_front();
            }
            !times.is_empty()
        });
    }
    if !hits.contains_key(&peer) && hits.len() >= MAX_RATE_TRACKED_PEERS {
        return false;
    }
    let times = hits.entry(peer).or_default();
    while window_start.is_some_and(|start| times.front().is_some_and(|t| *t <= start)) {
        times.pop_front();
    }
    if times.len() >= limit as usize {
        return false;
    }
    times.push_back(now);
    true
}

async fn run_loop(
    mut swarm: Swarm<Behaviour>,
    mut commands: mpsc::Receiver<Command>,
    state: Arc<OperatorState>,
    config: LoopConfig,
) {
    let mut loop_state = LoopState {
        blocked: config.blocked,
        rpc_limit: config.rpc_limit,
        heartbeat: config.heartbeat,
        repair: RepairState::new(config.repair),
        ..LoopState::default()
    };
    let mut heartbeat_tick = tokio::time::interval(loop_state.heartbeat.interval);
    // Never burst-catch-up: under load, Burst fires missed ticks as
    // fast as polled, each doing sign+publish work that deepens the
    // overload (100% CPU spiral). Delay skips missed beats instead.
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut repair_tick = tokio::time::interval(loop_state.repair.config.interval);
    repair_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Dial { addr } => {
                        // Block-list: refuse to dial a listed peer. Dials
                        // without a /p2p suffix cannot be attributed yet and
                        // are closed at ConnectionEstablished instead.
                        if let Some(peer) = peer_from_multiaddr(&addr) {
                            if loop_state.blocked.contains(&peer) {
                                continue;
                            }
                        }
                        let _ = swarm.dial(addr);
                    }
                    Command::IsConnected { peer, respond_to } => {
                        let _ = respond_to.send(swarm.is_connected(&peer));
                    }
                    Command::Listeners { respond_to } => {
                        let _ = respond_to.send(swarm.listeners().cloned().collect());
                    }
                    Command::RpcRequest { peer, request, respond_to } => {
                        let request_id = swarm.behaviour_mut().rpc.send_request(&peer, *request);
                        loop_state.pending.insert(request_id, respond_to);
                    }
                    Command::ListenOn { addr, respond_to } => {
                        let _ = respond_to.send(
                            swarm.listen_on(addr).map(|_| ()).map_err(|e| e.to_string()),
                        );
                    }
                    Command::ExternalAddrs { respond_to } => {
                        let _ = respond_to.send(swarm.external_addresses().cloned().collect());
                    }
                    Command::TakeDcutrUpgrades { respond_to } => {
                        let _ = respond_to.send(std::mem::take(&mut loop_state.dcutr_upgrades));
                    }
                    Command::PublishPeer { descriptor } => {
                        let record = records::peer_kad_record(&descriptor);
                        let _ = swarm
                            .behaviour_mut()
                            .kademlia
                            .put_record(record, Quorum::One);
                    }
                    Command::PutRawRecord { key, value } => {
                        let record = KadRecord::new(RecordKey::new(&key), value);
                        let _ = swarm
                            .behaviour_mut()
                            .kademlia
                            .put_record(record, Quorum::One);
                    }
                    Command::GetVerifiedPeers {
                        signing_pk_hex,
                        respond_to,
                    } => {
                        let key = records::peer_record_key(&signing_pk_hex);
                        let id = swarm.behaviour_mut().kademlia.get_record(key);
                        loop_state.pending_kad.insert(
                            id,
                            KadGetState {
                                want_pk: signing_pk_hex,
                                found: Vec::new(),
                                respond_to: Some(respond_to),
                            },
                        );
                    }
                    Command::AddExternalAddr { addr } => {
                        swarm.add_external_address(addr);
                    }
                    Command::RendezvousRegister { server } => {
                        let _ = swarm
                            .behaviour_mut()
                            .rendezvous_client
                            .register(behaviour::rendezvous_namespace(), server, None);
                    }
                    Command::RendezvousDiscover { server, limit } => {
                        swarm.behaviour_mut().rendezvous_client.discover(
                            Some(behaviour::rendezvous_namespace()),
                            None,
                            limit,
                            server,
                        );
                    }
                    Command::TakeRendezvousDiscoveries { respond_to } => {
                        let _ = respond_to.send(std::mem::take(
                            &mut loop_state.rendezvous_discoveries,
                        ));
                    }
                    Command::ProvideChunk { cid } => {
                        let _ = swarm
                            .behaviour_mut()
                            .kademlia
                            .start_providing(RecordKey::new(&cid));
                    }
                    Command::GetProviders { cid, respond_to } => {
                        let id = swarm
                            .behaviour_mut()
                            .kademlia
                            .get_providers(RecordKey::new(&cid));
                        loop_state.pending_providers.insert(
                            id,
                            ProviderGetState {
                                found: HashSet::new(),
                                respond_to: Some(respond_to),
                            },
                        );
                    }
                    Command::BlockPeer { peer } => {
                        loop_state.blocked.insert(peer);
                        // Drop any live connection now; re-dials are refused
                        // above and inbound re-connects die at establishment.
                        let _ = swarm.disconnect_peer_id(peer);
                    }
                    Command::UnblockPeer { peer } => {
                        loop_state.blocked.remove(&peer);
                    }
                    Command::IsBlocked { peer, respond_to } => {
                        let _ = respond_to.send(loop_state.blocked.contains(&peer));
                    }
                    Command::PublishControl { data, respond_to } => {
                        let topic = libp2p::gossipsub::IdentTopic::new(CONTROL_TOPIC);
                        let result = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic, data)
                            .map(|id| hex::encode(id.0))
                            .map_err(|e| e.to_string());
                        let _ = respond_to.send(result);
                    }
                    Command::LivePeers { respond_to } => {
                        let _ = respond_to.send(
                            loop_state.liveness.live_peers(loop_state.heartbeat.timeout),
                        );
                    }
                    Command::IsLive { peer, respond_to } => {
                        let _ = respond_to
                            .send(loop_state.liveness.is_live(&peer, loop_state.heartbeat.timeout));
                    }
                    Command::TriggerRepair { cid } => {
                        start_repair_check(&mut swarm, &state, &mut loop_state, cid, true);
                    }
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, &state, &mut loop_state, event).await;
            }
            _ = heartbeat_tick.tick() => {
                // Liveness tick: prune dead entries, export the gauge, and
                // gossip our own heartbeat. Publish failures (solo node,
                // full queue) are routine — the next tick retries.
                loop_state.liveness.prune(loop_state.heartbeat.timeout);
                state.metrics.set_peers_live(
                    loop_state.liveness.live_count(loop_state.heartbeat.timeout) as u64,
                );
                loop_state.heartbeat_seq += 1;
                let hb = liveness::Heartbeat::new(
                    state.operator_id.clone(),
                    *swarm.local_peer_id(),
                    loop_state.heartbeat_seq,
                    liveness::now_ms(),
                    &state.signing_key,
                );
                if let Ok(data) = serde_json::to_vec(&liveness::ControlMessage::Heartbeat(hb)) {
                    let topic = libp2p::gossipsub::IdentTopic::new(CONTROL_TOPIC);
                    if swarm.behaviour_mut().gossipsub.publish(topic, data).is_ok() {
                        state.metrics.observe_heartbeat_sent();
                    }
                }
            }
            _ = repair_tick.tick() => {
                repair_scan(&mut swarm, &state, &mut loop_state);
            }
        }
    }
}

async fn handle_swarm_event(
    swarm: &mut Swarm<Behaviour>,
    state: &OperatorState,
    loop_state: &mut LoopState,
    event: SwarmEvent<behaviour::BehaviourEvent>,
) {
    match event {
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::Rpc(rpc_event)) => {
            use libp2p::request_response::{Event as ReqEvent, Message};
            match rpc_event {
                ReqEvent::Message { peer, message, .. } => match message {
                    Message::Request {
                        request, channel, ..
                    } => {
                        if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                            eprintln!(
                                "swarm: rpc inbound from {peer}: {:?}",
                                std::mem::discriminant(&request.body)
                            );
                        }
                        // DoS posture: the per-peer rate check runs BEFORE
                        // auth/serve so a flood cannot burn session/crypto
                        // work. Over-limit callers get a plain 429.
                        if !rpc_allowed(&mut loop_state.rpc_hits, peer, loop_state.rpc_limit) {
                            let response = OperatorRpcResponse::Err {
                                status: 429,
                                message: "rpc rate limit exceeded".to_string(),
                            };
                            let _ = swarm.behaviour_mut().rpc.send_response(channel, response);
                            return;
                        }
                        let response = serve::serve_operator_rpc(state, &request);
                        let _ = swarm.behaviour_mut().rpc.send_response(channel, response);
                    }
                    Message::Response {
                        request_id,
                        response,
                    } => {
                        if let Some(cid) = loop_state.repair.inflight.remove(&request_id) {
                            handle_repair_response(state, loop_state, cid, &response);
                            return;
                        }
                        if let Some(respond_to) = loop_state.pending.remove(&request_id) {
                            let _ = respond_to.send(Ok(response));
                        }
                    }
                },
                ReqEvent::OutboundFailure {
                    request_id, error, ..
                } => {
                    if let Some(cid) = loop_state.repair.inflight.remove(&request_id) {
                        // Transport failure (peer gone mid-push): paced
                        // retry; the next assessment sees new membership.
                        schedule_repair_backoff(state, loop_state, cid);
                        if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                            eprintln!("swarm: repair push transport failure: {error}");
                        }
                        return;
                    }
                    if let Some(respond_to) = loop_state.pending.remove(&request_id) {
                        let _ = respond_to.send(Err(SwarmError::RequestFailed(error.to_string())));
                    }
                }
                ReqEvent::InboundFailure { .. } | ReqEvent::ResponseSent { .. } => {}
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::Gossipsub(gossip_event)) => {
            use libp2p::gossipsub::Event as GossipEvent;
            // Strict validation mode: EVERY control message gets an
            // explicit verdict, or it stays pending in the mesh cache.
            // (We subscribe to exactly one topic, so no topic check.)
            if let GossipEvent::Message {
                propagation_source,
                message_id,
                message,
            } = gossip_event
            {
                let acceptance = accept_control_message(state, loop_state, &message.data);
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(&message_id, &propagation_source, acceptance);
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::Mdns(mdns_event)) => {
            use libp2p::mdns::Event as MdnsEvent;
            match mdns_event {
                MdnsEvent::Discovered(peers) => {
                    for (peer, addr) in peers {
                        // Block-list: excluded from routing AND dialing, so
                        // a listed LAN peer cannot re-enter via discovery.
                        if loop_state.blocked.contains(&peer) {
                            continue;
                        }
                        swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer, addr.clone());
                        let _ = swarm.dial(addr);
                    }
                }
                MdnsEvent::Expired(_) => {}
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::Identify(identify_event)) => {
            use libp2p::identify::Event as IdentifyEvent;
            if let IdentifyEvent::Received { peer_id, info, .. } = identify_event {
                if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                    eprintln!(
                        "swarm: identify from {peer_id}: protocols={:?} addrs={:?}",
                        info.protocols, info.listen_addrs
                    );
                }
                for addr in info.listen_addrs {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::Dcutr(dcutr_event)) => {
            loop_state.dcutr_upgrades.push(DcutrUpgrade {
                peer: dcutr_event.remote_peer_id,
                success: dcutr_event.result.is_ok(),
            });
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!(
                    "swarm: dcutr upgrade to {}: {:?}",
                    dcutr_event.remote_peer_id, dcutr_event.result
                );
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::AutonatClient(autonat_event)) => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!(
                    "swarm: autonat probe of {} via {}: {:?}",
                    autonat_event.tested_addr, autonat_event.server, autonat_event.result
                );
            }
        }
        SwarmEvent::ExternalAddrConfirmed { address } => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!("swarm: external address confirmed: {address}");
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::RelayClient(relay_event)) => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!("swarm: relay client event: {relay_event:?}");
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::RelayServer(relay_event)) => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!("swarm: relay server event: {relay_event:?}");
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::RendezvousClient(rz_event)) => {
            use libp2p::rendezvous::client::Event as RzEvent;
            match rz_event {
                RzEvent::Discovered { registrations, .. } => {
                    for registration in registrations {
                        let peer = registration.record.peer_id();
                        let addrs = registration.record.addresses().to_vec();
                        // Latest registration wins.
                        loop_state
                            .rendezvous_discoveries
                            .retain(|known| known.peer != peer);
                        loop_state
                            .rendezvous_discoveries
                            .push(RendezvousPeer { peer, addrs });
                    }
                }
                RzEvent::Expired { peer } => {
                    loop_state
                        .rendezvous_discoveries
                        .retain(|known| known.peer != peer);
                }
                RzEvent::Registered { .. }
                | RzEvent::RegisterFailed { .. }
                | RzEvent::DiscoverFailed { .. } => {
                    if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                        eprintln!("swarm: rendezvous client event: {rz_event:?}");
                    }
                }
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::RendezvousServer(rz_event)) => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!("swarm: rendezvous server event: {rz_event:?}");
            }
        }
        SwarmEvent::Behaviour(behaviour::BehaviourEvent::Kademlia(kad_event)) => {
            use libp2p::kad::{Event as KadEvent, GetProvidersOk, GetRecordOk, QueryResult};
            let KadEvent::OutboundQueryProgressed {
                id,
                result,
                stats,
                step,
                ..
            } = kad_event
            else {
                return;
            };
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!("swarm: kad query {id:?} stats={stats:?} step={step:?} => {result:?}");
            }
            match result {
                QueryResult::GetRecord(outcome) => {
                    match outcome {
                        Ok(GetRecordOk::FoundRecord(peer_record)) => {
                            if let Some(query) = loop_state.pending_kad.get_mut(&id) {
                                if let Some(descriptor) = records::decode_and_verify_peer_record(
                                    &query.want_pk,
                                    &peer_record.record.value,
                                ) {
                                    // Same record can arrive from several providers;
                                    // dedupe on the signature.
                                    if !query.found.iter().any(|known| {
                                        known.signature_hex == descriptor.signature_hex
                                    }) {
                                        query.found.push(descriptor);
                                    }
                                }
                            }
                        }
                        Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) | Err(_) => {
                            if let Some(query) = loop_state.pending_kad.remove(&id) {
                                if let Some(respond_to) = query.respond_to {
                                    let _ = respond_to.send(query.found);
                                }
                            }
                        }
                    }
                }
                QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders {
                    providers, ..
                })) => {
                    if let Some(query) = loop_state.pending_providers.get_mut(&id) {
                        query.found.extend(providers);
                    } else if let Some(query) = loop_state.repair.pending_queries.get_mut(&id) {
                        query.found.extend(providers);
                    }
                }
                QueryResult::GetProviders(
                    Ok(GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) | Err(_),
                ) => {
                    if let Some(query) = loop_state.pending_providers.remove(&id) {
                        if let Some(respond_to) = query.respond_to {
                            let mut found: Vec<PeerId> = query.found.into_iter().collect();
                            found.sort();
                            let _ = respond_to.send(found);
                        }
                    } else if let Some(query) = loop_state.repair.pending_queries.remove(&id) {
                        // Provider set complete (possibly empty on query
                        // error): assess against the live set.
                        finish_repair_check(swarm, state, loop_state, query.cid, query.found);
                    }
                }
                _ => {}
            }
        }
        SwarmEvent::ListenerClosed {
            listener_id,
            reason,
            ..
        } => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!("swarm: listener {listener_id:?} closed: {reason:?}");
            }
        }
        SwarmEvent::ListenerError {
            listener_id, error, ..
        } => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!("swarm: listener {listener_id:?} error: {error}");
            }
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint,
            ..
        } => {
            // Block-list backstop: covers inbound dials and outbound dials
            // that carried no /p2p suffix to attribute at dial time.
            if loop_state.blocked.contains(&peer_id) {
                swarm.close_connection(connection_id);
                return;
            }
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!("swarm: connected to {peer_id} conn={connection_id:?} via {endpoint:?}");
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            cause,
            ..
        } => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!(
                    "swarm: connection to {peer_id} conn={connection_id:?} closed: {cause:?}"
                );
            }
        }
        SwarmEvent::OutgoingConnectionError {
            peer_id,
            connection_id,
            error,
        } => {
            if std::env::var("CIPHERVAULT_SWARM_DEBUG").is_ok() {
                eprintln!(
                    "swarm: outgoing to {peer_id:?} conn={connection_id:?} failed: {error:?}"
                );
            }
        }
        SwarmEvent::NewListenAddr { .. }
        | SwarmEvent::Behaviour(_)
        | SwarmEvent::Dialing { .. }
        | SwarmEvent::IncomingConnectionError { .. } => {}
        _ => {}
    }
}

#[cfg(test)]
mod dos_tests {
    use super::*;

    #[test]
    fn rate_limiter_admits_up_to_limit_then_rejects() {
        let mut hits = HashMap::new();
        let peer = PeerId::random();
        let now = Instant::now();
        assert!(rpc_allowed_at(&mut hits, peer, 3, now));
        assert!(rpc_allowed_at(&mut hits, peer, 3, now));
        assert!(rpc_allowed_at(&mut hits, peer, 3, now));
        assert!(!rpc_allowed_at(&mut hits, peer, 3, now));
    }

    #[test]
    fn rate_limiter_window_expiry_readmits() {
        let mut hits = HashMap::new();
        let peer = PeerId::random();
        let start = Instant::now();
        assert!(rpc_allowed_at(&mut hits, peer, 1, start));
        assert!(!rpc_allowed_at(&mut hits, peer, 1, start));
        let later = start + RPC_RATE_WINDOW + Duration::from_millis(1);
        assert!(rpc_allowed_at(&mut hits, peer, 1, later));
    }

    #[test]
    fn rate_limiter_budgets_are_per_peer() {
        let mut hits = HashMap::new();
        let busy = PeerId::random();
        let quiet = PeerId::random();
        let now = Instant::now();
        assert!(rpc_allowed_at(&mut hits, busy, 1, now));
        assert!(!rpc_allowed_at(&mut hits, busy, 1, now));
        assert!(rpc_allowed_at(&mut hits, quiet, 1, now));
    }

    #[test]
    fn rate_limiter_zero_limit_rejects_everything() {
        let mut hits = HashMap::new();
        assert!(!rpc_allowed_at(
            &mut hits,
            PeerId::random(),
            0,
            Instant::now()
        ));
    }

    #[test]
    fn rate_limiter_full_tracker_fails_closed_for_new_peers() {
        let mut hits = HashMap::new();
        let now = Instant::now();
        let mut known = None;
        for _ in 0..MAX_RATE_TRACKED_PEERS {
            let peer = PeerId::random();
            hits.insert(peer, VecDeque::from([now]));
            known = Some(peer);
        }
        assert_eq!(hits.len(), MAX_RATE_TRACKED_PEERS);
        // A tracked peer with budget left is still admitted ...
        assert!(rpc_allowed_at(&mut hits, known.unwrap(), 50, now));
        // ... but a never-seen peer is rejected rather than growing the map.
        assert!(!rpc_allowed_at(&mut hits, PeerId::random(), 50, now));
        assert_eq!(hits.len(), MAX_RATE_TRACKED_PEERS);
    }

    #[test]
    fn rate_limiter_hygiene_evicts_idle_peers() {
        let mut hits = HashMap::new();
        let stale = Instant::now()
            .checked_sub(RPC_RATE_WINDOW + Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        for _ in 0..(MAX_RATE_TRACKED_PEERS / 2 + 1) {
            hits.insert(PeerId::random(), VecDeque::from([stale]));
        }
        // The next admission triggers hygiene, evicting every idle peer and
        // admitting the newcomer.
        assert!(rpc_allowed_at(
            &mut hits,
            PeerId::random(),
            50,
            Instant::now()
        ));
        assert_eq!(hits.len(), 1);
    }
}

#[cfg(test)]
mod join_tests {
    use super::*;

    #[test]
    fn repair_candidates_exclude_probationary_joiners() {
        // Pre-seed a probation record (no fleet env needed): the filter
        // reads standing, not tickets.
        let root = std::env::temp_dir().join(format!("cv-joinfilter-{}", rand::random::<u128>()));
        let key = ciphervault_crypto::generate_signing_key();
        drop(OperatorState::new(
            "test-op".into(),
            root.clone(),
            key.clone(),
        ));
        let now = chrono::Utc::now().timestamp() as u64;
        let mut records = HashMap::new();
        records.insert(
            "joiner-1".to_string(),
            crate::state::PeerMembership {
                status: crate::state::MembershipStatus::Probation,
                joined_utc: now,
                last_seen_utc: now,
                graduated_utc: None,
            },
        );
        std::fs::write(
            root.join("peer-membership.json"),
            serde_json::to_vec_pretty(&records).unwrap(),
        )
        .unwrap();
        let state = OperatorState::new("test-op".into(), root.clone(), key);
        assert!(state.is_probationary("joiner-1"));
        assert!(!state.is_probationary("full-1"));

        let mut liveness = liveness::LivenessTracker::new();
        let joiner_peer = PeerId::random();
        let full_peer = PeerId::random();
        liveness.note_heartbeat(joiner_peer, "joiner-1", 1);
        liveness.note_heartbeat(full_peer, "full-1", 1);
        let self_peer = PeerId::random();

        let mut live = vec![joiner_peer, full_peer, self_peer];
        retain_eligible_recipients(&mut live, &liveness, &state, self_peer);
        assert!(!live.contains(&joiner_peer));
        assert!(live.contains(&full_peer));
        assert!(live.contains(&self_peer));

        drop(state);
        std::fs::remove_dir_all(root).unwrap();
    }
}
