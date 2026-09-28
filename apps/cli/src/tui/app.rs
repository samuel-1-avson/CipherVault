use ciphervault_crypto::hsm::{
    list_pcsc_readers, probe_all as probe_hw_tokens, HardwareSecurityModule, HsmSlot,
    PcscHardwareToken,
};
use ciphervault_local_store::AccountStore;
use ciphervault_snapshot::fastcdc::{config_from_env, fastcdc_chunk, FastCdcConfig, GEAR_MATRIX};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tokio::task::JoinSet;

/// Upper bound for the FastCDC inspector. Files above this are not read into
/// memory; the tab reports the cap instead of freezing the UI on a huge read.
pub const MAX_INSPECT_BYTES: u64 = 64 * 1024 * 1024;

/// True when called inside a Tokio runtime. Background spawns no-op without
/// one so unit tests can construct `TuiApp` on a plain thread.
fn have_runtime() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiTab {
    Overview = 0,
    Files = 1,
    Snapshots = 2,
    Operators = 3,
    FastCdc = 4,
    HardwareToken = 5,
    Explorer = 6,
}

impl TuiTab {
    pub const ALL: [TuiTab; 7] = [
        TuiTab::Overview,
        TuiTab::Files,
        TuiTab::Snapshots,
        TuiTab::Operators,
        TuiTab::FastCdc,
        TuiTab::HardwareToken,
        TuiTab::Explorer,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            TuiTab::Overview => "1: Overview",
            TuiTab::Files => "2: Files",
            TuiTab::Snapshots => "3: History",
            TuiTab::Operators => "4: Operators",
            TuiTab::FastCdc => "5: FastCDC",
            TuiTab::HardwareToken => "6: Token",
            TuiTab::Explorer => "7: Explorer",
        }
    }

    pub fn from_index(idx: usize) -> Self {
        match idx % 7 {
            0 => TuiTab::Overview,
            1 => TuiTab::Files,
            2 => TuiTab::Snapshots,
            3 => TuiTab::Operators,
            4 => TuiTab::FastCdc,
            5 => TuiTab::HardwareToken,
            _ => TuiTab::Explorer,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct TrackedFileItem {
    pub path: String,
    pub size_bytes: u64,
    pub file_id_hex: String,
    pub exists_on_disk: bool,
}

#[derive(Debug, Clone)]
pub struct SnapshotItem {
    pub snapshot_id_hex: String,
    pub parent_id_hex: String,
    pub message: String,
    pub timestamp_rfc3339: String,
    pub files_count: usize,
    pub is_head: bool,
}

/// How many recent successful probes feed the displayed operator
/// latency. Raw per-poll samples on long/lossy paths swing several
/// hundred milliseconds poll to poll (retransmits, TLS re-handshakes);
/// the median of this window is what the table shows.
pub const LATENCY_WINDOW: usize = 5;

#[derive(Debug, Clone)]
pub struct OperatorHealthItem {
    pub endpoint: String,
    pub online: bool,
    pub latency_ms: u64,
    /// Recent successful probe samples; `latency_ms` is their median.
    /// Cleared on probe failure so recovery starts from a fresh baseline.
    pub latency_window: VecDeque<u64>,
    pub operator_id: String,
    pub retention_policy: Option<String>,
    /// Short diagnostic retained for the operator table when a probe fails.
    /// Keeping this separate from `online` prevents a timeout from looking
    /// like a generic/offline state with no actionable explanation.
    pub last_error: Option<String>,
}

/// How a FastCDC chunk boundary was decided by the real chunker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryKind {
    /// Cut inside the avg_size window: the boundary hash satisfies mask_s.
    MaskS,
    /// Cut past avg_size: the boundary hash satisfies mask_l.
    MaskL,
    /// No mask matched: forced cut at max_chunk (the size cap, or the end of
    /// input when fewer than max_size bytes remain).
    ForcedMax,
    /// Final remainder chunk (at most min_size bytes): no boundary decision.
    Tail,
}

impl BoundaryKind {
    pub fn label(self) -> &'static str {
        match self {
            BoundaryKind::MaskS => "S",
            BoundaryKind::MaskL => "L",
            BoundaryKind::ForcedMax => "max",
            BoundaryKind::Tail => "tail",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FastCdcTuiChunk {
    pub index: usize,
    pub offset: usize,
    pub length: usize,
    pub cid_hex: String,
    /// The actual Gear rolling-hash state at the cut point (replicated from
    /// the chunker recurrence), or "—" for tail chunks where no boundary
    /// decision was made.
    pub gear_fingerprint: String,
    pub boundary: BoundaryKind,
    pub entropy: f64,
    pub is_duplicate: bool,
}

#[derive(Debug, Clone)]
pub struct FastCdcTuiMetrics {
    pub source_name: String,
    pub profile: String,
    pub total_bytes: usize,
    pub total_chunks: usize,
    pub unique_chunks: usize,
    pub duplicate_chunks: usize,
    pub saved_bytes: usize,
    pub dedup_savings_pct: f64,
}

#[derive(Debug, Clone)]
pub struct SlotReadiness {
    pub ready: bool,
    pub detail: String,
}

impl SlotReadiness {
    fn missing() -> Self {
        Self {
            ready: false,
            detail: "no token".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HardwareTokenTuiStatus {
    pub readers: Vec<String>,
    pub token_attached: bool,
    pub probing: bool,
    pub token_label: Option<String>,
    pub slot_9c_ready: bool,
    pub slot_9d_ready: bool,
    pub slot_9c_detail: Option<String>,
    pub slot_9d_detail: Option<String>,
    pub last_error: Option<String>,
}

/// Outcome of a blocking PC/SC probe: responsive PIV token plus per-slot
/// metadata reads. Slots report ready only when the token answers a metadata
/// query with a non-empty public key.
#[derive(Debug, Clone)]
pub struct TokenProbeOutcome {
    pub readers: Vec<String>,
    pub attached: bool,
    pub token_label: Option<String>,
    pub slot_9c: SlotReadiness,
    pub slot_9d: SlotReadiness,
    pub error: Option<String>,
}

/// Point-in-time explorer fetch: cluster telemetry plus the signed checkpoint
/// feed, collected off the UI loop.
#[derive(Debug, Clone)]
pub struct ExplorerSnapshot {
    pub observed_at: String,
    pub operators: Vec<ExplorerOperatorRow>,
    pub feed_configured: bool,
    pub checkpoints: Vec<ExplorerCheckpointRow>,
    pub feed_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjectProbeOutcome {
    pub result: Option<ExplorerObjectResult>,
    pub status: String,
    pub level: StatusLevel,
}

#[derive(Debug, Clone)]
pub struct UpdateCheckOutcome {
    pub manual: bool,
    pub pending: Option<crate::PendingUpdate>,
    pub current: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum UpdateApplyOutcome {
    Installed,
    PendingRestart,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct InspectionOutput {
    pub metrics: FastCdcTuiMetrics,
    pub chunks: Vec<FastCdcTuiChunk>,
}

#[derive(Debug, Clone)]
pub enum InspectError {
    TooLarge(u64),
    Unreadable(String),
}

/// Completion values for background tasks. Every network call, blocking PC/SC
/// probe, and file inspection runs inside `TuiApp::tasks`; the event loop
/// drains these each tick and applies them via `apply_task_out`, so input and
/// rendering never stall on I/O.
pub enum TuiTaskOut {
    OperatorsPolled {
        endpoints: Vec<String>,
        probes: Vec<OperatorProbeResult>,
    },
    ExplorerRefreshed(ExplorerSnapshot),
    ObjectProbed(ObjectProbeOutcome),
    TokenProbed(TokenProbeOutcome),
    PushFinished(Result<String, String>),
    AnchorFinished(Result<String, String>),
    UpdateChecked(UpdateCheckOutcome),
    UpdateApplied {
        tag: String,
        pending: Option<crate::PendingUpdate>,
        outcome: UpdateApplyOutcome,
    },
    Inspected {
        index: usize,
        result: Result<InspectionOutput, InspectError>,
    },
}

/// Tables with keyboard navigation and scroll windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiTable {
    Files,
    Snapshots,
    Chunks,
    Checkpoints,
}

/// Cache key for the FastCDC inspector: same path, size, and mtime means the
/// same bytes were already chunked, so navigation back is free.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InspectCacheKey {
    path: PathBuf,
    size: u64,
    mtime: Option<SystemTime>,
}

#[derive(Debug, Clone, Default)]
pub struct ExplorerOperatorRow {
    pub display_name: String,
    pub operator_id: String,
    pub region: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub identity: String,
}

#[derive(Debug, Clone, Default)]
pub struct ExplorerCheckpointRow {
    pub network: String,
    pub commitment_hex: String,
    pub tx_hash_hex: Option<String>,
    pub finality_status: String,
    pub confirmations: Option<u64>,
    pub published_at_utc: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ExplorerReplicaRow {
    pub endpoint: String,
    pub operator_id: Option<String>,
    pub status: String,
    pub latency_ms: u64,
    pub size_bytes: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ExplorerObjectResult {
    pub cid_hex: String,
    pub present: usize,
    pub checked: usize,
    pub required: usize,
    pub satisfied: bool,
    pub replicas: Vec<ExplorerReplicaRow>,
}

pub struct TuiApp {
    pub active_tab: TuiTab,
    pub should_quit: bool,
    pub status_message: String,
    pub status_level: StatusLevel,
    pub last_status_update: Instant,

    // Vault metadata
    pub is_initialized: bool,
    pub vault_id_hex: String,
    pub active_epoch: u64,
    pub head_cid_hex: String,
    pub recovery_signing_pk_hex: String,
    pub recovery_locator_hex: String,

    // Optional account/session identity. The TUI never handles hosted vault
    // plaintext; it only reports and controls the local OS-protected account
    // session used by device-bound vault operations.
    pub account_configured: bool,
    pub account_id: String,
    pub account_authenticated: bool,
    pub account_session_device_id: Option<String>,
    pub account_session_expires_at_utc: Option<u64>,

    // Collections
    pub tracked_files: Vec<TrackedFileItem>,
    pub file_table_index: usize,
    pub file_scroll: usize,
    pub file_visible: usize,

    pub snapshots: Vec<SnapshotItem>,
    pub snapshot_table_index: usize,
    pub snapshot_scroll: usize,
    pub snapshot_visible: usize,

    pub operators: Vec<OperatorHealthItem>,
    pub operator_table_index: usize,
    operator_http: reqwest::Client,

    // FastCDC inspector
    pub fastcdc_metrics: Option<FastCdcTuiMetrics>,
    pub fastcdc_chunks: Vec<FastCdcTuiChunk>,
    pub chunk_table_index: usize,
    pub chunk_scroll: usize,
    pub chunk_visible: usize,
    /// Explains an empty inspector (file too large, unreadable) so the tab
    /// never blames "no tracked files" for a cap skip.
    pub fastcdc_notice: Option<String>,
    inspect_cache_key: Option<InspectCacheKey>,

    // Token
    pub token_status: HardwareTokenTuiStatus,

    // Network explorer (mirrors the public web explorer: cluster telemetry,
    // checkpoint feed, and presence-only object quorum lookup)
    pub explorer_observed_at: String,
    pub explorer_operators: Vec<ExplorerOperatorRow>,
    pub explorer_checkpoints: Vec<ExplorerCheckpointRow>,
    pub explorer_checkpoint_index: usize,
    pub explorer_checkpoint_scroll: usize,
    pub explorer_checkpoint_visible: usize,
    pub explorer_feed_configured: bool,
    pub explorer_object: Option<ExplorerObjectResult>,

    // Background tasks plus one in-flight guard per task kind so keypresses
    // and poll ticks never stack duplicate work.
    tasks: JoinSet<TuiTaskOut>,
    pub poll_in_flight: bool,
    pub explorer_in_flight: bool,
    pub token_in_flight: bool,
    pub object_probe_in_flight: bool,
    pub push_in_flight: bool,
    pub anchor_in_flight: bool,
    pub update_in_flight: bool,
    pub inspect_in_flight: Option<usize>,

    // Self-update (shared engine with `ciphervault update`)
    pub update_check_done: bool,
    pub update_pending: Option<crate::PendingUpdate>,
    pub show_update_modal: bool,
    pub update_in_progress: bool,

    // Modal dialogs
    pub show_track_modal: bool,
    pub track_input_buffer: String,
    pub show_explorer_search_modal: bool,
    pub explorer_search_buffer: String,
    pub show_help: bool,

    // Background polling
    pub last_poll: Instant,
    pub poll_interval: Duration,
    /// Set by manual refresh ([r]): the next operator-poll completion reports
    /// its result on the status line instead of staying silent.
    pub refresh_echo: bool,
}

impl TuiApp {
    pub fn new(poll_interval: Duration) -> Self {
        let mut app = Self {
            active_tab: TuiTab::Overview,
            should_quit: false,
            status_message: "Ready. Press [?] for keybindings, [Tab/1-7] to navigate.".into(),
            status_level: StatusLevel::Info,
            last_status_update: Instant::now(),

            is_initialized: false,
            vault_id_hex: "Not Initialized".into(),
            active_epoch: 0,
            head_cid_hex: "None".into(),
            recovery_signing_pk_hex: "None".into(),
            recovery_locator_hex: "None".into(),

            account_configured: false,
            account_id: "Not configured".into(),
            account_authenticated: false,
            account_session_device_id: None,
            account_session_expires_at_utc: None,

            tracked_files: Vec::new(),
            file_table_index: 0,
            file_scroll: 0,
            file_visible: 10,

            snapshots: Vec::new(),
            snapshot_table_index: 0,
            snapshot_scroll: 0,
            snapshot_visible: 10,

            operators: Vec::new(),
            operator_table_index: 0,
            operator_http: build_operator_http_client(),

            fastcdc_metrics: None,
            fastcdc_chunks: Vec::new(),
            chunk_table_index: 0,
            chunk_scroll: 0,
            chunk_visible: 10,
            fastcdc_notice: None,
            inspect_cache_key: None,

            token_status: HardwareTokenTuiStatus {
                readers: Vec::new(),
                token_attached: false,
                probing: false,
                token_label: None,
                slot_9c_ready: false,
                slot_9d_ready: false,
                slot_9c_detail: None,
                slot_9d_detail: None,
                last_error: None,
            },

            explorer_observed_at: "Never".into(),
            explorer_operators: Vec::new(),
            explorer_checkpoints: Vec::new(),
            explorer_checkpoint_index: 0,
            explorer_checkpoint_scroll: 0,
            explorer_checkpoint_visible: 10,
            explorer_feed_configured: false,
            explorer_object: None,

            tasks: JoinSet::new(),
            poll_in_flight: false,
            explorer_in_flight: false,
            token_in_flight: false,
            object_probe_in_flight: false,
            push_in_flight: false,
            anchor_in_flight: false,
            update_in_flight: false,
            inspect_in_flight: None,

            update_check_done: false,
            update_pending: None,
            show_update_modal: false,
            update_in_progress: false,

            show_track_modal: false,
            track_input_buffer: String::new(),
            show_explorer_search_modal: false,
            explorer_search_buffer: String::new(),
            show_help: false,

            last_poll: Instant::now() - poll_interval, // trigger immediate poll
            poll_interval,
            refresh_echo: false,
        };

        app.refresh_local_state();
        app
    }

    pub fn set_status(&mut self, message: impl Into<String>, level: StatusLevel) {
        self.status_message = message.into();
        self.status_level = level;
        self.last_status_update = Instant::now();
    }

    pub fn next_tab(&mut self) {
        let current_idx = self.active_tab as usize;
        self.active_tab = TuiTab::from_index(current_idx + 1);
    }

    pub fn previous_tab(&mut self) {
        let current_idx = self.active_tab as usize;
        let next_idx = if current_idx == 0 { 6 } else { current_idx - 1 };
        self.active_tab = TuiTab::from_index(next_idx);
    }

    pub fn switch_tab(&mut self, tab: TuiTab) {
        self.active_tab = tab;
    }

    pub fn refresh_local_state(&mut self) {
        self.refresh_account_state();
        let store_result = crate::get_vault_store();
        match store_result {
            Ok(store) => {
                self.is_initialized = true;
                if let Ok(id) = store.get_vault_id() {
                    self.vault_id_hex = hex::encode(id);
                }
                if let Ok((_dev_id, _, _counter, epoch)) = store.get_device_state() {
                    self.active_epoch = epoch;
                }
                if let Ok(head_opt) = store.get_active_head() {
                    self.head_cid_hex = head_opt
                        .map(|h| hex::encode(&h.snapshot_id))
                        .unwrap_or_else(|| "Genesis (No commits)".into());
                }
                if let Ok(desc) = store.get_recovery_descriptors() {
                    self.recovery_signing_pk_hex = hex::encode(desc.0);
                    self.recovery_locator_hex = hex::encode(desc.2);
                }

                // Tracked files
                let mut tracked_count = 0;
                if let Ok(files) = store.list_tracked_files() {
                    tracked_count = files.len();
                    self.tracked_files = files
                        .into_iter()
                        .map(|(p, file_id)| {
                            let exists = p.exists();
                            let size = if exists {
                                fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
                            } else {
                                0
                            };
                            TrackedFileItem {
                                path: p.to_string_lossy().replace('\\', "/"),
                                size_bytes: size,
                                file_id_hex: hex::encode(&file_id[..4]),
                                exists_on_disk: exists,
                            }
                        })
                        .collect();
                }

                // Snapshots DAG
                if let Ok(snaps) = store.list_snapshots() {
                    let head_cid_hex = self.head_cid_hex.clone();
                    self.snapshots = snaps
                        .into_iter()
                        .map(|s| {
                            let id_hex = hex::encode(&s.snapshot_id);
                            let parent_hex = if s.parent_snapshot_ids.is_empty() {
                                "Genesis".to_string()
                            } else {
                                s.parent_snapshot_ids
                                    .iter()
                                    .map(|p| hex::encode(&p[..p.len().min(4)]))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            };
                            let dt = chrono::DateTime::from_timestamp(
                                s.advisory_timestamp_utc as i64,
                                0,
                            )
                            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "Unknown".into());
                            let is_h = id_hex == head_cid_hex;
                            SnapshotItem {
                                snapshot_id_hex: id_hex,
                                parent_id_hex: parent_hex,
                                message: format!(
                                    "Epoch #{} (Counter: {}, Manifest: {} B)",
                                    s.epoch, s.device_counter, s.encrypted_manifest_len
                                ),
                                timestamp_rfc3339: dt,
                                files_count: tracked_count,
                                is_head: is_h,
                            }
                        })
                        .collect();
                }
            }
            Err(_) => {
                self.is_initialized = false;
                self.vault_id_hex = "Not Initialized (Run 'ciphervault init')".into();
            }
        }

        // Reuse the CLI's canonical operator resolution so the TUI honors
        // CIPHERVAULT_OPERATORS, the vault-local config, and the production
        // defaults in exactly the same order as push/audit/repair commands.
        let configured_ops = crate::get_configured_operators();
        let endpoints_changed = self.operators.len() != configured_ops.len()
            || self
                .operators
                .iter()
                .zip(configured_ops.iter())
                .any(|(current, configured)| current.endpoint != *configured);
        if endpoints_changed {
            self.operators = configured_ops
                .into_iter()
                .map(|endpoint| OperatorHealthItem {
                    endpoint,
                    online: false,
                    latency_ms: 0,
                    latency_window: VecDeque::new(),
                    operator_id: "--".into(),
                    retention_policy: None,
                    last_error: None,
                })
                .collect();
        }
        if self.operator_table_index >= self.operators.len() {
            self.operator_table_index = 0;
        }

        // Hardware token state refreshes in a background task: PC/SC calls
        // block and must never run on the event loop.
        self.spawn_token_probe();
        self.clamp_table_indices();

        // Inspect the selected tracked file for FastCDC (cache-aware; the
        // chunking itself runs in a background task).
        self.request_inspection();
    }

    /// Clamps every navigable table index and scroll offset after the
    /// underlying collections change size.
    pub fn clamp_table_indices(&mut self) {
        if self.file_table_index >= self.tracked_files.len() {
            self.file_table_index = 0;
        }
        if self.snapshot_table_index >= self.snapshots.len() {
            self.snapshot_table_index = 0;
        }
        if self.chunk_table_index >= self.fastcdc_chunks.len() {
            self.chunk_table_index = 0;
        }
        if self.explorer_checkpoint_index >= self.explorer_checkpoints.len() {
            self.explorer_checkpoint_index = 0;
        }
        self.file_scroll = scroll_offset_for(
            self.file_scroll,
            self.file_table_index,
            self.tracked_files.len(),
            self.file_visible,
        );
        self.snapshot_scroll = scroll_offset_for(
            self.snapshot_scroll,
            self.snapshot_table_index,
            self.snapshots.len(),
            self.snapshot_visible,
        );
        self.chunk_scroll = scroll_offset_for(
            self.chunk_scroll,
            self.chunk_table_index,
            self.fastcdc_chunks.len(),
            self.chunk_visible,
        );
        self.explorer_checkpoint_scroll = scroll_offset_for(
            self.explorer_checkpoint_scroll,
            self.explorer_checkpoint_index,
            self.explorer_checkpoints.len(),
            self.explorer_checkpoint_visible,
        );
    }

    fn refresh_account_state(&mut self) {
        let Ok(account) = AccountStore::open(None) else {
            self.account_configured = false;
            self.account_id = "Not configured".into();
            self.account_authenticated = false;
            self.account_session_device_id = None;
            self.account_session_expires_at_utc = None;
            return;
        };
        let session = account.session_status();
        self.account_configured = true;
        self.account_id = account.account_id().to_string();
        self.account_authenticated = session.authenticated;
        self.account_session_device_id = session.device_id_hex;
        self.account_session_expires_at_utc = session.expires_at_utc;
    }

    /// Unlock the local account key and establish a short-lived session. A
    /// linked vault binds the session to its current device identity; an
    /// unlinked account remains account-only until the vault is linked.
    pub fn login_local_account(&mut self) {
        let result = AccountStore::open(None).and_then(|account| {
            let device = crate::current_device_identity().ok();
            let device_id = device
                .as_ref()
                .and_then(|(vault_id, device_id, device_pk)| {
                    (account.is_vault_linked(vault_id)
                        && account.is_device_active(device_id, device_pk))
                    .then_some(device_id.as_str())
                });
            account.login(device_id)
        });
        match result {
            Ok(session) => {
                self.refresh_account_state();
                let binding = if session.device_id_hex.is_some() {
                    "device-bound"
                } else {
                    "account-only"
                };
                self.set_status(
                    format!("✓ Local account session established ({binding})."),
                    StatusLevel::Success,
                );
            }
            Err(error) => self.set_status(
                format!("Account sign-in failed: {error}"),
                StatusLevel::Error,
            ),
        }
    }

    pub fn logout_local_account(&mut self) {
        match AccountStore::open(None).and_then(|account| account.logout()) {
            Ok(()) => {
                self.refresh_account_state();
                self.set_status("✓ Local account session revoked.", StatusLevel::Success);
            }
            Err(error) => self.set_status(
                format!("Account sign-out failed: {error}"),
                StatusLevel::Error,
            ),
        }
    }

    /// Moves the selection one row down with wraparound, keeping the
    /// selected row inside the visible scroll window.
    pub fn select_next(&mut self, table: TuiTable) {
        match table {
            TuiTable::Files => {
                if self.tracked_files.is_empty() {
                    return;
                }
                self.file_table_index = (self.file_table_index + 1) % self.tracked_files.len();
                self.file_scroll = scroll_offset_for(
                    self.file_scroll,
                    self.file_table_index,
                    self.tracked_files.len(),
                    self.file_visible,
                );
                self.request_inspection();
            }
            TuiTable::Snapshots => {
                if self.snapshots.is_empty() {
                    return;
                }
                self.snapshot_table_index = (self.snapshot_table_index + 1) % self.snapshots.len();
                self.snapshot_scroll = scroll_offset_for(
                    self.snapshot_scroll,
                    self.snapshot_table_index,
                    self.snapshots.len(),
                    self.snapshot_visible,
                );
            }
            TuiTable::Chunks => {
                if self.fastcdc_chunks.is_empty() {
                    return;
                }
                self.chunk_table_index = (self.chunk_table_index + 1) % self.fastcdc_chunks.len();
                self.chunk_scroll = scroll_offset_for(
                    self.chunk_scroll,
                    self.chunk_table_index,
                    self.fastcdc_chunks.len(),
                    self.chunk_visible,
                );
            }
            TuiTable::Checkpoints => {
                if self.explorer_checkpoints.is_empty() {
                    return;
                }
                self.explorer_checkpoint_index =
                    (self.explorer_checkpoint_index + 1) % self.explorer_checkpoints.len();
                self.explorer_checkpoint_scroll = scroll_offset_for(
                    self.explorer_checkpoint_scroll,
                    self.explorer_checkpoint_index,
                    self.explorer_checkpoints.len(),
                    self.explorer_checkpoint_visible,
                );
            }
        }
    }

    /// Moves the selection one row up with wraparound, keeping the selected
    /// row inside the visible scroll window.
    pub fn select_prev(&mut self, table: TuiTable) {
        match table {
            TuiTable::Files => {
                if self.tracked_files.is_empty() {
                    return;
                }
                self.file_table_index = if self.file_table_index == 0 {
                    self.tracked_files.len() - 1
                } else {
                    self.file_table_index - 1
                };
                self.file_scroll = scroll_offset_for(
                    self.file_scroll,
                    self.file_table_index,
                    self.tracked_files.len(),
                    self.file_visible,
                );
                self.request_inspection();
            }
            TuiTable::Snapshots => {
                if self.snapshots.is_empty() {
                    return;
                }
                self.snapshot_table_index = if self.snapshot_table_index == 0 {
                    self.snapshots.len() - 1
                } else {
                    self.snapshot_table_index - 1
                };
                self.snapshot_scroll = scroll_offset_for(
                    self.snapshot_scroll,
                    self.snapshot_table_index,
                    self.snapshots.len(),
                    self.snapshot_visible,
                );
            }
            TuiTable::Chunks => {
                if self.fastcdc_chunks.is_empty() {
                    return;
                }
                self.chunk_table_index = if self.chunk_table_index == 0 {
                    self.fastcdc_chunks.len() - 1
                } else {
                    self.chunk_table_index - 1
                };
                self.chunk_scroll = scroll_offset_for(
                    self.chunk_scroll,
                    self.chunk_table_index,
                    self.fastcdc_chunks.len(),
                    self.chunk_visible,
                );
            }
            TuiTable::Checkpoints => {
                if self.explorer_checkpoints.is_empty() {
                    return;
                }
                self.explorer_checkpoint_index = if self.explorer_checkpoint_index == 0 {
                    self.explorer_checkpoints.len() - 1
                } else {
                    self.explorer_checkpoint_index - 1
                };
                self.explorer_checkpoint_scroll = scroll_offset_for(
                    self.explorer_checkpoint_scroll,
                    self.explorer_checkpoint_index,
                    self.explorer_checkpoints.len(),
                    self.explorer_checkpoint_visible,
                );
            }
        }
    }

    /// Refreshes the FastCDC inspector for the selected file. Re-inspection is
    /// skipped when path, size, and mtime match the cached inspection, and the
    /// chunking itself runs in a background task so key navigation never
    /// stalls on file I/O.
    pub fn request_inspection(&mut self) {
        if self.tracked_files.is_empty() {
            self.fastcdc_metrics = None;
            self.fastcdc_chunks.clear();
            self.fastcdc_notice = None;
            self.inspect_cache_key = None;
            return;
        }
        if self.file_table_index >= self.tracked_files.len() {
            self.file_table_index = 0;
        }
        let index = self.file_table_index;
        let path = PathBuf::from(&self.tracked_files[index].path);
        let key = fs::metadata(&path).ok().map(|meta| InspectCacheKey {
            path: path.clone(),
            size: meta.len(),
            mtime: meta.modified().ok(),
        });
        if key.is_some() && key == self.inspect_cache_key && self.fastcdc_metrics.is_some() {
            return;
        }
        if self.inspect_in_flight == Some(index) {
            return;
        }
        if !have_runtime() {
            return;
        }
        self.fastcdc_notice = None;
        self.inspect_in_flight = Some(index);
        // Cache the pre-hash key: a file that changes mid-hash re-inspects on
        // the next request instead of pinning stale chunk data.
        self.inspect_cache_key = key;
        self.tasks.spawn(async move {
            let result = tokio::task::spawn_blocking(move || compute_inspection(&path))
                .await
                .unwrap_or_else(|error| Err(InspectError::Unreadable(error.to_string())));
            TuiTaskOut::Inspected { index, result }
        });
    }

    /// Probes every configured operator in a background task. Results land
    /// via `TuiTaskOut::OperatorsPolled`; the loop keeps rendering and reading
    /// input while the requests are in flight.
    pub fn spawn_operator_poll(&mut self) {
        if self.poll_in_flight || self.operators.is_empty() || !have_runtime() {
            return;
        }
        self.poll_in_flight = true;
        let client = self.operator_http.clone();
        let endpoints: Vec<String> = self
            .operators
            .iter()
            .map(|op| op.endpoint.clone())
            .collect();
        self.tasks.spawn(async move {
            let probes = fetch_operator_probes(client, endpoints.clone()).await;
            TuiTaskOut::OperatorsPolled { endpoints, probes }
        });
    }

    /// Refreshes cluster telemetry and the signed checkpoint feed in a
    /// background task. Telemetry is cached for 30 s and finality for 60 s.
    pub fn spawn_explorer_refresh(&mut self) {
        if self.explorer_in_flight || !have_runtime() {
            return;
        }
        self.explorer_in_flight = true;
        self.tasks
            .spawn(async move { TuiTaskOut::ExplorerRefreshed(fetch_explorer_snapshot().await) });
    }

    /// Presence-only object lookup in a background task: PoS-challenge every
    /// configured operator for the CID in the search buffer. Object bytes are
    /// never fetched.
    pub fn spawn_object_probe(&mut self) {
        if self.object_probe_in_flight {
            self.set_status("Object probe already running...", StatusLevel::Info);
            return;
        }
        if !have_runtime() {
            return;
        }
        let query = self.explorer_search_buffer.trim().to_string();
        self.object_probe_in_flight = true;
        self.set_status(
            "Probing operators for object presence...",
            StatusLevel::Info,
        );
        self.tasks
            .spawn(async move { TuiTaskOut::ObjectProbed(probe_object_presence(query).await) });
    }

    /// Probes PC/SC readers and PIV slot metadata in a background task. The
    /// underlying calls block on smartcard I/O and must never run on the loop.
    pub fn spawn_token_probe(&mut self) {
        if self.token_in_flight || !have_runtime() {
            return;
        }
        self.token_in_flight = true;
        self.token_status.probing = true;
        self.tasks.spawn(async move {
            let outcome = tokio::task::spawn_blocking(probe_token_blocking)
                .await
                .unwrap_or_else(|error| TokenProbeOutcome {
                    readers: Vec::new(),
                    attached: false,
                    token_label: None,
                    slot_9c: SlotReadiness::missing(),
                    slot_9d: SlotReadiness::missing(),
                    error: Some(error.to_string()),
                });
            TuiTaskOut::TokenProbed(outcome)
        });
    }

    /// Runs the quick snapshot push in a background task.
    pub fn spawn_push(&mut self) {
        if self.push_in_flight {
            self.set_status("Snapshot push already running...", StatusLevel::Info);
            return;
        }
        if !have_runtime() {
            return;
        }
        self.push_in_flight = true;
        self.set_status(
            "Pushing encrypted snapshot across operators...",
            StatusLevel::Info,
        );
        self.tasks.spawn(async move {
            TuiTaskOut::PushFinished(execute_quick_push().await.map_err(|e| e.to_string()))
        });
    }

    /// Runs the quick L2 anchor in a background task.
    pub fn spawn_anchor(&mut self) {
        if self.anchor_in_flight {
            self.set_status("L2 anchor already running...", StatusLevel::Info);
            return;
        }
        if !have_runtime() {
            return;
        }
        self.anchor_in_flight = true;
        self.set_status(
            "Submitting state commitment to Arbitrum L2 relayer...",
            StatusLevel::Info,
        );
        self.tasks.spawn(async move {
            TuiTaskOut::AnchorFinished(execute_quick_anchor().await.map_err(|e| e.to_string()))
        });
    }

    /// One-shot update check in a background task. The boot check is silent
    /// on failure (offline is normal) and opens the update modal when a newer
    /// release exists; the manual check always reports its outcome.
    pub fn spawn_update_check(&mut self, manual: bool) {
        if self.update_in_flight || !have_runtime() {
            return;
        }
        self.update_check_done = true;
        self.update_in_flight = true;
        if manual {
            self.set_status("Checking for CipherVault updates...", StatusLevel::Info);
        }
        self.tasks.spawn(async move {
            let outcome = match crate::check_for_updates().await {
                Ok(check) => UpdateCheckOutcome {
                    manual,
                    pending: check.pending,
                    current: check.current,
                    error: None,
                },
                Err(error) => UpdateCheckOutcome {
                    manual,
                    pending: None,
                    current: String::new(),
                    error: Some(error.to_string()),
                },
            };
            TuiTaskOut::UpdateChecked(outcome)
        });
    }

    /// Installs the pending update in a background task. The running process
    /// keeps the old binary: a restart is always required.
    pub fn spawn_update_apply(&mut self) {
        if self.update_in_flight {
            return;
        }
        let Some(pending) = self.update_pending.take() else {
            self.set_status("No update is pending.", StatusLevel::Warning);
            return;
        };
        if !have_runtime() {
            self.update_pending = Some(pending);
            return;
        }
        self.update_in_flight = true;
        self.update_in_progress = true;
        self.set_status("Installing update in the background...", StatusLevel::Info);
        self.tasks.spawn(async move {
            let tag = pending.tag.clone();
            // Stage progress cannot touch the UI from here; start and finish
            // statuses bracket the install instead.
            let outcome = match crate::apply_update(&pending, |_| {}).await {
                Ok(crate::InstallOutcome::Installed) => UpdateApplyOutcome::Installed,
                Ok(crate::InstallOutcome::PendingRestart) => UpdateApplyOutcome::PendingRestart,
                Err(error) => UpdateApplyOutcome::Failed(error.to_string()),
            };
            let pending = match &outcome {
                UpdateApplyOutcome::Failed(_) => Some(pending),
                _ => None,
            };
            TuiTaskOut::UpdateApplied {
                tag,
                pending,
                outcome,
            }
        });
    }

    /// Drains finished background tasks, applying each completion. Called on
    /// every event-loop tick; never blocks.
    pub fn drain_tasks(&mut self) {
        while let Some(joined) = self.tasks.try_join_next() {
            match joined {
                Ok(out) => self.apply_task_out(out),
                Err(error) => {
                    self.poll_in_flight = false;
                    self.explorer_in_flight = false;
                    self.token_in_flight = false;
                    self.object_probe_in_flight = false;
                    self.push_in_flight = false;
                    self.anchor_in_flight = false;
                    self.update_in_flight = false;
                    self.inspect_in_flight = None;
                    self.token_status.probing = false;
                    self.update_in_progress = false;
                    self.set_status(
                        format!("Background task failed: {error}"),
                        StatusLevel::Error,
                    );
                }
            }
        }
    }

    /// Applies one background-task completion to the visible state. Stale
    /// completions (endpoint list changed, newer inspection requested) are
    /// dropped so late results never overwrite fresher state.
    pub fn apply_task_out(&mut self, out: TuiTaskOut) {
        match out {
            TuiTaskOut::OperatorsPolled { endpoints, probes } => {
                self.poll_in_flight = false;
                let current: Vec<&str> = self
                    .operators
                    .iter()
                    .map(|op| op.endpoint.as_str())
                    .collect();
                let fresh = endpoints.len() == current.len()
                    && endpoints.iter().zip(current.iter()).all(|(a, b)| a == b);
                if !fresh {
                    return;
                }
                let before: Vec<bool> = self.operators.iter().map(|op| op.online).collect();
                for (op, probe) in self.operators.iter_mut().zip(probes) {
                    op.online = probe.online;
                    if probe.online {
                        op.latency_window.push_back(probe.latency_ms);
                        while op.latency_window.len() > LATENCY_WINDOW {
                            op.latency_window.pop_front();
                        }
                        op.latency_ms = median_latency(&op.latency_window);
                    } else {
                        op.latency_window.clear();
                        op.latency_ms = probe.latency_ms;
                    }
                    op.last_error = probe.error;
                    if let Some(operator_id) = probe.operator_id {
                        op.operator_id = operator_id;
                    }
                    if let Some(retention_policy) = probe.retention_policy {
                        op.retention_policy = Some(retention_policy);
                    }
                }
                let after: Vec<bool> = self.operators.iter().map(|op| op.online).collect();
                if self.refresh_echo {
                    self.refresh_echo = false;
                    let up = after.iter().filter(|online| **online).count();
                    let total = after.len();
                    let level = if total > 0 && up == total {
                        StatusLevel::Success
                    } else if up > 0 {
                        StatusLevel::Warning
                    } else {
                        StatusLevel::Error
                    };
                    self.set_status(
                        format!("✓ Refresh finished: {up}/{total} operators responding."),
                        level,
                    );
                } else if before != after {
                    let up = after.iter().filter(|online| **online).count();
                    let total = after.len();
                    let flap: Vec<String> = self
                        .operators
                        .iter()
                        .zip(before.iter())
                        .filter(|(op, was)| op.online != **was)
                        .map(|(op, _)| {
                            format!(
                                "{} {}",
                                short_operator_label(&op.endpoint, &op.operator_id),
                                if op.online { "recovered" } else { "went dark" }
                            )
                        })
                        .collect();
                    let (level, detail) = if up == total {
                        (StatusLevel::Success, "all responding".to_string())
                    } else if up == 0 {
                        (StatusLevel::Error, "none responding".to_string())
                    } else {
                        (StatusLevel::Warning, format!("{up}/{total} responding"))
                    };
                    self.set_status(
                        format!("Operator poll: {detail} ({}).", flap.join(", ")),
                        level,
                    );
                }
            }
            TuiTaskOut::ExplorerRefreshed(snapshot) => {
                self.explorer_in_flight = false;
                self.explorer_observed_at = snapshot.observed_at;
                self.explorer_operators = snapshot.operators;
                self.explorer_feed_configured = snapshot.feed_configured;
                self.explorer_checkpoints = snapshot.checkpoints;
                if let Some(error) = snapshot.feed_error {
                    self.set_status(
                        format!("Checkpoint feed unavailable: {error}"),
                        StatusLevel::Warning,
                    );
                }
                self.clamp_table_indices();
            }
            TuiTaskOut::ObjectProbed(outcome) => {
                self.object_probe_in_flight = false;
                self.explorer_object = outcome.result;
                self.set_status(outcome.status, outcome.level);
            }
            TuiTaskOut::TokenProbed(outcome) => {
                self.token_in_flight = false;
                self.token_status.probing = false;
                self.token_status.readers = outcome.readers;
                self.token_status.token_attached = outcome.attached;
                self.token_status.token_label = outcome.token_label;
                self.token_status.slot_9c_ready = outcome.slot_9c.ready;
                self.token_status.slot_9d_ready = outcome.slot_9d.ready;
                self.token_status.slot_9c_detail = Some(outcome.slot_9c.detail);
                self.token_status.slot_9d_detail = Some(outcome.slot_9d.detail);
                self.token_status.last_error = outcome.error;
            }
            TuiTaskOut::PushFinished(result) => {
                self.push_in_flight = false;
                match result {
                    Ok(message) => {
                        self.set_status(message, StatusLevel::Success);
                        self.refresh_local_state();
                    }
                    Err(error) => self
                        .set_status(format!("Snapshot push failed: {error}"), StatusLevel::Error),
                }
            }
            TuiTaskOut::AnchorFinished(result) => {
                self.anchor_in_flight = false;
                match result {
                    Ok(message) => {
                        self.set_status(message, StatusLevel::Success);
                        self.refresh_local_state();
                    }
                    Err(error) => {
                        self.set_status(format!("L2 anchor failed: {error}"), StatusLevel::Error)
                    }
                }
            }
            TuiTaskOut::UpdateChecked(outcome) => {
                self.update_in_flight = false;
                if let Some(error) = outcome.error {
                    if outcome.manual {
                        self.set_status(
                            format!("Update check failed: {error}"),
                            StatusLevel::Error,
                        );
                    }
                    return;
                }
                match outcome.pending {
                    Some(pending) => {
                        let tag = pending.tag.clone();
                        self.update_pending = Some(pending);
                        self.show_update_modal = true;
                        if outcome.manual {
                            self.set_status(
                                format!("Update available: {tag}."),
                                StatusLevel::Warning,
                            );
                        }
                    }
                    None => {
                        if outcome.manual {
                            self.set_status(
                                format!("Already on the latest release (v{}).", outcome.current),
                                StatusLevel::Success,
                            );
                        }
                    }
                }
            }
            TuiTaskOut::UpdateApplied {
                tag,
                pending,
                outcome,
            } => {
                self.update_in_flight = false;
                self.update_in_progress = false;
                match outcome {
                    UpdateApplyOutcome::Installed => {
                        self.show_update_modal = false;
                        self.set_status(
                            format!("✓ Updated to {tag}. Quit ([q]) and relaunch to use it."),
                            StatusLevel::Success,
                        );
                    }
                    UpdateApplyOutcome::PendingRestart => {
                        // Windows: the swap helper can only replace the binary
                        // after this process exits. Lingering would stall it,
                        // so quit now; the user relaunches into the new
                        // version.
                        self.show_update_modal = false;
                        self.set_status(
                            format!(
                                "✓ {tag} staged. Quitting now so Windows can install it — relaunch."
                            ),
                            StatusLevel::Success,
                        );
                        self.should_quit = true;
                    }
                    UpdateApplyOutcome::Failed(error) => {
                        self.update_pending = pending;
                        self.set_status(format!("Update failed: {error}"), StatusLevel::Error);
                    }
                }
            }
            TuiTaskOut::Inspected { index, result } => {
                if self.inspect_in_flight != Some(index) {
                    return;
                }
                self.inspect_in_flight = None;
                match result {
                    Ok(output) => {
                        self.fastcdc_metrics = Some(output.metrics);
                        self.fastcdc_chunks = output.chunks;
                        self.fastcdc_notice = None;
                        self.chunk_table_index = 0;
                        self.chunk_scroll = 0;
                    }
                    Err(InspectError::TooLarge(bytes)) => {
                        self.fastcdc_metrics = None;
                        self.fastcdc_chunks.clear();
                        self.inspect_cache_key = None;
                        let notice = format!(
                            "Selected file is {} (inspector cap {}): not loaded.",
                            format_inspect_bytes(bytes),
                            format_inspect_bytes(MAX_INSPECT_BYTES),
                        );
                        self.fastcdc_notice = Some(notice.clone());
                        self.set_status(
                            format!("Inspector skipped a large file: {notice}"),
                            StatusLevel::Warning,
                        );
                    }
                    Err(InspectError::Unreadable(error)) => {
                        self.fastcdc_metrics = None;
                        self.fastcdc_chunks.clear();
                        self.inspect_cache_key = None;
                        let notice = format!("Inspector could not read the file: {error}");
                        self.fastcdc_notice = Some(notice.clone());
                        self.set_status(notice, StatusLevel::Warning);
                    }
                }
                self.clamp_table_indices();
            }
        }
    }
}

pub(crate) async fn execute_quick_push() -> anyhow::Result<String> {
    crate::cmd_push(
        Some("TUI Snapshot commit".into()),
        false,
        false,
        false,
        None,
        None,
        None,
        None,
    )
    .await?;
    Ok("✓ Encrypted snapshot created and confirmed across operator quorum.".into())
}

pub(crate) async fn execute_quick_anchor() -> anyhow::Result<String> {
    let store = crate::get_vault_store()?;
    let head = store.get_active_head()?;
    let head_record = match head {
        Some(h) => h,
        None => {
            anyhow::bail!(
                "Vault has no snapshots committed yet. Press [p] to create a snapshot first."
            );
        }
    };
    let head_hex = hex::encode(&head_record.snapshot_id);
    let relayer_url = crate::get_configured_operators().first().cloned();

    match crate::cmd_anchor(
        Some(head_hex),
        None,
        None,
        None,
        None,
        None,
        true,
        relayer_url,
    )
    .await
    {
        Ok(_) => Ok("✓ Checkpoint registered with Arbitrum L2 relayer (QueuedForRelay).".into()),
        Err(e) => {
            anyhow::bail!("{e}");
        }
    }
}

fn explorer_json_str(value: &serde_json::Value, key: &str, fallback: &str) -> String {
    value
        .get(key)
        .and_then(|field| field.as_str())
        .unwrap_or(fallback)
        .to_string()
}

fn explorer_operator_rows(operators: &[serde_json::Value]) -> Vec<ExplorerOperatorRow> {
    operators
        .iter()
        .map(|operator| ExplorerOperatorRow {
            display_name: explorer_json_str(operator, "display_name", "Operator"),
            operator_id: explorer_json_str(operator, "operator_id", "--"),
            region: explorer_json_str(operator, "region", "--"),
            reachable: operator.get("status").and_then(|status| status.as_str())
                == Some("reachable"),
            latency_ms: operator.get("latency_ms").and_then(|value| value.as_u64()),
            identity: explorer_json_str(operator, "identity_verification", "not_observed"),
        })
        .collect()
}

fn explorer_checkpoint_rows(checkpoints: &[serde_json::Value]) -> Vec<ExplorerCheckpointRow> {
    checkpoints
        .iter()
        .map(|checkpoint| ExplorerCheckpointRow {
            network: explorer_json_str(checkpoint, "network", "--"),
            commitment_hex: explorer_json_str(checkpoint, "commitment_hex", ""),
            tx_hash_hex: checkpoint
                .get("tx_hash_hex")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            finality_status: explorer_json_str(checkpoint, "finality_status", "unverified"),
            confirmations: checkpoint
                .get("confirmations")
                .and_then(|value| value.as_u64()),
            published_at_utc: checkpoint
                .get("published_at_utc")
                .and_then(|value| value.as_u64())
                .unwrap_or(0),
        })
        .collect()
}

fn explorer_object_result(
    cid_hex: &str,
    replicas: &[serde_json::Value],
    required: usize,
) -> ExplorerObjectResult {
    let rows = replicas
        .iter()
        .map(|replica| ExplorerReplicaRow {
            endpoint: explorer_json_str(replica, "endpoint", "--"),
            operator_id: replica
                .get("operator_id")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            status: explorer_json_str(replica, "status", "unknown"),
            latency_ms: replica
                .get("latency_ms")
                .and_then(|value| value.as_u64())
                .unwrap_or(0),
            size_bytes: replica.get("size_bytes").and_then(|value| value.as_u64()),
            error: replica
                .get("error")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        })
        .collect::<Vec<_>>();
    let present = rows.iter().filter(|row| row.status == "present").count();
    ExplorerObjectResult {
        cid_hex: cid_hex.to_string(),
        present,
        checked: rows.len(),
        required,
        satisfied: present >= required,
        replicas: rows,
    }
}

fn build_operator_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        // Reuse DNS, TCP, and TLS connections across refreshes. Constructing
        // a new client for every poll paid the full public-gateway handshake on
        // every cycle, which is why all rows could settle around one second.
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(8)
        .build()
        .unwrap_or_default()
}

pub struct OperatorProbeResult {
    online: bool,
    latency_ms: u64,
    operator_id: Option<String>,
    retention_policy: Option<String>,
    error: Option<String>,
}

async fn probe_operator(client: reqwest::Client, endpoint: String) -> OperatorProbeResult {
    let start = Instant::now();
    let url = format!("{}/v1/info", endpoint.trim_end_matches('/'));
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            let label = if error.is_timeout() {
                "timeout"
            } else if error.is_connect() {
                "connect failed"
            } else {
                "request failed"
            };
            return OperatorProbeResult {
                online: false,
                latency_ms: 999,
                operator_id: None,
                retention_policy: None,
                error: Some(label.into()),
            };
        }
    };

    let latency_ms = (start.elapsed().as_millis() as u64).max(1);
    if !response.status().is_success() {
        return OperatorProbeResult {
            online: false,
            latency_ms: 999,
            operator_id: None,
            retention_policy: None,
            error: Some(format!("HTTP {}", response.status().as_u16())),
        };
    }

    let info = response.json::<serde_json::Value>().await.ok();
    let operator_id = info.as_ref().and_then(|info| {
        info.get("operator_id")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
    });
    let retention_policy = info.as_ref().and_then(|info| {
        info.get("retention_terms")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
    });

    OperatorProbeResult {
        online: true,
        latency_ms,
        operator_id,
        retention_policy,
        error: None,
    }
}

fn median_latency(window: &VecDeque<u64>) -> u64 {
    if window.is_empty() {
        return 0;
    }
    let mut sorted: Vec<u64> = window.iter().copied().collect();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / len;
            ent -= p * p.log2();
        }
    }
    ent
}

/// Keeps `index` inside the `[offset, offset + visible)` window with the
/// smallest possible scroll adjustment.
fn scroll_offset_for(offset: usize, index: usize, len: usize, visible: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let visible = visible.max(1);
    let mut offset = offset.min(len.saturating_sub(1));
    if index < offset {
        offset = index;
    } else if index >= offset + visible {
        offset = index + 1 - visible;
    }
    offset.min(len.saturating_sub(1))
}

fn short_operator_label(endpoint: &str, operator_id: &str) -> String {
    if !operator_id.is_empty() && operator_id != "--" {
        return operator_id.to_string();
    }
    endpoint
        .split("://")
        .nth(1)
        .unwrap_or(endpoint)
        .split('/')
        .next()
        .unwrap_or(endpoint)
        .to_string()
}

fn format_inspect_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Probes all gateways concurrently. Concurrency keeps one slow region from
/// delaying the rest and makes each displayed latency representative of its
/// own operator rather than the sum of earlier requests.
async fn fetch_operator_probes(
    client: reqwest::Client,
    endpoints: Vec<String>,
) -> Vec<OperatorProbeResult> {
    futures_util::future::join_all(
        endpoints
            .into_iter()
            .map(|endpoint| probe_operator(client.clone(), endpoint)),
    )
    .await
}

/// Collects cluster telemetry and the signed checkpoint feed, reusing the
/// same collectors as the public web explorer.
async fn fetch_explorer_snapshot() -> ExplorerSnapshot {
    let telemetry = crate::public_operator_telemetry().await;
    let observed_at = telemetry
        .observed_at
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let operators = explorer_operator_rows(&telemetry.operators);
    match crate::load_public_feed_with_finality().await {
        Ok(Some(checkpoints)) => ExplorerSnapshot {
            observed_at,
            operators,
            feed_configured: true,
            checkpoints: explorer_checkpoint_rows(&checkpoints),
            feed_error: None,
        },
        Ok(None) => ExplorerSnapshot {
            observed_at,
            operators,
            feed_configured: false,
            checkpoints: Vec::new(),
            feed_error: None,
        },
        Err(error) => ExplorerSnapshot {
            observed_at,
            operators,
            feed_configured: true,
            checkpoints: Vec::new(),
            feed_error: Some(error.to_string()),
        },
    }
}

/// Presence-only object lookup: PoS-challenge every configured operator for
/// the queried CID. Object bytes are never fetched.
async fn probe_object_presence(query: String) -> ObjectProbeOutcome {
    let fail = |status: &str| ObjectProbeOutcome {
        result: None,
        status: status.to_string(),
        level: StatusLevel::Warning,
    };
    let Some((cid, cid_hex)) = crate::parse_explorer_cid(query.trim()) else {
        return fail("Explorer lookup needs a 64-character hex content ID.");
    };
    let endpoints = crate::get_configured_operators();
    if endpoints.is_empty() {
        return fail("Explorer has no operator endpoints configured.");
    }
    let replicas = futures_util::future::join_all(
        endpoints
            .into_iter()
            .map(|endpoint| crate::probe_explorer_replica(endpoint, cid)),
    )
    .await;
    let required = ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS;
    let result = explorer_object_result(&cid_hex, &replicas, required);
    let verdict = if result.satisfied {
        "quorum satisfied"
    } else {
        "quorum NOT satisfied"
    };
    let level = if result.satisfied {
        StatusLevel::Success
    } else {
        StatusLevel::Warning
    };
    let status = format!(
        "Object {}...{}: {}/{} present ({}).",
        &cid_hex[..8],
        &cid_hex[cid_hex.len() - 8..],
        result.present,
        result.checked,
        verdict
    );
    ObjectProbeOutcome {
        result: Some(result),
        status,
        level,
    }
}

/// Blocking PC/SC probe: enumerate readers, find the first responsive PIV
/// token, and read slots 9C/9D metadata. Runs on `spawn_blocking`, never on
/// the event loop.
fn probe_token_blocking() -> TokenProbeOutcome {
    let readers = list_pcsc_readers().unwrap_or_default();
    let tokens = match probe_hw_tokens() {
        Ok(tokens) => tokens,
        Err(error) => {
            return TokenProbeOutcome {
                readers,
                attached: false,
                token_label: None,
                slot_9c: SlotReadiness::missing(),
                slot_9d: SlotReadiness::missing(),
                error: Some(error.to_string()),
            }
        }
    };
    let Some(token) = tokens.into_iter().next() else {
        return TokenProbeOutcome {
            readers,
            attached: false,
            token_label: None,
            slot_9c: SlotReadiness::missing(),
            slot_9d: SlotReadiness::missing(),
            error: None,
        };
    };
    TokenProbeOutcome {
        readers,
        attached: true,
        token_label: Some(token.reader_name().to_string()),
        slot_9c: slot_readiness(&token, HsmSlot::DigitalSignature),
        slot_9d: slot_readiness(&token, HsmSlot::KeyManagement),
        error: None,
    }
}

/// Reads one PIV slot's metadata. Ready means the token answered with a
/// non-empty public key; anything else is reported with its reason, never
/// assumed provisioned.
fn slot_readiness(token: &PcscHardwareToken, slot: HsmSlot) -> SlotReadiness {
    match token.get_slot_info(slot) {
        Ok(info) if !info.public_key_hex.is_empty() => SlotReadiness {
            ready: true,
            detail: format!(
                "{} · touch {} · PIN {}",
                info.algorithm, info.touch_policy, info.pin_policy
            ),
        },
        Ok(_) => SlotReadiness {
            ready: false,
            detail: "empty slot".into(),
        },
        Err(error) => SlotReadiness {
            ready: false,
            detail: format!("unreadable: {error}"),
        },
    }
}

/// Chunks one file for the FastCDC inspector using the active chunk profile
/// (`CIPHERVAULT_CHUNK_PROFILE`, default `default`). Runs on
/// `spawn_blocking` via `request_inspection`.
fn compute_inspection(path: &Path) -> Result<InspectionOutput, InspectError> {
    let source_name = path.to_string_lossy().replace('\\', "/");
    let size = fs::metadata(path)
        .map(|meta| meta.len())
        .map_err(|error| InspectError::Unreadable(error.to_string()))?;
    if size > MAX_INSPECT_BYTES {
        return Err(InspectError::TooLarge(size));
    }
    let raw_bytes = fs::read(path).map_err(|error| InspectError::Unreadable(error.to_string()))?;
    let profile = std::env::var("CIPHERVAULT_CHUNK_PROFILE")
        .map(|name| {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                "default".to_string()
            } else {
                trimmed.to_string()
            }
        })
        .unwrap_or_else(|_| "default".to_string());
    let config = config_from_env();
    let chunks = fastcdc_chunk(&raw_bytes, &config);
    let total_bytes = raw_bytes.len();

    let mut offset = 0usize;
    let mut records = Vec::with_capacity(chunks.len());
    let mut unique_cids = std::collections::HashSet::new();
    let mut unique_bytes = 0usize;

    for (i, slice) in chunks.iter().enumerate() {
        let cid_bytes = ciphervault_format::compute_digest(slice);
        let cid_hex = hex::encode(cid_bytes);
        let entropy = compute_entropy(slice);
        let (boundary_hash, boundary) = replicate_boundary(slice, offset, total_bytes, &config);
        let gear_fingerprint = boundary_hash
            .map(|hash| format!("0x{hash:016x}"))
            .unwrap_or_else(|| "—".to_string());
        let is_dup = !unique_cids.insert(cid_bytes);
        if !is_dup {
            unique_bytes += slice.len();
        }

        records.push(FastCdcTuiChunk {
            index: i,
            offset,
            length: slice.len(),
            cid_hex,
            gear_fingerprint,
            boundary,
            entropy: (entropy * 100.0).round() / 100.0,
            is_duplicate: is_dup,
        });

        offset += slice.len();
    }

    let saved_bytes = total_bytes.saturating_sub(unique_bytes);
    let dedup_savings_pct = if total_bytes > 0 {
        (saved_bytes as f64 / total_bytes as f64) * 100.0
    } else {
        0.0
    };

    Ok(InspectionOutput {
        metrics: FastCdcTuiMetrics {
            source_name,
            profile,
            total_bytes,
            total_chunks: chunks.len(),
            unique_chunks: unique_cids.len(),
            duplicate_chunks: chunks.len().saturating_sub(unique_cids.len()),
            saved_bytes,
            dedup_savings_pct: (dedup_savings_pct * 10.0).round() / 10.0,
        },
        chunks: records,
    })
}

/// Replicates the exact Gear rolling-hash state the chunker held when it cut
/// this chunk, then classifies which mask (if any) the boundary satisfied.
///
/// The chunker hashes bytes `[min_size, cut_point)` with
/// `hash = (hash << 1) + GEAR[byte]` starting from zero; `cut_point` equals
/// the chunk length, so re-running that recurrence over the same range
/// reproduces the decision value bit-for-bit. Remainder chunks (at most
/// `min_size` bytes left) never hash, so they report no boundary.
fn replicate_boundary(
    chunk: &[u8],
    offset: usize,
    total: usize,
    config: &FastCdcConfig,
) -> (Option<u64>, BoundaryKind) {
    let remaining = total.saturating_sub(offset);
    let cut = chunk.len();
    if remaining <= config.min_size || cut == 0 {
        return (None, BoundaryKind::Tail);
    }
    let start = config.min_size.min(cut);
    let mut hash = 0u64;
    for &byte in &chunk[start..cut] {
        hash = (hash << 1).wrapping_add(GEAR_MATRIX[byte as usize]);
    }
    let normal_split = remaining.min(config.avg_size);
    let max_chunk = remaining.min(config.max_size);
    // A cut at max_chunk is ambiguous: it can be a mask hit on the last byte
    // or an exhausted scan (phase 1 may exhaust with no phase 2 when
    // normal_split == max_chunk). The satisfied mask disambiguates: phase-1
    // cuts always satisfy mask_s, phase-2 cuts always satisfy mask_l, and
    // anything else is forced.
    let s_hit = (hash & config.mask_s) == 0;
    let l_hit = (hash & config.mask_l) == 0;
    let in_phase1 = cut <= normal_split;
    let kind = if in_phase1 && s_hit {
        BoundaryKind::MaskS
    } else if !in_phase1 && (cut < max_chunk || l_hit) {
        BoundaryKind::MaskL
    } else {
        BoundaryKind::ForcedMax
    };
    (Some(hash), kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_cycle_covers_explorer() {
        assert_eq!(TuiTab::ALL.len(), 7);
        assert_eq!(TuiTab::from_index(6), TuiTab::Explorer);
        assert_eq!(TuiTab::from_index(7), TuiTab::Overview);
        assert_eq!(TuiTab::Explorer.title(), "7: Explorer");

        let mut app = TuiApp::new(Duration::from_secs(30));
        app.switch_tab(TuiTab::HardwareToken);
        app.next_tab();
        assert_eq!(app.active_tab, TuiTab::Explorer);
        app.next_tab();
        assert_eq!(app.active_tab, TuiTab::Overview);
        app.previous_tab();
        assert_eq!(app.active_tab, TuiTab::Explorer);
    }

    #[test]
    fn explorer_operator_rows_map_telemetry_shapes() {
        let rows = explorer_operator_rows(&[
            serde_json::json!({
                "display_name": "Operator 1",
                "operator_id": "op-1",
                "region": "us-central1",
                "status": "reachable",
                "latency_ms": 42,
                "identity_verification": "verified",
            }),
            serde_json::json!({
                "display_name": "Operator 2",
                "operator_id": "operator-2",
                "status": "unreachable",
                "latency_ms": null,
            }),
        ]);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].reachable);
        assert_eq!(rows[0].latency_ms, Some(42));
        assert_eq!(rows[0].identity, "verified");
        assert!(!rows[1].reachable);
        assert_eq!(rows[1].latency_ms, None);
        assert_eq!(rows[1].region, "--");
        assert_eq!(rows[1].identity, "not_observed");
    }

    #[test]
    fn explorer_checkpoint_rows_default_missing_finality() {
        let rows = explorer_checkpoint_rows(&[serde_json::json!({
            "network": "arbitrum-one",
            "commitment_hex": "ab12",
            "tx_hash_hex": "0x99",
            "finality_status": "deeply_confirmed",
            "confirmations": 20,
            "published_at_utc": 1_700_000_000u64,
        })]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].network, "arbitrum-one");
        assert_eq!(rows[0].tx_hash_hex.as_deref(), Some("0x99"));
        assert_eq!(rows[0].confirmations, Some(20));

        let bare = explorer_checkpoint_rows(&[serde_json::json!({})]);
        assert_eq!(bare[0].finality_status, "unverified");
        assert_eq!(bare[0].tx_hash_hex, None);
    }

    #[test]
    fn explorer_object_result_computes_quorum() {
        let present = serde_json::json!({
            "endpoint": "https://op.example",
            "operator_id": "op-1",
            "status": "present",
            "size_bytes": 128,
            "latency_ms": 12,
        });
        let absent = serde_json::json!({"endpoint": "https://op2.example", "status": "absent", "latency_ms": 9});
        let cid = "ab".repeat(32);

        let satisfied =
            explorer_object_result(&cid, &[present.clone(), present, absent.clone()], 2);
        assert_eq!((satisfied.present, satisfied.checked), (2, 3));
        assert!(satisfied.satisfied);
        assert_eq!(satisfied.replicas[0].size_bytes, Some(128));

        let missing = explorer_object_result(&cid, &[absent], 2);
        assert!(!missing.satisfied);
        assert_eq!(missing.present, 0);
    }

    #[tokio::test]
    async fn explorer_probe_rejects_malformed_cid_without_network() {
        let outcome = probe_object_presence("not-a-cid".into()).await;
        assert!(outcome.result.is_none());
        assert_eq!(outcome.level, StatusLevel::Warning);
    }

    #[test]
    fn tab_cycle_wraps_both_ends() {
        assert_eq!(TuiTab::from_index(7), TuiTab::Overview);
        assert_eq!(TuiTab::from_index(13), TuiTab::Explorer);
        let mut app = TuiApp::new(Duration::from_secs(30));
        app.switch_tab(TuiTab::Explorer);
        app.next_tab();
        assert_eq!(app.active_tab, TuiTab::Overview);
        app.previous_tab();
        assert_eq!(app.active_tab, TuiTab::Explorer);
    }

    fn prng_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.max(1);
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 33) as u8
            })
            .collect()
    }

    /// Every replicated boundary must agree with the real chunker's decision:
    /// phase-1 cuts satisfy mask_s, phase-2 cuts satisfy mask_l, forced cuts
    /// sit exactly on max_chunk with no mask satisfied, and remainder chunks
    /// carry no boundary. Adversarial fills exercise the wrapping arithmetic.
    fn assert_boundaries_match_chunker(data: &[u8], config: &FastCdcConfig) {
        let chunks = fastcdc_chunk(data, config);
        let total = data.len();
        let mut offset = 0usize;
        for slice in &chunks {
            let remaining = total - offset;
            let (hash, kind) = replicate_boundary(slice, offset, total, config);
            let cut = slice.len();
            match kind {
                BoundaryKind::Tail => {
                    assert!(hash.is_none());
                    assert!(
                        remaining <= config.min_size,
                        "tail requires remaining <= min_size"
                    );
                }
                BoundaryKind::MaskS => {
                    let hash = hash.expect("mask cut has a boundary hash");
                    let normal_split = remaining.min(config.avg_size);
                    assert!(cut <= normal_split, "S-cut inside avg window");
                    assert_eq!(hash & config.mask_s, 0, "S-cut satisfies mask_s");
                }
                BoundaryKind::MaskL => {
                    let hash = hash.expect("mask cut has a boundary hash");
                    let normal_split = remaining.min(config.avg_size);
                    assert!(cut > normal_split, "L-cut past avg window");
                    assert_eq!(hash & config.mask_l, 0, "L-cut satisfies mask_l");
                }
                BoundaryKind::ForcedMax => {
                    let hash = hash.expect("forced cut has a boundary hash");
                    assert_eq!(cut, remaining.min(config.max_size), "forced cut at max");
                    // An exhausted scan verified its final byte too, so the
                    // trailing hash provably satisfies neither phase's mask.
                    if cut <= remaining.min(config.avg_size) {
                        assert_ne!(hash & config.mask_s, 0, "phase-1 scan exhausted");
                    } else {
                        assert_ne!(hash & config.mask_l, 0, "phase-2 scan exhausted");
                    }
                }
            }
            offset += cut;
        }
        assert_eq!(offset, total, "chunks tile the input");
    }

    #[test]
    fn boundary_hashes_match_chunker_masks() {
        for config in [
            FastCdcConfig::default(),
            FastCdcConfig::new(2 * 1024, 8 * 1024, 32 * 1024),
            FastCdcConfig::new(16 * 1024, 64 * 1024, 256 * 1024),
        ] {
            assert_boundaries_match_chunker(&prng_bytes(200_000, 0x1234_5678), &config);
            assert_boundaries_match_chunker(&vec![0u8; 100_000], &config);
            assert_boundaries_match_chunker(&vec![0xFFu8; 100_000], &config);
            assert_boundaries_match_chunker(&prng_bytes(3_000, 7), &config);
            assert_boundaries_match_chunker(&[], &config);
        }
    }

    #[test]
    fn scroll_offset_for_keeps_selection_visible() {
        assert_eq!(scroll_offset_for(0, 0, 0, 10), 0);
        assert_eq!(scroll_offset_for(0, 3, 10, 4), 0);
        assert_eq!(scroll_offset_for(0, 4, 10, 4), 1);
        assert_eq!(scroll_offset_for(5, 2, 10, 4), 2);
        assert_eq!(scroll_offset_for(0, 9, 10, 4), 6);
        assert_eq!(scroll_offset_for(99, 1, 10, 4), 1);
        assert_eq!(scroll_offset_for(0, 2, 3, 10), 0);
    }

    #[test]
    fn select_next_wraps_and_scrolls() {
        let mut app = TuiApp::new(Duration::from_secs(30));
        app.tracked_files = (0..5)
            .map(|i| TrackedFileItem {
                path: format!("/tmp/definitely-not-inspected-{i}.bin"),
                size_bytes: 1,
                file_id_hex: "00".into(),
                exists_on_disk: false,
            })
            .collect();
        app.file_visible = 2;
        for _ in 0..4 {
            app.select_next(TuiTable::Files);
        }
        assert_eq!(app.file_table_index, 4);
        assert_eq!(app.file_scroll, 3);
        app.select_next(TuiTable::Files);
        assert_eq!(app.file_table_index, 0);
        assert_eq!(app.file_scroll, 0);
        app.select_prev(TuiTable::Files);
        assert_eq!(app.file_table_index, 4);
        assert_eq!(app.file_scroll, 3);
    }

    #[test]
    fn clamp_table_indices_resets_out_of_range() {
        let mut app = TuiApp::new(Duration::from_secs(30));
        app.file_table_index = 9;
        app.snapshot_table_index = 9;
        app.chunk_table_index = 9;
        app.explorer_checkpoint_index = 9;
        app.clamp_table_indices();
        assert_eq!(app.file_table_index, 0);
        assert_eq!(app.snapshot_table_index, 0);
        assert_eq!(app.chunk_table_index, 0);
        assert_eq!(app.explorer_checkpoint_index, 0);
    }

    #[test]
    fn apply_task_out_drops_stale_operator_poll() {
        let mut app = TuiApp::new(Duration::from_secs(30));
        app.operators = vec![OperatorHealthItem {
            endpoint: "https://a.example".into(),
            online: false,
            latency_ms: 0,
            latency_window: VecDeque::new(),
            operator_id: "--".into(),
            retention_policy: None,
            last_error: None,
        }];
        app.poll_in_flight = true;
        app.apply_task_out(TuiTaskOut::OperatorsPolled {
            endpoints: vec!["https://b.example".into()],
            probes: vec![OperatorProbeResult {
                online: true,
                latency_ms: 5,
                operator_id: Some("op-b".into()),
                retention_policy: None,
                error: None,
            }],
        });
        assert!(!app.poll_in_flight);
        assert!(!app.operators[0].online);
        assert_eq!(app.operators[0].operator_id, "--");
    }

    fn polled(app: &mut TuiApp, endpoint: &str, online: bool, latency_ms: u64) {
        app.poll_in_flight = true;
        app.apply_task_out(TuiTaskOut::OperatorsPolled {
            endpoints: vec![endpoint.into()],
            probes: vec![OperatorProbeResult {
                online,
                latency_ms,
                operator_id: Some("op-a".into()),
                retention_policy: None,
                error: None,
            }],
        });
    }

    fn single_operator_app() -> TuiApp {
        let mut app = TuiApp::new(Duration::from_secs(30));
        app.operators = vec![OperatorHealthItem {
            endpoint: "https://a.example".into(),
            online: false,
            latency_ms: 0,
            latency_window: VecDeque::new(),
            operator_id: "--".into(),
            retention_policy: None,
            last_error: None,
        }];
        app
    }

    #[test]
    fn operator_latency_reports_window_median() {
        let mut app = single_operator_app();
        // A lone retransmit spike must not dominate the displayed value.
        for sample in [300, 310, 1900, 320, 305] {
            polled(&mut app, "https://a.example", true, sample);
        }
        assert_eq!(app.operators[0].latency_ms, 310);
        assert_eq!(app.operators[0].latency_window.len(), LATENCY_WINDOW);
    }

    #[test]
    fn operator_latency_window_rolls_and_clears_on_failure() {
        let mut app = single_operator_app();
        for sample in [100, 110, 120, 130, 140, 150] {
            polled(&mut app, "https://a.example", true, sample);
        }
        // Oldest sample (100) rolled out: median of [110..150] is 130.
        assert_eq!(app.operators[0].latency_ms, 130);
        polled(&mut app, "https://a.example", false, 999);
        assert!(!app.operators[0].online);
        assert_eq!(app.operators[0].latency_ms, 999);
        assert!(app.operators[0].latency_window.is_empty());
        // Recovery starts from a fresh baseline, not ancient samples.
        polled(&mut app, "https://a.example", true, 400);
        assert_eq!(app.operators[0].latency_ms, 400);
    }

    #[test]
    fn apply_task_out_token_probe_sets_slots() {
        let mut app = TuiApp::new(Duration::from_secs(30));
        app.token_in_flight = true;
        app.token_status.probing = true;
        app.apply_task_out(TuiTaskOut::TokenProbed(TokenProbeOutcome {
            readers: vec!["YubiKey OTP+FIDO+CCID 00 00".into()],
            attached: true,
            token_label: Some("YubiKey OTP+FIDO+CCID 00 00".into()),
            slot_9c: SlotReadiness {
                ready: true,
                detail: "ECCP256 · touch cached · PIN default".into(),
            },
            slot_9d: SlotReadiness {
                ready: false,
                detail: "empty slot".into(),
            },
            error: None,
        }));
        assert!(!app.token_in_flight);
        assert!(!app.token_status.probing);
        assert!(app.token_status.token_attached);
        assert!(app.token_status.slot_9c_ready);
        assert!(!app.token_status.slot_9d_ready);
        assert_eq!(
            app.token_status.slot_9d_detail.as_deref(),
            Some("empty slot")
        );
    }

    #[test]
    fn apply_task_out_inspection_applies_latest_only() {
        let mut app = TuiApp::new(Duration::from_secs(30));
        let output = InspectionOutput {
            metrics: FastCdcTuiMetrics {
                source_name: "stale".into(),
                profile: "default".into(),
                total_bytes: 1,
                total_chunks: 1,
                unique_chunks: 1,
                duplicate_chunks: 0,
                saved_bytes: 0,
                dedup_savings_pct: 0.0,
            },
            chunks: Vec::new(),
        };
        app.inspect_in_flight = Some(1);
        app.apply_task_out(TuiTaskOut::Inspected {
            index: 0,
            result: Ok(output.clone()),
        });
        assert!(app.fastcdc_metrics.is_none());
        app.inspect_in_flight = Some(0);
        app.apply_task_out(TuiTaskOut::Inspected {
            index: 0,
            result: Ok(output),
        });
        assert_eq!(app.fastcdc_metrics.as_ref().unwrap().source_name, "stale");
        assert!(app.inspect_in_flight.is_none());
    }

    #[test]
    fn compute_inspection_chunks_small_file_and_caps_large() {
        let dir = std::env::temp_dir().join(format!("cvtui-inspect-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let small = dir.join("small.bin");
        fs::write(&small, prng_bytes(50_000, 99)).unwrap();
        let output = compute_inspection(&small).expect("small file inspects");
        assert_eq!(output.metrics.total_chunks, output.chunks.len());
        assert!(!output.chunks.is_empty());
        let mut offset = 0usize;
        for chunk in &output.chunks {
            assert_eq!(chunk.offset, offset);
            offset += chunk.length;
        }
        assert_eq!(offset, output.metrics.total_bytes);

        let big = dir.join("big.bin");
        let handle = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&big)
            .unwrap();
        handle.set_len(MAX_INSPECT_BYTES + 1).unwrap();
        drop(handle);
        assert!(matches!(
            compute_inspection(&big),
            Err(InspectError::TooLarge(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
