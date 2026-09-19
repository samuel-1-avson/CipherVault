use ciphervault_crypto::hsm::list_pcsc_readers;
use ciphervault_local_store::AccountStore;
use ciphervault_snapshot::fastcdc::{fastcdc_chunk, FastCdcConfig, GEAR_MATRIX};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone)]
pub struct OperatorHealthItem {
    pub endpoint: String,
    pub online: bool,
    pub latency_ms: u64,
    pub operator_id: String,
    pub retention_policy: Option<String>,
    /// Short diagnostic retained for the operator table when a probe fails.
    /// Keeping this separate from `online` prevents a timeout from looking
    /// like a generic/offline state with no actionable explanation.
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FastCdcTuiChunk {
    pub index: usize,
    pub offset: usize,
    pub length: usize,
    pub cid_hex: String,
    pub gear_fingerprint: String,
    pub entropy: f64,
    pub is_duplicate: bool,
}

#[derive(Debug, Clone)]
pub struct FastCdcTuiMetrics {
    pub source_name: String,
    pub total_bytes: usize,
    pub total_chunks: usize,
    pub unique_chunks: usize,
    pub duplicate_chunks: usize,
    pub saved_bytes: usize,
    pub dedup_savings_pct: f64,
}

#[derive(Debug, Clone)]
pub struct HardwareTokenTuiStatus {
    pub readers: Vec<String>,
    pub token_attached: bool,
    pub slot_9c_ready: bool,
    pub slot_9d_ready: bool,
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

    pub snapshots: Vec<SnapshotItem>,
    pub snapshot_table_index: usize,

    pub operators: Vec<OperatorHealthItem>,
    pub operator_table_index: usize,
    operator_http: reqwest::Client,

    // FastCDC inspector
    pub fastcdc_metrics: Option<FastCdcTuiMetrics>,
    pub fastcdc_chunks: Vec<FastCdcTuiChunk>,
    pub chunk_table_index: usize,

    // Token
    pub token_status: HardwareTokenTuiStatus,

    // Network explorer (mirrors the public web explorer: cluster telemetry,
    // checkpoint feed, and presence-only object quorum lookup)
    pub explorer_observed_at: String,
    pub explorer_operators: Vec<ExplorerOperatorRow>,
    pub explorer_checkpoints: Vec<ExplorerCheckpointRow>,
    pub explorer_checkpoint_index: usize,
    pub explorer_feed_configured: bool,
    pub explorer_object: Option<ExplorerObjectResult>,

    // Modal dialogs
    pub show_track_modal: bool,
    pub track_input_buffer: String,
    pub show_explorer_search_modal: bool,
    pub explorer_search_buffer: String,
    pub show_help: bool,

    // Background polling
    pub last_poll: Instant,
    pub poll_interval: Duration,
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

            snapshots: Vec::new(),
            snapshot_table_index: 0,

            operators: Vec::new(),
            operator_table_index: 0,
            operator_http: build_operator_http_client(),

            fastcdc_metrics: None,
            fastcdc_chunks: Vec::new(),
            chunk_table_index: 0,

            token_status: HardwareTokenTuiStatus {
                readers: Vec::new(),
                token_attached: false,
                slot_9c_ready: false,
                slot_9d_ready: false,
            },

            explorer_observed_at: "Never".into(),
            explorer_operators: Vec::new(),
            explorer_checkpoints: Vec::new(),
            explorer_checkpoint_index: 0,
            explorer_feed_configured: false,
            explorer_object: None,

            show_track_modal: false,
            track_input_buffer: String::new(),
            show_explorer_search_modal: false,
            explorer_search_buffer: String::new(),
            show_help: false,

            last_poll: Instant::now() - poll_interval, // trigger immediate poll
            poll_interval,
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

        if self.operators.is_empty() || self.operators.len() != configured_ops.len() {
            self.operators = configured_ops
                .into_iter()
                .map(|endpoint| OperatorHealthItem {
                    endpoint,
                    online: false,
                    latency_ms: 0,
                    operator_id: "--".into(),
                    retention_policy: None,
                    last_error: None,
                })
                .collect();
        }

        // Update hardware token state
        let readers = list_pcsc_readers().unwrap_or_default();
        let token_attached = !readers.is_empty();
        self.token_status = HardwareTokenTuiStatus {
            readers,
            token_attached,
            slot_9c_ready: token_attached,
            slot_9d_ready: token_attached,
        };

        // Inspect first real tracked file for FastCDC
        self.run_fastcdc_inspection();
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

    pub fn run_fastcdc_inspection(&mut self) {
        if self.tracked_files.is_empty() {
            self.fastcdc_metrics = None;
            self.fastcdc_chunks.clear();
            return;
        }

        let selected_file = if self.file_table_index < self.tracked_files.len() {
            &self.tracked_files[self.file_table_index]
        } else {
            &self.tracked_files[0]
        };

        let path = PathBuf::from(&selected_file.path);
        let raw_bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.fastcdc_metrics = None;
                self.fastcdc_chunks.clear();
                return;
            }
        };

        let config = FastCdcConfig::default();
        let chunks = fastcdc_chunk(&raw_bytes, &config);

        let mut offset = 0usize;
        let mut records = Vec::with_capacity(chunks.len());
        let mut unique_cids = std::collections::HashSet::new();
        let mut unique_bytes = 0usize;

        for (i, slice) in chunks.iter().enumerate() {
            let cid_bytes = ciphervault_format::compute_digest(slice);
            let cid_hex = hex::encode(cid_bytes);
            let entropy = compute_entropy(slice);
            let gear = compute_gear_hash(slice);
            let is_dup = !unique_cids.insert(cid_bytes);
            if !is_dup {
                unique_bytes += slice.len();
            }

            records.push(FastCdcTuiChunk {
                index: i,
                offset,
                length: slice.len(),
                cid_hex,
                gear_fingerprint: format!("0x{:016x}", gear),
                entropy: (entropy * 100.0).round() / 100.0,
                is_duplicate: is_dup,
            });

            offset += slice.len();
        }

        let total_bytes = raw_bytes.len();
        let saved_bytes = total_bytes.saturating_sub(unique_bytes);
        let dedup_savings_pct = if total_bytes > 0 {
            (saved_bytes as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };

        self.fastcdc_metrics = Some(FastCdcTuiMetrics {
            source_name: selected_file.path.clone(),
            total_bytes,
            total_chunks: chunks.len(),
            unique_chunks: unique_cids.len(),
            duplicate_chunks: chunks.len().saturating_sub(unique_cids.len()),
            saved_bytes,
            dedup_savings_pct: (dedup_savings_pct * 10.0).round() / 10.0,
        });
        self.fastcdc_chunks = records;
    }

    pub async fn poll_operators_async(&mut self) {
        let client = self.operator_http.clone();
        // Probe all gateways concurrently. This keeps the TUI responsive when
        // one region is slow and makes the displayed latency representative of
        // each operator rather than the sum of earlier requests.
        let probes = futures_util::future::join_all(
            self.operators
                .iter()
                .map(|op| probe_operator(client.clone(), op.endpoint.clone())),
        )
        .await;

        for (op, probe) in self.operators.iter_mut().zip(probes) {
            op.online = probe.online;
            op.latency_ms = probe.latency_ms;
            op.last_error = probe.error;
            if let Some(operator_id) = probe.operator_id {
                op.operator_id = operator_id;
            }
            if let Some(retention_policy) = probe.retention_policy {
                op.retention_policy = Some(retention_policy);
            }
        }
    }

    /// Refresh cluster telemetry and the signed checkpoint feed, reusing the
    /// same collectors as the public web explorer. Telemetry is cached for
    /// 30 s and finality for 60 s, so this stays cheap on the poll tick.
    pub async fn refresh_explorer_async(&mut self) {
        let telemetry = crate::public_operator_telemetry().await;
        self.explorer_observed_at = telemetry
            .observed_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();
        self.explorer_operators = explorer_operator_rows(&telemetry.operators);

        match crate::load_public_feed_with_finality().await {
            Ok(Some(checkpoints)) => {
                self.explorer_feed_configured = true;
                self.explorer_checkpoints = explorer_checkpoint_rows(&checkpoints);
            }
            Ok(None) => {
                self.explorer_feed_configured = false;
                self.explorer_checkpoints.clear();
            }
            Err(error) => {
                self.explorer_feed_configured = true;
                self.explorer_checkpoints.clear();
                self.set_status(
                    format!("Checkpoint feed unavailable: {error}"),
                    StatusLevel::Warning,
                );
            }
        }
        if self.explorer_checkpoint_index >= self.explorer_checkpoints.len() {
            self.explorer_checkpoint_index = 0;
        }
    }

    /// Presence-only object lookup: PoS-challenge every configured operator
    /// for the CID in the search buffer. Object bytes are never fetched.
    pub async fn run_explorer_object_probe(&mut self) {
        let query = self.explorer_search_buffer.trim().to_string();
        let Some((cid, cid_hex)) = crate::parse_explorer_cid(&query) else {
            self.explorer_object = None;
            self.set_status(
                "Explorer lookup needs a 64-character hex content ID.",
                StatusLevel::Warning,
            );
            return;
        };
        let endpoints = crate::get_configured_operators();
        if endpoints.is_empty() {
            self.explorer_object = None;
            self.set_status(
                "Explorer has no operator endpoints configured.",
                StatusLevel::Warning,
            );
            return;
        }
        self.set_status(
            format!(
                "Probing {} operator(s) for object presence...",
                endpoints.len()
            ),
            StatusLevel::Info,
        );
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
        self.set_status(
            format!(
                "Object {}...{}: {}/{} present ({}).",
                &cid_hex[..8],
                &cid_hex[cid_hex.len() - 8..],
                result.present,
                result.checked,
                verdict
            ),
            if result.satisfied {
                StatusLevel::Success
            } else {
                StatusLevel::Warning
            },
        );
        self.explorer_object = Some(result);
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

struct OperatorProbeResult {
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

fn compute_gear_hash(chunk: &[u8]) -> u64 {
    let mut hash = 0u64;
    let tail = if chunk.len() > 64 {
        &chunk[chunk.len() - 64..]
    } else {
        chunk
    };
    for &b in tail {
        hash = (hash << 1).wrapping_add(GEAR_MATRIX[b as usize]);
    }
    hash
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
            "finality_status": "finalized",
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
        let mut app = TuiApp::new(Duration::from_secs(30));
        app.explorer_search_buffer = "not-a-cid".into();
        app.run_explorer_object_probe().await;
        assert!(app.explorer_object.is_none());
        assert_eq!(app.status_level, StatusLevel::Warning);
    }
}
