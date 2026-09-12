use ciphervault_crypto::hsm::list_pcsc_readers;
use ciphervault_snapshot::fastcdc::{fastcdc_chunk, FastCdcConfig, GEAR_MATRIX};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiTab {
    Overview = 0,
    Files = 1,
    Snapshots = 2,
    Operators = 3,
    FastCdc = 4,
    HardwareToken = 5,
}

impl TuiTab {
    pub const ALL: [TuiTab; 6] = [
        TuiTab::Overview,
        TuiTab::Files,
        TuiTab::Snapshots,
        TuiTab::Operators,
        TuiTab::FastCdc,
        TuiTab::HardwareToken,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            TuiTab::Overview => "1: Overview",
            TuiTab::Files => "2: Files",
            TuiTab::Snapshots => "3: History",
            TuiTab::Operators => "4: Operators",
            TuiTab::FastCdc => "5: FastCDC",
            TuiTab::HardwareToken => "6: Token",
        }
    }

    pub fn from_index(idx: usize) -> Self {
        match idx % 6 {
            0 => TuiTab::Overview,
            1 => TuiTab::Files,
            2 => TuiTab::Snapshots,
            3 => TuiTab::Operators,
            4 => TuiTab::FastCdc,
            _ => TuiTab::HardwareToken,
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
    pub preview: String,
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

    // Collections
    pub tracked_files: Vec<TrackedFileItem>,
    pub file_table_index: usize,

    pub snapshots: Vec<SnapshotItem>,
    pub snapshot_table_index: usize,

    pub operators: Vec<OperatorHealthItem>,
    pub operator_table_index: usize,

    // FastCDC inspector
    pub fastcdc_metrics: Option<FastCdcTuiMetrics>,
    pub fastcdc_chunks: Vec<FastCdcTuiChunk>,
    pub chunk_table_index: usize,

    // Token
    pub token_status: HardwareTokenTuiStatus,

    // Modal dialogs
    pub show_track_modal: bool,
    pub track_input_buffer: String,
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
            status_message: "Ready. Press [?] for keybindings, [Tab/1-6] to navigate.".into(),
            status_level: StatusLevel::Info,
            last_status_update: Instant::now(),

            is_initialized: false,
            vault_id_hex: "Not Initialized".into(),
            active_epoch: 0,
            head_cid_hex: "None".into(),
            recovery_signing_pk_hex: "None".into(),
            recovery_locator_hex: "None".into(),

            tracked_files: Vec::new(),
            file_table_index: 0,

            snapshots: Vec::new(),
            snapshot_table_index: 0,

            operators: Vec::new(),
            operator_table_index: 0,

            fastcdc_metrics: None,
            fastcdc_chunks: Vec::new(),
            chunk_table_index: 0,

            token_status: HardwareTokenTuiStatus {
                readers: Vec::new(),
                token_attached: false,
                slot_9c_ready: false,
                slot_9d_ready: false,
            },

            show_track_modal: false,
            track_input_buffer: String::new(),
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
        let next_idx = if current_idx == 0 { 5 } else { current_idx - 1 };
        self.active_tab = TuiTab::from_index(next_idx);
    }

    pub fn switch_tab(&mut self, tab: TuiTab) {
        self.active_tab = tab;
    }

    pub fn refresh_local_state(&mut self) {
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
                            let dt = chrono::DateTime::from_timestamp(s.advisory_timestamp_utc as i64, 0)
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

        // Read configured operators from .ciphervault/operators.json
        let ops_file = Path::new(".ciphervault").join("operators.json");
        let configured_ops: Vec<String> = if ops_file.exists() {
            fs::read_to_string(&ops_file)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            vec![
                "http://127.0.0.1:8201".into(),
                "http://127.0.0.1:8202".into(),
                "http://127.0.0.1:8203".into(),
            ]
        };

        if self.operators.is_empty() || self.operators.len() != configured_ops.len() {
            self.operators = configured_ops
                .into_iter()
                .map(|endpoint| OperatorHealthItem {
                    endpoint,
                    online: false,
                    latency_ms: 0,
                    operator_id: "--".into(),
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

            let preview = if slice.iter().all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n') {
                let s = String::from_utf8_lossy(&slice[..slice.len().min(40)]);
                s.trim().replace('\n', " ").to_string()
            } else {
                format!("hex:{}", hex::encode(&slice[..slice.len().min(16)]))
            };

            records.push(FastCdcTuiChunk {
                index: i,
                offset,
                length: slice.len(),
                cid_hex,
                gear_fingerprint: format!("0x{:016x}", gear),
                entropy: (entropy * 100.0).round() / 100.0,
                is_duplicate: is_dup,
                preview,
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
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(800))
            .build()
            .unwrap_or_default();

        for op in &mut self.operators {
            let start = Instant::now();
            let url = format!("{}/v1/info", op.endpoint.trim_end_matches('/'));
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let lat = start.elapsed().as_millis() as u64;
                    op.online = true;
                    op.latency_ms = lat.max(1);
                    if let Ok(info) = resp.json::<serde_json::Value>().await {
                        if let Some(id) = info.get("operator_id").and_then(|v| v.as_str()) {
                            op.operator_id = id.to_string();
                        }
                    }
                }
                _ => {
                    op.online = false;
                    op.latency_ms = 999;
                }
            }
        }
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
