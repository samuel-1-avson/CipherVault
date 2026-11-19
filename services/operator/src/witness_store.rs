//! Operator witness (ADR-014 Phase 3): a `c2sp.org/tlog-witness` server
//! that cosigns other logs' checkpoints with ML-DSA-44.
//!
//! State lives under `data_dir/witness/`:
//!
//! * `witness.key` — the 32-byte ML-DSA-44 seed. Created owner-only on
//!   first open and never overwritten; a wrong-length file fails the open.
//! * `name` — the witness (cosigner) name, pinned on first open. The
//!   ML-DSA-44 message commits to the name, so renaming would make a new
//!   witness; a different configured name fails closed instead.
//! * `logs/<sha256(origin) hex>` — for each log, the latest checkpoint this
//!   witness cosigned, with the log's signature and this witness's
//!   cosignature. It is written atomically before the cosignature is
//!   returned, as the spec requires, and it is re-verified on open: a
//!   witness that lost or cannot trust its state could be made to cosign
//!   a fork, so a damaged file fails the open.
//! * `evidence/<sha256(origin) hex>/<size>-<root hex>.txt` — log-signed
//!   checkpoints this witness refused as inconsistent, each beside the
//!   checkpoint it had witnessed: the self-verifying evidence pair of
//!   ADR-014. Only checkpoints that verified under the log key are kept,
//!   one file per distinct (size, root) and at most
//!   [`MAX_EVIDENCE_PER_LOG`] per log, so evidence cannot fill the disk.
//!
//! One mutex covers checking a request against the stored size, signing
//! and persisting, which is the atomicity the spec requires.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ciphervault_translog::checkpoint::open_checkpoint;
use ciphervault_translog::cosignature::WitnessVerifier;
use ciphervault_translog::mldsa::MlDsa44CosignatureSigner;
use ciphervault_translog::note::{Ed25519NoteVerifier, MAX_NOTE_SIZE};
use ciphervault_translog::witness::{
    encode_cosignatures, AddCheckpointRequest, WitnessError, WitnessedTree, MAX_PROOF_LINES,
};
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::log_store::{sync_parent_dir, write_atomic};
use crate::state::lock_or_recover;

/// The largest `add-checkpoint` body accepted: a maximal note plus the
/// old-size line and a maximal proof.
pub const WITNESS_MAX_BODY: usize = MAX_NOTE_SIZE + 64 + (MAX_PROOF_LINES + 1) * 45;

/// The most evidence files kept per log.
pub const MAX_EVIDENCE_PER_LOG: usize = 1024;

/// Witness configuration, fixed when the operator state is built.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WitnessConfig {
    /// Run the witness (`CIPHERVAULT_WITNESS_ENABLED=1` / `--witness`).
    /// Configuring a trusted log enables it too.
    pub enabled: bool,
    /// Witness name override (`CIPHERVAULT_WITNESS_NAME` /
    /// `--witness-name`). `None` derives
    /// `cipherchain.<operator-id>.cipherv.online/witness`.
    pub name: Option<String>,
    /// Ed25519 verifier keys of the logs this witness cosigns
    /// (`CIPHERVAULT_WITNESS_TRUSTED_LOGS`, separated by commas or
    /// whitespace / `--witness-trusted-log`, repeatable). Each key's name
    /// is the log origin, as `c2sp.org/tlog-checkpoint` recommends.
    pub trusted_logs: Vec<String>,
}

impl WitnessConfig {
    /// Configuration from the environment.
    pub fn from_env() -> Self {
        let trusted_logs = std::env::var("CIPHERVAULT_WITNESS_TRUSTED_LOGS")
            .map(|value| split_list(&value))
            .unwrap_or_default();
        let enabled = std::env::var("CIPHERVAULT_WITNESS_ENABLED").as_deref() == Ok("1");
        let name = std::env::var("CIPHERVAULT_WITNESS_NAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Self {
            enabled,
            name,
            trusted_logs,
        }
    }

    /// Whether the witness should run.
    pub fn is_enabled(&self) -> bool {
        self.enabled || !self.trusted_logs.is_empty()
    }

    /// The witness name this configuration asks for, derived from the
    /// operator id when unset.
    pub fn name_for(&self, operator_id: &str) -> String {
        if let Some(name) = &self.name {
            return name.clone();
        }
        format!("cipherchain.{}.cipherv.online/witness", slug(operator_id))
    }
}

/// Splits a list given as one string, separated by commas or whitespace.
pub(crate) fn split_list(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// An operator id reduced to characters valid in an origin or key name.
pub(crate) fn slug(operator_id: &str) -> String {
    let slug: String = operator_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if slug.is_empty() {
        "operator".to_string()
    } else {
        slug
    }
}

/// Lowercase hex SHA-256 of a log origin: how the monitoring API and the
/// state directory name a log.
pub fn origin_hash(origin: &str) -> String {
    hex::encode(Sha256::digest(origin.as_bytes()))
}

/// Why the witness could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum WitnessStoreError {
    /// A witness file could not be read or written.
    #[error("witness I/O: {0}")]
    Io(String),
    /// The configured name differs from the pinned one.
    #[error("witness name mismatch: configured {configured:?}, stored {stored:?}")]
    NameMismatch {
        /// The name this open was configured with.
        configured: String,
        /// The name pinned in the witness directory.
        stored: String,
    },
    /// The configuration is invalid.
    #[error("witness configuration: {0}")]
    Config(String),
    /// Stored witness state does not verify.
    #[error("witness state is corrupt: {0}")]
    Corrupt(String),
}

fn io_error(path: &Path, error: io::Error) -> WitnessStoreError {
    WitnessStoreError::Io(format!("{}: {error}", path.display()))
}

/// Why an `add-checkpoint` request failed.
#[derive(Debug, thiserror::Error)]
pub enum AddCheckpointError {
    /// The request was refused under the protocol.
    #[error(transparent)]
    Refused(#[from] WitnessError),
    /// The witness could not sign or persist; nothing was cosigned.
    #[error("witness unavailable: {0}")]
    Unavailable(String),
}

/// Loads the 32-byte witness seed, creating it owner-only on first use.
fn load_or_create_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>, WitnessStoreError> {
    match fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                WitnessStoreError::Corrupt(format!(
                    "witness key {} must contain exactly 32 bytes, got {}",
                    path.display(),
                    bytes.len()
                ))
            })?;
            Ok(Zeroizing::new(seed))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut seed = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(seed.as_mut());
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(mut file) => {
                    file.write_all(seed.as_ref())
                        .map_err(|e| io_error(path, e))?;
                    file.sync_all().map_err(|e| io_error(path, e))?;
                    drop(file);
                    sync_parent_dir(path);
                    if let Err(e) = ciphervault_file_lock::lock_secret_file(path) {
                        eprintln!(
                            "WARNING: could not restrict {} to the current user ({e}); \
                             anyone with disk access may read the witness key",
                            path.display()
                        );
                    }
                    Ok(seed)
                }
                // Lost a creation race: read the winner's key.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => load_or_create_seed(path),
                Err(e) => Err(io_error(path, e)),
            }
        }
        Err(e) => Err(io_error(path, e)),
    }
}

struct WitnessedLog {
    tree: WitnessedTree,
    note: String,
}

/// The operator's witness. All methods take `&self` and serialize
/// internally.
pub struct WitnessStore {
    dir: PathBuf,
    signer: MlDsa44CosignatureSigner,
    verifier_key: String,
    trusted: BTreeMap<String, Ed25519NoteVerifier>,
    logs: Mutex<HashMap<String, WitnessedLog>>,
}

impl WitnessStore {
    /// Opens (or creates) the witness in `data_dir/witness`.
    pub fn open(
        data_dir: &Path,
        config: &WitnessConfig,
        operator_id: &str,
    ) -> Result<Self, WitnessStoreError> {
        let dir = data_dir.join("witness");
        fs::create_dir_all(dir.join("logs")).map_err(|e| io_error(&dir, e))?;

        let mut trusted = BTreeMap::new();
        for vkey in &config.trusted_logs {
            let key = Ed25519NoteVerifier::from_vkey(vkey)
                .map_err(|e| WitnessStoreError::Config(format!("trusted log key {vkey:?}: {e}")))?;
            let origin = ciphervault_translog::note::NoteVerifier::name(&key).to_string();
            if trusted.insert(origin.clone(), key).is_some() {
                return Err(WitnessStoreError::Config(format!(
                    "two trusted log keys for origin {origin:?}"
                )));
            }
        }

        let configured = config.name_for(operator_id);
        let name_path = dir.join("name");
        let name = match fs::read_to_string(&name_path) {
            Ok(stored) => {
                let stored = stored.trim().to_string();
                if stored != configured {
                    return Err(WitnessStoreError::NameMismatch { configured, stored });
                }
                stored
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => configured,
            Err(e) => return Err(io_error(&name_path, e)),
        };

        let seed = load_or_create_seed(&dir.join("witness.key"))?;
        let signer = MlDsa44CosignatureSigner::from_seed(name.clone(), &seed)
            .map_err(|e| WitnessStoreError::Config(format!("witness name {name:?}: {e}")))?;
        if !name_path.exists() {
            write_atomic(&name_path, name.as_bytes())
                .map_err(|e| WitnessStoreError::Io(e.to_string()))?;
        }
        let own_key = WitnessVerifier::from(
            signer
                .verifier()
                .map_err(|e| WitnessStoreError::Config(e.to_string()))?,
        );
        let verifier_key = own_key
            .verifier_key()
            .map_err(|e| WitnessStoreError::Config(e.to_string()))?
            .to_string();

        // Reload and re-verify the latest cosigned checkpoint of every
        // trusted log.
        let mut logs = HashMap::new();
        for (origin, log_key) in &trusted {
            let path = dir.join("logs").join(origin_hash(origin));
            let note = match fs::read_to_string(&path) {
                Ok(note) => note,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io_error(&path, e)),
            };
            let verified = open_checkpoint(
                note.as_bytes(),
                origin,
                log_key,
                std::slice::from_ref(&own_key),
            )
            .map_err(|e| WitnessStoreError::Corrupt(format!("{}: {e}", path.display())))?;
            if verified.cosignatures().is_empty() {
                return Err(WitnessStoreError::Corrupt(format!(
                    "{}: no cosignature from this witness",
                    path.display()
                )));
            }
            let checkpoint = verified.checkpoint();
            logs.insert(
                origin.clone(),
                WitnessedLog {
                    tree: WitnessedTree {
                        size: checkpoint.size(),
                        root: *checkpoint.root(),
                    },
                    note,
                },
            );
        }

        Ok(Self {
            dir,
            signer,
            verifier_key,
            trusted,
            logs: Mutex::new(logs),
        })
    }

    /// The witness (cosigner) name.
    pub fn name(&self) -> &str {
        self.signer.name()
    }

    /// The witness's ML-DSA-44 verifier key, for log configuration and
    /// client policies.
    pub fn verifier_key(&self) -> &str {
        &self.verifier_key
    }

    /// The origins this witness cosigns.
    pub fn trusted_origins(&self) -> Vec<String> {
        self.trusted.keys().cloned().collect()
    }

    /// The tree this witness last cosigned for `origin`.
    pub fn witnessed(&self, origin: &str) -> Option<WitnessedTree> {
        lock_or_recover(&self.logs, "witness_logs")
            .get(origin)
            .map(|log| log.tree)
    }

    /// The latest cosigned checkpoint for the log whose origin hashes to
    /// `origin_hash` (lowercase hex SHA-256), for monitors.
    pub fn checkpoint_for_hash(&self, origin_hash_hex: &str) -> Option<String> {
        let logs = lock_or_recover(&self.logs, "witness_logs");
        logs.iter()
            .find(|(origin, _)| origin_hash(origin) == origin_hash_hex)
            .map(|(_, log)| log.note.clone())
    }

    /// The evidence files kept for `origin`, sorted.
    pub fn evidence_files(&self, origin: &str) -> Vec<PathBuf> {
        let dir = self.evidence_dir(origin);
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok().map(|e| e.path()))
                    .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        files
    }

    fn evidence_dir(&self, origin: &str) -> PathBuf {
        self.dir.join("evidence").join(origin_hash(origin))
    }

    /// Handles one `add-checkpoint` request body at time `now` (POSIX
    /// seconds) and returns the `200` response body: this witness's
    /// cosignature line.
    pub fn add_checkpoint(&self, body: &[u8], now: u64) -> Result<String, AddCheckpointError> {
        let request = AddCheckpointRequest::parse(body)?;
        let origin = request.claimed_origin().to_string();
        let log_key = self.trusted.get(&origin).ok_or(WitnessError::UnknownLog)?;

        let mut logs = lock_or_recover(&self.logs, "witness_logs");
        let latest = logs.get(&origin);
        let accepted = match request.verify(log_key, latest.map(|log| &log.tree)) {
            Ok(accepted) => accepted,
            Err(error) => {
                if error.is_evidence() {
                    self.keep_evidence(&origin, log_key, &request, latest, &error);
                }
                return Err(error.into());
            }
        };
        let cosignature = self
            .signer
            .cosign(accepted.checkpoint(), now)
            .map_err(|e| AddCheckpointError::Unavailable(e.to_string()))?;
        let note = accepted
            .cosigned_note(std::slice::from_ref(&cosignature))
            .map_err(|e| AddCheckpointError::Unavailable(e.to_string()))?;
        // Persist before answering: a cosignature the witness could forget
        // would let a restarted witness cosign a fork.
        write_atomic(
            &self.dir.join("logs").join(origin_hash(&origin)),
            note.as_bytes(),
        )
        .map_err(|e| AddCheckpointError::Unavailable(e.to_string()))?;
        logs.insert(
            origin,
            WitnessedLog {
                tree: accepted.tree(),
                note,
            },
        );
        Ok(encode_cosignatures(std::slice::from_ref(&cosignature)))
    }

    /// Keeps a refused, log-signed checkpoint beside the witnessed one.
    /// Best-effort: failing to keep evidence never changes the answer.
    fn keep_evidence(
        &self,
        origin: &str,
        log_key: &Ed25519NoteVerifier,
        request: &AddCheckpointRequest,
        latest: Option<&WitnessedLog>,
        error: &WitnessError,
    ) {
        let Ok(refused) = open_checkpoint(request.signed_checkpoint(), origin, log_key, &[]) else {
            return;
        };
        let refused = refused.checkpoint();
        if latest
            .is_some_and(|log| log.tree.size == refused.size() && &log.tree.root == refused.root())
        {
            // Same tree as witnessed: only the proof was bad, which the
            // log did not sign.
            return;
        }
        let dir = self.evidence_dir(origin);
        let path = dir.join(format!(
            "{}-{}.txt",
            refused.size(),
            hex::encode(refused.root())
        ));
        if path.exists() {
            return;
        }
        if let Err(e) = fs::create_dir_all(&dir) {
            eprintln!("witness: cannot keep evidence for {origin}: {e}");
            return;
        }
        if self.evidence_files(origin).len() >= MAX_EVIDENCE_PER_LOG {
            eprintln!(
                "witness: evidence for {origin} is at the {MAX_EVIDENCE_PER_LOG}-file cap; \
                 not keeping size {}",
                refused.size()
            );
            return;
        }
        let mut text = String::new();
        text.push_str("CipherVault witness evidence v1\n");
        text.push_str(&format!("origin: {origin}\n"));
        text.push_str(&format!("witness: {}\n", self.name()));
        text.push_str(&format!("refused: {error}\n"));
        text.push_str("\n-- witnessed checkpoint --\n");
        text.push_str(latest.map_or("(none)\n", |log| log.note.as_str()));
        text.push_str("-- refused add-checkpoint request --\n");
        text.push_str(&String::from_utf8_lossy(&AddCheckpointRequest::encode(
            request.old_size(),
            request.proof(),
            request.signed_checkpoint(),
        )));
        match write_atomic(&path, text.as_bytes()) {
            Ok(()) => eprintln!(
                "WARNING: witness refused an inconsistent checkpoint from {origin} \
                 (size {}): possible log misbehavior; evidence kept in {}",
                refused.size(),
                path.display()
            ),
            Err(e) => eprintln!("witness: cannot keep evidence for {origin}: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_translog::checkpoint::Checkpoint;
    use ciphervault_translog::note::Ed25519NoteSigner;
    use ciphervault_translog::{consistency_proof, leaf_hash, root_from_leaf_hashes, Hash};
    use ed25519_dalek::SigningKey;

    const ORIGIN: &str = "example.com/log";

    fn fresh_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cv-witness-{tag}-{}", rand::random::<u128>()))
    }

    fn log_signer() -> Ed25519NoteSigner {
        Ed25519NoteSigner::new(ORIGIN, SigningKey::from_bytes(&[4; 32])).unwrap()
    }

    fn config() -> WitnessConfig {
        WitnessConfig {
            enabled: true,
            name: Some("witness.example/w".into()),
            trusted_logs: vec![log_signer().verifier().unwrap().verifier_key().to_string()],
        }
    }

    fn leaves(n: u64, salt: u8) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&[salt, i as u8])).collect()
    }

    fn body(leaves: &[Hash], old: u64) -> Vec<u8> {
        let size = leaves.len() as u64;
        let checkpoint = Checkpoint::new(ORIGIN, size, root_from_leaf_hashes(leaves)).unwrap();
        let note = checkpoint.sign(&log_signer()).unwrap().encode().unwrap();
        let proof = if old == 0 || old == size {
            Vec::new()
        } else {
            consistency_proof(leaves, old).unwrap()
        };
        AddCheckpointRequest::encode(old, &proof, note.as_bytes())
    }

    #[test]
    fn persists_and_reloads_state() {
        let dir = fresh_dir("reload");
        let store = WitnessStore::open(&dir, &config(), "op").unwrap();
        let vkey = store.verifier_key().to_string();
        let history = leaves(10, 0);
        store.add_checkpoint(&body(&history[..4], 0), 100).unwrap();
        store.add_checkpoint(&body(&history, 4), 101).unwrap();
        drop(store);

        let store = WitnessStore::open(&dir, &config(), "op").unwrap();
        assert_eq!(store.verifier_key(), vkey, "the key survives a restart");
        assert_eq!(store.witnessed(ORIGIN).unwrap().size, 10);
        let err = store.add_checkpoint(&body(&history, 0), 102).unwrap_err();
        assert!(matches!(
            err,
            AddCheckpointError::Refused(WitnessError::Conflict { latest_size: 10 })
        ));
        assert!(store.checkpoint_for_hash(&origin_hash(ORIGIN)).is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn name_is_pinned_and_state_is_verified() {
        let dir = fresh_dir("pinned");
        let store = WitnessStore::open(&dir, &config(), "op").unwrap();
        store.add_checkpoint(&body(&leaves(3, 0), 0), 100).unwrap();
        drop(store);

        let renamed = WitnessConfig {
            name: Some("witness.example/other".into()),
            ..config()
        };
        assert!(matches!(
            WitnessStore::open(&dir, &renamed, "op"),
            Err(WitnessStoreError::NameMismatch { .. })
        ));

        // A tampered state file fails closed.
        let state = dir.join("witness/logs").join(origin_hash(ORIGIN));
        let text = fs::read_to_string(&state).unwrap();
        fs::write(&state, text.replacen("\n3\n", "\n4\n", 1)).unwrap();
        assert!(matches!(
            WitnessStore::open(&dir, &config(), "op"),
            Err(WitnessStoreError::Corrupt(_))
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_requests_cosign_exactly_once() {
        let dir = fresh_dir("race");
        let store = std::sync::Arc::new(WitnessStore::open(&dir, &config(), "op").unwrap());
        let history = leaves(40, 0);
        store.add_checkpoint(&body(&history[..8], 0), 100).unwrap();
        // Many clients race from the same old size to different new sizes.
        let handles: Vec<_> = (9..=40u64)
            .map(|size| {
                let store = store.clone();
                let body = body(&history[..size as usize], 8);
                std::thread::spawn(move || store.add_checkpoint(&body, 200).is_ok())
            })
            .collect();
        let accepted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(accepted, 1, "only one request from size 8 may win");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn evidence_is_kept_once_per_signed_checkpoint() {
        let dir = fresh_dir("evidence");
        let store = WitnessStore::open(&dir, &config(), "op").unwrap();
        let history = leaves(12, 0);
        store.add_checkpoint(&body(&history[..6], 0), 100).unwrap();

        // A fork at the same size: signed by the log, different root.
        let fork = leaves(12, 1);
        for _ in 0..3 {
            let err = store.add_checkpoint(&body(&fork[..6], 6), 101).unwrap_err();
            assert!(matches!(
                err,
                AddCheckpointError::Refused(WitnessError::Inconsistent(_))
            ));
        }
        let files = store.evidence_files(ORIGIN);
        assert_eq!(files.len(), 1, "one file per distinct signed checkpoint");
        let evidence = fs::read_to_string(&files[0]).unwrap();
        assert!(evidence.contains("-- witnessed checkpoint --"));
        assert!(evidence.contains("-- refused add-checkpoint request --"));

        // A bad proof for the witnessed tree itself is refused but is not
        // evidence: the log did not sign the proof.
        let checkpoint = Checkpoint::new(ORIGIN, 6, root_from_leaf_hashes(&history[..6])).unwrap();
        let note = checkpoint.sign(&log_signer()).unwrap().encode().unwrap();
        let bad = AddCheckpointRequest::encode(6, &[[7; 32]], note.as_bytes());
        assert!(store.add_checkpoint(&bad, 102).is_err());
        assert_eq!(store.evidence_files(ORIGIN).len(), 1);

        // The witnessed state is unchanged.
        assert_eq!(store.witnessed(ORIGIN).unwrap().size, 6);
        let _ = fs::remove_dir_all(dir);
    }
}
