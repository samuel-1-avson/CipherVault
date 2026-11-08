//! OperatorState: Vouchers, quotas, objects, PoS, and atomic persistence.

use super::*;

impl OperatorState {
    /// Enables voucher enforcement: writes without a valid voucher are
    /// rejected before persistence. Default off (static mode unchanged).
    pub fn set_vouchers_required(&self, required: bool) {
        self.vouchers_required.store(required, Ordering::SeqCst);
    }

    pub fn vouchers_required(&self) -> bool {
        self.vouchers_required.load(Ordering::SeqCst)
    }

    /// Caps the largest single voucher grant this operator honors.
    pub fn set_voucher_max_quota(&self, max_quota_bytes: u64) {
        lock_or_recover(&self.voucher_ledger, "voucher_ledger").set_max_quota(max_quota_bytes);
    }

    /// Sets the uniform per-user (holder-key) lifetime write cap in bytes
    /// (0 = unlimited). Without it a holder can chain vouchers into
    /// unbounded disk growth; with it, spend aggregates across every
    /// voucher the holder presents. Voucher-mode only: anonymous writes
    /// carry no holder identity to charge.
    pub fn set_user_quota_bytes(&self, user_quota_bytes: u64) {
        lock_or_recover(&self.voucher_ledger, "voucher_ledger")
            .set_user_quota_bytes(user_quota_bytes);
    }

    /// Self-issues a voucher (D3 barter model): this operator's key signs a
    /// grant the operator itself will honor. Served over HTTP with service-
    /// token auth; never over P2P (no operator-admin surface there).
    pub fn issue_voucher(
        &self,
        holder_pk_hex: String,
        quota_bytes: u64,
        ttl_secs: u64,
    ) -> Result<WriteVoucher, StorageError> {
        WriteVoucher::issue(&self.signing_key, holder_pk_hex, quota_bytes, ttl_secs)
    }

    fn issuer_pk_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Pre-persistence write gate shared by all transports: verifies the
    /// presented voucher and charges `bytes`, or rejects voucherless writes
    /// when policy requires vouchers. Returns the charge to release if
    /// persistence fails or stores no new bytes.
    pub(crate) fn authorize_write(
        &self,
        voucher: Option<&WriteVoucher>,
        bytes: u64,
    ) -> Result<Option<(String, u64)>, StorageError> {
        if self.voucher_ledger_failed.load(Ordering::SeqCst) {
            return Err(StorageError::ServerError {
                status: 503,
                message: "Voucher accounting unavailable; repair the persisted ledger".into(),
            });
        }
        match voucher {
            Some(voucher) => {
                let mut ledger = lock_or_recover(&self.voucher_ledger, "voucher_ledger");
                let now = chrono::Utc::now().timestamp() as u64;
                ledger.try_consume(voucher, &self.issuer_pk_hex(), now, bytes)?;
                // Durable before bytes hit disk: the lock is held across
                // the file persist (same convention as the relay/peer/
                // approval stores) so concurrent charges cannot interleave
                // file writes and lose spend on restart.
                let encoded = ledger.encode().map_err(|error| StorageError::ServerError {
                    status: 500,
                    message: format!("Unable to encode voucher ledger: {error}"),
                })?;
                if let Err(error) = self.persist_voucher_ledger(&encoded) {
                    ledger.release(&voucher.nonce_hex, bytes);
                    return Err(StorageError::ServerError {
                        status: 500,
                        message: format!("Unable to persist voucher ledger: {error}"),
                    });
                }
                Ok(Some((voucher.nonce_hex.clone(), bytes)))
            }
            None if self.vouchers_required() => Err(StorageError::ServerError {
                status: 403,
                message: "write voucher required".into(),
            }),
            None => Ok(None),
        }
    }

    pub(crate) fn release_write(&self, charge: Option<(String, u64)>) -> Result<(), StorageError> {
        let Some((nonce, bytes)) = charge else {
            return Ok(());
        };
        let mut ledger = lock_or_recover(&self.voucher_ledger, "voucher_ledger");
        ledger.release(&nonce, bytes);
        let encoded = ledger.encode().map_err(|error| StorageError::ServerError {
            status: 500,
            message: format!("Unable to encode voucher ledger: {error}"),
        })?;
        self.persist_voucher_ledger(&encoded)
            .map_err(|error| StorageError::ServerError {
                status: 500,
                message: format!("Unable to persist voucher ledger: {error}"),
            })
    }

    /// Legacy policy gate for the original write methods: identical behavior
    /// when policy is off, hard rejection when on. Keeps frozen callers
    /// compiling and behaving while closing the voucherless bypass.
    pub(crate) fn require_voucher_legacy(&self) -> Result<(), String> {
        if self.vouchers_required() {
            return Err("write voucher required".into());
        }
        Ok(())
    }

    pub fn put_object(&self, cid_hex: &str, bytes: &[u8]) -> Result<(), String> {
        self.require_voucher_legacy()?;
        let started = std::time::Instant::now();
        let outcome = self.put_object_inner(cid_hex, bytes).map(|_| ());
        self.metrics
            .observe_put(bytes.len() as u64, started.elapsed(), outcome.is_ok());
        outcome
    }

    /// Overrides the receiver-side repair budget (bytes/sec). Tests and
    /// operators tune the repair lane without touching client quotas.
    pub fn set_repair_budget(&self, bytes_per_sec: u64) {
        lock_or_recover(&self.repair_budget, "repair_budget").set_rate(bytes_per_sec);
    }

    /// Spends `bytes` from the repair budget. False means the push must
    /// 429 without storing.
    pub fn try_spend_repair_budget(&self, bytes: u64) -> bool {
        lock_or_recover(&self.repair_budget, "repair_budget").try_take(bytes)
    }

    /// Persists one operator-signed repair push. Runs the SAME validation
    /// as client puts (size cap, digest match, atomic persist) but skips
    /// the voucher/quota lane — repair is bounded by the repair budget
    /// instead (checked by the caller BEFORE invoking this). Returns
    /// whether the bytes were net-new. Deliberately absent from
    /// `objects_put_*` metrics: repair has its own telemetry series.
    pub fn put_repair_object(&self, cid_hex: &str, bytes: &[u8]) -> Result<bool, String> {
        self.put_object_inner(cid_hex, bytes)
    }

    /// Whether the store holds a complete object for `cid_hex` (atomic
    /// renames mean presence implies completeness). Metadata-only: the
    /// repair scanner filters candidates without reading bytes.
    pub fn has_object(&self, cid_hex: &str) -> bool {
        cid_hex.len() == 64 && self.data_dir.join("objects").join(cid_hex).is_file()
    }

    /// Lists locally stored object CIDs for the repair scanner: up to
    /// `limit` entries past `offset`, in directory order. Unparseable
    /// names (tmp files, future layouts) are skipped, never errors. A
    /// short return (fewer than `limit`) signals the cursor should wrap.
    pub fn list_object_cids(&self, offset: usize, limit: usize) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        if limit == 0 {
            return out;
        }
        let entries = match fs::read_dir(self.data_dir.join("objects")) {
            Ok(entries) => entries,
            Err(_) => return out,
        };
        for entry in entries.filter_map(|entry| entry.ok()).skip(offset) {
            if out.len() >= limit {
                break;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() != 64 {
                continue;
            }
            let Ok(raw) = hex::decode(&name) else {
                continue;
            };
            if raw.len() != 32 {
                continue;
            }
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&raw);
            out.push(cid);
        }
        out
    }

    /// Voucher-carrying put: verifies the voucher, charges quota only for
    /// bytes not already stored, then persists. The pre-check keeps
    /// idempotent retries free even with the quota fully spent (mesh repair
    /// depends on this); objects are content-addressed and never deleted,
    /// so a present pre-check stays present. Any race the other way (absent
    /// at pre-check, stored by a concurrent put) releases after the fact.
    /// Inner errors keep the legacy 400 mapping.
    pub fn put_object_with_voucher(
        &self,
        cid_hex: &str,
        bytes: &[u8],
        voucher: Option<&WriteVoucher>,
    ) -> Result<(), StorageError> {
        let already_present = self.object_matches(cid_hex, bytes);
        let billable = if already_present {
            0
        } else {
            bytes.len() as u64
        };
        let charge = self.authorize_write(voucher, billable)?;
        let started = std::time::Instant::now();
        let outcome = self.put_object_inner(cid_hex, bytes);
        self.metrics
            .observe_put(bytes.len() as u64, started.elapsed(), outcome.is_ok());
        match outcome {
            Ok(net_new) => {
                if !net_new {
                    self.release_write(charge)?;
                }
                Ok(())
            }
            Err(e) => {
                // The write error is the true cause; a release-persist
                // failure on top is logged loudly but must not mask it.
                if let Err(release_error) = self.release_write(charge) {
                    eprintln!(
                        "operator voucher release persist failed after write error: {release_error}"
                    );
                }
                Err(StorageError::ServerError {
                    status: 400,
                    message: e,
                })
            }
        }
    }

    /// Best-effort idempotency pre-check: true only if the object file
    /// exists with byte-identical content. False on any doubt (missing,
    /// unreadable, malformed CID) — the inner write then validates fully.
    fn object_matches(&self, cid_hex: &str, bytes: &[u8]) -> bool {
        if cid_hex.len() != 64 {
            return false;
        }
        let obj_path = self.data_dir.join("objects").join(cid_hex);
        fs::read(&obj_path).ok().as_deref() == Some(bytes)
    }

    fn put_object_inner(&self, cid_hex: &str, bytes: &[u8]) -> Result<bool, String> {
        let limit = max_object_size();
        if bytes.len() > limit {
            return Err(format!(
                "Object exceeds maximum size limit of {} bytes",
                limit
            ));
        }
        if cid_hex.len() != 64 {
            return Err("Invalid CID length (must be 64 hex characters)".into());
        }
        let expected_digest = hex::decode(cid_hex).map_err(|e| e.to_string())?;
        if expected_digest.len() != 32 {
            return Err("Invalid CID digest length".into());
        }
        let actual_digest = compute_digest(bytes);

        if actual_digest.as_slice() != expected_digest.as_slice() {
            return Err("Digest mismatch".into());
        }

        let _stripe_guard = lock_or_recover(self.io_stripe(cid_hex), "io_stripe");
        let obj_path = self.data_dir.join("objects").join(cid_hex);
        if fs::read(&obj_path).ok().as_deref() != Some(bytes) {
            self.persist_atomic(&obj_path, bytes)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn get_object(&self, cid_hex: &str) -> Option<Vec<u8>> {
        let started = std::time::Instant::now();
        let outcome = self.get_object_inner(cid_hex);
        self.metrics.observe_get(
            outcome.as_ref().map(|bytes| bytes.len() as u64),
            started.elapsed(),
        );
        outcome
    }

    fn get_object_inner(&self, cid_hex: &str) -> Option<Vec<u8>> {
        if cid_hex.len() != 64 || hex::decode(cid_hex).is_err() {
            return None;
        }
        let obj_path = self.data_dir.join("objects").join(cid_hex);
        fs::read(obj_path).ok()
    }

    /// Computes and signs a cryptographic Proof-of-Storage receipt for a challenged object.
    pub fn generate_pos_proof(
        &self,
        cid_hex: &str,
        nonce: &[u8; 32],
    ) -> Result<ciphervault_storage::ProofOfStorageReceipt, String> {
        let started = std::time::Instant::now();
        let outcome = self.generate_pos_proof_inner(cid_hex, nonce);
        self.metrics.observe_pos(started.elapsed(), outcome.is_ok());
        outcome
    }

    fn generate_pos_proof_inner(
        &self,
        cid_hex: &str,
        nonce: &[u8; 32],
    ) -> Result<ciphervault_storage::ProofOfStorageReceipt, String> {
        if cid_hex.len() != 64 {
            return Err("Invalid CID length (must be 64 hex characters)".into());
        }
        let cid_bytes = hex::decode(cid_hex).map_err(|e| e.to_string())?;
        if cid_bytes.len() != 32 {
            return Err("Invalid CID digest length".into());
        }
        let mut cid_arr = [0u8; 32];
        cid_arr.copy_from_slice(&cid_bytes);

        let obj_path = self.data_dir.join("objects").join(cid_hex);
        let bytes = fs::read(&obj_path).map_err(|_| "Object not found".to_string())?;

        let proof = ciphervault_storage::compute_pos_proof(&cid_arr, nonce, &bytes);

        let mut receipt = ciphervault_storage::ProofOfStorageReceipt {
            operator_id: self.operator_id.clone(),
            cid_hex: cid_hex.to_lowercase(),
            nonce_hex: hex::encode(nonce),
            proof_hex: hex::encode(proof),
            signature_hex: String::new(),
            size_bytes: bytes.len() as u64,
        };

        let msg = receipt.signing_bytes();
        let sig = ciphervault_crypto::signatures::sign_with_domain(
            &self.signing_key,
            b"operator_pos",
            &msg,
        );
        receipt.signature_hex = hex::encode(sig);

        Ok(receipt)
    }

    pub(crate) fn persist_atomic(
        &self,
        path: &std::path::Path,
        bytes: &[u8],
    ) -> Result<(), String> {
        self.persist_atomic_inner(path, bytes, false)
    }

    /// Atomic + fsynced persist for secret-bearing stores (sessions,
    /// challenges, enrolled identities). On unix the temp file is created
    /// 0600, so bearer tokens are never visible at wider perms — not even
    /// between creation and rename. Rename carries the mode to `path`.
    pub(crate) fn persist_atomic_secure(
        &self,
        path: &std::path::Path,
        bytes: &[u8],
    ) -> Result<(), String> {
        self.persist_atomic_inner(path, bytes, true)
    }

    fn persist_atomic_inner(
        &self,
        path: &std::path::Path,
        bytes: &[u8],
        secure: bool,
    ) -> Result<(), String> {
        #[cfg(not(unix))]
        let _ = secure;
        let temp = path.with_extension(format!("{}.tmp", rand::random::<u128>()));
        let result = (|| -> std::io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            if secure {
                opts.mode(0o600);
            }
            let mut file = opts.open(&temp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if secure {
                // Windows has no mode bits: apply the owner-only DACL
                // explicitly (it was a no-op before, leaving bearer
                // tokens at default ACLs). Fails closed.
                ciphervault_file_lock::lock_secret_file(&temp)?;
            }
            fs::rename(&temp, path)?;
            #[cfg(unix)]
            std::fs::File::open(path.parent().expect("lease temp path always has a parent"))?
                .sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(|e| e.to_string())
    }
}
