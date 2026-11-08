//! OperatorState: Lease issuance, renewal, and ownership.

use super::*;

impl OperatorState {
    fn persist_lease(&self, mut receipt: LeaseReceipt) -> Result<LeaseReceipt, String> {
        receipt.signature_hex = hex::encode(sign_with_domain(
            &self.signing_key,
            b"operator_lease",
            &receipt.signing_bytes(),
        ));
        let path = self
            .data_dir
            .join("leases")
            .join(format!("{}.json", receipt.lease_id));
        let serialized = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        self.persist_atomic(&path, &serialized)?;
        Ok(receipt)
    }

    pub fn create_lease(
        &self,
        closure_digest_hex: &str,
        bytes: u64,
        term_days: u32,
    ) -> Result<LeaseReceipt, String> {
        self.require_voucher_legacy()?;
        let outcome = self.create_lease_inner(closure_digest_hex, bytes, term_days);
        self.metrics.observe_lease_create(outcome.is_ok());
        outcome
    }

    /// Voucher-carrying lease commit: the voucher authorizes, nothing is
    /// charged (leases store no bytes). Inner errors keep the legacy 500
    /// mapping.
    pub fn create_lease_with_voucher(
        &self,
        closure_digest_hex: &str,
        bytes: u64,
        term_days: u32,
        voucher: Option<&WriteVoucher>,
    ) -> Result<LeaseReceipt, StorageError> {
        self.authorize_write(voucher, 0)?;
        let outcome = self.create_lease_inner(closure_digest_hex, bytes, term_days);
        self.metrics.observe_lease_create(outcome.is_ok());
        outcome.map_err(|e| StorageError::ServerError {
            status: 500,
            message: e,
        })
    }

    fn create_lease_inner(
        &self,
        closure_digest_hex: &str,
        bytes: u64,
        term_days: u32,
    ) -> Result<LeaseReceipt, String> {
        if closure_digest_hex.len() != 64
            || hex::decode(closure_digest_hex).is_err()
            || term_days == 0
        {
            return Err("Invalid closure digest or retention term".into());
        }
        // Upper bound: leases are promises, not storage — cap at ~100 years so
        // u32::MAX (~12M years) cannot sit in the ledger. Renew path already
        // uses checked_add; create expiry uses it below for the same reason.
        if term_days > 36_500 {
            return Err("Retention term exceeds maximum (36500 days)".into());
        }
        let _stripe_guard = lock_or_recover(self.io_stripe(closure_digest_hex), "io_stripe");
        let now = Utc::now().timestamp() as u64;
        let expires_at_utc = now
            .checked_add(u64::from(term_days) * 86400)
            .ok_or("Expiry overflow")?;
        self.persist_lease(LeaseReceipt {
            lease_id: hex::encode(rand::random::<[u8; 16]>()),
            operator_id: self.operator_id.clone(),
            closure_digest_hex: closure_digest_hex.into(),
            term_days,
            bytes,
            issued_at_utc: now,
            expires_at_utc,
            signature_hex: String::new(),
        })
    }

    pub fn renew_lease(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
    ) -> Result<LeaseReceipt, String> {
        self.require_voucher_legacy()?;
        let outcome = self.renew_lease_inner(lease_id, additional_days, bytes, None);
        self.metrics.observe_lease_renew(outcome.is_ok());
        outcome
    }

    /// Voucher-carrying lease renewal: authorizes without charging (no new
    /// bytes). Inner errors keep the legacy 400 mapping.
    pub fn renew_lease_with_voucher(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
        voucher: Option<&WriteVoucher>,
    ) -> Result<LeaseReceipt, StorageError> {
        self.authorize_write(voucher, 0)?;
        let outcome = self.renew_lease_inner(lease_id, additional_days, bytes, None);
        self.metrics.observe_lease_renew(outcome.is_ok());
        outcome.map_err(|e| StorageError::ServerError {
            status: 400,
            message: e,
        })
    }

    fn renew_lease_inner(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
        caller_vault: Option<&str>,
    ) -> Result<LeaseReceipt, String> {
        if lease_id.len() != 32 || hex::decode(lease_id).is_err() || additional_days == 0 {
            return Err("Invalid lease ID or retention term".into());
        }
        let _stripe_guard = lock_or_recover(self.io_stripe(lease_id), "io_stripe");
        let owner_path = self
            .data_dir
            .join("leases")
            .join(format!("{lease_id}.owner"));
        match (caller_vault, fs::read_to_string(&owner_path)) {
            (Some(vault), Ok(owner)) if owner.trim().eq_ignore_ascii_case(vault) => {}
            (None, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("Lease ownership does not match caller vault".into()),
        }
        let path = self
            .data_dir
            .join("leases")
            .join(format!("{}.json", lease_id));
        let mut receipt: LeaseReceipt =
            serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        receipt
            .verify(&self.signing_key.verifying_key().to_bytes())
            .map_err(|e| e.to_string())?;
        if receipt.bytes != bytes {
            return Err("Lease byte count mismatch".into());
        }
        receipt.term_days = receipt
            .term_days
            .checked_add(additional_days)
            .ok_or("Retention overflow")?;
        receipt.expires_at_utc = receipt
            .expires_at_utc
            .max(Utc::now().timestamp() as u64)
            .checked_add(u64::from(additional_days) * 86400)
            .ok_or("Expiry overflow")?;
        self.persist_lease(receipt)
    }

    /// Records which vault owns a lease in a `<id>.owner` sidecar. The
    /// signed receipt itself is untouched, so legacy leases keep verifying.
    pub fn record_lease_owner(&self, lease_id: &str, vault_id_hex: &str) -> Result<(), String> {
        if lease_id.len() != 32 || hex::decode(lease_id).is_err() {
            return Err("Invalid lease ID".into());
        }
        if vault_id_hex.len() != 64 || hex::decode(vault_id_hex).is_err() {
            return Err("Invalid vault ID".into());
        }
        let path = self
            .data_dir
            .join("leases")
            .join(format!("{}.owner", lease_id));
        let _stripe_guard = lock_or_recover(self.io_stripe(lease_id), "io_stripe");
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => file
                .write_all(vault_id_hex.to_ascii_lowercase().as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if fs::read_to_string(&path)
                    .map_err(|e| e.to_string())?
                    .trim()
                    .eq_ignore_ascii_case(vault_id_hex)
                {
                    Ok(())
                } else {
                    Err("Lease already belongs to another vault".into())
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn renew_owned_lease_with_voucher(
        &self,
        lease_id: &str,
        additional_days: u32,
        bytes: u64,
        vault_id_hex: &str,
        voucher: Option<&WriteVoucher>,
    ) -> Result<LeaseReceipt, StorageError> {
        self.authorize_write(voucher, 0)?;
        let outcome = self.renew_lease_inner(lease_id, additional_days, bytes, Some(vault_id_hex));
        self.metrics.observe_lease_renew(outcome.is_ok());
        outcome.map_err(|message| StorageError::ServerError {
            status: 403,
            message,
        })
    }

    /// Lists this vault's leases, soonest-expiring first. Legacy leases
    /// without an owner sidecar, corrupt records, and signature failures
    /// are skipped rather than failing the whole listing.
    pub fn list_leases_for_vault(&self, vault_id_hex: &str) -> Vec<LeaseReceipt> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(self.data_dir.join("leases")) {
            Ok(entries) => entries,
            Err(_) => return out,
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(lease_id) = name.strip_suffix(".json") else {
                continue;
            };
            if lease_id.len() != 32 || hex::decode(lease_id).is_err() {
                continue;
            }
            let owner_path = self
                .data_dir
                .join("leases")
                .join(format!("{lease_id}.owner"));
            let owned_by_caller = fs::read_to_string(owner_path)
                .map(|owner| owner.trim().eq_ignore_ascii_case(vault_id_hex))
                .unwrap_or(false);
            if !owned_by_caller {
                continue;
            }
            let Ok(raw) = fs::read(entry.path()) else {
                continue;
            };
            let Ok(receipt): Result<LeaseReceipt, _> = serde_json::from_slice(&raw) else {
                continue;
            };
            if receipt
                .verify(&self.signing_key.verifying_key().to_bytes())
                .is_err()
            {
                continue;
            }
            out.push(receipt);
        }
        out.sort_by_key(|receipt| receipt.expires_at_utc);
        out
    }
}
