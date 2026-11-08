//! OperatorState: Recovery records and paginated recovery log.

use super::*;

impl OperatorState {
    pub fn append_authorized_recovery_record(
        &self,
        locator_hex: &str,
        record: &[u8],
        caller_pk: Option<&[u8; 32]>,
    ) -> Result<u64, String> {
        self.require_voucher_legacy()?;
        let outcome = self.append_authorized_recovery_record_inner(locator_hex, record, caller_pk);
        self.metrics
            .observe_recovery_append(record.len() as u64, outcome.is_ok());
        outcome
    }

    /// Voucher-carrying recovery append: authorizes and charges quota before
    /// touching disk, releases the charge when persistence fails. Appends
    /// always store new bytes, so success never releases. Inner errors keep
    /// the legacy 400 mapping.
    pub fn append_recovery_record_with_voucher(
        &self,
        locator_hex: &str,
        record: &[u8],
        caller_pk: Option<&[u8; 32]>,
        voucher: Option<&WriteVoucher>,
    ) -> Result<u64, StorageError> {
        let charge = self.authorize_write(voucher, record.len() as u64)?;
        let outcome = self.append_authorized_recovery_record_inner(locator_hex, record, caller_pk);
        self.metrics
            .observe_recovery_append(record.len() as u64, outcome.is_ok());
        match outcome {
            Ok(sequence) => Ok(sequence),
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

    fn append_authorized_recovery_record_inner(
        &self,
        locator_hex: &str,
        record: &[u8],
        caller_pk: Option<&[u8; 32]>,
    ) -> Result<u64, String> {
        if locator_hex.len() != 64 || hex::decode(locator_hex).is_err() {
            return Err("Invalid recovery locator (must be 64 hex characters)".into());
        }
        let limit = max_recovery_record_size();
        if record.len() > limit {
            return Err(format!(
                "Record exceeds maximum size limit of {} bytes",
                limit
            ));
        }

        // The locator lock covers authority/capacity validation and durable append.
        let _stripe_guard = lock_or_recover(self.io_stripe(locator_hex), "io_stripe");
        let log_path = self
            .data_dir
            .join("recovery")
            .join(format!("{}.log", locator_hex));
        // Cryptographic Authorization Check
        // Inspect existing records to find registered recovery_signing_pk and authorized device public keys.
        let mut registered_recovery_pk: Option<[u8; 32]> = None;
        let mut authorized_device_pks: Vec<[u8; 32]> = Vec::new();
        let (record_count, committed_offset) = Self::scan_recovery_log(&log_path, |r| {
            if let Ok(genesis) = from_canonical_cbor::<GenesisRecord>(r) {
                if genesis.verify().is_ok() && genesis.recovery_signing_pk.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&genesis.recovery_signing_pk);
                    registered_recovery_pk = Some(pk);
                }
            }
            if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(r) {
                if let Some(r_pk) = registered_recovery_pk {
                    if cert.verify(&r_pk).is_ok() && cert.device_signing_pk.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&cert.device_signing_pk);
                        if !authorized_device_pks.contains(&pk) {
                            authorized_device_pks.push(pk);
                        }
                    }
                }
            }
        })?;
        if record_count >= MAX_RECORDS_PER_LOCATOR
            || committed_offset.saturating_add(4 + record.len() as u64) > MAX_RECOVERY_LOG_BYTES
        {
            return Err("Locator recovery log capacity exceeded".into());
        }

        // Verify incoming record against authority
        let mut is_authorized = false;

        // 1. GenesisRecord: Must be signed by recovery authority. If one already registered, must match it.
        if let Ok(genesis) = from_canonical_cbor::<GenesisRecord>(record) {
            if genesis.version == PROTOCOL_VERSION
                && genesis.verify().is_ok()
                && genesis.recovery_signing_pk.len() == 32
            {
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&genesis.recovery_signing_pk);
                if let Some(existing_pk) = registered_recovery_pk {
                    if existing_pk == pk {
                        is_authorized = true;
                    }
                } else {
                    is_authorized = true;
                }
            }
        }

        // 2. DeviceCertificate: Must be signed by registered recovery authority (r_pk)
        if !is_authorized {
            if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(record) {
                if cert.version == PROTOCOL_VERSION && cert.device_signing_pk.len() == 32 {
                    if let Some(r_pk) = registered_recovery_pk {
                        if cert.verify(&r_pk).is_ok() {
                            is_authorized = true;
                        }
                    }
                }
            }
        }

        // 3. HeadRecord: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(head) = from_canonical_cbor::<HeadRecord>(record) {
                if head.version == PROTOCOL_VERSION && head.snapshot_id.len() == 32 {
                    for d_pk in &authorized_device_pks {
                        if head.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if head.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        // 4. EpochEnvelope: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(envelope) = from_canonical_cbor::<EpochEnvelope>(record) {
                if envelope.version == PROTOCOL_VERSION
                    && envelope.recipient_fingerprint.len() == 32
                {
                    for d_pk in &authorized_device_pks {
                        if envelope.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if envelope.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        // 5. SnapshotRecord: Must be signed by an authorized device key or recovery authority
        if !is_authorized {
            if let Ok(snap) = from_canonical_cbor::<SnapshotRecord>(record) {
                if snap.version == PROTOCOL_VERSION {
                    for d_pk in &authorized_device_pks {
                        if snap.verify(d_pk).is_ok() {
                            is_authorized = true;
                            break;
                        }
                    }
                    if !is_authorized {
                        if let Some(r_pk) = registered_recovery_pk {
                            if snap.verify(&r_pk).is_ok() {
                                is_authorized = true;
                            }
                        }
                    }
                }
            }
        }

        if !is_authorized {
            return Err("Record failed cryptographic authorization against registered vault recovery key or authorized device certificate".into());
        }

        // Caller authorization check:
        // Once recovery authority is registered, any caller modifying the log MUST be either
        // the recovery authority or one of the certified device public keys.
        if let Some(c_pk) = caller_pk {
            if let Some(r_pk) = registered_recovery_pk {
                let newly_certified_pk =
                    if let Ok(cert) = from_canonical_cbor::<DeviceCertificate>(record) {
                        if cert.verify(&r_pk).is_ok() && cert.device_signing_pk.len() == 32 {
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(&cert.device_signing_pk);
                            Some(pk)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                let is_trusted_caller = c_pk == &r_pk
                    || authorized_device_pks.contains(c_pk)
                    || newly_certified_pk.as_ref() == Some(c_pk);
                if !is_trusted_caller {
                    return Err(
                        "Caller session key is not authorized for this vault locator".into(),
                    );
                }
            }
        }

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&log_path)
            .map_err(|e| e.to_string())?;

        // Discard only the incomplete final frame left by an interrupted write.
        // Valid acknowledged frames are kept; oversized/corrupt frames fail closed.
        if file.metadata().map_err(|e| e.to_string())?.len() != committed_offset {
            file.set_len(committed_offset)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
        }
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;

        // Format: [4 bytes length prefix in big endian][record bytes]
        let len = (record.len() as u32).to_be_bytes();
        let original_len = file.metadata().map_err(|e| e.to_string())?.len();
        if let Err(e) = file
            .write_all(&len)
            .and_then(|_| file.write_all(record))
            .and_then(|_| file.sync_all())
        {
            let _ = file.set_len(original_len);
            let _ = file.sync_all();
            return Err(e.to_string());
        }

        Ok(record_count as u64 + 1)
    }

    pub fn append_recovery_record(&self, locator_hex: &str, record: &[u8]) -> Result<u64, String> {
        self.append_authorized_recovery_record(locator_hex, record, None)
    }

    pub fn get_recovery_records(&self, locator_hex: &str) -> Vec<Vec<u8>> {
        let records = self.get_recovery_records_inner(locator_hex);
        self.metrics.observe_recovery_read(&records);
        records
    }

    fn get_recovery_records_inner(&self, locator_hex: &str) -> Vec<Vec<u8>> {
        if locator_hex.len() != 64 || hex::decode(locator_hex).is_err() {
            return Vec::new();
        }
        let _stripe_guard = lock_or_recover(self.io_stripe(locator_hex), "io_stripe");
        let log_path = self
            .data_dir
            .join("recovery")
            .join(format!("{}.log", locator_hex));
        let mut out = Vec::new();
        if Self::scan_recovery_log(&log_path, |record| out.push(record.to_vec())).is_err() {
            return Vec::new();
        }
        out
    }

    /// Read one frame at a time; callers hold the locator stripe. An incomplete
    /// tail returns the last committed offset for append-time crash recovery.
    fn scan_recovery_log(
        path: &std::path::Path,
        mut visit: impl FnMut(&[u8]),
    ) -> Result<(usize, u64), String> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(e.to_string()),
        };
        if file.metadata().map_err(|e| e.to_string())?.len() > MAX_RECOVERY_LOG_BYTES {
            return Err("Recovery log exceeds byte limit".into());
        }
        let mut reader = std::io::BufReader::new(file);
        let mut count = 0;
        let mut offset = 0;
        loop {
            let mut prefix = [0u8; 4];
            match reader.read_exact(&mut prefix) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok((count, offset))
                }
                Err(e) => return Err(e.to_string()),
            }
            let len = u32::from_be_bytes(prefix) as usize;
            if len == 0 || len > max_recovery_record_size() {
                return Err("Invalid recovery record length".into());
            }
            let mut record = vec![0; len];
            match reader.read_exact(&mut record) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok((count, offset))
                }
                Err(e) => return Err(e.to_string()),
            }
            visit(&record);
            count += 1;
            offset += 4 + len as u64;
            if count > MAX_RECORDS_PER_LOCATOR {
                return Err("Recovery log exceeds record limit".into());
            }
        }
    }

    pub fn get_recovery_page(
        &self,
        locator_hex: &str,
        cursor: u64,
    ) -> Result<RecoveryPage, String> {
        if hex::decode(locator_hex).map(|bytes| bytes.len()) != Ok(32) {
            return Err("Invalid recovery locator".into());
        }
        let _stripe_guard = lock_or_recover(self.io_stripe(locator_hex), "io_stripe");
        let path = self
            .data_dir
            .join("recovery")
            .join(format!("{locator_hex}.log"));
        let mut file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && cursor == 0 => {
                return Ok(RecoveryPage {
                    records: Vec::new(),
                    next_cursor: None,
                })
            }
            Err(e) => return Err(e.to_string()),
        };
        let end = file.metadata().map_err(|e| e.to_string())?.len();
        if end > MAX_RECOVERY_LOG_BYTES || cursor > end {
            return Err("Invalid recovery cursor or oversized log".into());
        }
        file.seek(SeekFrom::Start(cursor))
            .map_err(|e| e.to_string())?;
        let mut offset = cursor;
        let mut bytes = 0;
        let mut records = Vec::new();
        while offset < end {
            let mut prefix = [0u8; 4];
            file.read_exact(&mut prefix)
                .map_err(|_| "Incomplete recovery log tail; repair required")?;
            let len = u32::from_be_bytes(prefix) as usize;
            if len == 0 || len > max_recovery_record_size() || offset + 4 + len as u64 > end {
                return Err("Invalid or incomplete recovery record".into());
            }
            if bytes + len > RECOVERY_PAGE_BYTES && !records.is_empty() {
                break;
            }
            let mut record = vec![0; len];
            file.read_exact(&mut record).map_err(|e| e.to_string())?;
            offset += 4 + len as u64;
            bytes += len;
            records.push(record);
        }
        self.metrics.observe_recovery_read(&records);
        Ok(RecoveryPage {
            records,
            next_cursor: (offset < end).then_some(offset),
        })
    }
}
