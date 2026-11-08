//! OperatorState: Peer registry, membership lifecycle, and approvals.

use super::*;

impl OperatorState {
    /// Validates a peer descriptor's self-signature, freshness window, and
    /// endpoint shape. Shared by control-plane announces, verified ticket
    /// joins, and refreshes; trust (allowlist vs invite vs known key) is
    /// decided by the caller.
    fn validate_peer_descriptor(peer: &ciphervault_storage::PeerDescriptor) -> Result<(), String> {
        peer.verify()
            .map_err(|e| format!("Invalid peer signature: {}", e))?;
        // Freshness: the timestamp is signature-covered, so these bounds
        // close replay of stale announces and immortal future-dated ones.
        // Covers the HTTP route, the P2P mirror, and test callers alike.
        let now = Utc::now().timestamp() as u64;
        if peer.timestamp_utc > now.saturating_add(MAX_PEER_ANNOUNCE_SKEW_SECS) {
            return Err("Peer announcement timestamp is too far in the future".into());
        }
        if now.saturating_sub(peer.timestamp_utc) >= MAX_PEER_ANNOUNCE_AGE_SECS {
            return Err("Peer announcement is stale".into());
        }
        let endpoint = peer.endpoint.trim();
        if !(endpoint.starts_with("https://") || endpoint.starts_with("http://"))
            || endpoint.contains('@')
            || endpoint.bytes().any(|byte| byte < 0x20)
        {
            return Err("Peer endpoint must be an absolute HTTP(S) URL without credentials".into());
        }
        Ok(())
    }

    /// Inserts a validated descriptor into the routing table (stale prune,
    /// capacity check, persist). Single writer used by announces, joins,
    /// and refreshes; the previous entry is restored when the persist
    /// fails so a failed write never drops a live route.
    fn insert_peer(&self, peer: ciphervault_storage::PeerDescriptor) -> Result<usize, String> {
        let mut lock = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
        let now = Utc::now().timestamp() as u64;
        lock.retain(|_, p| now.saturating_sub(p.timestamp_utc) < 86400);
        if !lock.contains_key(&peer.operator_id) && lock.len() >= MAX_ACTIVE_PEERS {
            return Err("Peer routing table capacity reached".into());
        }
        let peer_id = peer.operator_id.clone();
        let previous = lock.insert(peer_id.clone(), peer);
        let snapshot = lock.clone();
        if let Err(error) = self.persist_peer_routing_table(&snapshot) {
            match previous {
                Some(descriptor) => {
                    lock.insert(peer_id, descriptor);
                }
                None => {
                    lock.remove(&peer_id);
                }
            }
            return Err(format!("Unable to persist peer routing table: {error}"));
        }
        Ok(lock.len())
    }

    /// Registers a gossip peer announcement in the active routing table.
    /// Control-plane trust: the caller authenticated with the service
    /// token, so the peer is recorded as a full member — promoting any
    /// probation record, because an admin announce is an explicit trust
    /// grant. The routing insert rolls back when the membership write
    /// fails, so the announce stays atomic.
    pub fn register_peer(
        &self,
        peer: ciphervault_storage::PeerDescriptor,
    ) -> Result<usize, String> {
        Self::validate_peer_descriptor(&peer)?;
        if let Ok(allowed) = std::env::var("CIPHERVAULT_TRUSTED_PEER_KEYS") {
            let trusted = allowed
                .split(',')
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .any(|value| value == peer.signing_pk_hex.to_ascii_lowercase());
            if !trusted {
                return Err("Peer signing key is not in the configured trust registry".into());
            }
        }
        let previous_peer = lock_or_recover(&self.peer_routing_table, "peer_routing_table")
            .get(&peer.operator_id)
            .cloned();
        let count = self.insert_peer(peer.clone())?;
        match self.mark_full_member(&peer.operator_id) {
            Ok(newly_full) => {
                if newly_full {
                    self.metrics.observe_peer_graduated();
                }
                Ok(count)
            }
            Err(error) => {
                let mut lock = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
                match previous_peer {
                    Some(descriptor) => {
                        lock.insert(peer.operator_id.clone(), descriptor);
                    }
                    None => {
                        lock.remove(&peer.operator_id);
                    }
                }
                let snapshot = lock.clone();
                if let Err(rollback_error) = self.persist_peer_routing_table(&snapshot) {
                    eprintln!(
                        "operator peer rollback failed after membership error ({error}): {rollback_error}"
                    );
                }
                Err(error)
            }
        }
    }

    /// Retrieves all currently active and unexpired peer operators in the cluster.
    pub fn get_active_peers(&self) -> Vec<ciphervault_storage::PeerDescriptor> {
        let now = Utc::now().timestamp() as u64;
        let mut lock = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
        lock.retain(|_, peer| now.saturating_sub(peer.timestamp_utc) < 86400);
        lock.values().cloned().collect()
    }

    /// Routing-table membership check used by repair election: a peer that is
    /// live but not a vetted routing member must never win pusher election or
    /// receive repair pushes (fake provider-record holders).
    pub fn is_routing_member(&self, operator_id: &str) -> bool {
        let lock = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
        lock.contains_key(operator_id)
    }

    /// Admits a new node into probation on a fleet-signed invite (public
    /// `POST /v1/peers/join`: no service token — the ticket is the
    /// authorization). Two modes: legacy single-key (only
    /// `CIPHERVAULT_FLEET_KEY` set — byte-for-byte the v1 behavior) and
    /// quorum (`CIPHERVAULT_FLEET_KEYS` + `CIPHERVAULT_QUORUM_K`). Fails
    /// closed when neither is configured, so static fleets keep working
    /// byte-for-byte. The invite nonce is spent before the insert, so one
    /// ticket admits exactly one node key even if the insert fails
    /// partway; the admission evidence entry is mandatory — a log-write
    /// failure rolls back routing, membership, and spend.
    pub fn join_with_invite(
        &self,
        peer: ciphervault_storage::PeerDescriptor,
        invite: &JoinInvite,
    ) -> Result<usize, String> {
        let auth = Self::join_auth_config()?;
        let now = Utc::now().timestamp() as u64;
        let (signers, quorum_mode) = match &auth {
            JoinAuth::Legacy { key } => {
                invite.verify(key, now).map_err(|error| error.to_string())?;
                (vec![invite.issuer_pk_hex.clone()], false)
            }
            JoinAuth::Quorum { set, threshold } => {
                let signers = invite
                    .verify_quorum(set, *threshold, now)
                    .map_err(|error| error.to_string())?;
                (signers, true)
            }
        };
        if !peer
            .signing_pk_hex
            .eq_ignore_ascii_case(&invite.node_pk_hex)
        {
            return Err("Invite node key does not match the announced descriptor".into());
        }
        Self::validate_peer_descriptor(&peer)?;
        self.spend_invite(
            &invite.nonce_hex,
            invite.expires_utc,
            &peer.operator_id,
            now,
        )?;
        let previous_peer = lock_or_recover(&self.peer_routing_table, "peer_routing_table")
            .get(&peer.operator_id)
            .cloned();
        let previous_membership = lock_or_recover(&self.peer_membership, "peer_membership")
            .get(&peer.operator_id)
            .cloned();
        let count = match self.insert_peer(peer.clone()) {
            Ok(count) => count,
            Err(error) => {
                self.unspend_invite(&invite.nonce_hex);
                return Err(error);
            }
        };
        if let Err(error) = self.mark_probation_member(&peer.operator_id, now) {
            self.rollback_peer_insert(&peer.operator_id, previous_peer, "membership", &error);
            self.unspend_invite(&invite.nonce_hex);
            return Err(error);
        }
        let ticket_json = serde_json::to_vec(invite).map_err(|error| error.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(&ticket_json);
        let record = AdmissionRecord {
            admitted_utc: now,
            node_pk_hex: invite.node_pk_hex.clone(),
            operator_id: peer.operator_id.clone(),
            nonce_hex: invite.nonce_hex.clone(),
            expires_utc: invite.expires_utc,
            ticket_version: invite.version,
            signer_pks: signers,
            ticket_sha256: hex::encode(hasher.finalize()),
        };
        if let Err(error) = self.log_admission(record) {
            self.rollback_peer_insert(&peer.operator_id, previous_peer, "admission-log", &error);
            self.restore_membership(&peer.operator_id, previous_membership);
            self.unspend_invite(&invite.nonce_hex);
            return Err(error);
        }
        self.metrics.observe_peer_joined();
        if quorum_mode {
            self.metrics.observe_quorum_peer_joined();
        }
        Ok(count)
    }

    /// Re-presents a fresh self-signed descriptor for an already-known
    /// node key (public `POST /v1/peers/join/refresh`). The presenter must
    /// hold the node key (signature) and match the stored operator id and
    /// key — so a refresh can only ever extend its own entry, never
    /// another node's. Notes liveness and graduates when probation is
    /// served; returns the resulting standing.
    pub fn refresh_peer_join(
        &self,
        peer: ciphervault_storage::PeerDescriptor,
    ) -> Result<MembershipStatus, String> {
        Self::validate_peer_descriptor(&peer)?;
        {
            let table = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
            match table.get(&peer.operator_id) {
                Some(stored)
                    if stored
                        .signing_pk_hex
                        .eq_ignore_ascii_case(&peer.signing_pk_hex) => {}
                _ => {
                    return Err(
                        "Unknown joiner: no routing entry for this operator id and key".into(),
                    )
                }
            }
        }
        self.insert_peer(peer.clone())?;
        let now = Utc::now().timestamp() as u64;
        self.note_peer_liveness(&peer.operator_id, now)
    }

    /// Spends one invite nonce (single-use per admission). Expired
    /// entries are pruned first so the ledger cannot grow without bound.
    ///
    /// Trust note (grace rejoin): a spent nonce is re-presentable ONLY by
    /// the same admission — the caller verified the fleet signature, the
    /// ticket expiry, the ticket-to-descriptor key match, and the
    /// descriptor's signature + recency before this point, and a
    /// membership record must exist for `operator_id` (proof this node
    /// admitted this id before). That combination means the presenter
    /// holds the node key and the fleet authorized it within TTL: the
    /// same bar as the first join, so no new trust is granted. New
    /// admissions (no record: fresh id, or a different id reusing the
    /// key) with a spent ticket stay 409. There is no HTTP-layer removal
    /// API for grace to resurrect against (quarantine is P2P-layer
    /// `blocked_peers` only), and standing is preserved, not reset, by
    /// the existing rejoin path — authorization plus served time, not
    /// continuous presence. Operationally, grace lasts as long as the
    /// ticket: issue TTL comfortably beyond the 24 h routing TTL (e.g.
    /// 7 days) so lapsed nodes self-recover; the 24 h issue default is
    /// unchanged.
    fn spend_invite(
        &self,
        nonce_hex: &str,
        expires_utc: u64,
        operator_id: &str,
        now: u64,
    ) -> Result<(), String> {
        // Membership records are append-only (never evicted), so this
        // check is race-safe outside the spend lock, which also avoids
        // nesting the two mutexes.
        let admitted =
            lock_or_recover(&self.peer_membership, "peer_membership").contains_key(operator_id);
        let mut lock = lock_or_recover(&self.spent_invites, "spent_invites");
        lock.retain(|_, expiry| *expiry > now);
        if lock.contains_key(nonce_hex) {
            if !admitted {
                return Err("Join invite was already spent".into());
            }
            return Ok(());
        }
        lock.insert(nonce_hex.to_string(), expires_utc);
        let snapshot = lock.clone();
        if let Err(error) = self.persist_spent_invites(&snapshot) {
            lock.remove(nonce_hex);
            return Err(format!("Unable to persist spent invites: {error}"));
        }
        Ok(())
    }

    /// Releases a nonce spent by a join that failed after the spend. The
    /// ticket becomes redeemable again — correct, because nothing was
    /// admitted under it.
    fn unspend_invite(&self, nonce_hex: &str) {
        let mut lock = lock_or_recover(&self.spent_invites, "spent_invites");
        if lock.remove(nonce_hex).is_some() {
            let snapshot = lock.clone();
            if let Err(error) = self.persist_spent_invites(&snapshot) {
                eprintln!("operator invite unspend persist failed for {nonce_hex}: {error}");
            }
        }
    }

    /// Appends one admission record after a successful probation insert.
    /// Evidence is mandatory: a persist failure removes the record and
    /// errors, and the caller rolls back the admission.
    fn log_admission(&self, record: AdmissionRecord) -> Result<(), String> {
        let mut lock = lock_or_recover(&self.admissions, "admissions");
        lock.push(record);
        let snapshot = lock.clone();
        if let Err(error) = self.persist_admissions(&snapshot) {
            lock.pop();
            return Err(format!("Unable to persist admission log: {error}"));
        }
        Ok(())
    }

    /// Clones the admission evidence log (control-plane route).
    pub fn admissions_snapshot(&self) -> Vec<AdmissionRecord> {
        lock_or_recover(&self.admissions, "admissions").clone()
    }

    /// Maximum inbound join requests held. Oldest-first eviction keeps the
    /// inbox bounded; resubmits update in place and never count twice.
    pub const MAX_JOIN_REQUESTS: usize = 512;

    fn join_requests_store_path(&self) -> PathBuf {
        self.data_dir.join("join-requests.json")
    }

    pub(crate) fn load_join_requests(&self) {
        let Ok(bytes) = fs::read(self.join_requests_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<Vec<JoinRequestRecord>>(&bytes) else {
            return;
        };
        *lock_or_recover(&self.join_requests, "join_requests") = records;
    }

    pub(crate) fn persist_join_requests(
        &self,
        records: &[JoinRequestRecord],
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.join_requests_store_path(), &encoded)
    }

    /// Records an inbound fleet-join request. The descriptor must
    /// self-verify (same bar as announces/joins); contact is free text.
    /// One record per operator id — resubmits refresh endpoint/contact.
    /// Grants no trust: admission still requires tickets + graduation.
    pub fn submit_join_request(
        &self,
        descriptor: &ciphervault_storage::PeerDescriptor,
        contact: &str,
    ) -> Result<String, String> {
        Self::validate_peer_descriptor(descriptor)?;
        if descriptor.operator_id.trim().is_empty() || descriptor.operator_id.len() > 64 {
            return Err("operator_id must be 1-64 characters".into());
        }
        let contact = contact.trim();
        if contact.len() > 140 {
            return Err("contact must be at most 140 characters".into());
        }
        let now = Utc::now().timestamp() as u64;
        let mut lock = lock_or_recover(&self.join_requests, "join_requests");
        if let Some(existing) = lock
            .iter_mut()
            .find(|r| r.operator_id == descriptor.operator_id)
        {
            existing.endpoint = descriptor.endpoint.clone();
            existing.node_pk_hex = descriptor.signing_pk_hex.clone();
            existing.contact = contact.to_string();
            existing.requested_at_utc = now;
            let id = existing.request_id.clone();
            let snapshot = lock.clone();
            drop(lock);
            self.persist_join_requests(&snapshot)?;
            return Ok(id);
        }
        let mut id_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let id = hex::encode(id_bytes);
        lock.push(JoinRequestRecord {
            request_id: id.clone(),
            operator_id: descriptor.operator_id.clone(),
            endpoint: descriptor.endpoint.clone(),
            node_pk_hex: descriptor.signing_pk_hex.clone(),
            contact: contact.to_string(),
            requested_at_utc: now,
            status: "pending".into(),
        });
        if lock.len() > Self::MAX_JOIN_REQUESTS {
            if let Some(oldest) = lock
                .iter()
                .enumerate()
                .filter(|(_, r)| r.request_id != id)
                .min_by_key(|(_, r)| r.requested_at_utc)
                .map(|(i, _)| i)
            {
                lock.remove(oldest);
            }
        }
        let snapshot = lock.clone();
        drop(lock);
        self.persist_join_requests(&snapshot)?;
        Ok(id)
    }

    /// Clones the join-request inbox, oldest first. Control-plane only.
    pub fn list_join_requests(&self) -> Vec<JoinRequestRecord> {
        let mut out = lock_or_recover(&self.join_requests, "join_requests").clone();
        out.sort_by_key(|r| r.requested_at_utc);
        out
    }

    /// Resolves one inbox entry: `approved` (hand the node key to the
    /// offline `invite issue` ceremony) or `rejected` (spam/abuse).
    /// Pending-only — resolving a consumed entry is a 409, never a silent
    /// re-mint. Persisted alongside the inbox so restarts can't revive a
    /// decided request.
    pub fn resolve_join_request(
        &self,
        request_id: &str,
        decision: &str,
    ) -> Result<JoinRequestRecord, String> {
        let decision = decision.trim().to_ascii_lowercase();
        if decision != "approved" && decision != "rejected" {
            return Err("decision must be \"approved\" or \"rejected\"".into());
        }
        let mut lock = lock_or_recover(&self.join_requests, "join_requests");
        let record = lock
            .iter_mut()
            .find(|r| r.request_id == request_id)
            .ok_or_else(|| "join request not found".to_string())?;
        if record.status != "pending" {
            return Err(format!(
                "join request already {} (request_id {})",
                record.status, record.request_id
            ));
        }
        record.status = decision;
        let resolved = record.clone();
        let snapshot = lock.clone();
        drop(lock);
        self.persist_join_requests(&snapshot)?;
        Ok(resolved)
    }

    /// Restores the routing table after a post-insert failure (membership
    /// or evidence-log write). Best-effort persist; the spend release is
    /// the caller's job.
    fn rollback_peer_insert(
        &self,
        operator_id: &str,
        previous: Option<ciphervault_storage::PeerDescriptor>,
        stage: &str,
        cause: &str,
    ) {
        let mut lock = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
        match previous {
            Some(descriptor) => {
                lock.insert(operator_id.to_string(), descriptor);
            }
            None => {
                lock.remove(operator_id);
            }
        }
        let snapshot = lock.clone();
        if let Err(rollback_error) = self.persist_peer_routing_table(&snapshot) {
            eprintln!(
                "operator peer rollback failed after {stage} error ({cause}): {rollback_error}"
            );
        }
    }

    /// Restores the membership map after an evidence-log failure that
    /// voids the admission: reinserts the pre-join record, or removes the
    /// fresh probation entry when the joiner was new. Best-effort persist
    /// (the spend release is what keeps the ticket redeemable).
    fn restore_membership(&self, operator_id: &str, previous: Option<PeerMembership>) {
        let mut lock = lock_or_recover(&self.peer_membership, "peer_membership");
        match previous {
            Some(record) => {
                lock.insert(operator_id.to_string(), record);
            }
            None => {
                lock.remove(operator_id);
            }
        }
        let snapshot = lock.clone();
        if let Err(error) = self.persist_peer_membership(&snapshot) {
            eprintln!("operator membership restore failed for {operator_id}: {error}");
        }
    }

    /// Resolves verified-join authorization from env. Quorum mode wins
    /// when `CIPHERVAULT_FLEET_KEYS` is set; legacy single-key mode when
    /// only `CIPHERVAULT_FLEET_KEY` is set; fail-closed otherwise.
    /// Config mistakes fail closed with a stderr diagnostic, never open.
    fn join_auth_config() -> Result<JoinAuth, String> {
        const CLOSED: &str = "Verified join is not configured on this node";
        let list = std::env::var("CIPHERVAULT_FLEET_KEYS")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if let Some(list) = list {
            let set: Vec<String> = list
                .split(',')
                .map(|key| key.trim().to_string())
                .filter(|key| !key.is_empty())
                .collect();
            if set.is_empty() {
                eprintln!("operator join disabled: CIPHERVAULT_FLEET_KEYS lists no keys");
                return Err(CLOSED.into());
            }
            let raw = std::env::var("CIPHERVAULT_QUORUM_K")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            let threshold = match raw {
                None => JoinInvite::quorum_default(set.len()),
                Some(text) => match text.parse::<usize>() {
                    Ok(value) if value >= 1 && value <= set.len() => value,
                    _ => {
                        eprintln!(
                            "operator join disabled: CIPHERVAULT_QUORUM_K must be 1..={}",
                            set.len()
                        );
                        return Err(CLOSED.into());
                    }
                },
            };
            return Ok(JoinAuth::Quorum { set, threshold });
        }
        let key = std::env::var("CIPHERVAULT_FLEET_KEY")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CLOSED.to_string())?;
        Ok(JoinAuth::Legacy { key })
    }

    /// Inserts a probation record for a ticket join, or notes liveness on
    /// an existing record. Standing is never changed here: re-joining a
    /// full member keeps it full; only graduation promotes.
    fn mark_probation_member(&self, operator_id: &str, now: u64) -> Result<(), String> {
        let mut lock = lock_or_recover(&self.peer_membership, "peer_membership");
        let previous = lock.get(operator_id).cloned();
        let updated = match &previous {
            Some(record) => PeerMembership {
                last_seen_utc: now,
                ..record.clone()
            },
            None => PeerMembership {
                status: MembershipStatus::Probation,
                joined_utc: now,
                last_seen_utc: now,
                graduated_utc: None,
            },
        };
        lock.insert(operator_id.to_string(), updated);
        let snapshot = lock.clone();
        if let Err(error) = self.persist_peer_membership(&snapshot) {
            match previous {
                Some(record) => {
                    lock.insert(operator_id.to_string(), record);
                }
                None => {
                    lock.remove(operator_id);
                }
            }
            return Err(format!("Unable to persist peer membership: {error}"));
        }
        Ok(())
    }

    /// Records a control-plane trust grant: the peer is a full member from
    /// now on (new record, or promotion of a probation record — an admin
    /// announce overrides probation). Returns whether this call newly
    /// conferred full standing. Rolls back on persist failure.
    fn mark_full_member(&self, operator_id: &str) -> Result<bool, String> {
        let now = Utc::now().timestamp() as u64;
        let mut lock = lock_or_recover(&self.peer_membership, "peer_membership");
        let previous = lock.get(operator_id).cloned();
        let newly_full = !previous
            .as_ref()
            .is_some_and(|record| record.status == MembershipStatus::Full);
        let joined_utc = previous
            .as_ref()
            .map(|record| record.joined_utc)
            .unwrap_or(now);
        lock.insert(
            operator_id.to_string(),
            PeerMembership {
                status: MembershipStatus::Full,
                joined_utc,
                last_seen_utc: now,
                graduated_utc: Some(now),
            },
        );
        let snapshot = lock.clone();
        if let Err(error) = self.persist_peer_membership(&snapshot) {
            match previous {
                Some(record) => {
                    lock.insert(operator_id.to_string(), record);
                }
                None => {
                    lock.remove(operator_id);
                }
            }
            return Err(format!("Unable to persist peer membership: {error}"));
        }
        Ok(newly_full)
    }

    /// Notes one proof of life for a peer: refreshes `last_seen_utc` and
    /// graduates probation once time served (liveness is now by
    /// construction on this path). Returns the resulting standing. Peers
    /// without a record read as full — nothing to track.
    fn note_peer_liveness(&self, operator_id: &str, now: u64) -> Result<MembershipStatus, String> {
        let mut lock = lock_or_recover(&self.peer_membership, "peer_membership");
        let Some(record) = lock.get(operator_id).cloned() else {
            return Ok(MembershipStatus::Full);
        };
        let mut updated = record.clone();
        updated.last_seen_utc = now;
        if updated.status == MembershipStatus::Probation
            && now.saturating_sub(updated.joined_utc) >= min_probation_secs()
        {
            updated.status = MembershipStatus::Full;
            updated.graduated_utc = Some(now);
        }
        let status = updated.status;
        let graduated =
            status == MembershipStatus::Full && record.status == MembershipStatus::Probation;
        lock.insert(operator_id.to_string(), updated);
        let snapshot = lock.clone();
        if let Err(error) = self.persist_peer_membership(&snapshot) {
            lock.insert(operator_id.to_string(), record);
            return Err(format!("Unable to persist peer membership: {error}"));
        }
        if graduated {
            self.metrics.observe_peer_graduated();
        }
        Ok(status)
    }

    /// Notes a verified P2P heartbeat as proof of life. The in-memory
    /// `last_seen` moves on every call; the membership file is written
    /// only on the probation→full transition edge — heartbeats arrive
    /// every few seconds, and persisting each would burn disk for nothing.
    pub fn note_peer_heartbeat(&self, operator_id: &str) {
        let now = Utc::now().timestamp() as u64;
        let mut lock = lock_or_recover(&self.peer_membership, "peer_membership");
        let transition = match lock.get_mut(operator_id) {
            None => return,
            Some(record) => {
                record.last_seen_utc = now;
                if record.status == MembershipStatus::Probation
                    && now.saturating_sub(record.joined_utc) >= min_probation_secs()
                {
                    record.status = MembershipStatus::Full;
                    record.graduated_utc = Some(now);
                    true
                } else {
                    false
                }
            }
        };
        if transition {
            let snapshot = lock.clone();
            if let Err(error) = self.persist_peer_membership(&snapshot) {
                if let Some(record) = lock.get_mut(operator_id) {
                    record.status = MembershipStatus::Probation;
                    record.graduated_utc = None;
                }
                eprintln!("operator membership graduation persist failed: {error}");
                return;
            }
            self.metrics.observe_peer_graduated();
        }
    }

    /// Admin graduation override: confers full membership immediately.
    /// Returns false for unknown operator ids (no routing entry and no
    /// record — nothing to graduate).
    pub fn graduate_peer(&self, operator_id: &str) -> Result<bool, String> {
        let known = lock_or_recover(&self.peer_routing_table, "peer_routing_table")
            .contains_key(operator_id)
            || lock_or_recover(&self.peer_membership, "peer_membership").contains_key(operator_id);
        if !known {
            return Ok(false);
        }
        if self.mark_full_member(operator_id)? {
            self.metrics.observe_peer_graduated();
        }
        Ok(true)
    }

    /// Reads one peer's standing for repair planning: only an explicit
    /// probation record excludes. Missing records (pre-join meshes) and
    /// full members are eligible repair recipients.
    pub fn is_probationary(&self, operator_id: &str) -> bool {
        lock_or_recover(&self.peer_membership, "peer_membership")
            .get(operator_id)
            .is_some_and(|record| record.status == MembershipStatus::Probation)
    }

    /// Control-plane membership listing: every active routing entry plus
    /// its standing, sorted by operator id. Lazily graduates probation
    /// whose time is served with recent liveness — the recency half that
    /// refresh/heartbeat paths satisfy by construction is enforced here,
    /// so a node that served its time but went silent does not graduate
    /// until it proves life again. A failed graduation persist reverts to
    /// probation in memory and logs loudly.
    pub fn membership_snapshot(&self) -> Vec<MembershipView> {
        let now = Utc::now().timestamp() as u64;
        let mut flipped_ids = Vec::new();
        {
            let mut membership = lock_or_recover(&self.peer_membership, "peer_membership");
            for (operator_id, record) in membership.iter_mut() {
                if record.status == MembershipStatus::Probation
                    && now.saturating_sub(record.joined_utc) >= min_probation_secs()
                    && now.saturating_sub(record.last_seen_utc) <= join_liveness_grace_secs()
                {
                    record.status = MembershipStatus::Full;
                    record.graduated_utc = Some(now);
                    flipped_ids.push(operator_id.clone());
                }
            }
            if !flipped_ids.is_empty() {
                let snapshot = membership.clone();
                if let Err(error) = self.persist_peer_membership(&snapshot) {
                    for operator_id in &flipped_ids {
                        if let Some(record) = membership.get_mut(operator_id) {
                            record.status = MembershipStatus::Probation;
                            record.graduated_utc = None;
                        }
                    }
                    eprintln!("operator membership graduation persist failed: {error}");
                    flipped_ids.clear();
                }
            }
        }
        for _ in &flipped_ids {
            self.metrics.observe_peer_graduated();
        }
        let peers = self.get_active_peers();
        let membership = lock_or_recover(&self.peer_membership, "peer_membership");
        let mut views: Vec<MembershipView> = peers
            .into_iter()
            .map(|peer| {
                let record = membership.get(&peer.operator_id);
                MembershipView {
                    operator_id: peer.operator_id.clone(),
                    endpoint: peer.endpoint.clone(),
                    signing_pk_hex: peer.signing_pk_hex.clone(),
                    status: record
                        .map(|entry| entry.status)
                        .unwrap_or(MembershipStatus::Full),
                    joined_utc: record.map(|entry| entry.joined_utc),
                    last_seen_utc: record.map(|entry| entry.last_seen_utc),
                    graduated_utc: record.and_then(|entry| entry.graduated_utc),
                }
            })
            .collect();
        views.sort_by(|a, b| a.operator_id.cmp(&b.operator_id));
        views
    }

    /// Registers a pending out-of-band authorization challenge.
    pub fn register_approval_challenge(
        &self,
        challenge: ciphervault_recovery::ApprovalChallenge,
    ) -> Result<(), String> {
        if challenge.is_expired() {
            return Err("Challenge is already expired".into());
        }
        let mut lock = lock_or_recover(&self.approval_challenges, "approval_challenges");
        let now = Utc::now().timestamp() as u64;
        lock.retain(|_, (c, _)| c.expires_at_utc > now);
        let challenge_id = challenge.challenge_id.clone();
        lock.insert(challenge_id.clone(), (challenge, Vec::new()));
        let snapshot = lock.clone();
        if let Err(error) = self.persist_approval_challenges(&snapshot) {
            lock.remove(&challenge_id);
            return Err(format!("Unable to persist approval challenges: {error}"));
        }
        Ok(())
    }

    /// Lists all pending and unexpired authorization challenges.
    pub fn get_pending_challenges(&self) -> Vec<ciphervault_recovery::ApprovalChallenge> {
        let lock = lock_or_recover(&self.approval_challenges, "approval_challenges");
        let now = Utc::now().timestamp() as u64;
        lock.values()
            .filter(|(c, receipts)| c.expires_at_utc > now && receipts.is_empty())
            .map(|(c, _)| c.clone())
            .collect()
    }

    /// Retrieves challenge details and collected signed receipts.
    pub fn get_challenge_status(
        &self,
        challenge_id: &str,
    ) -> Option<(
        ciphervault_recovery::ApprovalChallenge,
        Vec<ciphervault_recovery::SignedApprovalReceipt>,
    )> {
        let lock = lock_or_recover(&self.approval_challenges, "approval_challenges");
        lock.get(challenge_id).cloned()
    }

    /// Submits a cryptographically signed approval receipt.
    pub fn submit_approval_receipt(
        &self,
        receipt: ciphervault_recovery::SignedApprovalReceipt,
    ) -> Result<usize, String> {
        let challenge_id = receipt.challenge_id.clone();
        let mut lock = lock_or_recover(&self.approval_challenges, "approval_challenges");
        let (already_recorded, count) =
            if let Some((challenge, receipts)) = lock.get_mut(&challenge_id) {
                receipt
                    .verify(challenge)
                    .map_err(|e| format!("Invalid receipt: {}", e))?;
                let already_recorded = receipts
                    .iter()
                    .any(|r| r.approver_pk_hex == receipt.approver_pk_hex);
                if !already_recorded {
                    receipts.push(receipt);
                }
                (already_recorded, receipts.len())
            } else {
                return Err("Challenge ID not found or already expired".into());
            };
        let snapshot = lock.clone();
        if let Err(error) = self.persist_approval_challenges(&snapshot) {
            if !already_recorded {
                if let Some((_, receipts)) = lock.get_mut(&challenge_id) {
                    receipts.pop();
                }
            }
            return Err(format!("Unable to persist approval challenges: {error}"));
        }
        Ok(count)
    }
}
