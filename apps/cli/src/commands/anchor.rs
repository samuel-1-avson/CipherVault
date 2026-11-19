//! Sovereign chain-anchor and anchor-verification commands.
//!
//! Ethereum/Arbitrum anchoring was removed in Phase 1 of the sovereign-chain
//! migration (legacy EVM path preserved in git tag `last-evm-anchor`).

use anyhow::{bail, Context, Result};
use chrono::Utc;
use colored::Colorize;
use rand::RngCore;

use crate::util::get_vault_store;

pub(crate) async fn cmd_anchor(
    head_hex_opt: Option<String>,
    rotate_to: Option<String>,
) -> Result<()> {
    let store = get_vault_store()?;
    let active_head = match head_hex_opt {
        Some(h) => {
            let bytes = hex::decode(h.trim().trim_start_matches("0x"))?;
            if bytes.len() != 32 {
                bail!("Head CID must be 32 bytes (64 hex characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            let head = store
                .get_active_head()?
                .context("No active head snapshot found to anchor")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherVault Sovereign Blockchain (CipherChain) Anchor"
            .bold()
            .green()
    );
    println!(
        "  Target Network:    {} (Chain ID: {})",
        ciphervault_chain::SOVEREIGN_CHAIN_ID_STR.cyan(),
        ciphervault_chain::SOVEREIGN_CHAIN_ID_NUM
    );
    println!("  Head Record CID:   {}", hex::encode(active_head).yellow());

    // Anchor salts are derived from the snapshot's epoch key, so the vault
    // owner can re-derive them from replicated recovery records after local
    // state loss. A one-time random salt is a legacy fallback for heads
    // whose snapshot is unknown locally, and stays local-only.
    let (salt, commitment) = if let Ok(Some(existing)) = store.get_checkpoint_evidence(&active_head)
    {
        let mut s = [0u8; 32];
        let mut c = [0u8; 32];
        if existing.salt.len() == 32 && existing.commitment.len() == 32 {
            s.copy_from_slice(&existing.salt);
            c.copy_from_slice(&existing.commitment);
            println!("  Reusing Pending Commitment: {}", hex::encode(c).green());
            (s, c)
        } else {
            let s = fresh_anchor_salt(&store, &active_head);
            let c = ciphervault_format::CheckpointEvidence::compute_commitment(&s, &active_head);
            (s, c)
        }
    } else {
        let s = fresh_anchor_salt(&store, &active_head);
        let c = ciphervault_format::CheckpointEvidence::compute_commitment(&s, &active_head);
        (s, c)
    };

    println!("  Preimage Salt:     {}", hex::encode(salt).dimmed());
    println!(
        "  Opaque Commitment: {}",
        hex::encode(commitment).green().bold()
    );

    let vault_id = store.get_vault_id().unwrap_or([0u8; 32]);

    // Phase 2: persistent device key + explicit validator set (no throwaway keys).
    let (chain_dir, device_signer, validator_set) = load_device_and_validators()?;
    println!(
        "  Device Key:        {}",
        hex::encode(device_signer.public_key()).dimmed()
    );
    println!(
        "  Validator Set:     {} key(s), quorum {}",
        validator_set.len(),
        validator_set.quorum_threshold()
    );

    let mut ledger = open_or_fresh_genesis(&chain_dir, &validator_set, &device_signer)?;

    // Optional validator-set rotation: the new set takes effect for the
    // NEXT height once this block commits with current-set quorum.
    let rotation: Option<Vec<[u8; 32]>> = match rotate_to {
        Some(raw) => {
            let keys = super::genesis::parse_pubkey_list(&raw)?;
            println!(
                "  Rotation:          activating {} member(s) next height",
                keys.len()
            );
            Some(keys)
        }
        None => None,
    };

    let now_ms = Utc::now().timestamp_millis() as u64;
    // Private (v2) commitment transactions keep the salt/head preimage
    // off-chain. They are only understood by v1.0.31+ validators, so
    // emission is opt-in until the fleet advertises support:
    // CIPHERVAULT_ANCHOR_TX_VERSION=2. Local checkpoint evidence keeps
    // the preimage either way (see below), so proofs keep working.
    let private_tx = std::env::var("CIPHERVAULT_ANCHOR_TX_VERSION").as_deref() == Ok("2");
    let mut tx = if private_tx {
        ciphervault_chain::CommitmentTx::new_private(
            &vault_id,
            &salt,
            &active_head,
            [0u8; 32],
            ledger.next_nonce(&device_signer.public_key()),
            now_ms,
        )
    } else {
        let mut tx = ciphervault_chain::CommitmentTx {
            version: 0,
            vault_id,
            salt,
            head_cid: active_head,
            commitment,
            client_pubkey: [0u8; 32],
            signature: [0u8; 64],
            nonce: ledger.next_nonce(&device_signer.public_key()),
            timestamp_ms: now_ms,
        };
        tx.client_pubkey = [0u8; 32];
        tx
    };
    if private_tx {
        println!("  Tx Privacy:        private v2 (preimage stays in local evidence)");
    }
    device_signer.sign_tx(&mut tx, ciphervault_chain::SOVEREIGN_CHAIN_ID_STR);
    println!("  Tx Nonce:          {}", tx.nonce);

    // Multi-validator chains keep their parent's block version so validators
    // on older builds are not stranded mid-upgrade; set
    // CIPHERVAULT_CHAIN_ACTIVATE_LATEST=1 once the whole fleet is upgraded.
    // Single-validator chains always use the latest version.
    let activate_latest = std::env::var("CIPHERVAULT_CHAIN_ACTIVATE_LATEST").as_deref() == Ok("1");
    let proposed_block = if activate_latest {
        ledger.propose_block_upgrading(
            &device_signer,
            vec![tx],
            now_ms.saturating_add(10),
            rotation,
        )?
    } else {
        ledger.propose_block(
            &device_signer,
            vec![tx],
            now_ms.saturating_add(10),
            rotation,
        )?
    };
    let quorum = validator_set.quorum_threshold();
    let sigs = proposed_block.header.signatures.len();

    // Federate the proposal BEFORE any local commit: with a
    // multi-validator set this device alone cannot reach quorum, and
    // committing locally first would fork from the fleet. Operators
    // vote through the chain sync hub; the block commits when a quorum
    // certificate is assembled there (local catch-up follows sync).
    let operators = crate::util::get_explicitly_configured_operators();
    let mut accepted = 0usize;
    if !operators.is_empty() {
        let envelope = ciphervault_chain::ChainSyncEnvelope::seal(
            &device_signer,
            ciphervault_chain::ChainSyncMsg::Proposal(ciphervault_chain::ProposalMsg {
                block: proposed_block.clone(),
            }),
        );
        let body = serde_json::to_value(&envelope)?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        accepted = publish_proposal_to_operators(&http, &operators, &body).await;
    }

    if sigs < quorum {
        // Persist the pending proposal for inspection/catch-up; do NOT
        // save checkpoint evidence (nothing is anchored yet).
        let pending_path = chain_dir.join("pending_proposal.json");
        if let Ok(raw) = serde_json::to_string_pretty(&proposed_block) {
            let _ = std::fs::write(&pending_path, raw);
        }
        println!("  Validator Quorum:  {sigs}/{quorum} signatures — NOT committed locally");
        println!(
            "  Fleet Publish:     {accepted}/{} operator(s) accepted the proposal",
            operators.len()
        );
        println!(
            "  Status:            PROPOSED — awaiting fleet quorum via chain sync (pending copy: {})",
            pending_path.display()
        );
        bail!(
            "anchor proposed but not committed: this device holds {sigs} of the {quorum} \
             signatures required. The fleet commits it through chain sync; re-run \
             'ciphervault verify-anchor' after sync. For a single-device chain, keep \
             validators.json to this device only."
        );
    }

    ledger.commit_block(proposed_block.clone())?;

    let block_hash = proposed_block.header.block_hash();
    let block_num = proposed_block.header.height;
    let contract_bytes = [0u8; 20];

    let evidence = ciphervault_format::CheckpointEvidence::new(
        salt,
        active_head,
        ciphervault_chain::SOVEREIGN_CHAIN_ID_NUM,
        contract_bytes,
        block_hash,
        block_num,
        Utc::now().timestamp() as u64,
    );
    store.save_checkpoint_evidence(&evidence)?;

    println!(
        "{}",
        "✓ Sovereign Block Endorsed & Committed to Ledger!"
            .bold()
            .green()
    );
    println!("  Block Height:      #{}", block_num);
    println!("  Block Hash:        0x{}", hex::encode(block_hash).cyan());
    println!(
        "  Validator Quorum:  {}/{} signatures (quorum met{})",
        proposed_block.header.signatures.len(),
        quorum,
        if validator_set.len() == 1 {
            "; solo validator mode — single-device chain, no fleet quorum"
        } else {
            ""
        }
    );
    println!(
        "  Cumulative Root:   0x{}",
        hex::encode(ledger.state_root()).dimmed()
    );
    println!(
        "  Finality Guarantee: {}",
        "Deterministic Sovereign Finality (Zero-Gas, Self-Custodial)"
            .green()
            .bold()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    if operators.is_empty() {
        println!("  Fleet Publish:     skipped (no explicitly configured operators)");
    } else {
        println!(
            "  Fleet Publish:     {accepted}/{} operator(s) accepted the proposal",
            operators.len()
        );
    }
    Ok(())
}

/// POSTs one sealed proposal body to every operator's `/v1/chain/publish`
/// endpoint. Best-effort: unreachable operators and non-2xx answers are
/// ignored. Returns the number of accepting operators. `CIPHERVAULT_*`
/// service-token headers are attached by `operator_service_request` when
/// set, but the endpoint is public (envelopes self-authenticate).
pub(crate) async fn publish_proposal_to_operators(
    http: &reqwest::Client,
    operators: &[String],
    body: &serde_json::Value,
) -> usize {
    let mut accepted = 0;
    for op in operators {
        let url = format!("{}/v1/chain/publish", op.trim_end_matches('/'));
        if let Ok(resp) = crate::util::operator_service_request(http.post(&url))
            .json(body)
            .send()
            .await
        {
            if resp.status().is_success() {
                accepted += 1;
            }
        }
    }
    accepted
}

pub(crate) async fn cmd_verify_anchor(head_hex_opt: Option<String>) -> Result<()> {
    let store = get_vault_store()?;
    let head_cid = match head_hex_opt {
        Some(h) => {
            let bytes = hex::decode(h.trim().trim_start_matches("0x"))?;
            if bytes.len() != 32 {
                bail!("Head CID must be 32 bytes hex string");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            let head = store
                .get_active_head()?
                .context("No active head snapshot found to verify")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

    let evidence = store
        .get_checkpoint_evidence(&head_cid)?
        .context("No on-chain checkpoint evidence recorded for this snapshot head")?;

    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherChain Sovereign Anchor Verification Report"
            .bold()
            .green()
    );
    println!(
        "  Commitment:        0x{}",
        hex::encode(&evidence.commitment).yellow()
    );

    let (chain_dir, _device_signer, validator_set) = load_device_and_validators()?;
    // Every failure exits non-zero: scripts and CI rely on the exit code,
    // so an unverifiable anchor must never read as verified (review CC-03).
    let verified = match verify_anchor_evidence(&chain_dir, &evidence, &validator_set) {
        Ok(verified) => verified,
        Err(e) => {
            println!("  Status:            {}", "NOT VERIFIED".red().bold());
            println!(
                "{}",
                "=======================================================".cyan()
            );
            return Err(e.context("anchor NOT verified"));
        }
    };
    let result = &verified.result;

    println!("  Sovereign Network: {}", result.chain_id.cyan());
    println!("  Block Height:      #{}", result.height);
    println!("  Block Hash:        0x{}", result.block_hash_hex.cyan());
    println!("  Proposer ID:       0x{}", result.proposer_hex.dimmed());
    println!(
        "  Quorum Signatures: {}/{} validator signatures verified (trusted set: {} key(s), walked from genesis)",
        result.signatures_verified, result.quorum_required, verified.trusted_keys
    );
    let when = chrono::DateTime::from_timestamp_millis(result.timestamp_ms as i64)
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| result.timestamp_ms.to_string());
    if result.timestamp_signed {
        println!("  Block Time:        {when} (validator-signed)");
    } else {
        println!(
            "  Block Time:        {when} {}",
            format!(
                "(NOT signed: block version {} predates signed block time; re-anchor for a signed time)",
                verified.block_version
            )
            .yellow()
        );
    }
    if verified.trusted_keys == 1 {
        println!(
            "  Trust Note:        {}",
            "solo validator: this device signed its own chain, so it is tamper-evident only against parties without this device's key"
                .yellow()
        );
    }
    println!(
        "  Status:            {}",
        "ANCHORED (verified against the trusted validator set)"
            .green()
            .bold()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    Ok(())
}

/// What `verify-anchor` established, for reporting.
pub(crate) struct VerifiedAnchor {
    pub(crate) result: ciphervault_chain::SovereignVerificationResult,
    /// Size of the validator set the proof was checked against.
    pub(crate) trusted_keys: usize,
    /// Header version of the anchoring block (time is signed for v1 and v4+).
    pub(crate) block_version: u16,
}

/// Whether two validator sets have the same members, in any order.
fn same_members(a: &ciphervault_chain::ValidatorSet, b: &ciphervault_chain::ValidatorSet) -> bool {
    let mut left = a.validators().to_vec();
    let mut right = b.validators().to_vec();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

fn evidence_field_32(bytes: &[u8], name: &str) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        bail!(
            "malformed checkpoint evidence: {name} is {} bytes, expected 32",
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

/// Verifies checkpoint evidence against the local CipherChain ledger and
/// fails closed on every path (review CC-03):
///
/// - the evidence must match its own commitment;
/// - legacy EVM evidence is refused (its on-chain path was removed);
/// - the ledger must open, re-verify from genesis, and hold the commitment
///   in the block the evidence names;
/// - the proof is checked by the light client against the set that
///   certified genesis, walked forward through every certified rotation
///   before the anchoring height, never against the block's own proposer.
///
/// Private (v2) anchors verify through the local preimage, since their
/// on-chain transaction carries only the commitment.
pub(crate) fn verify_anchor_evidence(
    chain_dir: &std::path::Path,
    evidence: &ciphervault_format::CheckpointEvidence,
    configured: &ciphervault_chain::ValidatorSet,
) -> Result<VerifiedAnchor> {
    if !evidence.verify_commitment() {
        bail!(
            "the stored checkpoint evidence does not match its own commitment (tampered or corrupt)"
        );
    }
    let is_sovereign = evidence.chain_id == ciphervault_chain::SOVEREIGN_CHAIN_ID_NUM
        || evidence.contract_address == [0u8; 20];
    if !is_sovereign {
        bail!(
            "legacy Arbitrum evidence can no longer be verified on-chain (the EVM path was removed; \
             see git tag last-evm-anchor). Re-anchor with 'ciphervault anchor'"
        );
    }
    let salt = evidence_field_32(&evidence.salt, "salt")?;
    let head = evidence_field_32(&evidence.head_record_cid, "head record CID")?;
    let commitment = evidence_field_32(&evidence.commitment, "commitment")?;

    if !chain_dir.join("blocks").exists() {
        bail!("no local CipherChain ledger at {}", chain_dir.display());
    }
    let ledger = ciphervault_chain::SovereignLedger::open(
        ciphervault_chain::SOVEREIGN_CHAIN_ID_STR,
        configured.clone(),
        chain_dir,
    )
    .context("the local CipherChain ledger failed to open or re-verify")?;
    if ledger.earliest_height() != 0 {
        bail!(
            "the local CipherChain ledger has no genesis-anchored history yet (unbackfilled tip)"
        );
    }
    let proof = ledger
        .get_proof_for_commitment(&commitment)
        .context("the commitment is not in the local CipherChain ledger")?;
    if evidence.block_number != proof.height
        || evidence.tx_hash.as_slice() != proof.block_hash.as_slice()
    {
        bail!(
            "evidence names block #{} (0x{}), but the ledger holds this commitment in block #{} (0x{})",
            evidence.block_number,
            hex::encode(&evidence.tx_hash),
            proof.height,
            hex::encode(proof.block_hash)
        );
    }

    // Trust root: the set that certified genesis (on-disk record, else the
    // configured set), advanced only through rotations the then-current set
    // certified, so the proof verifies against the set active at its height.
    let genesis_set = ciphervault_chain::SovereignLedger::read_genesis_validators(chain_dir)?
        .unwrap_or_else(|| configured.clone());
    let mut light = ciphervault_chain::SovereignLightClient::new(
        ciphervault_chain::SOVEREIGN_CHAIN_ID_STR,
        genesis_set.validators().to_vec(),
    );
    for block in ledger
        .blocks()
        .iter()
        .take_while(|b| b.header.height < proof.height)
    {
        if block.header.next_validators.is_some() {
            light.advance_to_rotation(&block.header).with_context(|| {
                format!(
                    "validator rotation at height {} does not verify",
                    block.header.height
                )
            })?;
        }
    }
    // The on-disk genesis record and the replayed blocks are local data, so
    // they cannot be their own trust root. Anchor the walk to the configured
    // set (validators.json): it must be the genesis set, or the set active at
    // the proof's height. Either way every key the proof relies on traces to
    // the configured set, so a self-consistent replacement chain under other
    // keys (with a rewritten genesis record) is refused.
    let anchored_at_genesis = same_members(&genesis_set, configured);
    let anchored_at_proof = light.trusts_exactly(configured.validators());
    if !anchored_at_genesis && !anchored_at_proof {
        bail!(
            "the chain's genesis validator record and the validator set active at block #{} \
             both differ from the configured validator set (validators.json); refusing to \
             trust a replaced genesis record",
            proof.height
        );
    }
    let trusted_keys = light.trusted_len();
    let result = light
        .verify_anchor(&head, &salt, &proof)
        .context("light-client verification of the anchor proof failed")?;
    Ok(VerifiedAnchor {
        result,
        trusted_keys,
        block_version: proof.header.version,
    })
}

/// Loads the persistent device consensus key and the explicit validator set.
/// Shared by anchor and verify so both operate on the same fleet identity.
pub(crate) fn load_device_and_validators() -> Result<(
    std::path::PathBuf,
    ciphervault_chain::ConsensusSigner,
    ciphervault_chain::ValidatorSet,
)> {
    let chain_dir = crate::util::get_vault_directory().join("chain");
    let device_signer =
        ciphervault_chain::ConsensusSigner::load_or_create(&chain_dir.join("device.key"))
            .context("Failed to load device consensus key")?;
    let validator_set = load_validator_set(&chain_dir, &device_signer)?;
    Ok((chain_dir, device_signer, validator_set))
}

/// Reads the explicit fleet validator set (`validators.json`), or bootstraps a
/// solo set from the local device key and persists it for transparency.
fn load_validator_set(
    chain_dir: &std::path::Path,
    local: &ciphervault_chain::ConsensusSigner,
) -> Result<ciphervault_chain::ValidatorSet> {
    let path = chain_dir.join("validators.json");
    if path.exists() {
        let raw: Vec<String> = serde_json::from_str(
            &std::fs::read_to_string(&path).context("Failed to read validators.json")?,
        )
        .context("validators.json must be a JSON array of hex public keys")?;
        let mut keys = Vec::with_capacity(raw.len());
        for (i, h) in raw.iter().enumerate() {
            let bytes = hex::decode(h.trim().trim_start_matches("0x"))
                .with_context(|| format!("validators.json entry {i} is not hex"))?;
            if bytes.len() != 32 {
                bail!("validators.json entry {i} must be 32 bytes");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            keys.push(arr);
        }
        return Ok(ciphervault_chain::ValidatorSet::new(keys)?);
    }
    let set = ciphervault_chain::ValidatorSet::new(vec![local.public_key()])?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&vec![hex::encode(local.public_key())])?,
    )?;
    Ok(set)
}

/// Opens the existing local ledger, or creates a fresh genesis when none exists.
/// Pre-Phase-2 chains (throwaway genesis keys) fail to verify against the
/// persistent set: they are renamed aside (never deleted) and replaced.
fn open_or_fresh_genesis(
    chain_dir: &std::path::Path,
    validator_set: &ciphervault_chain::ValidatorSet,
    device_signer: &ciphervault_chain::ConsensusSigner,
) -> Result<ciphervault_chain::SovereignLedger> {
    if chain_dir.join("blocks").exists() {
        match ciphervault_chain::SovereignLedger::open(
            ciphervault_chain::SOVEREIGN_CHAIN_ID_STR,
            validator_set.clone(),
            chain_dir,
        ) {
            Ok(ledger) => return Ok(ledger),
            Err(e) if is_legacy_key_mismatch(&e) => {
                let backup = chain_dir
                    .with_extension(format!("pre-phase2-{}", Utc::now().timestamp_millis()));
                std::fs::rename(chain_dir, &backup)
                    .context("Failed to back up legacy pre-Phase-2 chain")?;
                eprintln!(
                    "Notice: pre-Phase-2 local chain (throwaway keys) backed up to {}. Starting fresh genesis.",
                    backup.display()
                );
            }
            Err(e) => return Err(e.into()),
        }
    }
    ciphervault_chain::SovereignLedger::create_genesis(
        ciphervault_chain::SOVEREIGN_CHAIN_ID_STR,
        validator_set.clone(),
        &[device_signer],
        Utc::now().timestamp_millis() as u64,
        Some(chain_dir.to_path_buf()),
    )
    .map_err(Into::into)
}

/// Derives the recoverable anchor salt for a head from its epoch key,
/// falling back to a one-time random (local-only) salt when the snapshot
/// is unknown locally. Free function (not a closure) so `cmd_anchor`'s
/// future stays `Send`: no borrow of the `RefCell`-backed store is held
/// across an await.
fn fresh_anchor_salt(
    store: &ciphervault_local_store::LocalVaultStore,
    head: &[u8; 32],
) -> [u8; 32] {
    match store.derive_head_anchor_salt(head) {
        Ok(salt) => salt,
        Err(e) => {
            eprintln!(
                "{}: cannot derive recoverable salt ({e}); using one-time local salt",
                "warning".yellow()
            );
            let mut s = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            s
        }
    }
}

/// Key-identity failures (as opposed to corruption) marking a pre-Phase-2
/// throwaway chain that cannot verify under the persistent validator set.
fn is_legacy_key_mismatch(e: &ciphervault_chain::ChainError) -> bool {
    use ciphervault_chain::ChainError as E;
    matches!(
        e,
        E::InvalidGenesis(_)
            | E::InvalidProposer(_)
            | E::InvalidSignature(_)
            | E::InsufficientQuorum { .. }
            | E::UnauthorizedValidator(_)
            | E::DuplicateValidatorSignature(_)
    )
}

#[cfg(test)]
mod tests {
    use super::publish_proposal_to_operators;
    use super::verify_anchor_evidence;
    use ciphervault_chain::{
        CommitmentTx, ConsensusSigner, SovereignLedger, ValidatorSet, SOVEREIGN_CHAIN_ID_NUM,
        SOVEREIGN_CHAIN_ID_STR,
    };
    use ciphervault_format::CheckpointEvidence;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn temp_chain_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cv-verify-anchor-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    /// A solo chain (device = sole validator, as `cmd_anchor` builds it)
    /// holding one anchored commitment, plus the evidence `cmd_anchor` saves.
    fn anchored_solo_chain(
        name: &str,
        private: bool,
    ) -> (std::path::PathBuf, ValidatorSet, CheckpointEvidence) {
        let dir = temp_chain_dir(name);
        let signer = ConsensusSigner::generate();
        let set = ValidatorSet::new(vec![signer.public_key()]).unwrap();
        let evidence = anchor_solo_chain_into(&dir, &signer, private);
        (dir, set, evidence)
    }

    /// Writes a fresh solo chain signed by `signer` into `dir` (replacing any
    /// chain there) with the helper's fixed commitment anchored at height 1.
    fn anchor_solo_chain_into(
        dir: &std::path::Path,
        signer: &ConsensusSigner,
        private: bool,
    ) -> CheckpointEvidence {
        let set = ValidatorSet::new(vec![signer.public_key()]).unwrap();
        let mut ledger = SovereignLedger::create_genesis(
            SOVEREIGN_CHAIN_ID_STR,
            set,
            &[signer],
            1_000,
            Some(dir.to_path_buf()),
        )
        .unwrap();
        let salt = [0x5au8; 32];
        let head = [0xc3u8; 32];
        let mut tx = if private {
            CommitmentTx::new_private(&[0x77u8; 32], &salt, &head, [0u8; 32], 1, 1_500)
        } else {
            CommitmentTx {
                version: 0,
                vault_id: [0x77u8; 32],
                salt,
                head_cid: head,
                commitment: CommitmentTx::calculate_commitment(&salt, &head),
                client_pubkey: [0u8; 32],
                signature: [0u8; 64],
                nonce: 1,
                timestamp_ms: 1_500,
            }
        };
        signer.sign_tx(&mut tx, SOVEREIGN_CHAIN_ID_STR);
        let block = ledger.propose_block(signer, vec![tx], 2_000, None).unwrap();
        let block_hash = block.header.block_hash();
        ledger.commit_block(block).unwrap();
        CheckpointEvidence::new(
            salt,
            head,
            SOVEREIGN_CHAIN_ID_NUM,
            [0u8; 20],
            block_hash,
            1,
            2,
        )
    }

    /// Review: a self-consistent replacement chain (other key, rewritten
    /// genesis record, matching evidence) must not verify against the
    /// configured validator set.
    #[test]
    fn verify_anchor_evidence_refuses_a_replaced_genesis_record() {
        let (dir, set, evidence) = anchored_solo_chain("replaced-genesis", false);
        assert!(verify_anchor_evidence(&dir, &evidence, &set).is_ok());

        // An attacker re-creates the chain under their own key in the same
        // directory (blocks and genesis_validators.json) and rewrites the
        // evidence to name the forged block.
        std::fs::remove_dir_all(&dir).unwrap();
        let attacker = ConsensusSigner::generate();
        let forged_evidence = anchor_solo_chain_into(&dir, &attacker, false);
        assert_eq!(forged_evidence.commitment, evidence.commitment);
        let err = match verify_anchor_evidence(&dir, &forged_evidence, &set) {
            Ok(_) => panic!("replaced chain must not verify against the configured set"),
            Err(e) => e,
        };
        assert!(format!("{err:#}").contains("validators.json"), "{err:#}");

        // The same chain does verify for a vault that configured that key.
        let attacker_set = ValidatorSet::new(vec![attacker.public_key()]).unwrap();
        assert!(verify_anchor_evidence(&dir, &forged_evidence, &attacker_set).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_anchor_evidence_accepts_legacy_and_private_anchors() {
        for private in [false, true] {
            let (dir, set, evidence) =
                anchored_solo_chain(if private { "private" } else { "legacy" }, private);
            let verified = verify_anchor_evidence(&dir, &evidence, &set)
                .unwrap_or_else(|e| panic!("private={private}: {e:#}"));
            assert!(verified.result.verified);
            assert_eq!(verified.result.height, 1);
            assert_eq!(verified.trusted_keys, 1);
            assert!(verified.result.timestamp_signed);
            assert_eq!(verified.block_version, ciphervault_chain::PROTOCOL_VERSION);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn verify_anchor_evidence_fails_closed() {
        let (dir, set, evidence) = anchored_solo_chain("fail-closed", false);
        assert!(verify_anchor_evidence(&dir, &evidence, &set).is_ok());

        // Evidence that no longer matches its own commitment.
        let mut tampered = evidence.clone();
        tampered.salt[0] ^= 0x01;
        assert!(verify_anchor_evidence(&dir, &tampered, &set).is_err());

        // Self-consistent evidence for a commitment that was never anchored.
        let never = CheckpointEvidence::new(
            [0x01; 32],
            [0x02; 32],
            SOVEREIGN_CHAIN_ID_NUM,
            [0u8; 20],
            [0u8; 32],
            1,
            2,
        );
        assert!(verify_anchor_evidence(&dir, &never, &set).is_err());

        // Evidence naming a different block than the ledger holds.
        let mut wrong_block = evidence.clone();
        wrong_block.tx_hash = vec![0xee; 32];
        assert!(verify_anchor_evidence(&dir, &wrong_block, &set).is_err());

        // Legacy EVM evidence cannot be verified any more.
        let mut legacy = evidence.clone();
        legacy.chain_id = 42_161;
        legacy.contract_address = vec![0x11; 20];
        assert!(verify_anchor_evidence(&dir, &legacy, &set).is_err());

        // No ledger at all.
        assert!(verify_anchor_evidence(&dir.join("missing"), &evidence, &set).is_err());

        // A block whose time was rewritten on disk no longer re-verifies
        // (v4 signs every median sample).
        let block_path = dir.join("blocks").join(format!("{:012}.json", 1));
        let mut block: ciphervault_chain::CipherChainBlock =
            serde_json::from_str(&std::fs::read_to_string(&block_path).unwrap()).unwrap();
        block.header.timestamp_ms = 1_001;
        std::fs::write(&block_path, serde_json::to_string_pretty(&block).unwrap()).unwrap();
        assert!(verify_anchor_evidence(&dir, &evidence, &set).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Minimal HTTP responder: reads one request (headers + body), counts
    /// it, answers 200. Runs until aborted.
    async fn serve_ok_forever(
        listener: tokio::net::TcpListener,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let headers_end = req
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(req.len());
            let header_text = String::from_utf8_lossy(&req[..headers_end]).to_lowercase();
            let want: usize = header_text
                .split("content-length:")
                .nth(1)
                .and_then(|v| {
                    v.split(|c: char| !c.is_ascii_digit())
                        .next()
                        .and_then(|v| v.trim().parse().ok())
                })
                .unwrap_or(0);
            let mut have = req.len().saturating_sub(headers_end);
            while have < want {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => have += n,
                    Err(_) => break,
                }
            }
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\nconnection: close\r\n\r\n{\"status\":\"ok\"}",
                )
                .await;
        }
    }

    #[tokio::test]
    async fn test_publish_proposal_counts_accepts_and_ignores_dead() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_url = format!("http://{}", listener.local_addr().unwrap());
        // A port that is bound now but closed before the request lands.
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_url = format!("http://{}", closed_listener.local_addr().unwrap());
        drop(closed_listener);
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task = tokio::spawn(serve_ok_forever(listener, hits.clone()));
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let body = serde_json::json!({"sealed": true});
        let accepted = publish_proposal_to_operators(&http, &[mock_url, closed_url], &body).await;
        assert_eq!(accepted, 1);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        task.abort();
    }
}
