//! Multi-node consensus wire protocol (Phase 2, item 3).
//!
//! Transport-agnostic proposal / vote / certified-block gossip. A gossip
//! transport carries JSON [`ChainSyncEnvelope`]s (keep them under the
//! transport's size cap) and feeds each payload to
//! [`ChainSyncHub::ingest`]; all validation here is pure and synchronous.
//!
//! Round flow: a proposer gossips [`ChainSyncMsg::Proposal`] (full block,
//! proposer endorsement only). Validators vet it with
//! [`SovereignLedger::check_block`] and gossip [`ChainSyncMsg::Vote`]
//! carrying a header endorsement (proposers self-vote). Any hub that
//! collects 2N/3+1 endorsements over one proposal assembles the certificate
//! and commits. Hubs that missed the round ingest
//! [`ChainSyncMsg::CertifiedBlock`] and commit after re-verifying quorum.
//!
//! Votes bind to the *proposal* hash. The committed block hash additionally
//! covers the collected certificate, with signatures in canonical validator
//! order so every honest node assembles the identical block.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::consensus::{verify_raw_signature, ConsensusSigner, ValidatorSet};
use crate::error::ChainError;
use crate::ledger::SovereignLedger;
use crate::types::{BlockHeader, BlockSignature, CipherChainBlock};

/// Domain separator for gossip envelope signatures.
pub const SYNC_ENVELOPE_DOMAIN: &[u8] = b"CIPHERVAULT_SYNC_V1:";
/// Gossip topic carrying chain sync envelopes (transport subscribes here).
pub const CHAIN_SYNC_TOPIC: &str = "ciphervault/chain/1";

/// Consensus gossip message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainSyncMsg {
    /// Block proposal: full block with the proposer's endorsement only.
    Proposal(ProposalMsg),
    /// Header endorsement vote for a vetted proposal.
    Vote(VoteMsg),
    /// Fully-certified block (quorum signatures attached) for catch-up.
    CertifiedBlock(CipherChainBlock),
}

impl ChainSyncMsg {
    /// Chain this message belongs to (proposals/certified blocks carry it in
    /// the header; votes carry it explicitly).
    pub fn chain_id(&self) -> &str {
        match self {
            ChainSyncMsg::Proposal(p) => &p.block.header.chain_id,
            ChainSyncMsg::Vote(v) => &v.chain_id,
            ChainSyncMsg::CertifiedBlock(b) => &b.header.chain_id,
        }
    }
}

/// Block proposal payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalMsg {
    pub block: CipherChainBlock,
}

/// Header endorsement vote. The voter must have vetted the proposal with
/// [`SovereignLedger::check_block`]; the hub re-verifies the endorsement
/// cryptographically and checks quorum. One envelope per validator:
/// aggregators collect one envelope per validator.
///
/// Voter protocol (version-2 median time): the voter endorses the proposal
/// CONTENT (signatures cover everything except `timestamp_ms`) and reports
/// its own wall-clock observation in `observed_ms`, clamped with
/// [`crate::vote_observed_ms`] so the median can never violate chain
/// monotonicity, and only votes when
/// [`crate::proposal_time_acceptable`] holds for the proposal's suggested
/// time. The quorum median of `observed_ms` samples (plus the proposer's
/// suggested time as its sample) becomes the committed block timestamp —
/// validator-voted time, robust to f < quorum/3 liars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteMsg {
    pub chain_id: String,
    pub header: BlockHeader,
    pub observed_ms: u64,
    /// Endorsement of `header` by the envelope sender (no vote relaying:
    /// aggregators collect one envelope per validator).
    pub endorsement: BlockSignature,
}

/// Signed gossip envelope. Admission requires validator-set membership plus
/// a valid device-key signature over the message body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSyncEnvelope {
    pub validator: [u8; 32],
    pub msg: ChainSyncMsg,
    #[serde(with = "crate::types::serde_hex_64")]
    pub signature: [u8; 64],
}

impl ChainSyncEnvelope {
    /// Seals a message with the validator's device key.
    pub fn seal(signer: &ConsensusSigner, msg: ChainSyncMsg) -> Self {
        let signature = signer.sign_raw(&Self::body_bytes(&msg));
        Self {
            validator: signer.public_key(),
            msg,
            signature,
        }
    }

    fn body_bytes(msg: &ChainSyncMsg) -> Vec<u8> {
        let body = serde_json::to_vec(msg).expect("sync message serializes");
        let mut payload = Vec::with_capacity(SYNC_ENVELOPE_DOMAIN.len() + body.len());
        payload.extend_from_slice(SYNC_ENVELOPE_DOMAIN);
        payload.extend_from_slice(&body);
        payload
    }

    /// Verifies set membership + device-key signature; returns the message.
    pub fn open(&self, validator_set: &ValidatorSet) -> Result<&ChainSyncMsg, ChainError> {
        if !validator_set.contains(&self.validator) {
            return Err(ChainError::UnauthorizedValidator(hex::encode(
                self.validator,
            )));
        }
        verify_raw_signature(
            &self.validator,
            &Self::body_bytes(&self.msg),
            &self.signature,
        )?;
        Ok(&self.msg)
    }
}

fn verify_endorsement(
    header: &BlockHeader,
    endorsement: &BlockSignature,
) -> Result<(), ChainError> {
    let verifying_key = VerifyingKey::from_bytes(&endorsement.validator)
        .map_err(|e| ChainError::InvalidSignature(format!("Invalid endorser key: {e}")))?;
    let signature = Signature::from_bytes(&endorsement.signature);
    verifying_key
        .verify_strict(&header.signing_payload(), &signature)
        .map_err(|e| ChainError::InvalidSignature(format!("Endorsement failure: {e}")))
}

/// Conflicting endorsements from one validator at one height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    pub validator: [u8; 32],
    pub height: u64,
    pub first_hash: [u8; 32],
    pub second_hash: [u8; 32],
}

/// Outcome of recording one vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteOutcome {
    Accepted { count: usize, required: usize },
    Duplicate,
    Stale,
    Rejected(String),
    Equivocation(Equivocation),
}

/// Quorum vote accumulator keyed by (height, proposal hash). Each voter
/// contributes its endorsement plus its observed timestamp; the median of
/// the observed samples becomes the committed time for version-2 blocks.
#[derive(Debug)]
pub struct VoteCollector {
    validator_set: ValidatorSet,
    votes: HashMap<(u64, [u8; 32]), HashMap<[u8; 32], (BlockSignature, u64)>>,
    equivocations: Vec<Equivocation>,
    certified: HashSet<(u64, [u8; 32])>,
}

impl VoteCollector {
    pub fn new(validator_set: ValidatorSet) -> Self {
        Self {
            validator_set,
            votes: HashMap::new(),
            equivocations: Vec::new(),
            certified: HashSet::new(),
        }
    }

    /// Marks a (height, hash) pair decided so further votes read as stale.
    pub fn mark_certified(&mut self, height: u64, hash: [u8; 32]) {
        self.certified.insert((height, hash));
        self.votes.remove(&(height, hash));
    }

    /// Collected endorsements for one proposal (for certificate assembly).
    pub fn votes_for(
        &self,
        height: u64,
        hash: &[u8; 32],
    ) -> Option<&HashMap<[u8; 32], (BlockSignature, u64)>> {
        self.votes.get(&(height, *hash))
    }

    /// Replaces the validator set votes are checked against. The hub calls
    /// this after every ledger mutation so post-rotation votes verify
    /// against the active set, not the set that was current at construction.
    pub fn set_validator_set(&mut self, validator_set: ValidatorSet) {
        self.validator_set = validator_set;
    }

    /// Conflicting-vote evidence observed so far.
    pub fn equivocations(&self) -> &[Equivocation] {
        &self.equivocations
    }

    /// Records a vote whose envelope already passed admission. `latest_height`
    /// is the hub ledger tip: votes at or below it are stale history.
    pub fn add_vote(&mut self, vote: &VoteMsg, latest_height: u64) -> VoteOutcome {
        if vote.header.height <= latest_height
            || self.certified.iter().any(|(h, _)| *h == vote.header.height)
        {
            return VoteOutcome::Stale;
        }
        if vote.header.height > latest_height + 1 {
            return VoteOutcome::Rejected(format!(
                "vote for future height {} (latest {})",
                vote.header.height, latest_height
            ));
        }
        if !self.validator_set.contains(&vote.endorsement.validator) {
            return VoteOutcome::Rejected("endorser not in validator set".to_string());
        }
        if let Err(e) = verify_endorsement(&vote.header, &vote.endorsement) {
            return VoteOutcome::Rejected(e.to_string());
        }
        let key = (vote.header.height, vote.header.block_hash());
        for ((h, hash), voters) in &self.votes {
            if *h == vote.header.height
                && *hash != key.1
                && voters.contains_key(&vote.endorsement.validator)
            {
                let evidence = Equivocation {
                    validator: vote.endorsement.validator,
                    height: vote.header.height,
                    first_hash: *hash,
                    second_hash: key.1,
                };
                self.equivocations.push(evidence.clone());
                return VoteOutcome::Equivocation(evidence);
            }
        }
        let voters = self.votes.entry(key).or_default();
        if voters.contains_key(&vote.endorsement.validator) {
            return VoteOutcome::Duplicate;
        }
        voters.insert(
            vote.endorsement.validator,
            (vote.endorsement.clone(), vote.observed_ms),
        );
        VoteOutcome::Accepted {
            count: voters.len(),
            required: self.validator_set.quorum_threshold(),
        }
    }
}

/// Outcome of ingesting one gossip payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    ProposalAccepted {
        height: u64,
        hash: String,
    },
    VoteCollected {
        height: u64,
        count: usize,
        required: usize,
    },
    Committed {
        height: u64,
        hash: String,
    },
    Duplicate,
    Stale,
    Rejected(String),
    EquivocationDetected(Equivocation),
    ForkRejected {
        height: u64,
        existing: String,
        incoming: String,
    },
    NeedCatchup {
        height: u64,
        latest: u64,
    },
}

/// Node-side consensus engine: owns a ledger replica, collects votes,
/// assembles certificates, and commits. Transports call [`Self::ingest`].
#[derive(Debug)]
pub struct ChainSyncHub {
    ledger: SovereignLedger,
    collector: VoteCollector,
    proposals: HashMap<(u64, [u8; 32]), CipherChainBlock>,
    /// False for adopted tips until [`Self::backfill`] rebuilds genesis-
    /// anchored history. While false the hub relays and votes but never
    /// commits new proposals (its nonce/state view is incomplete).
    complete: bool,
}

impl ChainSyncHub {
    pub fn new(ledger: SovereignLedger) -> Self {
        let collector = VoteCollector::new(ledger.validator_set().clone());
        Self {
            ledger,
            collector,
            proposals: HashMap::new(),
            complete: true,
        }
    }

    /// Adopts a fully-certified block as an unanchored tip (federated
    /// catch-up). The hub stays incomplete until [`Self::backfill`] runs.
    pub fn adopt_tip(
        chain_id: &str,
        validator_set: ValidatorSet,
        tip: CipherChainBlock,
        storage: Option<std::path::PathBuf>,
    ) -> Result<Self, ChainError> {
        let ledger =
            SovereignLedger::from_certified_tip(chain_id, validator_set.clone(), tip, storage)?;
        Ok(Self {
            ledger,
            collector: VoteCollector::new(validator_set),
            proposals: HashMap::new(),
            complete: false,
        })
    }

    /// Rebuilds genesis-anchored history (backfill) and marks the replica
    /// complete. Prunes proposals at or below the new tip. `genesis_set`
    /// must be the set that certified block 0 (fetched alongside the
    /// blocks): block 0 verifies against it, and in-band rotations derive
    /// every later set during replay.
    pub fn backfill(
        &mut self,
        blocks: Vec<CipherChainBlock>,
        genesis_set: ValidatorSet,
    ) -> Result<(), ChainError> {
        let chain_id = self.ledger.chain_id().to_string();
        let storage = self.ledger.storage_path();
        let ledger = SovereignLedger::rebuild_from_blocks(&chain_id, genesis_set, blocks, storage)?;
        let tip = ledger.height();
        let active = ledger.validator_set().clone();
        self.ledger = ledger;
        self.collector = VoteCollector::new(active);
        self.proposals.retain(|(height, _), _| *height > tip);
        self.complete = true;
        Ok(())
    }

    /// Marks a genesis-anchored replica as syncing (used when reopening a
    /// tip-snapshot dir whose history has not been backfilled yet).
    pub fn mark_syncing(&mut self) {
        self.complete = false;
    }

    /// Whether the replica holds genesis-anchored history and may commit.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn ledger(&self) -> &SovereignLedger {
        &self.ledger
    }

    pub fn collector(&self) -> &VoteCollector {
        &self.collector
    }

    /// Validates and applies one gossip payload (JSON [`ChainSyncEnvelope`]).
    pub fn ingest(&mut self, raw: &[u8]) -> IngestOutcome {
        let envelope: ChainSyncEnvelope = match serde_json::from_slice(raw) {
            Ok(envelope) => envelope,
            Err(e) => return IngestOutcome::Rejected(format!("unparsable envelope: {e}")),
        };
        let msg = match envelope.open(self.ledger.validator_set()) {
            Ok(msg) => msg.clone(),
            Err(e) => return IngestOutcome::Rejected(e.to_string()),
        };
        if msg.chain_id() != self.ledger.chain_id() {
            return IngestOutcome::Rejected(format!("wrong chain: {}", msg.chain_id()));
        }
        self.ingest_msg(envelope.validator, &msg)
    }

    /// Validates and applies an admitted message (post admission).
    /// Split from [`Self::ingest`] so node code holding envelopes can feed
    /// the hub without re-serializing.
    pub fn ingest_msg(&mut self, sender: [u8; 32], msg: &ChainSyncMsg) -> IngestOutcome {
        match msg {
            ChainSyncMsg::Proposal(proposal) => {
                self.ingest_proposal(sender, proposal.block.clone())
            }
            ChainSyncMsg::Vote(vote) => {
                if vote.endorsement.validator != sender {
                    return IngestOutcome::Rejected(
                        "vote relay not accepted: endorser must seal own vote".to_string(),
                    );
                }
                self.ingest_vote(vote)
            }
            ChainSyncMsg::CertifiedBlock(block) => self.ingest_certified(block.clone()),
        }
    }

    fn ingest_proposal(&mut self, sender: [u8; 32], block: CipherChainBlock) -> IngestOutcome {
        let height = block.header.height;
        let hash = block.header.block_hash();
        let latest = self.ledger.height();
        if height <= latest {
            return match self.ledger.block_at_height(height) {
                Some(existing) if existing.header.block_hash() == hash => IngestOutcome::Duplicate,
                _ => IngestOutcome::Rejected(format!("stale proposal for decided height {height}")),
            };
        }
        if height > latest + 1 {
            return IngestOutcome::NeedCatchup { height, latest };
        }
        if !self.complete {
            return IngestOutcome::Rejected(
                "replica syncing: backfill required to validate proposals".to_string(),
            );
        }
        if block.header.proposer != sender {
            return IngestOutcome::Rejected("proposal sender is not the proposer".to_string());
        }
        if let Err(e) = self.ledger.check_block(&block) {
            return IngestOutcome::Rejected(format!("proposal failed validation: {e}"));
        }
        if let Err(e) = self
            .ledger
            .validator_set()
            .verify_proposer_signature(&block.header)
        {
            return IngestOutcome::Rejected(format!("bad proposer endorsement: {e}"));
        }
        let key = (height, hash);
        if self.proposals.contains_key(&key) {
            return IngestOutcome::Duplicate;
        }
        self.proposals.insert(key, block);
        if let Some(outcome) = self.attempt_commit(height, hash) {
            return outcome;
        }
        IngestOutcome::ProposalAccepted {
            height,
            hash: hex::encode(hash),
        }
    }

    fn ingest_vote(&mut self, vote: &VoteMsg) -> IngestOutcome {
        // Cheap linkage gate before touching the collector: votes must target
        // the next height and extend the local tip.
        let latest = self.ledger.height();
        if vote.header.height == latest + 1 {
            let tip = self.ledger.latest_block().header.block_hash();
            if vote.header.prev_block_hash != tip || vote.header.chain_id != *self.ledger.chain_id()
            {
                return IngestOutcome::Rejected(
                    "vote header does not extend the local tip".to_string(),
                );
            }
        }
        match self.collector.add_vote(vote, latest) {
            VoteOutcome::Accepted { count, required } => {
                let height = vote.header.height;
                let hash = vote.header.block_hash();
                if let Some(outcome) = self.attempt_commit(height, hash) {
                    return outcome;
                }
                IngestOutcome::VoteCollected {
                    height,
                    count,
                    required,
                }
            }
            VoteOutcome::Duplicate => IngestOutcome::Duplicate,
            VoteOutcome::Stale => IngestOutcome::Stale,
            VoteOutcome::Rejected(reason) => IngestOutcome::Rejected(reason),
            VoteOutcome::Equivocation(evidence) => IngestOutcome::EquivocationDetected(evidence),
        }
    }

    /// Tries to assemble a certificate from collected votes and commit.
    /// Certificate signatures are sorted by validator for determinism so all
    /// honest hubs assemble the identical block.
    fn attempt_commit(&mut self, height: u64, proposal_hash: [u8; 32]) -> Option<IngestOutcome> {
        // Incomplete replicas collect votes but never assemble: their
        // nonce/state view cannot rule out replays until backfilled.
        if !self.complete {
            return None;
        }
        let key = (height, proposal_hash);
        let proposal = self.proposals.get(&key)?.clone();
        let collected = self.collector.votes_for(height, &proposal_hash)?;
        let quorum = self.ledger.validator_set().quorum_threshold();
        let mut block = proposal;
        let mut seen: HashSet<[u8; 32]> = block
            .header
            .signatures
            .iter()
            .map(|sig| sig.validator)
            .collect();
        let mut fresh: Vec<(BlockSignature, u64)> = collected
            .values()
            .filter(|(sig, _)| !seen.contains(&sig.validator))
            .cloned()
            .collect();
        fresh.sort_by_key(|(sig, _)| sig.validator);
        // Version-2 median time: the proposer's suggested timestamp counts
        // as its sample and every collected vote contributes its observed
        // time. Signatures cover everything except the timestamp, so the
        // substitution keeps them valid; block_hash commits to the median.
        // Version-1 blocks keep proposer-stamped time (legacy rule).
        if block.header.version >= 2 {
            let mut samples: Vec<u64> = fresh.iter().map(|(_, observed)| *observed).collect();
            samples.push(block.header.timestamp_ms);
            block.header.timestamp_ms = crate::median_timestamp_ms(&mut samples);
        }
        for (sig, _) in fresh {
            seen.insert(sig.validator);
            block.header.signatures.push(sig);
        }
        if block.header.signatures.len() < quorum {
            return None;
        }
        block.header.signatures.sort_by_key(|sig| sig.validator);
        match self.ledger.commit_block(block) {
            Ok(()) => {
                // Rotation may have changed the active set: re-sync the
                // collector so later votes verify against current members.
                let set = self.ledger.validator_set().clone();
                self.collector.set_validator_set(set);
                let committed = self.ledger.latest_block().header.block_hash();
                self.collector.mark_certified(height, proposal_hash);
                self.proposals.remove(&key);
                Some(IngestOutcome::Committed {
                    height,
                    hash: hex::encode(committed),
                })
            }
            Err(e) => Some(IngestOutcome::Rejected(format!(
                "assembly commit failed: {e}"
            ))),
        }
    }

    fn ingest_certified(&mut self, block: CipherChainBlock) -> IngestOutcome {
        let height = block.header.height;
        let hash = block.header.block_hash();
        let latest = self.ledger.height();
        if height <= latest {
            return match self.ledger.block_at_height(height) {
                Some(existing) if existing.header.block_hash() == hash => IngestOutcome::Duplicate,
                Some(existing) => IngestOutcome::ForkRejected {
                    height,
                    existing: hex::encode(existing.header.block_hash()),
                    incoming: hex::encode(hash),
                },
                None => {
                    IngestOutcome::Rejected(format!("no local block at decided height {height}"))
                }
            };
        }
        if height > latest + 1 {
            return IngestOutcome::NeedCatchup { height, latest };
        }
        // Full gate: structure + quorum, then commit (persists when backed).
        if let Err(e) = self.ledger.check_block(&block) {
            return IngestOutcome::Rejected(format!("certified block invalid: {e}"));
        }
        if let Err(e) = self
            .ledger
            .validator_set()
            .verify_header_signatures(&block.header)
        {
            return IngestOutcome::Rejected(format!("quorum verification failed: {e}"));
        }
        match self.ledger.commit_block(block) {
            Ok(()) => {
                let set = self.ledger.validator_set().clone();
                self.collector.set_validator_set(set);
                self.collector.mark_certified(height, hash);
                self.proposals.remove(&(height, hash));
                IngestOutcome::Committed {
                    height,
                    hash: hex::encode(hash),
                }
            }
            Err(e) => IngestOutcome::Rejected(format!("certified commit failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CommitmentTx;

    const CHAIN_ID: &str = "ciphervault-sync-test";

    fn setup(n_validators: usize) -> (Vec<ConsensusSigner>, ValidatorSet, Vec<ChainSyncHub>) {
        let signers: Vec<ConsensusSigner> = (0..n_validators)
            .map(|_| ConsensusSigner::generate())
            .collect();
        let set = ValidatorSet::new(signers.iter().map(|s| s.public_key()).collect()).unwrap();
        let refs: Vec<&ConsensusSigner> = signers.iter().collect();
        let template =
            SovereignLedger::create_genesis(CHAIN_ID, set.clone(), &refs, 1_000, None).unwrap();
        let hubs = (0..n_validators)
            .map(|_| ChainSyncHub::new(template.clone()))
            .collect();
        (signers, set, hubs)
    }

    fn client_tx(
        client: &ConsensusSigner,
        salt_byte: u8,
        cid_byte: u8,
        nonce: u64,
    ) -> CommitmentTx {
        let salt = [salt_byte; 32];
        let head_cid = [cid_byte; 32];
        let commitment = CommitmentTx::calculate_commitment(&salt, &head_cid);
        let mut tx = CommitmentTx {
            vault_id: [0x33; 32],
            salt,
            head_cid,
            commitment,
            client_pubkey: [0u8; 32],
            signature: [0u8; 64],
            nonce,
            timestamp_ms: 1_100,
        };
        client.sign_tx(&mut tx, CHAIN_ID);
        tx
    }

    fn vote_for(signer: &ConsensusSigner, header: &BlockHeader) -> ChainSyncEnvelope {
        vote_for_at(signer, header, header.timestamp_ms)
    }

    fn vote_for_at(
        signer: &ConsensusSigner,
        header: &BlockHeader,
        observed_ms: u64,
    ) -> ChainSyncEnvelope {
        let endorsement = signer.sign_header(header);
        ChainSyncEnvelope::seal(
            signer,
            ChainSyncMsg::Vote(VoteMsg {
                chain_id: CHAIN_ID.to_string(),
                header: header.clone(),
                observed_ms,
                endorsement,
            }),
        )
    }

    fn raw(envelope: &ChainSyncEnvelope) -> Vec<u8> {
        serde_json::to_vec(envelope).unwrap()
    }

    fn support_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "ciphervault-sync-test-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        dir
    }

    #[test]
    fn test_three_node_round_commits_identical_blocks() {
        let (signers, _set, mut hubs) = setup(3);
        let client = ConsensusSigner::generate();

        let proposal_block = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                2_000,
                None,
            )
            .unwrap();
        let proposal_hash = proposal_block.header.block_hash();
        let votes: Vec<Vec<u8>> = signers
            .iter()
            .map(|s| raw(&vote_for(s, &proposal_block.header)))
            .collect();
        let proposal_raw = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: proposal_block,
            }),
        ));

        for hub in hubs.iter_mut() {
            assert!(matches!(
                hub.ingest(&proposal_raw),
                IngestOutcome::ProposalAccepted { .. }
            ));
        }

        let mut committed = 0;
        for hub in hubs.iter_mut() {
            for vote in &votes {
                match hub.ingest(vote) {
                    IngestOutcome::VoteCollected { .. } => {}
                    IngestOutcome::Committed { .. } => committed += 1,
                    other => panic!("unexpected outcome: {other:?}"),
                }
            }
        }
        assert_eq!(committed, 3);

        let hashes: Vec<[u8; 32]> = hubs
            .iter()
            .map(|h| h.ledger().latest_block().header.block_hash())
            .collect();
        assert_eq!(hubs[0].ledger().height(), 1);
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(hashes[1], hashes[2]);
        // Committed hash covers the certificate, so it differs from the voted proposal hash.
        assert_ne!(hashes[0], proposal_hash);
        let sigs = &hubs[0].ledger().latest_block().header.signatures;
        assert_eq!(sigs.len(), 3);
        assert!(sigs.windows(2).all(|w| w[0].validator <= w[1].validator));

        // Replayed history reads back as stale/rejected, never double commits:
        // the superseded proposal can no longer match the committed tip.
        assert!(matches!(
            hubs[0].ingest(&proposal_raw),
            IngestOutcome::Rejected(_)
        ));
        assert!(matches!(hubs[0].ingest(&votes[0]), IngestOutcome::Stale));
    }

    #[test]
    fn test_median_timestamp_replaces_proposer_suggestion() {
        let (signers, _set, mut hubs) = setup(3);
        let client = ConsensusSigner::generate();

        // Proposer suggests 9_000; voters observe 2_000 and 4_000. Samples
        // are [2000, 4000] plus the proposer suggestion 9000 → sorted
        // [2000, 4000, 9000] → upper median 4000, not the suggestion.
        let proposal_block = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                9_000,
                None,
            )
            .unwrap();
        assert_eq!(proposal_block.header.version, 3);
        let proposal_raw = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: proposal_block.clone(),
            }),
        ));
        let votes: Vec<Vec<u8>> = [&signers[1], &signers[2]]
            .into_iter()
            .zip([2_000u64, 4_000u64])
            .map(|(s, observed)| raw(&vote_for_at(s, &proposal_block.header, observed)))
            .collect();

        for hub in hubs.iter_mut() {
            assert!(matches!(
                hub.ingest(&proposal_raw),
                IngestOutcome::ProposalAccepted { .. }
            ));
        }
        let mut committed = 0;
        for hub in hubs.iter_mut() {
            for vote in &votes {
                match hub.ingest(vote) {
                    IngestOutcome::VoteCollected { .. } => {}
                    IngestOutcome::Committed { .. } => committed += 1,
                    other => panic!("unexpected outcome: {other:?}"),
                }
            }
        }
        assert_eq!(committed, 3);
        for hub in hubs.iter() {
            assert_eq!(hub.ledger().latest_block().header.timestamp_ms, 4_000);
        }
        let hashes: Vec<[u8; 32]> = hubs
            .iter()
            .map(|h| h.ledger().latest_block().header.block_hash())
            .collect();
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(hashes[1], hashes[2]);
    }

    #[test]
    fn test_version_one_blocks_keep_proposer_time() {
        let (signers, _set, mut hubs) = setup(3);
        let client = ConsensusSigner::generate();

        // Hand-rolled v1 proposal: timestamp inside the signed bytes, so
        // assembly must NOT substitute the median.
        let mut proposal_block = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xcc, 0xdd, 1)],
                9_000,
                None,
            )
            .unwrap();
        proposal_block.header.version = 1;
        proposal_block.header.signatures = vec![signers[0].sign_header(&proposal_block.header)];
        let proposal_raw = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: proposal_block.clone(),
            }),
        ));
        let votes: Vec<Vec<u8>> = [&signers[1], &signers[2]]
            .into_iter()
            .zip([2_000u64, 4_000u64])
            .map(|(s, observed)| raw(&vote_for_at(s, &proposal_block.header, observed)))
            .collect();

        for hub in hubs.iter_mut() {
            assert!(matches!(
                hub.ingest(&proposal_raw),
                IngestOutcome::ProposalAccepted { .. }
            ));
        }
        let mut committed = 0;
        for hub in hubs.iter_mut() {
            for vote in &votes {
                match hub.ingest(vote) {
                    IngestOutcome::VoteCollected { .. } => {}
                    IngestOutcome::Committed { .. } => committed += 1,
                    other => panic!("unexpected outcome: {other:?}"),
                }
            }
        }
        assert_eq!(committed, 3);
        for hub in hubs.iter() {
            assert_eq!(hub.ledger().latest_block().header.timestamp_ms, 9_000);
        }
    }

    #[test]
    fn test_median_and_voter_helpers() {
        assert_eq!(
            crate::median_timestamp_ms(&mut [9_000, 2_000, 4_000]),
            4_000
        );
        assert_eq!(crate::median_timestamp_ms(&mut [5_000]), 5_000);
        assert_eq!(
            crate::median_timestamp_ms(&mut [8_000, 2_000, 4_000, 6_000]),
            6_000
        );
        assert!(crate::proposal_time_acceptable(1_000, 1_000 + 60_000));
        assert!(!crate::proposal_time_acceptable(1_000, 1_000 + 60_001));
        assert_eq!(crate::vote_observed_ms(500, 1_000), 1_001);
        assert_eq!(crate::vote_observed_ms(2_000, 1_000), 2_000);
    }

    #[test]
    fn test_rotation_applies_on_commit_and_rekeys_voting() {
        let (signers_a, _set_a, mut hubs) = setup(3);
        let signers_b: Vec<ConsensusSigner> = (0..3).map(|_| ConsensusSigner::generate()).collect();
        let keys_b: Vec<[u8; 32]> = signers_b.iter().map(|s| s.public_key()).collect();
        let client = ConsensusSigner::generate();

        // Block 1 rotates A -> B, certified by an A quorum.
        let rotation_block = hubs[0]
            .ledger()
            .propose_block(
                &signers_a[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                2_000,
                Some(keys_b.clone()),
            )
            .unwrap();
        assert_eq!(rotation_block.header.version, 3);
        let proposal_hash = rotation_block.header.block_hash();
        let proposal_raw = raw(&ChainSyncEnvelope::seal(
            &signers_a[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: rotation_block.clone(),
            }),
        ));
        let votes: Vec<Vec<u8>> = signers_a
            .iter()
            .map(|s| raw(&vote_for(s, &rotation_block.header)))
            .collect();

        for hub in hubs.iter_mut() {
            assert!(matches!(
                hub.ingest(&proposal_raw),
                IngestOutcome::ProposalAccepted { .. }
            ));
            for vote in &votes {
                let _ = hub.ingest(vote);
            }
            assert_eq!(hub.ledger().height(), 1);
            assert_eq!(hub.ledger().validator_set().validators(), keys_b);
            // The vote record for the decided proposal is pruned on commit.
            assert_eq!(
                hub.collector()
                    .votes_for(1, &proposal_hash)
                    .map(|m| m.len()),
                None
            );
        }

        // Height 2 proposes and commits under the new set B.
        let block2 = hubs[0]
            .ledger()
            .propose_block(
                &signers_b[0],
                vec![client_tx(&client, 0xcc, 0xdd, 2)],
                3_000,
                None,
            )
            .unwrap();
        let proposal2_raw = raw(&ChainSyncEnvelope::seal(
            &signers_b[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: block2.clone(),
            }),
        ));
        let votes2: Vec<Vec<u8>> = signers_b
            .iter()
            .map(|s| raw(&vote_for(s, &block2.header)))
            .collect();
        for hub in hubs.iter_mut() {
            assert!(matches!(
                hub.ingest(&proposal2_raw),
                IngestOutcome::ProposalAccepted { .. }
            ));
        }
        let mut committed = 0;
        for hub in hubs.iter_mut() {
            for vote in &votes2 {
                if matches!(hub.ingest(vote), IngestOutcome::Committed { .. }) {
                    committed += 1;
                }
            }
        }
        assert_eq!(committed, 3);
        for hub in hubs.iter() {
            assert_eq!(hub.ledger().height(), 2);
            assert_eq!(hub.ledger().validator_set().validators(), keys_b);
        }

        // An old-set vote for a post-rotation height is rejected: A is no
        // longer a member of the active set.
        let stale = raw(&vote_for(&signers_a[1], &block2.header));
        assert!(matches!(hubs[0].ingest(&stale), IngestOutcome::Rejected(_)));
    }

    #[test]
    fn test_rotation_rejects_malformed_payloads() {
        let (signers, _set, mut hubs) = setup(3);
        let client = ConsensusSigner::generate();

        // Empty rotation set.
        let err = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                2_000,
                Some(Vec::new()),
            )
            .unwrap_err();
        assert!(matches!(err, ChainError::InvalidRotation(_)));

        // Rotation smuggled into a pre-v3 header.
        let mut legacy = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                2_000,
                None,
            )
            .unwrap();
        legacy.header.version = 2;
        legacy.header.next_validators = Some(vec![signers[0].public_key()]);
        legacy.header.signatures = vec![signers[0].sign_header(&legacy.header)];
        let err = hubs[0].ledger().check_block(&legacy).unwrap_err();
        assert!(matches!(err, ChainError::InvalidRotation(_)));
    }

    #[test]
    fn test_reopen_lands_on_rotated_set() {
        let (signers_a, set_a, _) = setup(3);
        let signers_b: Vec<ConsensusSigner> = (0..3).map(|_| ConsensusSigner::generate()).collect();
        let keys_b: Vec<[u8; 32]> = signers_b.iter().map(|s| s.public_key()).collect();
        let set_b = ValidatorSet::new(keys_b.clone()).unwrap();
        let client = ConsensusSigner::generate();
        let dir = support_dir("rotation-reopen");

        // Persist genesis + a rotation block directly on the ledger.
        {
            let refs: Vec<&ConsensusSigner> = signers_a.iter().collect();
            let mut ledger = SovereignLedger::create_genesis(
                CHAIN_ID,
                set_a.clone(),
                &refs,
                1_000,
                Some(dir.clone()),
            )
            .unwrap();
            let tx = client_tx(&client, 0xaa, 0xbb, 1);
            let mut block = ledger
                .propose_block(&signers_a[0], vec![tx], 2_000, Some(keys_b.clone()))
                .unwrap();
            for signer in [&signers_a[1], &signers_a[2]] {
                block
                    .header
                    .signatures
                    .push(signer.sign_header(&block.header));
            }
            ledger.commit_block(block).unwrap();
            assert_eq!(ledger.validator_set().validators(), keys_b);
            assert!(dir.join("genesis_validators.json").exists());
        }

        // Reopen with the NEW set (operator's updated file): genesis verifies
        // against the on-disk record, replay derives the rotation.
        let reopened = SovereignLedger::open(CHAIN_ID, set_b, &dir).unwrap();
        assert_eq!(reopened.height(), 1);
        assert_eq!(reopened.validator_set().validators(), keys_b);

        // Reopen with the OLD set also works: the genesis record (not the
        // passed set) anchors block 0, and replay derives forward.
        let reopened_old = SovereignLedger::open(CHAIN_ID, set_a, &dir).unwrap();
        assert_eq!(reopened_old.height(), 1);
        assert_eq!(reopened_old.validator_set().validators(), keys_b);
    }

    #[test]
    fn test_vote_before_proposal_still_commits() {
        let (signers, _set, mut hubs) = setup(3);
        let client = ConsensusSigner::generate();

        let proposal_block = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                2_000,
                None,
            )
            .unwrap();
        let votes: Vec<Vec<u8>> = signers
            .iter()
            .map(|s| raw(&vote_for(s, &proposal_block.header)))
            .collect();
        let proposal_raw = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: proposal_block,
            }),
        ));

        // Votes arrive first: collected, nothing committed.
        for vote in &votes {
            assert!(matches!(
                hubs[0].ingest(vote),
                IngestOutcome::VoteCollected { .. }
            ));
        }
        assert_eq!(hubs[0].ledger().height(), 0);
        // The late proposal triggers assembly and commit.
        assert!(matches!(
            hubs[0].ingest(&proposal_raw),
            IngestOutcome::Committed { .. }
        ));
        assert_eq!(hubs[0].ledger().height(), 1);
    }

    #[test]
    fn test_equivocation_is_detected() {
        let (signers, _set, mut hubs) = setup(4);
        let client = ConsensusSigner::generate();

        let block_x = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                2_000,
                None,
            )
            .unwrap();
        let block_y = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xcc, 0xdd, 1)],
                2_000,
                None,
            )
            .unwrap();
        let header_x = block_x.header.clone();
        let header_y = block_y.header.clone();
        let raw_x = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg { block: block_x }),
        ));
        let raw_y = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg { block: block_y }),
        ));
        assert!(matches!(
            hubs[0].ingest(&raw_x),
            IngestOutcome::ProposalAccepted { .. }
        ));
        assert!(matches!(
            hubs[0].ingest(&raw_y),
            IngestOutcome::ProposalAccepted { .. }
        ));

        // Validator 3 endorses X, then equivocates by endorsing Y.
        let vote_x = raw(&vote_for(&signers[3], &header_x));
        let vote_y = raw(&vote_for(&signers[3], &header_y));
        assert!(matches!(
            hubs[0].ingest(&vote_x),
            IngestOutcome::VoteCollected { .. }
        ));
        assert!(matches!(
            hubs[0].ingest(&vote_y),
            IngestOutcome::EquivocationDetected(_)
        ));
        assert_eq!(hubs[0].collector().equivocations().len(), 1);
        let evidence = &hubs[0].collector().equivocations()[0];
        assert_eq!(evidence.validator, signers[3].public_key());
        assert_eq!(evidence.height, 1);
        assert_ne!(evidence.first_hash, evidence.second_hash);
    }

    #[test]
    fn test_conflicting_certified_block_is_rejected_as_fork() {
        let (signers, _set, mut hubs) = setup(3);
        let client = ConsensusSigner::generate();

        // Hub 0 commits block 1 through a full proposal + vote round.
        let proposal_block = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                2_000,
                None,
            )
            .unwrap();
        let votes: Vec<Vec<u8>> = signers
            .iter()
            .map(|s| raw(&vote_for(s, &proposal_block.header)))
            .collect();
        hubs[0].ingest(&raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: proposal_block,
            }),
        )));
        for vote in &votes {
            hubs[0].ingest(vote);
        }
        assert_eq!(hubs[0].ledger().height(), 1);

        // A lagging hub catches up by ingesting the certified block.
        let certified = hubs[0].ledger().latest_block().clone();
        let certified_hash = certified.header.block_hash();
        let certified_raw = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::CertifiedBlock(certified),
        ));
        assert!(matches!(
            hubs[1].ingest(&certified_raw),
            IngestOutcome::Committed { .. }
        ));
        assert_eq!(
            hubs[1].ledger().latest_block().header.block_hash(),
            certified_hash
        );

        // A rival fully-signed block at the same height is a fork, not history.
        let mut fork = hubs[2]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xcc, 0xdd, 1)],
                2_000,
                None,
            )
            .unwrap();
        for signer in [&signers[1], &signers[2]] {
            fork.header
                .signatures
                .push(signer.sign_header(&fork.header));
        }
        assert_eq!(fork.header.signatures.len(), 3);
        let fork_raw = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::CertifiedBlock(fork),
        ));
        assert!(matches!(
            hubs[0].ingest(&fork_raw),
            IngestOutcome::ForkRejected { height: 1, .. }
        ));
        // The fork did not disturb the committed tip.
        assert_eq!(
            hubs[0].ledger().latest_block().header.block_hash(),
            certified_hash
        );
    }

    #[test]
    fn test_hostile_and_mismatched_inputs_rejected() {
        let (signers, _set, mut hubs) = setup(3);
        let client = ConsensusSigner::generate();
        let outsider = ConsensusSigner::generate();

        let bad_block = hubs[0]
            .ledger()
            .propose_block(
                &signers[0],
                vec![client_tx(&client, 0xaa, 0xbb, 1)],
                2_000,
                None,
            )
            .unwrap();

        // Non-member envelopes are rejected before any state changes.
        let outsider_raw = raw(&ChainSyncEnvelope::seal(
            &outsider,
            ChainSyncMsg::Proposal(ProposalMsg {
                block: bad_block.clone(),
            }),
        ));
        assert!(matches!(
            hubs[0].ingest(&outsider_raw),
            IngestOutcome::Rejected(_)
        ));

        // Tampered bytes fail signature admission (or parsing).
        let good = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg { block: bad_block }),
        ));
        let mut tampered = good.clone();
        tampered[20] ^= 0xff;
        assert!(matches!(
            hubs[0].ingest(&tampered),
            IngestOutcome::Rejected(_)
        ));

        // Wrong-chain votes are rejected before any other handling.
        let genesis_header = hubs[0].ledger().latest_block().header.clone();
        let wrong_chain = raw(&ChainSyncEnvelope::seal(
            &signers[1],
            ChainSyncMsg::Vote(VoteMsg {
                chain_id: "other-chain".to_string(),
                header: genesis_header.clone(),
                observed_ms: genesis_header.timestamp_ms,
                endorsement: signers[1].sign_header(&genesis_header),
            }),
        ));
        assert!(matches!(
            hubs[0].ingest(&wrong_chain),
            IngestOutcome::Rejected(_)
        ));
        assert_eq!(hubs[0].ledger().height(), 0);
    }

    fn full_chain(
        signers: &[ConsensusSigner],
        set: &ValidatorSet,
        client: &ConsensusSigner,
        blocks: u64,
    ) -> SovereignLedger {
        let refs: Vec<&ConsensusSigner> = signers.iter().collect();
        let mut ledger =
            SovereignLedger::create_genesis(CHAIN_ID, set.clone(), &refs, 1_000, None).unwrap();
        for n in 1..=blocks {
            let tx = client_tx(&client, n as u8, n as u8, n);
            let mut block = ledger
                .propose_block(&signers[0], vec![tx], 1_000 + n * 1_000, None)
                .unwrap();
            for signer in [&signers[1], &signers[2]] {
                block
                    .header
                    .signatures
                    .push(signer.sign_header(&block.header));
            }
            ledger.commit_block(block).unwrap();
        }
        ledger
    }

    #[test]
    fn test_adopt_tip_then_backfill_then_commit() {
        let (signers, set, _) = setup(3);
        let client = ConsensusSigner::generate();
        let full = full_chain(&signers, &set, &client, 3);
        assert_eq!(full.height(), 3);

        // A new hub adopts the certified tip with no history.
        let tip = full.latest_block().clone();
        let mut hub = ChainSyncHub::adopt_tip(CHAIN_ID, set.clone(), tip, None).unwrap();
        assert!(!hub.is_complete());
        assert_eq!(hub.ledger().height(), 3);

        // Proposals are refused until backfilled; votes still collected.
        let new_tx = client_tx(&client, 0xaa, 0xbb, 4);
        let new_proposal = hub
            .ledger()
            .propose_block(&signers[0], vec![new_tx], 5_000, None)
            .unwrap();
        let header4 = new_proposal.header.clone();
        let new_raw = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: new_proposal,
            }),
        ));
        assert!(matches!(hub.ingest(&new_raw), IngestOutcome::Rejected(_)));
        assert!(matches!(
            hub.ingest(&raw(&vote_for(&signers[1], &header4))),
            IngestOutcome::VoteCollected { .. }
        ));
        assert_eq!(hub.ledger().height(), 3);

        // Backfill with full history completes the replica...
        let history: Vec<CipherChainBlock> = (0..=3)
            .map(|h| full.block_at_height(h).unwrap().clone())
            .collect();
        hub.backfill(history, set.clone()).unwrap();
        assert!(hub.is_complete());

        // ...and the same round now commits.
        let retry_raw = raw(&ChainSyncEnvelope::seal(
            &signers[0],
            ChainSyncMsg::Proposal(ProposalMsg {
                block: hub
                    .ledger()
                    .propose_block(
                        &signers[0],
                        vec![client_tx(&client, 0xaa, 0xbb, 4)],
                        5_000,
                        None,
                    )
                    .unwrap(),
            }),
        ));
        assert!(matches!(
            hub.ingest(&retry_raw),
            IngestOutcome::ProposalAccepted { .. }
        ));
        for signer in &signers {
            let vote = raw(&vote_for(
                signer,
                &hub.proposals
                    .get(&(4, hub.proposals.keys().find(|(h, _)| *h == 4).unwrap().1))
                    .unwrap()
                    .header
                    .clone(),
            ));
            if let IngestOutcome::Committed { height: 4, .. } = hub.ingest(&vote) {
                assert_eq!(hub.ledger().height(), 4);
                return;
            }
        }
        panic!("quorum round did not commit after backfill");
    }

    #[test]
    fn test_backfill_rejects_gaps_and_wrong_genesis() {
        let (signers, set, _) = setup(3);
        let client = ConsensusSigner::generate();
        let full = full_chain(&signers, &set, &client, 3);

        // Gap at height 1.
        let gappy = vec![
            full.block_at_height(0).unwrap().clone(),
            full.block_at_height(2).unwrap().clone(),
            full.block_at_height(3).unwrap().clone(),
        ];
        let mut hub =
            ChainSyncHub::adopt_tip(CHAIN_ID, set.clone(), full.latest_block().clone(), None)
                .unwrap();
        assert!(hub.backfill(gappy, set.clone()).is_err());
        assert!(!hub.is_complete());

        // Wrong chain in history.
        let mut wrong = full.block_at_height(0).unwrap().clone();
        wrong.header.chain_id = "other-chain".to_string();
        let history = vec![wrong];
        assert!(hub.backfill(history, set.clone()).is_err());
    }

    #[test]
    fn test_tip_snapshot_resume_and_backfill_persist() {
        let (signers, set, _) = setup(3);
        let client = ConsensusSigner::generate();
        let dir = support_dir("tip-resume");
        let full = {
            let refs: Vec<&ConsensusSigner> = signers.iter().collect();
            let mut ledger = SovereignLedger::create_genesis(
                CHAIN_ID,
                set.clone(),
                &refs,
                1_000,
                Some(dir.clone()),
            )
            .unwrap();
            for n in 1..=2u64 {
                let tx = client_tx(&client, n as u8, n as u8, n);
                let mut block = ledger
                    .propose_block(&signers[0], vec![tx], 1_000 + n * 1_000, None)
                    .unwrap();
                for signer in [&signers[1], &signers[2]] {
                    block
                        .header
                        .signatures
                        .push(signer.sign_header(&block.header));
                }
                ledger.commit_block(block).unwrap();
            }
            ledger
        };
        assert_eq!(full.height(), 2);

        // Adopt the certified tip into the same dir (tip.json + tip block file).
        let tip = full.latest_block().clone();
        let hub =
            ChainSyncHub::adopt_tip(CHAIN_ID, set.clone(), tip.clone(), Some(dir.clone())).unwrap();
        assert!(!hub.is_complete());
        assert!(dir.join("tip.json").exists());
        drop(hub);

        // Reopen resumes from the snapshot instead of demanding height 0.
        let reopened = SovereignLedger::open(CHAIN_ID, set.clone(), &dir).unwrap();
        assert_eq!(reopened.height(), 2);
        assert_eq!(
            reopened.latest_block().header.block_hash(),
            tip.header.block_hash()
        );

        // Backfill rebuilds full history and clears the snapshot marker.
        let history: Vec<CipherChainBlock> = (0..=2)
            .map(|h| full.block_at_height(h).unwrap().clone())
            .collect();
        let rebuilt =
            SovereignLedger::rebuild_from_blocks(CHAIN_ID, set.clone(), history, Some(dir.clone()))
                .unwrap();
        assert_eq!(rebuilt.height(), 2);
        assert!(!dir.join("tip.json").exists());

        std::fs::remove_dir_all(&dir).ok();
    }
}
