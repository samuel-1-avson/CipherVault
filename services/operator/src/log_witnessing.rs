//! Log side of witnessing (ADR-014 Phase 3): push the log's checkpoint to
//! its witnesses with `c2sp.org/tlog-witness` `add-checkpoint`, collect
//! their cosignatures, and publish the checkpoint once a quorum has
//! cosigned it.
//!
//! Each round signs the current tree head and sends it to every witness
//! with a consistency proof from the size that witness last cosigned. A
//! witness's size is learned the way the spec intends: a fresh cursor
//! sends `old 0`, and a `409` answer carries the witness's real size, which
//! the next attempt proves from. A witness reporting a size above the
//! log's is a serious fault (the log lost entries, or someone else signed
//! with its key) and is reported, never "fixed".
//!
//! Every cosignature is verified against the witness key configured here
//! before it counts, so a misbehaving witness cannot add a bad line to the
//! published checkpoint.

use std::sync::Arc;
use std::time::Duration;

use ciphervault_translog::checkpoint::Checkpoint;
use ciphervault_translog::cosignature::WitnessVerifier;
use ciphervault_translog::hash::Hash;
use ciphervault_translog::note::{Note, NoteSignature};
use ciphervault_translog::witness::{
    parse_size, verify_cosignature_response, AddCheckpointRequest,
};

use crate::log_store::{LogConfig, LogError, LogStore};
use crate::state::OperatorState;

/// ADR-014's default `witnesses_required`.
pub const DEFAULT_WITNESS_QUORUM: usize = 2;

/// The largest witness response body read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Per-request timeout for witness calls.
const WITNESS_TIMEOUT: Duration = Duration::from_secs(10);

/// One witness this log pushes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogWitness {
    /// The witness's cosignature key.
    pub verifier: WitnessVerifier,
    /// The witness's submission prefix, e.g.
    /// `https://op2.example/v1/witness`.
    pub url: String,
}

impl LogWitness {
    /// Parses `<witness vkey>@<submission URL>`. The URL must be `http` or
    /// `https`; the vkey is split off at the `@` that starts it.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let at = ["@https://", "@http://"]
            .iter()
            .filter_map(|marker| spec.find(marker))
            .min()
            .ok_or_else(|| format!("witness {spec:?} must be <vkey>@<http(s) URL>"))?;
        let (vkey, url) = (&spec[..at], &spec[at + 1..]);
        let verifier =
            WitnessVerifier::from_vkey(vkey).map_err(|e| format!("witness key {vkey:?}: {e}"))?;
        Ok(Self {
            verifier,
            url: url.trim_end_matches('/').to_string(),
        })
    }
}

/// The validated witnessing configuration of a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessPlan {
    /// The witnesses, each with a distinct name.
    pub witnesses: Vec<LogWitness>,
    /// Cosignatures needed to publish a checkpoint as witnessed.
    pub quorum: usize,
    /// Time between rounds.
    pub interval: Duration,
}

impl LogConfig {
    /// The witnessing plan, `None` when no witness is configured. Fails on
    /// any invalid witness, a repeated witness name, or a quorum of 0 or
    /// above the number of witnesses: a misconfiguration must stop
    /// startup, not silently lower the quorum.
    pub fn witness_plan(&self) -> Result<Option<WitnessPlan>, String> {
        if self.witnesses.is_empty() {
            return match self.witness_quorum {
                Some(quorum) if quorum > 0 => Err(format!(
                    "log witness quorum {quorum} is set but no witnesses are configured"
                )),
                _ => Ok(None),
            };
        }
        let witnesses = self
            .witnesses
            .iter()
            .map(|spec| LogWitness::parse(spec))
            .collect::<Result<Vec<_>, _>>()?;
        for (i, witness) in witnesses.iter().enumerate() {
            if witnesses[..i]
                .iter()
                .any(|w| w.verifier.name() == witness.verifier.name())
            {
                return Err(format!(
                    "witness name {:?} is configured twice",
                    witness.verifier.name()
                ));
            }
        }
        let quorum = self
            .witness_quorum
            .unwrap_or_else(|| DEFAULT_WITNESS_QUORUM.min(witnesses.len()));
        if quorum == 0 || quorum > witnesses.len() {
            return Err(format!(
                "log witness quorum must be between 1 and the {} configured witness(es)",
                witnesses.len()
            ));
        }
        Ok(Some(WitnessPlan {
            witnesses,
            quorum,
            interval: Duration::from_secs(self.witness_interval_secs.max(1)),
        }))
    }
}

/// What the log knows about one witness.
struct Cursor {
    witness: LogWitness,
    /// The size the witness last cosigned, as far as the log knows.
    known_size: Option<u64>,
    /// Its cosignature of the checkpoint at that size.
    last: Option<(u64, Hash, NoteSignature)>,
}

/// The outcome of one witnessing round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundReport {
    /// The tree size pushed.
    pub tree_size: u64,
    /// Verified cosignatures collected for it.
    pub cosignatures: usize,
    /// Whether it was published as the witnessed checkpoint.
    pub published: bool,
    /// One message per witness that did not cosign.
    pub failures: Vec<String>,
}

/// Pushes checkpoints to witnesses. One instance per log; rounds must not
/// overlap, which `&mut self` enforces.
pub struct Witnessing {
    plan: WitnessPlan,
    client: reqwest::Client,
    cursors: Vec<Cursor>,
}

impl Witnessing {
    /// A witnessing driver for `plan`.
    pub fn new(plan: WitnessPlan) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(WITNESS_TIMEOUT)
            .build()
            .map_err(|e| format!("witness HTTP client: {e}"))?;
        let cursors = plan
            .witnesses
            .iter()
            .cloned()
            .map(|witness| Cursor {
                witness,
                known_size: None,
                last: None,
            })
            .collect();
        Ok(Self {
            plan,
            client,
            cursors,
        })
    }

    /// Runs one round: push the current head to every witness, then
    /// publish it if a quorum cosigned.
    pub async fn round(&mut self, store: &LogStore) -> Result<RoundReport, LogError> {
        let (checkpoint, note) = store.signed_head()?;
        let pushes = self
            .cursors
            .iter_mut()
            .map(|cursor| push(&self.client, cursor, store, &checkpoint, &note));
        let results = futures_util::future::join_all(pushes).await;

        let mut cosignatures = Vec::new();
        let mut failures = Vec::new();
        for result in results {
            match result {
                Ok(signature) => cosignatures.push(signature),
                Err(message) => failures.push(message),
            }
        }
        let mut published = false;
        if cosignatures.len() >= self.plan.quorum {
            let mut witnessed =
                Note::parse(note.as_bytes()).map_err(|e| LogError::Checkpoint(e.to_string()))?;
            for signature in &cosignatures {
                witnessed
                    .add_signature(signature.clone())
                    .map_err(|e| LogError::Checkpoint(e.to_string()))?;
            }
            let encoded = witnessed
                .encode()
                .map_err(|e| LogError::Checkpoint(e.to_string()))?;
            published = store.publish_witnessed(encoded)?;
        }
        Ok(RoundReport {
            tree_size: checkpoint.size(),
            cosignatures: cosignatures.len(),
            published,
            failures,
        })
    }
}

/// Pushes `checkpoint` to one witness and returns its verified
/// cosignature.
async fn push(
    client: &reqwest::Client,
    cursor: &mut Cursor,
    store: &LogStore,
    checkpoint: &Checkpoint,
    note: &str,
) -> Result<NoteSignature, String> {
    let name = cursor.witness.verifier.name().to_string();
    if let Some((size, root, signature)) = &cursor.last {
        if *size == checkpoint.size() && root == checkpoint.root() {
            return Ok(signature.clone());
        }
    }
    // At most one retry, after a 409 teaches the witness's real size.
    for _ in 0..2 {
        let old = cursor.known_size.unwrap_or(0);
        if old > checkpoint.size() {
            return Err(format!(
                "witness {name} has cosigned size {old}, above this log's size {}: \
                 the log may have lost entries or its key signed another tree",
                checkpoint.size()
            ));
        }
        let proof = if old == 0 || old == checkpoint.size() {
            Vec::new()
        } else {
            store
                .consistency_proof(old, Some(checkpoint.size()))
                .map_err(|e| format!("witness {name}: consistency proof: {e}"))?
        };
        let body = AddCheckpointRequest::encode(old, &proof, note.as_bytes());
        let url = format!("{}/add-checkpoint", cursor.witness.url);
        let mut response = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("witness {name} at {url}: {e}"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| format!("witness {name}: reading response: {e}"))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(format!("witness {name}: response is too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        match status {
            200 => {
                let signatures =
                    verify_cosignature_response(checkpoint, &bytes, &cursor.witness.verifier)
                        .map_err(|e| format!("witness {name}: {e}"))?;
                let signature = signatures[0].0.clone();
                cursor.known_size = Some(checkpoint.size());
                cursor.last = Some((checkpoint.size(), *checkpoint.root(), signature.clone()));
                return Ok(signature);
            }
            409 => {
                let size = parse_size(&bytes)
                    .ok_or_else(|| format!("witness {name}: malformed 409 body"))?;
                cursor.known_size = Some(size);
            }
            other => {
                // The witness's state is unknown again; relearn it.
                cursor.known_size = None;
                return Err(format!(
                    "witness {name} refused size {} with {other}: {}",
                    checkpoint.size(),
                    String::from_utf8_lossy(&bytes).trim()
                ));
            }
        }
    }
    Err(format!("witness {name} kept answering 409"))
}

/// Starts the witnessing loop for the operator's log. A log that is not
/// open is retried every round.
pub fn spawn(
    state: Arc<OperatorState>,
    plan: WitnessPlan,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let interval = plan.interval;
    let quorum = plan.quorum;
    let count = plan.witnesses.len();
    let mut witnessing = Witnessing::new(plan)?;
    println!(
        "  Witnessing: {count} witness(es), quorum {quorum}, every {}s",
        interval.as_secs()
    );
    Ok(tokio::spawn(async move {
        let mut last_failures: Vec<String> = Vec::new();
        loop {
            match state.transparency_log() {
                Ok(store) => match witnessing.round(store).await {
                    Ok(report) => {
                        // Log failures when they change, not every round.
                        if report.failures != last_failures {
                            for failure in &report.failures {
                                eprintln!("transparency log witnessing: {failure}");
                            }
                            last_failures = report.failures;
                        }
                    }
                    Err(e) => eprintln!("transparency log witnessing: {e}"),
                },
                Err(e) => eprintln!("transparency log witnessing: log unavailable: {e}"),
            }
            tokio::time::sleep(interval).await;
        }
    }))
}
