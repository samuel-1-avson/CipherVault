//! The `c2sp.org/tlog-witness` `add-checkpoint` protocol, without storage,
//! clock or HTTP, so the witness server and the log that pushes to it
//! share one implementation.
//!
//! A request body is
//!
//! ```text
//! old <size>
//! <base64 consistency proof hash>      (zero to 63 lines)
//!
//! <signed checkpoint note>
//! ```
//!
//! The witness answers `200` with its cosignature lines, or one of the
//! status codes in [`WitnessError::status`]. Checking a request against
//! the latest cosigned size and recording the new checkpoint must happen
//! atomically; [`AddCheckpointRequest::verify`] only does the checking, so
//! the caller must hold its per-log lock across `verify`, cosigning and
//! persisting.

use crate::checkpoint::{open_checkpoint, Checkpoint, CheckpointError};
use crate::cosignature::WitnessVerifier;
use crate::encoding::{b64_decode, b64_encode, parse_decimal_u64};
use crate::hash::{empty_root, Hash};
use crate::note::{Ed25519NoteVerifier, Note, NoteError, NoteSignature, NoteVerifier as _};
use crate::proof::verify_consistency;

/// The most consistency proof lines a request may carry.
pub const MAX_PROOF_LINES: usize = 63;

/// The content type of a `409 Conflict` response body.
pub const SIZE_CONTENT_TYPE: &str = "text/x.tlog.size";

/// Why a witness refused an `add-checkpoint` request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
    /// The request does not follow the protocol, or the old size is above
    /// the checkpoint size (`400 Bad Request`).
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    /// The witness does not know the checkpoint's origin (`404 Not Found`).
    #[error("unknown log origin")]
    UnknownLog,
    /// No trusted log signature verified, or one from a trusted key failed
    /// (`403 Forbidden`).
    #[error("checkpoint is not validly signed by the log")]
    Forbidden,
    /// The old size is not the latest size this witness cosigned
    /// (`409 Conflict`). The response body is that size.
    #[error("old size does not match the latest cosigned size {latest_size}")]
    Conflict {
        /// The size of the latest checkpoint the witness cosigned for
        /// this log, or 0 if it never cosigned one.
        latest_size: u64,
    },
    /// The checkpoint is validly signed but not consistent with what the
    /// witness cosigned before (`422 Unprocessable Entity`). This can be
    /// evidence that the log misbehaved.
    #[error("checkpoint is not consistent with the witnessed tree: {0}")]
    Inconsistent(&'static str),
}

impl WitnessError {
    /// The HTTP status code the spec requires for this refusal.
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Forbidden => 403,
            Self::UnknownLog => 404,
            Self::Conflict { .. } => 409,
            Self::Inconsistent(_) => 422,
        }
    }

    /// Whether the request carried a validly signed checkpoint that the
    /// witness could not cosign because it conflicts with an earlier one,
    /// so it is worth keeping as evidence.
    pub fn is_evidence(&self) -> bool {
        matches!(self, Self::Inconsistent(_))
    }
}

/// The tree a witness last cosigned for one log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessedTree {
    /// The tree size.
    pub size: u64,
    /// The root hash at that size.
    pub root: Hash,
}

/// A parsed `add-checkpoint` request. Nothing in it is trusted until
/// [`AddCheckpointRequest::verify`] succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddCheckpointRequest {
    old_size: u64,
    proof: Vec<Hash>,
    note: Vec<u8>,
    origin: String,
}

impl AddCheckpointRequest {
    /// Parses a request body.
    pub fn parse(body: &[u8]) -> Result<Self, WitnessError> {
        let (first, mut rest) = split_line(body).ok_or(WitnessError::BadRequest(
            "request must start with an old size line",
        ))?;
        let old_size = first
            .strip_prefix(b"old ")
            .and_then(|size| std::str::from_utf8(size).ok())
            .and_then(parse_decimal_u64)
            .ok_or(WitnessError::BadRequest(
                "old size line must be \"old <decimal>\"",
            ))?;

        let mut proof = Vec::new();
        loop {
            let (line, after) = split_line(rest).ok_or(WitnessError::BadRequest(
                "missing empty line before the checkpoint",
            ))?;
            rest = after;
            if line.is_empty() {
                break;
            }
            if proof.len() == MAX_PROOF_LINES {
                return Err(WitnessError::BadRequest("more than 63 proof lines"));
            }
            let hash: Hash = std::str::from_utf8(line)
                .ok()
                .and_then(b64_decode)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(WitnessError::BadRequest(
                    "proof line must be a 32-byte hash in canonical base64",
                ))?;
            proof.push(hash);
        }

        // The origin is read before any signature is checked, only to pick
        // the log key; `verify` checks it again under the key.
        let note = Note::parse(rest).map_err(|_| WitnessError::BadRequest("malformed note"))?;
        let checkpoint = Checkpoint::parse_text(note.text())
            .map_err(|_| WitnessError::BadRequest("note is not a checkpoint"))?;
        Ok(Self {
            old_size,
            proof,
            note: rest.to_vec(),
            origin: checkpoint.origin().to_owned(),
        })
    }

    /// Encodes a request body, for a log pushing a checkpoint.
    pub fn encode(old_size: u64, proof: &[Hash], signed_checkpoint: &[u8]) -> Vec<u8> {
        let mut body = format!("old {old_size}\n").into_bytes();
        for hash in proof {
            body.extend_from_slice(b64_encode(hash).as_bytes());
            body.push(b'\n');
        }
        body.push(b'\n');
        body.extend_from_slice(signed_checkpoint);
        body
    }

    /// The old size the client claims the witness last cosigned.
    pub fn old_size(&self) -> u64 {
        self.old_size
    }

    /// The consistency proof from the old size to the checkpoint size.
    pub fn proof(&self) -> &[Hash] {
        &self.proof
    }

    /// The signed checkpoint note, as sent.
    pub fn signed_checkpoint(&self) -> &[u8] {
        &self.note
    }

    /// The checkpoint's origin, unverified: only for choosing the log key
    /// and the witness state to check against.
    pub fn claimed_origin(&self) -> &str {
        &self.origin
    }

    /// Checks the request against the log key the witness trusts for its
    /// origin and the tree it last cosigned for that log (`None` if it
    /// never cosigned one), in the order of `c2sp.org/tlog-witness`.
    ///
    /// On success the caller may cosign the returned checkpoint and must
    /// record it as the latest before releasing its lock.
    pub fn verify(
        &self,
        log_key: &Ed25519NoteVerifier,
        latest: Option<&WitnessedTree>,
    ) -> Result<AcceptedCheckpoint, WitnessError> {
        let checkpoint = match open_checkpoint(&self.note, &self.origin, log_key, &[]) {
            Ok(verified) => verified.checkpoint().clone(),
            Err(
                CheckpointError::MissingLogSignature
                | CheckpointError::Note(NoteError::InvalidSignature { .. }),
            ) => return Err(WitnessError::Forbidden),
            Err(_) => return Err(WitnessError::BadRequest("invalid checkpoint")),
        };
        self.check_consistency(&checkpoint, latest)?;
        let log_signatures = Note::parse(&self.note)
            .map_err(|_| WitnessError::BadRequest("malformed note"))?
            .signatures()
            .iter()
            .filter(|s| s.name() == log_key.name() && s.key_id() == log_key.key_id())
            .cloned()
            .collect();
        Ok(AcceptedCheckpoint {
            checkpoint,
            log_signatures,
        })
    }

    fn check_consistency(
        &self,
        checkpoint: &Checkpoint,
        latest: Option<&WitnessedTree>,
    ) -> Result<(), WitnessError> {
        if self.old_size > checkpoint.size() {
            return Err(WitnessError::BadRequest(
                "old size is above the checkpoint size",
            ));
        }
        let latest_size = latest.map_or(0, |tree| tree.size);
        if self.old_size != latest_size {
            return Err(WitnessError::Conflict { latest_size });
        }
        if checkpoint.size() == 0 && checkpoint.root() != &empty_root() {
            return Err(WitnessError::Inconsistent(
                "an empty tree must have the empty root",
            ));
        }
        match latest.filter(|tree| tree.size > 0) {
            None => {
                if !self.proof.is_empty() {
                    return Err(WitnessError::Inconsistent(
                        "a proof from size 0 must be empty",
                    ));
                }
            }
            Some(tree) if tree.size == checkpoint.size() => {
                if &tree.root != checkpoint.root() {
                    return Err(WitnessError::Inconsistent(
                        "same size as the witnessed tree but a different root",
                    ));
                }
                if !self.proof.is_empty() {
                    return Err(WitnessError::Inconsistent(
                        "a proof between equal sizes must be empty",
                    ));
                }
            }
            Some(tree) => {
                verify_consistency(
                    tree.size,
                    checkpoint.size(),
                    &self.proof,
                    &tree.root,
                    checkpoint.root(),
                )
                .map_err(|_| WitnessError::Inconsistent("consistency proof does not verify"))?;
            }
        }
        Ok(())
    }
}

/// A checkpoint that passed every witness check and may be cosigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedCheckpoint {
    checkpoint: Checkpoint,
    log_signatures: Vec<NoteSignature>,
}

impl AcceptedCheckpoint {
    /// The verified checkpoint.
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    /// The tree it commits to.
    pub fn tree(&self) -> WitnessedTree {
        WitnessedTree {
            size: self.checkpoint.size(),
            root: *self.checkpoint.root(),
        }
    }

    /// The log signature lines that verified.
    pub fn log_signatures(&self) -> &[NoteSignature] {
        &self.log_signatures
    }

    /// The checkpoint with its verified log signatures followed by
    /// `cosignatures`: what a witness serves to monitors.
    pub fn cosigned_note(&self, cosignatures: &[NoteSignature]) -> Result<String, NoteError> {
        let mut note = Note::new(self.checkpoint.to_text())?;
        for signature in self.log_signatures.iter().chain(cosignatures) {
            note.add_signature(signature.clone())?;
        }
        note.encode()
    }
}

/// Splits off the first line of `bytes`, without its newline.
fn split_line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = bytes.iter().position(|&b| b == b'\n')?;
    Some((&bytes[..end], &bytes[end + 1..]))
}

/// The body of a `200` response: one cosignature line per signature.
pub fn encode_cosignatures(cosignatures: &[NoteSignature]) -> String {
    cosignatures.iter().map(NoteSignature::to_line).collect()
}

/// The body of a `409 Conflict` response.
pub fn encode_size(size: u64) -> String {
    format!("{size}\n")
}

/// Parses the body of a `409 Conflict` response.
pub fn parse_size(body: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(body).ok()?.strip_suffix('\n')?;
    parse_decimal_u64(text)
}

/// Why a witness's `200` response could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    /// The body is not a sequence of signature lines.
    #[error("malformed witness response")]
    Malformed,
    /// A line from the witness's key does not verify over the checkpoint.
    #[error("cosignature from the witness does not verify")]
    InvalidCosignature,
    /// No line in the body is from the witness's key.
    #[error("the witness returned no cosignature from its key")]
    Missing,
}

/// Verifies a witness's `200` response for `checkpoint` and returns the
/// cosignatures from `witness`, with their timestamps. Lines from other
/// keys are ignored, as the spec requires.
pub fn verify_cosignature_response(
    checkpoint: &Checkpoint,
    body: &[u8],
    witness: &WitnessVerifier,
) -> Result<Vec<(NoteSignature, u64)>, ResponseError> {
    let text = std::str::from_utf8(body).map_err(|_| ResponseError::Malformed)?;
    let lines = text.strip_suffix('\n').ok_or(ResponseError::Malformed)?;
    let mut out = Vec::new();
    for line in lines.split('\n') {
        let signature = NoteSignature::parse_line(line).map_err(|_| ResponseError::Malformed)?;
        if signature.name() != witness.name() || signature.key_id() != witness.key_id() {
            continue;
        }
        let timestamp = witness
            .verify_cosignature(checkpoint, signature.signature())
            .ok_or(ResponseError::InvalidCosignature)?;
        if !out.iter().any(|(s, _)| s == &signature) {
            out.push((signature, timestamp));
        }
    }
    if out.is_empty() {
        return Err(ResponseError::Missing);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_malformed_bodies() {
        let note = b"example.com/log\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n\xe2\x80\x94 example.com/log AAAAAAA=\n";
        let mut ok = b"old 0\n\n".to_vec();
        ok.extend_from_slice(note);
        let parsed = AddCheckpointRequest::parse(&ok).unwrap();
        assert_eq!(parsed.old_size(), 0);
        assert!(parsed.proof().is_empty());
        assert_eq!(parsed.claimed_origin(), "example.com/log");

        for (body, why) in [
            (&b"old 01\n\n"[..], "leading zero"),
            (b"old -1\n\n", "sign"),
            (b"Old 1\n\n", "keyword case"),
            (b"old 1", "no newline"),
            (b"old 1\nAAAA\n\n", "short hash"),
            (b"old 1\n", "no empty line"),
        ] {
            let mut body = body.to_vec();
            if body.ends_with(b"\n\n") {
                body.extend_from_slice(note);
            }
            assert!(
                matches!(
                    AddCheckpointRequest::parse(&body),
                    Err(WitnessError::BadRequest(_))
                ),
                "{why}"
            );
        }

        let mut many = b"old 1\n".to_vec();
        for _ in 0..64 {
            many.extend_from_slice(b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n");
        }
        many.push(b'\n');
        many.extend_from_slice(note);
        assert_eq!(
            AddCheckpointRequest::parse(&many),
            Err(WitnessError::BadRequest("more than 63 proof lines"))
        );
    }

    #[test]
    fn encode_parses_back() {
        let note = b"example.com/log\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n\xe2\x80\x94 example.com/log AAAAAAA=\n";
        let proof = [[1u8; 32], [2u8; 32]];
        let body = AddCheckpointRequest::encode(7, &proof, note);
        let parsed = AddCheckpointRequest::parse(&body).unwrap();
        assert_eq!(parsed.old_size(), 7);
        assert_eq!(parsed.proof(), &proof);
        assert_eq!(parsed.signed_checkpoint(), note);
    }

    #[test]
    fn size_bodies() {
        assert_eq!(encode_size(42), "42\n");
        assert_eq!(parse_size(b"42\n"), Some(42));
        assert_eq!(parse_size(b"42"), None);
        assert_eq!(parse_size(b"042\n"), None);
    }

    #[test]
    fn status_codes() {
        assert_eq!(WitnessError::BadRequest("x").status(), 400);
        assert_eq!(WitnessError::Forbidden.status(), 403);
        assert_eq!(WitnessError::UnknownLog.status(), 404);
        assert_eq!(WitnessError::Conflict { latest_size: 1 }.status(), 409);
        assert_eq!(WitnessError::Inconsistent("x").status(), 422);
        assert!(WitnessError::Inconsistent("x").is_evidence());
        assert!(!WitnessError::Forbidden.is_evidence());
    }
}
