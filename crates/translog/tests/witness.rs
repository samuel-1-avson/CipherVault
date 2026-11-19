//! The `c2sp.org/tlog-witness` add-checkpoint checks, in the spec's terms:
//! each refusal must carry the status code the spec names.

mod common;

use ciphervault_translog::checkpoint::Checkpoint;
use ciphervault_translog::mldsa::MlDsa44CosignatureSigner;
use ciphervault_translog::note::{Ed25519NoteSigner, NoteSignature};
use ciphervault_translog::witness::{
    encode_cosignatures, verify_cosignature_response, AddCheckpointRequest, ResponseError,
    WitnessError, WitnessedTree,
};
use ciphervault_translog::{
    consistency_proof, empty_root, open_checkpoint, root_from_leaf_hashes, Hash, WitnessVerifier,
};
use common::{flip_bit, random_leaves, rng};
use ed25519_dalek::SigningKey;

const ORIGIN: &str = "example.com/log";

struct Log {
    signer: Ed25519NoteSigner,
    leaves: Vec<Hash>,
}

impl Log {
    fn new(seed: u8, leaves: Vec<Hash>) -> Self {
        Self {
            signer: Ed25519NoteSigner::new(ORIGIN, SigningKey::from_bytes(&[seed; 32])).unwrap(),
            leaves,
        }
    }

    fn checkpoint(&self, size: u64) -> Checkpoint {
        let leaves = &self.leaves[..size as usize];
        Checkpoint::new(ORIGIN, size, root_from_leaf_hashes(leaves)).unwrap()
    }

    fn signed(&self, size: u64) -> Vec<u8> {
        self.checkpoint(size)
            .sign(&self.signer)
            .unwrap()
            .encode()
            .unwrap()
            .into_bytes()
    }

    fn tree(&self, size: u64) -> WitnessedTree {
        WitnessedTree {
            size,
            root: *self.checkpoint(size).root(),
        }
    }

    /// A request from `old` to `new` with a real consistency proof.
    fn request(&self, old: u64, new: u64) -> AddCheckpointRequest {
        let proof = if old == 0 {
            Vec::new()
        } else {
            consistency_proof(&self.leaves[..new as usize], old).unwrap()
        };
        let body = AddCheckpointRequest::encode(old, &proof, &self.signed(new));
        AddCheckpointRequest::parse(&body).unwrap()
    }
}

fn verify(
    log: &Log,
    request: &AddCheckpointRequest,
    latest: Option<WitnessedTree>,
) -> Result<WitnessedTree, WitnessError> {
    request
        .verify(&log.signer.verifier().unwrap(), latest.as_ref())
        .map(|accepted| accepted.tree())
}

#[test]
fn first_checkpoint_and_growth_are_accepted() {
    let (mut rng, _) = rng(0x3001);
    let log = Log::new(1, random_leaves(&mut rng, 40));

    // A witness that never saw the log accepts any validly signed size,
    // with an empty proof.
    assert_eq!(verify(&log, &log.request(0, 7), None), Ok(log.tree(7)));
    // Then it accepts consistent growth from exactly its size.
    for (old, new) in [(7, 8), (8, 8), (8, 21), (21, 40)] {
        assert_eq!(
            verify(&log, &log.request(old, new), Some(log.tree(old))),
            Ok(log.tree(new)),
            "{old} -> {new}"
        );
    }
    // The empty tree with the empty root is a valid first checkpoint.
    let empty = Log::new(1, Vec::new());
    assert_eq!(
        verify(&empty, &empty.request(0, 0), None),
        Ok(WitnessedTree {
            size: 0,
            root: empty_root()
        })
    );
}

#[test]
fn conflicting_old_size_is_409_with_the_latest_size() {
    let (mut rng, _) = rng(0x3002);
    let log = Log::new(1, random_leaves(&mut rng, 20));
    // The client thinks the witness is at 5; it is at 9.
    assert_eq!(
        verify(&log, &log.request(5, 12), Some(log.tree(9))),
        Err(WitnessError::Conflict { latest_size: 9 })
    );
    // A client that never talked to the witness learns its size from old 0.
    assert_eq!(
        verify(&log, &log.request(0, 12), Some(log.tree(9))),
        Err(WitnessError::Conflict { latest_size: 9 })
    );
    // And a witness with no state answers 409 with size 0.
    assert_eq!(
        verify(&log, &log.request(3, 12), None),
        Err(WitnessError::Conflict { latest_size: 0 })
    );
    assert_eq!(WitnessError::Conflict { latest_size: 9 }.status(), 409);
}

#[test]
fn old_size_above_checkpoint_size_is_400() {
    let (mut rng, _) = rng(0x3003);
    let log = Log::new(1, random_leaves(&mut rng, 10));
    let body = AddCheckpointRequest::encode(11, &[], &log.signed(10));
    let request = AddCheckpointRequest::parse(&body).unwrap();
    let err = verify(&log, &request, Some(log.tree(10))).unwrap_err();
    assert_eq!(err.status(), 400);
}

#[test]
fn bad_log_signatures_are_403() {
    let (mut rng, _) = rng(0x3004);
    let log = Log::new(1, random_leaves(&mut rng, 10));
    let request = log.request(0, 10);

    // Signed by a different key.
    let impostor = Log::new(2, log.leaves.clone());
    assert_eq!(
        request.verify(&impostor.signer.verifier().unwrap(), None),
        Err(WitnessError::Forbidden)
    );

    // A trusted key's signature that does not verify.
    let text = String::from_utf8(log.signed(10)).unwrap();
    let tampered = text.replacen("\n10\n", "\n11\n", 1);
    let body = AddCheckpointRequest::encode(0, &[], tampered.as_bytes());
    let request = AddCheckpointRequest::parse(&body).unwrap();
    let err = request
        .verify(&log.signer.verifier().unwrap(), None)
        .unwrap_err();
    assert_eq!(err, WitnessError::Forbidden);
    assert_eq!(err.status(), 403);
}

#[test]
fn inconsistent_checkpoints_are_422_evidence() {
    let (mut rng, _) = rng(0x3005);
    let log = Log::new(1, random_leaves(&mut rng, 30));

    // A fork: same key, different history from leaf 12 on.
    let mut forked_leaves = log.leaves.clone();
    forked_leaves[12] = flip_bit(&forked_leaves[12], 0);
    let fork = Log::new(1, forked_leaves);

    let cases: Vec<(&str, AddCheckpointRequest, Option<WitnessedTree>)> = vec![
        // The fork's proof from 10 to 30 does not lead from the witnessed
        // root at 20.
        ("forked growth", fork.request(20, 30), Some(log.tree(20))),
        // Same size, different root.
        ("same-size fork", fork.request(20, 20), Some(log.tree(20))),
        // A bad proof.
        (
            "bad proof",
            {
                let mut proof = consistency_proof(&log.leaves[..30], 20).unwrap();
                proof[0] = flip_bit(&proof[0], 3);
                let body = AddCheckpointRequest::encode(20, &proof, &log.signed(30));
                AddCheckpointRequest::parse(&body).unwrap()
            },
            Some(log.tree(20)),
        ),
        // A non-empty proof from size 0.
        (
            "proof from 0",
            {
                let body = AddCheckpointRequest::encode(0, &[[0; 32]], &log.signed(5));
                AddCheckpointRequest::parse(&body).unwrap()
            },
            None,
        ),
        // A non-empty proof between equal sizes.
        (
            "proof between equal sizes",
            {
                let body = AddCheckpointRequest::encode(20, &[[0; 32]], &log.signed(20));
                AddCheckpointRequest::parse(&body).unwrap()
            },
            Some(log.tree(20)),
        ),
    ];
    for (name, request, latest) in cases {
        let err = verify(&log, &request, latest).unwrap_err();
        assert!(
            matches!(err, WitnessError::Inconsistent(_)),
            "{name}: {err:?}"
        );
        assert_eq!(err.status(), 422, "{name}");
        assert!(err.is_evidence(), "{name}");
    }

    // A size-0 checkpoint with a non-empty root.
    let bogus = Checkpoint::new(ORIGIN, 0, [1; 32]).unwrap();
    let signed = bogus.sign(&log.signer).unwrap().encode().unwrap();
    let body = AddCheckpointRequest::encode(0, &[], signed.as_bytes());
    let request = AddCheckpointRequest::parse(&body).unwrap();
    assert_eq!(verify(&log, &request, None).unwrap_err().status(), 422);
}

#[test]
fn cosigned_note_and_response_round_trip() {
    let (mut rng, _) = rng(0x3006);
    let log = Log::new(1, random_leaves(&mut rng, 12));
    let witness = MlDsa44CosignatureSigner::from_seed("witness.example/a", &[9; 32]).unwrap();
    let other = MlDsa44CosignatureSigner::from_seed("witness.example/b", &[10; 32]).unwrap();
    let witness_key = WitnessVerifier::from(witness.verifier().unwrap());

    let accepted = log
        .request(0, 12)
        .verify(&log.signer.verifier().unwrap(), None)
        .unwrap();
    assert_eq!(accepted.log_signatures().len(), 1);
    let cosignature = witness
        .cosign(accepted.checkpoint(), 1_700_000_000)
        .unwrap();

    // The note a witness serves to monitors opens with the log key and the
    // witness key.
    let note = accepted
        .cosigned_note(std::slice::from_ref(&cosignature))
        .unwrap();
    let opened = open_checkpoint(
        note.as_bytes(),
        ORIGIN,
        &log.signer.verifier().unwrap(),
        std::slice::from_ref(&witness_key),
    )
    .unwrap();
    assert_eq!(opened.cosignatures().len(), 1);

    // The log side: lines from other keys are ignored, the witness's line
    // must verify, and a response without it is useless.
    let foreign = other.cosign(accepted.checkpoint(), 5).unwrap();
    let body = encode_cosignatures(&[foreign.clone(), cosignature.clone()]);
    let got =
        verify_cosignature_response(accepted.checkpoint(), body.as_bytes(), &witness_key).unwrap();
    assert_eq!(got, vec![(cosignature.clone(), 1_700_000_000)]);

    assert_eq!(
        verify_cosignature_response(
            accepted.checkpoint(),
            encode_cosignatures(&[foreign]).as_bytes(),
            &witness_key
        ),
        Err(ResponseError::Missing)
    );
    let mut raw = cosignature.signature().to_vec();
    raw[100] ^= 1;
    let bad = NoteSignature::new(witness.name(), witness.key_id(), raw).unwrap();
    assert_eq!(
        verify_cosignature_response(
            accepted.checkpoint(),
            encode_cosignatures(&[bad]).as_bytes(),
            &witness_key
        ),
        Err(ResponseError::InvalidCosignature)
    );
    assert_eq!(
        verify_cosignature_response(accepted.checkpoint(), b"not a line\n", &witness_key),
        Err(ResponseError::Malformed)
    );
}
