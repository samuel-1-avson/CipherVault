//! Mutation fuzzing of every parser and verifier, with a seeded RNG.
//!
//! Each parser must never panic, and must be canonical: whatever it
//! accepts re-encodes to exactly the input. Each verifier must never
//! panic on garbage, and a mutated signed checkpoint must either fail to
//! open or open as the original checkpoint with a subset of the original
//! cosignatures.
//!
//! Run longer with `TRANSLOG_TEST_SCALE=50` (and another
//! `TRANSLOG_TEST_SEED`).

mod common;

use ciphervault_translog::checkpoint::{open_checkpoint, Checkpoint, CheckpointError};
use ciphervault_translog::cosignature::{CosignatureV1Signer, WitnessVerifier};
use ciphervault_translog::entry::{LogEntry, ENTRY_V1_LEN};
use ciphervault_translog::note::{Ed25519NoteSigner, Note, NoteError, VerifierKey};
use ciphervault_translog::proof::{verify_consistency, verify_inclusion};
use ciphervault_translog::tiles::{Tile, TileKind};
use ciphervault_translog::Hash;
use common::{iterations, rng};
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::Rng;

/// Bytes that matter to the formats under test.
const INTERESTING: &[u8] = b"\n +=/0123456789x.-_abcpAZ\x00\x01\x7f\xe2\x80\x94\xff";

/// Applies one to three random edits to `input`.
fn mutate(rng: &mut StdRng, input: &[u8]) -> Vec<u8> {
    let mut out = input.to_vec();
    for _ in 0..rng.gen_range(1..=3) {
        let interesting = INTERESTING[rng.gen_range(0..INTERESTING.len())];
        match rng.gen_range(0..7) {
            0 if !out.is_empty() => {
                let i = rng.gen_range(0..out.len());
                out[i] ^= 1 << rng.gen_range(0..8);
            }
            1 if !out.is_empty() => {
                let i = rng.gen_range(0..out.len());
                out[i] = interesting;
            }
            2 => {
                let i = rng.gen_range(0..=out.len());
                out.insert(i, interesting);
            }
            3 if !out.is_empty() => {
                let i = rng.gen_range(0..out.len());
                out.remove(i);
            }
            4 => {
                let len = rng.gen_range(0..=out.len());
                out.truncate(len);
            }
            5 if !out.is_empty() => {
                let start = rng.gen_range(0..out.len());
                let end = rng.gen_range(start..=out.len());
                let chunk = out[start..end].to_vec();
                let at = rng.gen_range(0..=out.len());
                out.splice(at..at, chunk);
            }
            _ => {
                if out.is_empty() {
                    out.push(rng.gen());
                } else {
                    let i = rng.gen_range(0..out.len());
                    out[i] = rng.gen();
                }
            }
        }
    }
    out
}

fn random_bytes(rng: &mut StdRng, max_len: usize) -> Vec<u8> {
    let len = rng.gen_range(0..=max_len);
    (0..len).map(|_| rng.gen()).collect()
}

/// Mutations of the corpus, with one input in five pure noise.
fn inputs(rng: &mut StdRng, corpus: &[Vec<u8>], i: usize) -> Vec<u8> {
    if i % 5 == 4 {
        random_bytes(rng, 300)
    } else {
        mutate(rng, &corpus[i % corpus.len()])
    }
}

struct Fixture {
    origin: &'static str,
    checkpoint: Checkpoint,
    log: Ed25519NoteSigner,
    witnesses: Vec<CosignatureV1Signer>,
    signed: Vec<u8>,
}

fn fixture() -> Fixture {
    let origin = "cipherchain.op1.example/log";
    let checkpoint = Checkpoint::new(origin, 123_456, [0x5a; 32]).unwrap();
    let log = Ed25519NoteSigner::new(origin, SigningKey::from_bytes(&[1; 32])).unwrap();
    let witnesses: Vec<CosignatureV1Signer> = (0..3u8)
        .map(|i| {
            CosignatureV1Signer::new(
                format!("witness{i}.example/w"),
                SigningKey::from_bytes(&[10 + i; 32]),
            )
            .unwrap()
        })
        .collect();
    let mut note = checkpoint.sign(&log).unwrap();
    for (i, witness) in witnesses.iter().enumerate() {
        note.add_signature(
            witness
                .cosign(&checkpoint, 1_700_000_000 + i as u64)
                .unwrap(),
        )
        .unwrap();
    }
    let signed = note.encode().unwrap().into_bytes();
    Fixture {
        origin,
        checkpoint,
        log,
        witnesses,
        signed,
    }
}

#[test]
fn note_parser_is_canonical() {
    let (mut rng, seed) = rng(0xf001);
    let corpus = vec![
        fixture().signed,
        "text\n\nwith a blank line\n\n\u{2014} k AAAAAAE=\n\u{2014} k2 AAAAAgEC\n"
            .as_bytes()
            .to_vec(),
        "\n\n\u{2014} k AAAAAAE=\n".as_bytes().to_vec(),
    ];
    for msg in &corpus {
        let note = Note::parse(msg).unwrap();
        assert_eq!(note.encode().unwrap().as_bytes(), msg.as_slice());
    }
    let mut accepted = 0;
    for i in 0..iterations(4000) {
        let input = inputs(&mut rng, &corpus, i);
        if let Ok(note) = Note::parse(&input) {
            accepted += 1;
            assert_eq!(
                note.encode().unwrap().as_bytes(),
                input.as_slice(),
                "seed {seed}, iteration {i}: parse is not canonical for {:?}",
                String::from_utf8_lossy(&input)
            );
        }
    }
    println!(
        "note parser: {accepted} of {} mutated inputs accepted",
        iterations(4000)
    );
}

#[test]
fn checkpoint_text_parser_is_canonical() {
    let (mut rng, seed) = rng(0xf002);
    let corpus: Vec<Vec<u8>> = vec![
        fixture().checkpoint.to_text().into_bytes(),
        Checkpoint::new("a", 0, [0; 32])
            .unwrap()
            .to_text()
            .into_bytes(),
        Checkpoint::new("example.com/log", u64::MAX, [0xff; 32])
            .unwrap()
            .with_extensions(vec!["ext one".into(), "two".into()])
            .unwrap()
            .to_text()
            .into_bytes(),
    ];
    for i in 0..iterations(4000) {
        let input = inputs(&mut rng, &corpus, i);
        let Ok(text) = std::str::from_utf8(&input) else {
            continue;
        };
        if let Ok(checkpoint) = Checkpoint::parse_text(text) {
            assert_eq!(checkpoint.to_text(), text, "seed {seed}, iteration {i}");
        }
    }
}

#[test]
fn verifier_key_parser_is_canonical() {
    let (mut rng, seed) = rng(0xf003);
    let fixture = fixture();
    let corpus: Vec<Vec<u8>> = vec![
        fixture
            .log
            .verifier()
            .unwrap()
            .verifier_key()
            .to_string()
            .into_bytes(),
        fixture.witnesses[0]
            .verifier()
            .unwrap()
            .verifier_key()
            .unwrap()
            .to_string()
            .into_bytes(),
        b"PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW".to_vec(),
    ];
    for i in 0..iterations(4000) {
        let input = inputs(&mut rng, &corpus, i);
        let Ok(text) = std::str::from_utf8(&input) else {
            continue;
        };
        if let Ok(vkey) = VerifierKey::parse(text) {
            assert_eq!(vkey.to_string(), text, "seed {seed}, iteration {i}");
        }
    }
}

#[test]
fn tile_paths_round_trip_and_parse_canonically() {
    let (mut rng, seed) = rng(0xf004);
    let mut corpus = Vec::new();
    for _ in 0..iterations(2000) {
        let index = match rng.gen_range(0..4) {
            0 => rng.gen_range(0..1000),
            1 => rng.gen_range(0..10_000_000),
            2 => u64::MAX - rng.gen_range(0..1000),
            _ => rng.gen(),
        };
        let width = if rng.gen_bool(0.5) {
            256
        } else {
            rng.gen_range(1..=255)
        };
        let tile = if rng.gen_bool(0.2) {
            Tile::entries(index, width).unwrap()
        } else {
            Tile::hashes(rng.gen_range(0..=63), index, width).unwrap()
        };
        let path = tile.path();
        assert_eq!(Tile::parse_path(&path), Ok(tile), "seed {seed}: {path}");
        if let TileKind::Hashes(level) = tile.kind() {
            assert!(level <= 63);
        }
        if corpus.len() < 16 {
            corpus.push(path.into_bytes());
        }
    }
    for i in 0..iterations(4000) {
        let input = inputs(&mut rng, &corpus, i);
        let Ok(text) = std::str::from_utf8(&input) else {
            continue;
        };
        if let Ok(tile) = Tile::parse_path(text) {
            assert_eq!(tile.path(), text, "seed {seed}, iteration {i}");
        }
    }
}

#[test]
fn entry_decoder_accepts_only_v1() {
    let (mut rng, seed) = rng(0xf005);
    for i in 0..iterations(4000) {
        let entry = LogEntry::new(rng.gen(), rng.gen());
        assert_eq!(LogEntry::from_bytes(&entry.to_bytes()), Ok(entry));
        let input = if i % 2 == 0 {
            mutate(&mut rng, &entry.to_bytes())
        } else {
            random_bytes(&mut rng, 80)
        };
        let decoded = LogEntry::from_bytes(&input);
        let valid = input.len() == ENTRY_V1_LEN && input[0] == 0x01;
        assert_eq!(decoded.is_ok(), valid, "seed {seed}, iteration {i}");
        if let Ok(decoded) = decoded {
            assert_eq!(decoded.to_bytes().as_slice(), input.as_slice());
        }
    }
    let untagged = LogEntry::untagged([9; 32]);
    assert_eq!(untagged.monitor_tag, [0; 32]);
    assert_eq!(untagged.to_bytes()[0], 0x01);
    assert_eq!(&untagged.to_bytes()[1..33], &[9; 32]);
}

#[test]
fn mutated_signed_checkpoints_never_open_as_something_else() {
    let (mut rng, seed) = rng(0xf006);
    let fixture = fixture();
    let log_key = fixture.log.verifier().unwrap();
    let witnesses: Vec<WitnessVerifier> = fixture
        .witnesses
        .iter()
        .map(|w| w.verifier().unwrap().into())
        .collect();

    let opened = open_checkpoint(&fixture.signed, fixture.origin, &log_key, &witnesses).unwrap();
    assert_eq!(opened.checkpoint(), &fixture.checkpoint);
    let original = opened.cosignatures().to_vec();
    assert_eq!(original.len(), 3);
    assert_eq!(
        original.iter().map(|c| c.timestamp()).collect::<Vec<_>>(),
        vec![1_700_000_000, 1_700_000_001, 1_700_000_002]
    );

    let mut accepted = 0;
    for i in 0..iterations(600) {
        let mutated = mutate(&mut rng, &fixture.signed);
        if let Ok(opened) = open_checkpoint(&mutated, fixture.origin, &log_key, &witnesses) {
            accepted += 1;
            assert_eq!(
                opened.checkpoint(),
                &fixture.checkpoint,
                "seed {seed}, iteration {i}"
            );
            for cosignature in opened.cosignatures() {
                assert!(
                    original.contains(cosignature),
                    "seed {seed}, iteration {i}: new cosignature"
                );
            }
        }
    }
    println!(
        "signed checkpoint: {accepted} of {} mutations still opened",
        iterations(600)
    );
}

#[test]
fn open_checkpoint_rules() {
    let fixture = fixture();
    let log_key = fixture.log.verifier().unwrap();
    let witnesses: Vec<WitnessVerifier> = fixture
        .witnesses
        .iter()
        .map(|w| w.verifier().unwrap().into())
        .collect();
    let text = String::from_utf8(fixture.signed.clone()).unwrap();

    // Wrong origin.
    assert!(matches!(
        open_checkpoint(&fixture.signed, "other.example/log", &log_key, &witnesses),
        Err(CheckpointError::WrongOrigin { .. })
    ));
    // Without the log signature. Lines 0-2 are the checkpoint, line 3 is
    // blank, line 4 is the log signature and lines 5-7 are cosignatures.
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    assert_eq!(lines.len(), 8);
    let without_log = format!("{}{}", lines[..4].concat(), lines[5..].concat());
    assert_eq!(
        open_checkpoint(without_log.as_bytes(), fixture.origin, &log_key, &witnesses),
        Err(CheckpointError::MissingLogSignature)
    );
    // A repeated signature line.
    let repeated = format!("{text}{}", lines[5]);
    assert!(matches!(
        open_checkpoint(repeated.as_bytes(), fixture.origin, &log_key, &witnesses),
        Err(CheckpointError::DuplicateSignature { .. })
    ));
    // A cosignature of a different checkpoint is invalid, which rejects the
    // whole note.
    let other = Checkpoint::new(fixture.origin, 123_457, [0x5a; 32]).unwrap();
    let mut forged = fixture.checkpoint.sign(&fixture.log).unwrap();
    forged
        .add_signature(fixture.witnesses[0].cosign(&other, 5).unwrap())
        .unwrap();
    let forged = forged.encode().unwrap();
    assert!(matches!(
        open_checkpoint(forged.as_bytes(), fixture.origin, &log_key, &witnesses),
        Err(CheckpointError::Note(NoteError::InvalidSignature { .. }))
    ));
    // Unknown witnesses are ignored.
    let opened =
        open_checkpoint(&fixture.signed, fixture.origin, &log_key, &witnesses[..1]).unwrap();
    assert_eq!(opened.cosignatures().len(), 1);
    assert_eq!(opened.cosignatures()[0].name(), "witness0.example/w");
}

#[test]
fn proof_verifiers_reject_garbage_without_panicking() {
    let (mut rng, seed) = rng(0xf007);
    let special = [
        0,
        1,
        2,
        3,
        7,
        8,
        9,
        1 << 32,
        (1 << 63) - 1,
        1 << 63,
        u64::MAX - 1,
        u64::MAX,
    ];
    let pick = |rng: &mut StdRng| -> u64 {
        if rng.gen_bool(0.5) {
            special[rng.gen_range(0..special.len())]
        } else {
            let bits: u32 = rng.gen_range(1..64);
            rng.gen_range(0..(1u64 << bits))
        }
    };
    for i in 0..iterations(6000) {
        let size = pick(&mut rng);
        let index = match rng.gen_range(0..3) {
            0 => size.wrapping_sub(1),
            1 => pick(&mut rng),
            _ => rng.gen_range(0..=size.max(1) - 1),
        };
        let proof: Vec<Hash> = (0..rng.gen_range(0..=70)).map(|_| rng.gen()).collect();
        let (a, b): (Hash, Hash) = (rng.gen(), rng.gen());
        assert!(
            verify_inclusion(&a, index, size, &proof, &b).is_err(),
            "seed {seed}, iteration {i}: garbage inclusion proof accepted"
        );
        let other = pick(&mut rng);
        assert!(
            verify_consistency(size.min(other), size.max(other), &proof, &a, &b).is_err(),
            "seed {seed}, iteration {i}: garbage consistency proof accepted"
        );
    }
}
