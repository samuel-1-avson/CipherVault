//! Known-answer tests against published vectors. Sources and licenses are
//! listed in `tests/vectors/README.md`.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ciphervault_translog::checkpoint::{open_checkpoint, Checkpoint, CheckpointError};
use ciphervault_translog::cosignature::{self, CosignatureV1Signer, CosignatureV1Verifier};
use ciphervault_translog::note::{
    Ed25519NoteSigner, Ed25519NoteVerifier, KeyError, Note, NoteError, NoteSignature, NoteVerifier,
    VerifierKey,
};
use ciphervault_translog::tiles::{self, Tile};
use ciphervault_translog::{
    consistency_proof, empty_root, inclusion_proof, leaf_hash, node_hash, root_from_leaf_hashes,
    verify_consistency, verify_inclusion, CompactRange, Hash,
};
use common::{unhex, unhex32};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// transparency-dev/merkle testonly/constants.go (RFC 6962 / RFC 9162 tree)
// ---------------------------------------------------------------------------

const LEAF_INPUTS: [&str; 8] = [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
];

/// Root hashes of the trees of the first 0 to 8 leaf inputs.
const ROOT_HASHES: [&str; 9] = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

/// Hashes of every complete subtree of the 8-leaf tree, by level.
const NODE_HASHES: [&[&str]; 4] = [
    &[
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
        "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
        "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
        "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
    ],
    &[
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
    ],
    &[
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    ],
    &["5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"],
];

/// Compact-range states after 0 to 8 appends, as (level, index) pairs into
/// `NODE_HASHES`.
const COMPACT_TREES: [&[(usize, usize)]; 9] = [
    &[],
    &[(0, 0)],
    &[(1, 0)],
    &[(1, 0), (0, 2)],
    &[(2, 0)],
    &[(2, 0), (0, 4)],
    &[(2, 0), (1, 2)],
    &[(2, 0), (1, 2), (0, 6)],
    &[(3, 0)],
];

fn reference_leaves() -> Vec<Hash> {
    LEAF_INPUTS
        .iter()
        .map(|hex| leaf_hash(&unhex(hex)))
        .collect()
}

#[test]
fn reference_tree_roots() {
    let leaves = reference_leaves();
    assert_eq!(empty_root(), unhex32(ROOT_HASHES[0]));
    for (size, expected) in ROOT_HASHES.iter().enumerate() {
        assert_eq!(
            root_from_leaf_hashes(&leaves[..size]),
            unhex32(expected),
            "size {size}"
        );
    }
}

#[test]
fn reference_tree_node_hashes() {
    let leaves = reference_leaves();
    for (level, nodes) in NODE_HASHES.iter().enumerate() {
        let width = 1 << level;
        for (index, expected) in nodes.iter().enumerate() {
            let subtree = &leaves[index * width..(index + 1) * width];
            assert_eq!(
                root_from_leaf_hashes(subtree),
                unhex32(expected),
                "level {level} index {index}"
            );
        }
    }
}

#[test]
fn reference_tree_compact_ranges() {
    let leaves = reference_leaves();
    let mut range = CompactRange::new(0);
    for (size, expected) in COMPACT_TREES.iter().enumerate() {
        let expected: Vec<Hash> = expected
            .iter()
            .map(|&(level, index)| unhex32(NODE_HASHES[level][index]))
            .collect();
        assert_eq!(range.hashes(), expected.as_slice(), "size {size}");
        assert_eq!(
            range.root().unwrap(),
            unhex32(ROOT_HASHES[size]),
            "size {size}"
        );
        if size < leaves.len() {
            range.append(leaves[size]).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 9162 §2.1.5 worked example
// ---------------------------------------------------------------------------

#[test]
fn rfc9162_section_2_1_5_example() {
    // Leaves d0..d6; a..f and j are their leaf hashes (j is promoted).
    let d: Vec<Hash> = reference_leaves()[..7].to_vec();
    let (a, b, c, dd, e, f, j) = (d[0], d[1], d[2], d[3], d[4], d[5], d[6]);
    let g = node_hash(&a, &b);
    let h = node_hash(&c, &dd);
    let i = node_hash(&e, &f);
    let k = node_hash(&g, &h);
    let l = node_hash(&i, &j);
    let hash = node_hash(&k, &l);
    assert_eq!(root_from_leaf_hashes(&d), hash);
    assert_eq!(hash, unhex32(ROOT_HASHES[7]));

    // "The inclusion proof for d0 is [b, h, l]" and so on.
    for (index, expected) in [
        (0u64, vec![b, h, l]),
        (3, vec![c, g, l]),
        (4, vec![f, j, k]),
        (6, vec![i, k]),
    ] {
        let proof = inclusion_proof(&d, index).unwrap();
        assert_eq!(proof, expected, "inclusion of d{index}");
        verify_inclusion(&d[index as usize], index, 7, &proof, &hash).unwrap();
    }

    // The incrementally built trees: hash0 (3 leaves), hash1 = k (4),
    // hash2 (6).
    let hash0 = node_hash(&g, &c);
    let hash1 = k;
    let hash2 = node_hash(&k, &i);
    assert_eq!(root_from_leaf_hashes(&d[..3]), hash0);
    assert_eq!(root_from_leaf_hashes(&d[..4]), hash1);
    assert_eq!(root_from_leaf_hashes(&d[..6]), hash2);

    for (old_size, old_root, expected) in [
        (3u64, hash0, vec![c, dd, g, l]),
        (4, hash1, vec![l]),
        (6, hash2, vec![i, j, k]),
    ] {
        let proof = consistency_proof(&d, old_size).unwrap();
        assert_eq!(proof, expected, "PROOF({old_size}, D[7])");
        verify_consistency(old_size, 7, &proof, &old_root, &hash).unwrap();
    }
}

// ---------------------------------------------------------------------------
// transparency-dev/merkle proof probes
// ---------------------------------------------------------------------------

const PROBES: &str = include_str!("vectors/transparency-dev-merkle-proofs.txt");
const PROBES_SHA256: &str = "01ad75f38e97f864e532d6eb21621b15de9125365c9708fa468b633d2518bdc6";

enum ProbeKind {
    Inclusion { index: u64, size: u64 },
    Consistency { size1: u64, size2: u64 },
}

struct Probe {
    name: String,
    kind: ProbeKind,
    hash1: Vec<u8>,
    hash2: Vec<u8>,
    proof: Vec<Vec<u8>>,
    want_ok: bool,
}

fn decode_field(field: &str) -> Vec<u8> {
    let encoded = field.strip_prefix("b:").expect("field starts with b:");
    STANDARD.decode(encoded).expect("probe field is base64")
}

fn parse_probes() -> Vec<Probe> {
    PROBES
        .replace("\r\n", "\n")
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            assert_eq!(fields.len(), 8, "probe line {line:?}");
            let first: u64 = fields[2].parse().expect("number");
            let second: u64 = fields[3].parse().expect("number");
            let kind = match fields[0] {
                "I" => ProbeKind::Inclusion {
                    index: first,
                    size: second,
                },
                "C" => ProbeKind::Consistency {
                    size1: first,
                    size2: second,
                },
                other => panic!("unknown probe kind {other}"),
            };
            let proof_field = fields[6]
                .strip_prefix('[')
                .and_then(|p| p.strip_suffix(']'))
                .expect("bracketed proof");
            let proof = if proof_field.is_empty() {
                Vec::new()
            } else {
                proof_field.split(',').map(decode_field).collect()
            };
            Probe {
                name: fields[1].to_owned(),
                kind,
                hash1: decode_field(fields[4]),
                hash2: decode_field(fields[5]),
                proof,
                want_ok: match fields[7] {
                    "ok" => true,
                    "err" => false,
                    other => panic!("unknown expectation {other}"),
                },
            }
        })
        .collect()
}

/// A probe value as a hash, or `None` when it is not 32 bytes.
fn as_hash(bytes: &[u8]) -> Option<Hash> {
    bytes.try_into().ok()
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Accepted,
    Rejected,
    /// A root, leaf or proof value is not 32 bytes. This API only takes
    /// 32-byte hashes, so a caller must reject such input while decoding.
    NotAHash,
}

fn run_probe(probe: &Probe) -> Outcome {
    let (Some(hash1), Some(hash2)) = (as_hash(&probe.hash1), as_hash(&probe.hash2)) else {
        return Outcome::NotAHash;
    };
    let Some(proof) = probe
        .proof
        .iter()
        .map(|p| as_hash(p))
        .collect::<Option<Vec<Hash>>>()
    else {
        return Outcome::NotAHash;
    };
    let ok = match probe.kind {
        // Inclusion probes store the root first and the leaf hash second.
        ProbeKind::Inclusion { index, size } => {
            verify_inclusion(&hash2, index, size, &proof, &hash1).is_ok()
        }
        ProbeKind::Consistency { size1, size2 } => {
            verify_consistency(size1, size2, &proof, &hash1, &hash2).is_ok()
        }
    };
    if ok {
        Outcome::Accepted
    } else {
        Outcome::Rejected
    }
}

/// The one probe whose expected result this crate deliberately does not
/// reproduce: it expects two equal 12-byte "roots" of equal-size trees to
/// verify. The Go reference compares byte strings of any length; this
/// crate's verifiers only take 32-byte hashes, so such input is rejected
/// before verification. The 32-byte equivalent is checked in
/// `equal_sizes_need_equal_roots_and_an_empty_proof`.
const STRICTER_THAN_REFERENCE: &[&str] =
    &["consistency/additional/sizes-are-equal-one-and-proof-is-empty"];

#[test]
fn probe_file_is_intact() {
    let normalized = PROBES.replace("\r\n", "\n");
    let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
    assert_eq!(digest, PROBES_SHA256, "vendored probe file changed");
    assert_eq!(normalized.lines().count(), 196);
}

#[test]
fn transparency_dev_probes() {
    let probes = parse_probes();
    assert_eq!(probes.len(), 196);
    let mut failures = Vec::new();
    let mut stricter = Vec::new();
    for probe in &probes {
        let outcome = run_probe(probe);
        let matches = match outcome {
            Outcome::Accepted => probe.want_ok,
            Outcome::Rejected | Outcome::NotAHash => !probe.want_ok,
        };
        if matches {
            continue;
        }
        if outcome == Outcome::NotAHash && probe.want_ok {
            stricter.push(probe.name.as_str());
        } else {
            failures.push(format!(
                "{} (want {}, got {outcome:?})",
                probe.name,
                if probe.want_ok { "ok" } else { "err" }
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} probes failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(stricter, STRICTER_THAN_REFERENCE);
    // 12 probes are valid proofs; the other 184 are mutations or invalid
    // inputs that must fail.
    assert_eq!(probes.iter().filter(|p| p.want_ok).count(), 12);
}

#[test]
fn equal_sizes_need_equal_roots_and_an_empty_proof() {
    let root = [7u8; 32];
    verify_consistency(1, 1, &[], &root, &root).unwrap();
    verify_consistency(9, 9, &[], &root, &root).unwrap();
    assert!(verify_consistency(1, 1, &[], &root, &[8; 32]).is_err());
    assert!(verify_consistency(1, 1, &[root], &root, &root).is_err());
    assert!(verify_consistency(0, 0, &[], &empty_root(), &empty_root()).is_err());
}

#[test]
fn generated_proofs_match_happy_path_probes() {
    let leaves = reference_leaves();
    let mut compared = 0;
    for probe in parse_probes().iter().filter(|p| p.want_ok) {
        match probe.kind {
            ProbeKind::Inclusion { index, size } => {
                let size = size as usize;
                if size > leaves.len() || probe.hash2 != leaves[index as usize] {
                    continue; // not a probe over the reference tree
                }
                let generated = inclusion_proof(&leaves[..size], index).unwrap();
                assert_eq!(generated.concat(), probe.proof.concat(), "{}", probe.name);
                assert_eq!(root_from_leaf_hashes(&leaves[..size]).to_vec(), probe.hash1);
                compared += 1;
            }
            ProbeKind::Consistency { size1, size2 } => {
                let size2 = size2 as usize;
                if size2 > leaves.len()
                    || probe.hash1 != root_from_leaf_hashes(&leaves[..size1 as usize])
                {
                    continue;
                }
                let generated = consistency_proof(&leaves[..size2], size1).unwrap();
                assert_eq!(generated.concat(), probe.proof.concat(), "{}", probe.name);
                assert_eq!(
                    root_from_leaf_hashes(&leaves[..size2]).to_vec(),
                    probe.hash2
                );
                compared += 1;
            }
        }
    }
    // Five inclusion and five consistency happy paths use the reference
    // tree.
    assert_eq!(compared, 10);
}

// ---------------------------------------------------------------------------
// c2sp.org/signed-note@v1.1.0
// ---------------------------------------------------------------------------

const C2SP_VKEY: &str = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
const C2SP_NOTE: &str = "This is an example message.\n\n\u{2014} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";

#[test]
fn c2sp_signed_note_example() {
    let verifier = Ed25519NoteVerifier::from_vkey(C2SP_VKEY).unwrap();
    assert_eq!(verifier.key_id(), 0x530d_903a);
    assert_eq!(verifier.verifier_key().to_string(), C2SP_VKEY);

    let note = Note::parse(C2SP_NOTE.as_bytes()).unwrap();
    let verified = note.verify(&[&verifier]).unwrap();
    assert_eq!(verified.text(), "This is an example message.\n");
    assert_eq!(verified.verified().len(), 1);
    assert_eq!(note.encode().unwrap(), C2SP_NOTE);

    let tampered = C2SP_NOTE.replacen("example message", "example massage", 1);
    let err = Note::parse(tampered.as_bytes())
        .unwrap()
        .verify(&[&verifier])
        .unwrap_err();
    assert!(matches!(err, NoteError::InvalidSignature { .. }), "{err:?}");
}

// ---------------------------------------------------------------------------
// c2sp.org/tlog-checkpoint@v1.1.0 and c2sp.org/tlog-cosignature@v1.1.0
// ---------------------------------------------------------------------------

const C2SP_CHECKPOINT_TEXT: &str =
    "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
const C2SP_CHECKPOINT_SIG: &str = "\u{2014} example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n";

#[test]
fn c2sp_checkpoint_example() {
    let checkpoint = Checkpoint::parse_text(C2SP_CHECKPOINT_TEXT).unwrap();
    assert_eq!(checkpoint.origin(), "example.com/behind-the-sofa");
    assert_eq!(checkpoint.size(), 20_852_163);
    assert_eq!(
        checkpoint.root().to_vec(),
        STANDARD
            .decode("CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=")
            .unwrap()
    );
    assert!(checkpoint.extensions().is_empty());
    assert_eq!(checkpoint.to_text(), C2SP_CHECKPOINT_TEXT);

    // The signed example parses as a note with one Ed25519 signature. The
    // spec does not publish the log's key, so it cannot be verified here,
    // and an unrelated key must not open it.
    let signed = format!("{C2SP_CHECKPOINT_TEXT}\n{C2SP_CHECKPOINT_SIG}");
    let note = Note::parse(signed.as_bytes()).unwrap();
    assert_eq!(note.text(), C2SP_CHECKPOINT_TEXT);
    assert_eq!(note.signatures().len(), 1);
    assert_eq!(note.signatures()[0].name(), "example.com/behind-the-sofa");
    assert_eq!(note.signatures()[0].signature().len(), 64);
    assert_eq!(note.encode().unwrap(), signed);

    let other = Ed25519NoteSigner::new(
        "example.com/behind-the-sofa",
        SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap()
    .verifier()
    .unwrap();
    let err = open_checkpoint(
        signed.as_bytes(),
        "example.com/behind-the-sofa",
        &other,
        &[],
    )
    .unwrap_err();
    assert_eq!(err, CheckpointError::MissingLogSignature);
}

#[test]
fn c2sp_cosignature_signed_message_example() {
    // The spec's example signature input for a cosignature at 1679315147.
    let expected = "cosignature/v1\ntime 1679315147\nexample.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
    let checkpoint = Checkpoint::parse_text(C2SP_CHECKPOINT_TEXT).unwrap();
    assert_eq!(
        cosignature::signed_message(&checkpoint, 1_679_315_147),
        expected.as_bytes()
    );

    // Extension lines are signed too, after the root line.
    let extended = checkpoint
        .with_extensions(vec!["ext-a".into(), "ext-b".into()])
        .unwrap();
    assert_eq!(
        cosignature::signed_message(&extended, 7),
        format!("cosignature/v1\ntime 7\n{C2SP_CHECKPOINT_TEXT}ext-a\next-b\n").into_bytes()
    );
}

#[test]
fn cosignature_round_trip_with_deterministic_key() {
    let signer =
        CosignatureV1Signer::new("witness.example/w1", SigningKey::from_bytes(&[42; 32])).unwrap();
    let verifier = signer.verifier().unwrap();
    // Key ID is SHA-256(name || 0x0A || 0x04 || key)[:4].
    let mut id_input = b"witness.example/w1\n\x04".to_vec();
    id_input.extend_from_slice(verifier.public_key().as_bytes());
    let digest = Sha256::digest(&id_input);
    assert_eq!(
        signer.key_id(),
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
    );
    assert_eq!(verifier.verifier_key().unwrap().sig_type(), 0x04);

    let checkpoint = Checkpoint::parse_text(C2SP_CHECKPOINT_TEXT).unwrap();
    let cosig = signer.cosign(&checkpoint, 1_679_315_147).unwrap();
    assert_eq!(cosig.signature().len(), 72);
    assert_eq!(&cosig.signature()[..8], &1_679_315_147u64.to_be_bytes());
    // Ed25519 is deterministic, so cosigning again gives the same bytes.
    assert_eq!(signer.cosign(&checkpoint, 1_679_315_147).unwrap(), cosig);
    assert_eq!(
        verifier.verify_cosignature(&checkpoint, cosig.signature()),
        Some(1_679_315_147)
    );
    assert!(verifier.verify(C2SP_CHECKPOINT_TEXT.as_bytes(), cosig.signature()));

    // The timestamp is signed: changing it breaks the signature.
    let mut retimed = cosig.signature().to_vec();
    retimed[7] ^= 1;
    assert_eq!(verifier.verify_cosignature(&checkpoint, &retimed), None);
    // A plain Ed25519 signature of the checkpoint text is not a cosignature.
    assert!(!verifier.verify(C2SP_CHECKPOINT_TEXT.as_bytes(), &cosig.signature()[8..]));
    // A cosignature only covers checkpoints.
    assert!(!verifier.verify(b"not a checkpoint\n", cosig.signature()));
    // Timestamps above 2^63 - 1 are refused on both sides.
    assert_eq!(
        signer.cosign(&checkpoint, 1 << 63),
        Err(NoteError::TimestampOutOfRange)
    );
    let mut huge = cosig.signature().to_vec();
    huge[..8].copy_from_slice(&(1u64 << 63).to_be_bytes());
    assert_eq!(verifier.verify_cosignature(&checkpoint, &huge), None);
}

// ---------------------------------------------------------------------------
// golang.org/x/mod sumdb/note/note_test.go
// ---------------------------------------------------------------------------

const PETER_SKEY: &str =
    "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz";
const PETER_VKEY: &str = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
const ENOCH_VKEY: &str = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop";
const GO_TEXT: &str = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n";
const PETER_SIG: &str = "\u{2014} PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
const ENOCH_SIG: &str = "\u{2014} EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n";

/// The Ed25519 seed of a Go `PRIVATE+KEY+<name>+<id>+<base64(0x01 || seed)>`
/// signer key. That format is Go-specific, so only the tests read it.
fn go_signer(skey: &str) -> Ed25519NoteSigner {
    let rest = skey.strip_prefix("PRIVATE+KEY+").unwrap();
    let mut parts = rest.splitn(3, '+');
    let (name, _id, encoded) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let raw = STANDARD.decode(encoded).unwrap();
    assert_eq!(raw[0], 0x01);
    let seed: [u8; 32] = raw[1..].try_into().unwrap();
    Ed25519NoteSigner::new(name, SigningKey::from_bytes(&seed)).unwrap()
}

#[test]
fn go_note_sign_known_answer() {
    let signer = go_signer(PETER_SKEY);
    // The verifier derived from the private key is the published vkey.
    assert_eq!(
        signer.verifier().unwrap().verifier_key().to_string(),
        PETER_VKEY
    );

    let mut note = Note::new(GO_TEXT).unwrap();
    note.sign(&signer).unwrap();
    assert_eq!(note.encode().unwrap(), format!("{GO_TEXT}\n{PETER_SIG}"));

    // Note text must end in a newline.
    assert!(matches!(Note::new("abc"), Err(NoteError::Malformed(_))));
    // Key names may not contain '+' or spaces.
    assert_eq!(
        NoteSignature::new("a+b", 1, vec![1]),
        Err(NoteError::InvalidKeyName)
    );
}

#[test]
fn go_note_open_vectors() {
    let peter = Ed25519NoteVerifier::from_vkey(PETER_VKEY).unwrap();
    let enoch = Ed25519NoteVerifier::from_vkey(ENOCH_VKEY).unwrap();
    let both = format!("{GO_TEXT}\n{PETER_SIG}{ENOCH_SIG}");

    // One verified, one unverified.
    let opened = Note::parse(both.as_bytes())
        .unwrap()
        .verify(&[&peter])
        .unwrap();
    assert_eq!(opened.text(), GO_TEXT);
    assert_eq!(opened.verified().len(), 1);
    assert_eq!(opened.verified()[0].name(), "PeterNeumann");
    assert_eq!(opened.verified()[0].key_id(), 0xc74f_20a3);
    assert_eq!(opened.unverified().len(), 1);
    assert_eq!(opened.unverified()[0].name(), "EnochRoot");
    assert_eq!(opened.unverified()[0].key_id(), 0xaf0c_fe78);

    // Both verified.
    let opened = Note::parse(both.as_bytes())
        .unwrap()
        .verify(&[&peter, &enoch])
        .unwrap();
    assert_eq!(opened.verified().len(), 2);
    assert!(opened.unverified().is_empty());

    // No known key.
    let err = Note::parse(both.as_bytes())
        .unwrap()
        .verify(&[])
        .unwrap_err();
    assert_eq!(err, NoteError::NoVerifiedSignature);

    // The same verifier twice is ambiguous.
    let err = Note::parse(both.as_bytes())
        .unwrap()
        .verify(&[&enoch, &peter, &enoch])
        .unwrap_err();
    assert!(
        matches!(err, NoteError::AmbiguousVerifier { .. }),
        "{err:?}"
    );

    // More than 100 signatures.
    let many = format!("{GO_TEXT}\n{}", PETER_SIG.repeat(101));
    assert_eq!(
        Note::parse(many.as_bytes()),
        Err(NoteError::TooManySignatures)
    );

    // A corrupted signature from a known key rejects the note.
    let corrupt = format!("{GO_TEXT}\n{}ABCD{}", &PETER_SIG[..60], &PETER_SIG[60..]);
    let err = Note::parse(corrupt.as_bytes())
        .unwrap()
        .verify(&[&peter])
        .unwrap_err();
    assert!(matches!(err, NoteError::InvalidSignature { .. }), "{err:?}");

    // Repeated signatures are reported once; a corrupted signature from an
    // unknown key is just unverified.
    let repeated = format!(
        "{GO_TEXT}\n{PETER_SIG}{PETER_SIG}{ENOCH_SIG}{ENOCH_SIG}{}ABCD{}",
        &ENOCH_SIG[..60],
        &ENOCH_SIG[60..]
    );
    let opened = Note::parse(repeated.as_bytes())
        .unwrap()
        .verify(&[&peter])
        .unwrap();
    assert_eq!(opened.verified().len(), 1);
    assert_eq!(opened.unverified().len(), 2);
}

#[test]
fn go_note_rejects_malformed() {
    let peter = Ed25519NoteVerifier::from_vkey(PETER_VKEY).unwrap();
    let bad: Vec<Vec<u8>> = vec![
        GO_TEXT.into(),
        format!("{GO_TEXT}\n").into(),
        format!("{GO_TEXT}\n{}", &PETER_SIG[..PETER_SIG.len() - 1]).into(),
        [b"\x01".as_slice(), GO_TEXT.as_bytes(), b"\n", PETER_SIG.as_bytes()].concat(),
        [b"\xff".as_slice(), GO_TEXT.as_bytes(), b"\n", PETER_SIG.as_bytes()].concat(),
        format!("{GO_TEXT}\n\u{2014} Bad Name x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=").into(),
        format!("{GO_TEXT}\n{PETER_SIG}Unexpected line.\n").into(),
    ];
    for msg in bad {
        let result = Note::parse(&msg).and_then(|note| note.verify(&[&peter]));
        assert!(
            result.is_err(),
            "accepted {:?}",
            String::from_utf8_lossy(&msg)
        );
    }
}

#[test]
fn go_vkey_manglings_are_rejected() {
    Ed25519NoteVerifier::from_vkey(PETER_VKEY).unwrap();
    let bytes = PETER_VKEY.as_bytes();
    for i in 0..=bytes.len() {
        for j in i + 1..=bytes.len() {
            if i == 0 && j == bytes.len() {
                continue;
            }
            let sub = &PETER_VKEY[i..j];
            assert!(
                Ed25519NoteVerifier::from_vkey(sub).is_err(),
                "accepted substring {sub:?}"
            );
        }
    }
    for i in 0..bytes.len() {
        let mut mangled = bytes.to_vec();
        mangled[i] += 1;
        let mangled = String::from_utf8(mangled).unwrap();
        assert!(
            Ed25519NoteVerifier::from_vkey(&mangled).is_err(),
            "accepted {mangled:?}"
        );
    }
    // Wrong key length and unknown algorithm, each with a matching key ID.
    // (The first is also non-canonical base64, which Go's lenient decoder
    // accepts and the C2SP spec does not.)
    let wrong_length = "PeterNeumann+cc469956+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TWBADKEY==";
    assert!(Ed25519NoteVerifier::from_vkey(wrong_length).is_err());
    let unknown_type = "PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
    assert_eq!(
        Ed25519NoteVerifier::from_vkey(unknown_type),
        Err(KeyError::UnsupportedType(0x65))
    );
}

// ---------------------------------------------------------------------------
// transparency-dev/formats note/note_cosigv1_test.go
// ---------------------------------------------------------------------------

#[test]
fn formats_verifier_keys() {
    // An Ed25519 note key and an Ed25519 cosignature key.
    let ed = Ed25519NoteVerifier::from_vkey(
        "TEST+7997405c+AQcC+FTVKf0jlTdHDY3rbevmnKxxPjigCXlVtGe6RIr6",
    )
    .unwrap();
    assert_eq!(ed.key_id(), 0x7997_405c);
    let cosigner = CosignatureV1Verifier::from_vkey(
        "remora.n621.de+da77ade7+BOvN63jn/bLvkieywe8R6UYAtVtNbZpXh34x7onlmtw2",
    )
    .unwrap();
    assert_eq!(cosigner.key_id(), 0xda77_ade7);
    assert_eq!(
        cosigner.verifier_key().unwrap().to_string(),
        "remora.n621.de+da77ade7+BOvN63jn/bLvkieywe8R6UYAtVtNbZpXh34x7onlmtw2"
    );
    // A key of one type is not accepted as the other.
    assert_eq!(
        CosignatureV1Verifier::from_vkey(
            "TEST+7997405c+AQcC+FTVKf0jlTdHDY3rbevmnKxxPjigCXlVtGe6RIr6"
        ),
        Err(KeyError::UnsupportedType(0x01))
    );

    for bad in [
        "bananas.sigstore.dev+12344556",
        "rekor.sigstore.dev+12345678+THIS_IS_NOT_BASE64!",
        "rekor.sigstore.dev+12345678+AwEB",
    ] {
        assert!(VerifierKey::parse(bad).is_err(), "accepted {bad:?}");
    }
    // The key ID must be lowercase hex and match the key.
    assert!(
        VerifierKey::parse("TEST+7997405C+AQcC+FTVKf0jlTdHDY3rbevmnKxxPjigCXlVtGe6RIr6").is_err()
    );
    assert!(matches!(
        VerifierKey::parse("TEST+00000000+AQcC+FTVKf0jlTdHDY3rbevmnKxxPjigCXlVtGe6RIr6"),
        Err(KeyError::KeyIdMismatch { .. })
    ));
}

#[test]
fn formats_cosignature_timestamp() {
    let raw = STANDARD
        .decode("ZGhGuQAAAABm/qTPeyKXD+R2rzyQsxPiP8mXum7qq/iF0u4vanlqJyocWODBt97w9uL+8qT7S5gxEHWWOworDcFiEBYJXORmnFBOBA==")
        .unwrap();
    let key_id = u32::from_be_bytes(raw[..4].try_into().unwrap());
    let sig = NoteSignature::new("witness", key_id, raw[4..].to_vec()).unwrap();
    assert_eq!(
        cosignature::cosignature_timestamp(&sig),
        Some(1_727_964_367)
    );

    // A plain Ed25519 note signature and an 80-byte blob are not
    // cosignatures.
    for not_cosig in [
        STANDARD
            .decode("eQjRQm6eSKzFoiYalgwCPXu2y3ijtg68is9M46JKxuZB+dRfTmeQeDBoXnvxZx2ugnkyV+MUMLXpWs1hPb/W/4xkNQY=")
            .unwrap(),
        vec![0u8; 80],
    ] {
        let sig = NoteSignature::new("witness", 1, not_cosig[4..].to_vec()).unwrap();
        assert_eq!(cosignature::cosignature_timestamp(&sig), None);
    }
}

// ---------------------------------------------------------------------------
// c2sp.org/tlog-tiles@v1.0.0
// ---------------------------------------------------------------------------

#[test]
fn tlog_tiles_examples() {
    assert_eq!(tiles::encode_index(1_234_067), "x001/x234/067");
    assert_eq!(tiles::encode_index(0), "000");
    assert_eq!(tiles::encode_index(999), "999");
    assert_eq!(tiles::encode_index(1000), "x001/000");
    assert_eq!(
        tiles::encode_index(u64::MAX),
        "x018/x446/x744/x073/x709/x551/615"
    );

    // "a tree of size 70,000 will be represented by 273 full level 0 tiles,
    // one partial level 0 tile of width 112, one full level 1 tile, one
    // partial level 1 tile of width 17, and one partial level 2 tile of
    // width 1."
    let counts: Vec<(u64, u16)> = (0..4)
        .map(|level| {
            (
                tiles::full_tile_count(level, 70_000),
                tiles::partial_tile_width(level, 70_000),
            )
        })
        .collect();
    assert_eq!(counts, vec![(273, 112), (1, 17), (0, 1), (0, 0)]);
    // "a tree of size 256 will be represented by a full level 0 tile and a
    // partial level 1 tile of width 1."
    assert_eq!(
        (
            tiles::full_tile_count(0, 256),
            tiles::partial_tile_width(0, 256)
        ),
        (1, 0)
    );
    assert_eq!(
        (
            tiles::full_tile_count(1, 256),
            tiles::partial_tile_width(1, 256)
        ),
        (0, 1)
    );
    // Levels past the size of a u64 hold nothing.
    assert_eq!(tiles::full_tile_count(63, u64::MAX), 0);
    assert_eq!(tiles::partial_tile_width(7, u64::MAX), 0xff);
    assert_eq!(tiles::partial_tile_width(8, u64::MAX), 0);

    let full = Tile::hashes(0, 1_234_067, 256).unwrap();
    assert_eq!(full.path(), "tile/0/x001/x234/067");
    let partial = Tile::hashes(1, 1_234_067, 8).unwrap();
    assert_eq!(partial.path(), "tile/1/x001/x234/067.p/8");
    let bundle = Tile::entries(1_234_067, 255).unwrap();
    assert_eq!(bundle.path(), "tile/entries/x001/x234/067.p/255");
    for tile in [full, partial, bundle] {
        assert_eq!(Tile::parse_path(&tile.path()), Ok(tile));
    }
    assert_eq!(Tile::hashes(63, 0, 1).unwrap().path(), "tile/63/000.p/1");
    assert!(Tile::hashes(64, 0, 256).is_err());
    assert!(Tile::hashes(0, 0, 0).is_err());
    assert!(Tile::hashes(0, 0, 257).is_err());
}
