//! ADR-014 Phase 3 acceptance, over real HTTP:
//!
//! * three operators cross-witness each other's logs, and each log
//!   publishes a checkpoint carrying a quorum of ML-DSA-44 cosignatures
//!   that verifies with the Phase 1 client;
//! * the witness answers every `c2sp.org/tlog-witness` status code the
//!   spec names, refuses an inconsistent checkpoint, and keeps the
//!   evidence pair;
//! * the standalone `ciphervault-witness` binary serves the same protocol.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::log_store::LogConfig;
use ciphervault_operator::log_witnessing::Witnessing;
use ciphervault_operator::state::OperatorSecurityConfig;
use ciphervault_operator::witness_store::{origin_hash, WitnessConfig};
use ciphervault_operator::{create_router, OperatorState};
use ciphervault_translog::checkpoint::Checkpoint;
use ciphervault_translog::note::Ed25519NoteSigner;
use ciphervault_translog::witness::{verify_cosignature_response, AddCheckpointRequest};
use ciphervault_translog::{
    consistency_proof, leaf_hash, open_checkpoint, root_from_leaf_hashes, verify_inclusion,
    Ed25519NoteVerifier, Hash, LogEntry, WitnessVerifier,
};
use ed25519_dalek::SigningKey;
use tokio::net::TcpListener;

fn fresh_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cv-twit-{tag}-{}", rand::random::<u128>()))
}

fn state(
    root: &Path,
    operator_id: &str,
    key: &SigningKey,
    log: LogConfig,
    witness: WitnessConfig,
) -> Arc<OperatorState> {
    Arc::new(OperatorState::new_with_options(
        operator_id.into(),
        root.to_path_buf(),
        key.clone(),
        OperatorSecurityConfig::from_flags(None, None),
        log,
        witness,
    ))
}

fn serve(listener: TcpListener, state: Arc<OperatorState>) {
    let app = create_router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
}

async fn get_text(url: &str) -> (u16, String) {
    let response = reqwest::get(url).await.unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

async fn post(url: &str, body: Vec<u8>) -> (u16, String, String) {
    let response = reqwest::Client::new()
        .post(url)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, content_type, response.text().await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_operators_cross_witness_to_quorum() {
    let mut listeners = Vec::new();
    for _ in 0..3 {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let addrs: Vec<SocketAddr> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
    let roots: Vec<PathBuf> = (0..3).map(|i| fresh_dir(&format!("x{i}"))).collect();
    let keys: Vec<SigningKey> = (0..3).map(|_| generate_signing_key()).collect();
    let origin = |i: usize| format!("example.com/op{i}/log");
    let witness_name = |i: usize| format!("example.com/op{i}/witness");

    // First boot creates each operator's log and witness keys; the fleet
    // exchanges the verifier keys, as `--print-log-key` and
    // `--print-witness-key` would.
    let mut log_vkeys = Vec::new();
    let mut witness_vkeys = Vec::new();
    for i in 0..3 {
        let st = state(
            &roots[i],
            &format!("op{i}"),
            &keys[i],
            LogConfig::new(Some(origin(i)), 0),
            WitnessConfig {
                enabled: true,
                name: Some(witness_name(i)),
                trusted_logs: Vec::new(),
            },
        );
        log_vkeys.push(st.transparency_log().unwrap().info().verifier_key);
        witness_vkeys.push(st.witness().unwrap().verifier_key().to_string());
    }

    // Each operator's witness trusts the other two logs, and each log
    // pushes to the other two witnesses with a quorum of 2.
    let mut nodes = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let others: Vec<usize> = (0..3).filter(|j| *j != i).collect();
        let log_config = LogConfig {
            witnesses: others
                .iter()
                .map(|j| format!("{}@http://{}/v1/witness", witness_vkeys[*j], addrs[*j]))
                .collect(),
            witness_quorum: Some(2),
            ..LogConfig::new(Some(origin(i)), 0)
        };
        let plan = log_config.witness_plan().unwrap().unwrap();
        let st = state(
            &roots[i],
            &format!("op{i}"),
            &keys[i],
            log_config,
            WitnessConfig {
                enabled: true,
                name: Some(witness_name(i)),
                trusted_logs: others.iter().map(|j| log_vkeys[*j].clone()).collect(),
            },
        );
        assert_eq!(st.witness().unwrap().verifier_key(), witness_vkeys[i]);
        serve(listener, st.clone());
        nodes.push((st, Witnessing::new(plan).unwrap()));
    }

    let witness_keys = |i: usize| -> Vec<WitnessVerifier> {
        (0..3)
            .filter(|j| *j != i)
            .map(|j| WitnessVerifier::from_vkey(&witness_vkeys[j]).unwrap())
            .collect()
    };

    for round in 0..2u8 {
        for (i, (st, witnessing)) in nodes.iter_mut().enumerate() {
            let store = st.transparency_log().unwrap();
            for k in 0..(5 + round) {
                store
                    .append(
                        "device",
                        LogEntry::untagged([i as u8 * 50 + round * 10 + k; 32]),
                    )
                    .unwrap();
            }
            let report = witnessing.round(store).await.unwrap();
            assert_eq!(report.failures, Vec::<String>::new(), "op{i} round {round}");
            assert_eq!(report.cosignatures, 2, "op{i} round {round}");
            assert!(report.published, "op{i} round {round}");
        }
    }

    for i in 0..3 {
        let (status, note) =
            get_text(&format!("http://{}/v1/log/checkpoint/witnessed", addrs[i])).await;
        assert_eq!(status, 200);
        let log_key = Ed25519NoteVerifier::from_vkey(&log_vkeys[i]).unwrap();
        let opened = open_checkpoint(note.as_bytes(), &origin(i), &log_key, &witness_keys(i))
            .expect("the witnessed checkpoint verifies with the pinned keys");
        assert_eq!(opened.checkpoint().size(), 11, "5 + 6 entries");
        let mut names: Vec<&str> = opened.cosignatures().iter().map(|c| c.name()).collect();
        names.sort();
        let mut expected: Vec<String> = (0..3).filter(|j| *j != i).map(witness_name).collect();
        expected.sort();
        assert_eq!(names, expected);

        // An inclusion proof at the witnessed size verifies against it.
        let (status, proof) = get_text(&format!(
            "http://{}/v1/log/inclusion/3?size={}",
            addrs[i],
            opened.checkpoint().size()
        ))
        .await;
        assert_eq!(status, 200);
        let proof: serde_json::Value = serde_json::from_str(&proof).unwrap();
        let path: Vec<Hash> = proof["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                hex::decode(h.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect();
        let leaf: Hash = hex::decode(proof["leaf_hash"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        verify_inclusion(&leaf, 3, 11, &path, opened.checkpoint().root()).unwrap();

        // Each witness serves the checkpoint it cosigned to monitors.
        for j in (0..3).filter(|j| *j != i) {
            let (status, note) = get_text(&format!(
                "http://{}/v1/witness/{}/checkpoint",
                addrs[j],
                origin_hash(&origin(i))
            ))
            .await;
            assert_eq!(status, 200);
            let witness = WitnessVerifier::from_vkey(&witness_vkeys[j]).unwrap();
            let opened =
                open_checkpoint(note.as_bytes(), &origin(i), &log_key, &[witness]).unwrap();
            assert_eq!(opened.checkpoint().size(), 11);
            assert_eq!(opened.cosignatures().len(), 1);
        }
    }

    // A log restarted with no witness memory relearns each witness's size
    // from a 409 and is cosigned again.
    let (st, _) = &nodes[0];
    let log_config = LogConfig {
        witnesses: vec![
            format!("{}@http://{}/v1/witness", witness_vkeys[1], addrs[1]),
            format!("{}@http://{}/v1/witness", witness_vkeys[2], addrs[2]),
        ],
        witness_quorum: Some(2),
        ..LogConfig::new(Some(origin(0)), 0)
    };
    let mut fresh = Witnessing::new(log_config.witness_plan().unwrap().unwrap()).unwrap();
    st.transparency_log()
        .unwrap()
        .append("device", LogEntry::untagged([200; 32]))
        .unwrap();
    let report = fresh.round(st.transparency_log().unwrap()).await.unwrap();
    assert_eq!(report.failures, Vec::<String>::new());
    assert_eq!((report.tree_size, report.cosignatures), (12, 2));
    assert_eq!(
        st.transparency_log().unwrap().info().witnessed_tree_size,
        Some(12)
    );

    for root in roots {
        let _ = std::fs::remove_dir_all(root);
    }
}

/// A log the tests sign checkpoints for directly.
struct TestLog {
    origin: String,
    signer: Ed25519NoteSigner,
    leaves: Vec<Hash>,
}

impl TestLog {
    fn new(origin: &str, seed: u8, leaves: Vec<Hash>) -> Self {
        Self {
            origin: origin.to_string(),
            signer: Ed25519NoteSigner::new(origin, SigningKey::from_bytes(&[seed; 32])).unwrap(),
            leaves,
        }
    }

    fn vkey(&self) -> String {
        self.signer.verifier().unwrap().verifier_key().to_string()
    }

    fn checkpoint(&self, size: usize) -> Checkpoint {
        Checkpoint::new(
            self.origin.clone(),
            size as u64,
            root_from_leaf_hashes(&self.leaves[..size]),
        )
        .unwrap()
    }

    fn signed(&self, size: usize) -> Vec<u8> {
        self.checkpoint(size)
            .sign(&self.signer)
            .unwrap()
            .encode()
            .unwrap()
            .into_bytes()
    }

    fn request(&self, old: usize, new: usize) -> Vec<u8> {
        let proof = if old == 0 || old == new {
            Vec::new()
        } else {
            consistency_proof(&self.leaves[..new], old as u64).unwrap()
        };
        AddCheckpointRequest::encode(old as u64, &proof, &self.signed(new))
    }
}

fn leaves(n: usize, salt: u8) -> Vec<Hash> {
    (0..n).map(|i| leaf_hash(&[salt, i as u8])).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn witness_status_codes_and_fork_evidence() {
    const ORIGIN: &str = "example.com/witnessed-log";
    let log = TestLog::new(ORIGIN, 1, leaves(20, 0));
    let root = fresh_dir("codes");
    let st = state(
        &root,
        "w",
        &generate_signing_key(),
        LogConfig::new(Some("example.com/w/log".into()), 0),
        WitnessConfig {
            enabled: true,
            name: Some("example.com/w/witness".into()),
            trusted_logs: vec![log.vkey()],
        },
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    serve(listener, st.clone());
    let add = format!("http://{addr}/v1/witness/add-checkpoint");

    let (status, info) = get_text(&format!("http://{addr}/v1/witness/info")).await;
    assert_eq!(status, 200);
    let info: serde_json::Value = serde_json::from_str(&info).unwrap();
    assert_eq!(info["trusted_logs"], serde_json::json!([ORIGIN]));
    let witness = WitnessVerifier::from_vkey(info["verifier_key"].as_str().unwrap()).unwrap();

    // 400: not a request.
    assert_eq!(post(&add, b"garbage".to_vec()).await.0, 400);
    // 404: a log this witness does not know.
    let stranger = TestLog::new("example.com/stranger", 2, leaves(4, 0));
    assert_eq!(post(&add, stranger.request(0, 4)).await.0, 404);
    // 403: the right origin, signed by the wrong key.
    let impostor = TestLog::new(ORIGIN, 3, log.leaves.clone());
    assert_eq!(post(&add, impostor.request(0, 4)).await.0, 403);
    // 404 before the first cosignature on the monitoring endpoint.
    let monitor = format!(
        "http://{addr}/v1/witness/{}/checkpoint",
        origin_hash(ORIGIN)
    );
    assert_eq!(get_text(&monitor).await.0, 404);

    // 200: the first checkpoint, from old size 0.
    let (status, _, body) = post(&add, log.request(0, 4)).await;
    assert_eq!(status, 200);
    let cosignatures =
        verify_cosignature_response(&log.checkpoint(4), body.as_bytes(), &witness).unwrap();
    assert_eq!(cosignatures.len(), 1);

    // 409: the client's old size is stale; the body teaches the real one.
    let (status, content_type, body) = post(&add, log.request(0, 6)).await;
    assert_eq!(status, 409);
    assert_eq!(content_type, "text/x.tlog.size");
    assert_eq!(body, "4\n");
    // 400: old size above the checkpoint size.
    let body = AddCheckpointRequest::encode(4, &[], &log.signed(3));
    assert_eq!(post(&add, body).await.0, 400);

    // 422: a fork at the witnessed size. The witness refuses it, keeps the
    // evidence pair and still serves what it witnessed.
    let fork = TestLog::new(ORIGIN, 1, leaves(20, 9));
    let (status, _, _) = post(&add, fork.request(4, 4)).await;
    assert_eq!(status, 422);
    // 422: a fork that grows, with a proof that cannot reach the witnessed root.
    assert_eq!(post(&add, fork.request(4, 9)).await.0, 422);
    let store = st.witness().unwrap();
    let evidence = store.evidence_files(ORIGIN);
    assert_eq!(evidence.len(), 2, "one file per refused signed checkpoint");
    // Files are named <size>-<root>, so the same-size fork sorts first.
    let text = std::fs::read_to_string(&evidence[0]).unwrap();
    assert!(text.contains("-- witnessed checkpoint --"));
    assert!(
        text.contains(&log.checkpoint(4).to_text()),
        "the witnessed side"
    );
    assert!(
        text.contains(&fork.checkpoint(4).to_text()),
        "the refused side"
    );
    assert_eq!(store.witnessed(ORIGIN).unwrap().size, 4);

    // 200: honest growth with a consistency proof.
    let (status, _, _) = post(&add, log.request(4, 20)).await;
    assert_eq!(status, 200);
    let (status, note) = get_text(&monitor).await;
    assert_eq!(status, 200);
    let opened = open_checkpoint(
        note.as_bytes(),
        ORIGIN,
        &log.signer.verifier().unwrap(),
        &[witness],
    )
    .unwrap();
    assert_eq!(opened.checkpoint().size(), 20);
    assert_eq!(opened.cosignatures().len(), 1);

    // An operator without a witness treats every origin as unknown.
    let plain_root = fresh_dir("plain");
    let plain = state(
        &plain_root,
        "plain",
        &generate_signing_key(),
        LogConfig::new(Some("example.com/plain/log".into()), 0),
        WitnessConfig::default(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_addr = listener.local_addr().unwrap();
    serve(listener, plain);
    let (status, _, _) = post(
        &format!("http://{plain_addr}/v1/witness/add-checkpoint"),
        log.request(0, 4),
    )
    .await;
    assert_eq!(status, 404);

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(plain_root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_witness_binary_serves_the_protocol() {
    use std::io::BufRead as _;

    const ORIGIN: &str = "example.com/standalone-log";
    let log = TestLog::new(ORIGIN, 5, leaves(8, 0));
    let root = fresh_dir("standalone");
    let binary = env!("CARGO_BIN_EXE_ciphervault-witness");

    let printed = std::process::Command::new(binary)
        .args([
            "--data-dir",
            root.to_str().unwrap(),
            "--name",
            "example.com/sw",
            "--print-key",
        ])
        .output()
        .unwrap();
    assert!(printed.status.success(), "{printed:?}");
    let printed = String::from_utf8(printed.stdout).unwrap();
    let vkey = printed
        .lines()
        .find_map(|line| line.strip_prefix("verifier_key="))
        .unwrap()
        .to_string();
    let witness = WitnessVerifier::from_vkey(&vkey).unwrap();
    assert_eq!(witness.name(), "example.com/sw");

    let mut child = std::process::Command::new(binary)
        .args([
            "--data-dir",
            root.to_str().unwrap(),
            "--name",
            "example.com/sw",
            "--listen",
            "127.0.0.1:0",
            "--trusted-log",
            &log.vkey(),
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let base = tokio::task::spawn_blocking(move || {
        std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .find_map(|line| line.strip_prefix("listening on ").map(str::to_string))
    })
    .await
    .unwrap()
    .expect("the witness prints its address");

    let add = format!("{base}/v1/witness/add-checkpoint");
    let (status, _, body) = post(&add, log.request(0, 5)).await;
    assert_eq!(status, 200);
    verify_cosignature_response(&log.checkpoint(5), body.as_bytes(), &witness).unwrap();
    let (status, _, body) = post(&add, log.request(0, 8)).await;
    assert_eq!((status, body.as_str()), (409, "5\n"));
    let (status, _, _) = post(&add, log.request(5, 8)).await;
    assert_eq!(status, 200);

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(root);
}
