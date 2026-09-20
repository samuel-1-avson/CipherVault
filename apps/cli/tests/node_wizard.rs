//! End-to-end cover for the beginner node wizard: non-interactive setup,
//! background start, plain-language status, and stop. Uses a scratch data
//! dir and a high test port; a Drop guard stops the node even on failure.

use std::path::PathBuf;
use std::process::Command;

const TEST_PORT: u16 = 18511;
const STALE_PID_PORT: u16 = 18512;
const FOREIGN_PORT: u16 = 18513;
const FOREIGN_OTHER_PORT: u16 = 18514;
const BACKUP_PORT: u16 = 18515;
const PORTCLASH_PORT: u16 = 18516;
const P2P_A_PORT: u16 = 18525;
const P2P_B_PORT: u16 = 18526;

/// Extracts the `Peer ID:` value from `node p2p-info` output.
fn parse_peer_id(output: &str) -> String {
    output
        .lines()
        .find(|line| line.contains("Peer ID:"))
        .and_then(|line| line.split_whitespace().last().map(str::to_string))
        .expect("p2p-info prints a peer id")
}

/// Extracts the first TCP shareable address from `node p2p-info` output.
fn parse_tcp_bootstrap(output: &str) -> String {
    output
        .lines()
        .map(str::trim)
        .find(|line| line.contains("/tcp/") && line.contains("/p2p/"))
        .expect("p2p-info prints a TCP bootstrap address")
        .to_string()
}

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
}

fn scratch_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cv-node-wizard-{}-{}-{}",
        tag,
        std::process::id(),
        rand::random::<u16>()
    ))
}

struct StopOnDrop {
    dir: PathBuf,
}

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ = Command::new(bin())
            .args(["node", "stop", "--data-dir", &self.dir.to_string_lossy()])
            .output();
    }
}

#[test]
fn node_setup_start_status_stop_cycle() {
    let dir = scratch_dir("cycle");
    let guard = StopOnDrop { dir: dir.clone() };

    let setup = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "wizard-test-node",
            "--data-dir",
            &dir.to_string_lossy(),
            "--port",
            &TEST_PORT.to_string(),
            "--no-start",
        ])
        .output()
        .expect("run node setup");
    assert!(
        setup.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&setup.stderr)
    );
    assert!(dir.join("node.json").is_file());
    assert!(dir.join("operator.key").is_file());
    let token = std::fs::read_to_string(dir.join("service.token")).unwrap();
    assert_eq!(token.trim().len(), 64);

    let start = Command::new(bin())
        .args(["node", "start", "--data-dir", &dir.to_string_lossy()])
        .output()
        .expect("run node start");
    assert!(
        start.status.success(),
        "start failed: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    assert!(dir.join("node.pid").is_file());

    let status = Command::new(bin())
        .args(["node", "status", "--data-dir", &dir.to_string_lossy()])
        .output()
        .expect("run node status");
    assert!(status.status.success());
    let status_text = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_text.contains("running and healthy"),
        "plain-language status: {status_text}"
    );

    let stop = Command::new(bin())
        .args(["node", "stop", "--data-dir", &dir.to_string_lossy()])
        .output()
        .expect("run node stop");
    assert!(
        stop.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(!dir.join("node.pid").exists());

    let down = Command::new(bin())
        .args(["node", "status", "--data-dir", &dir.to_string_lossy()])
        .output()
        .expect("run node status while down");
    assert!(!down.status.success());

    drop(guard);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn stop_with_stale_pid_file_harms_nothing() {
    let dir = scratch_dir("stalepid");
    let setup = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "stale-pid-node",
            "--data-dir",
            &dir.to_string_lossy(),
            "--port",
            &STALE_PID_PORT.to_string(),
            "--no-start",
        ])
        .output()
        .expect("run node setup");
    assert!(
        setup.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&setup.stderr)
    );
    // Simulate PID reuse: a live-looking PID that is not our daemon.
    std::fs::write(dir.join("node.pid"), "999999").unwrap();
    let stop = Command::new(bin())
        .args(["node", "stop", "--data-dir", &dir.to_string_lossy()])
        .output()
        .expect("run node stop");
    assert!(
        stop.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    assert!(
        String::from_utf8_lossy(&stop.stdout).contains("no longer your node"),
        "expected stale-pid notice: {}",
        String::from_utf8_lossy(&stop.stdout)
    );
    assert!(!dir.join("node.pid").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn start_refuses_foreign_node_on_port() {
    let dir_a = scratch_dir("foreign-a");
    let guard_a = StopOnDrop { dir: dir_a.clone() };
    let setup_a = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "foreign-node-a",
            "--data-dir",
            &dir_a.to_string_lossy(),
            "--port",
            &FOREIGN_PORT.to_string(),
        ])
        .output()
        .expect("run node setup A");
    assert!(
        setup_a.status.success(),
        "setup A failed: {}",
        String::from_utf8_lossy(&setup_a.stderr)
    );

    let dir_b = scratch_dir("foreign-b");
    let setup_b = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "foreign-node-b",
            "--data-dir",
            &dir_b.to_string_lossy(),
            "--port",
            &FOREIGN_OTHER_PORT.to_string(),
            "--no-start",
        ])
        .output()
        .expect("run node setup B");
    assert!(
        setup_b.status.success(),
        "setup B failed: {}",
        String::from_utf8_lossy(&setup_b.stderr)
    );
    // Point B at A's live port behind setup's back (setup itself would refuse).
    let config = std::fs::read_to_string(dir_b.join("node.json")).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&config).unwrap();
    value["port"] = serde_json::json!(FOREIGN_PORT);
    std::fs::write(dir_b.join("node.json"), value.to_string()).unwrap();

    let start_b = Command::new(bin())
        .args(["node", "start", "--data-dir", &dir_b.to_string_lossy()])
        .output()
        .expect("run node start B");
    assert!(
        !start_b.status.success(),
        "start B should refuse a foreign node"
    );
    assert!(
        String::from_utf8_lossy(&start_b.stderr).contains("different node"),
        "expected foreign-node refusal: {}",
        String::from_utf8_lossy(&start_b.stderr)
    );

    drop(guard_a);
    std::fs::remove_dir_all(&dir_a).unwrap();
    std::fs::remove_dir_all(&dir_b).unwrap();
}

#[test]
fn setup_rejects_occupied_port() {
    let dir_a = scratch_dir("portclash-a");
    let guard_a = StopOnDrop { dir: dir_a.clone() };
    let setup_a = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "portclash-node-a",
            "--data-dir",
            &dir_a.to_string_lossy(),
            "--port",
            &PORTCLASH_PORT.to_string(),
        ])
        .output()
        .expect("run node setup A");
    assert!(
        setup_a.status.success(),
        "setup A failed: {}",
        String::from_utf8_lossy(&setup_a.stderr)
    );

    let dir_b = scratch_dir("portclash-b");
    let setup_b = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "portclash-node-b",
            "--data-dir",
            &dir_b.to_string_lossy(),
            "--port",
            &PORTCLASH_PORT.to_string(),
            "--no-start",
        ])
        .output()
        .expect("run node setup B");
    assert!(
        !setup_b.status.success(),
        "setup B should refuse an occupied port"
    );
    assert!(
        String::from_utf8_lossy(&setup_b.stderr).contains("already in use"),
        "expected port-in-use refusal: {}",
        String::from_utf8_lossy(&setup_b.stderr)
    );

    drop(guard_a);
    std::fs::remove_dir_all(&dir_a).unwrap();
    // Refusal happens before any write: no half-made node folder is left behind.
    assert!(!dir_b.exists());
}

#[test]
fn two_wizard_nodes_peer_over_p2p() {
    // Seed boots first with P2P and no bootstrap; the joiner bootstraps
    // to the seed's advertised address. Committed signal: the wizard P2P
    // path end to end (flags plumbed, swarm booted, endpoint serving).
    // Live mesh proof (probe-peer RPC) is the drill script's job.
    let dir_a = scratch_dir("p2p-a");
    let guard_a = StopOnDrop { dir: dir_a.clone() };
    let setup_a = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "p2p-node-a",
            "--data-dir",
            &dir_a.to_string_lossy(),
            "--port",
            &P2P_A_PORT.to_string(),
            "--p2p",
        ])
        .output()
        .expect("run node setup A");
    assert!(
        setup_a.status.success(),
        "setup A failed: {}",
        String::from_utf8_lossy(&setup_a.stderr)
    );
    let info_a = Command::new(bin())
        .args(["node", "p2p-info", "--data-dir", &dir_a.to_string_lossy()])
        .output()
        .expect("run p2p-info A");
    assert!(
        info_a.status.success(),
        "p2p-info A failed: {}",
        String::from_utf8_lossy(&info_a.stderr)
    );
    let text_a = String::from_utf8_lossy(&info_a.stdout).into_owned();
    let peer_a = parse_peer_id(&text_a);
    let bootstrap_a = parse_tcp_bootstrap(&text_a);

    let dir_b = scratch_dir("p2p-b");
    let guard_b = StopOnDrop { dir: dir_b.clone() };
    let setup_b = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "p2p-node-b",
            "--data-dir",
            &dir_b.to_string_lossy(),
            "--port",
            &P2P_B_PORT.to_string(),
            "--p2p",
            "--p2p-bootstrap",
            &bootstrap_a,
        ])
        .output()
        .expect("run node setup B");
    assert!(
        setup_b.status.success(),
        "setup B failed: {}",
        String::from_utf8_lossy(&setup_b.stderr)
    );
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir_b.join("node.json")).unwrap()).unwrap();
    assert_eq!(stored["p2p"], true);
    assert!(stored["p2p_bootstrap"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry.as_str() == Some(&bootstrap_a)));

    let info_b = Command::new(bin())
        .args(["node", "p2p-info", "--data-dir", &dir_b.to_string_lossy()])
        .output()
        .expect("run p2p-info B");
    assert!(
        info_b.status.success(),
        "p2p-info B failed: {}",
        String::from_utf8_lossy(&info_b.stderr)
    );
    let peer_b = parse_peer_id(&String::from_utf8_lossy(&info_b.stdout));
    assert_ne!(peer_a, peer_b, "each node must mint its own peer id");

    drop(guard_a);
    drop(guard_b);
    std::fs::remove_dir_all(&dir_a).unwrap();
    std::fs::remove_dir_all(&dir_b).unwrap();
}

#[test]
fn backup_round_trip_copies_identity_files() {
    let dir = scratch_dir("backup");
    let setup = Command::new(bin())
        .args([
            "node",
            "setup",
            "--yes",
            "--name",
            "backup-node",
            "--data-dir",
            &dir.to_string_lossy(),
            "--port",
            &BACKUP_PORT.to_string(),
            "--no-start",
        ])
        .output()
        .expect("run node setup");
    assert!(
        setup.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let dest = dir.join("backup-out");
    let backup = Command::new(bin())
        .args([
            "node",
            "backup",
            "--data-dir",
            &dir.to_string_lossy(),
            "--to",
            &dest.to_string_lossy(),
        ])
        .output()
        .expect("run node backup");
    assert!(
        backup.status.success(),
        "backup failed: {}",
        String::from_utf8_lossy(&backup.stderr)
    );
    for name in ["node.json", "service.token", "operator.key"] {
        assert!(dest.join(name).is_file(), "backup is missing {name}");
        assert_eq!(
            std::fs::read(dir.join(name)).unwrap(),
            std::fs::read(dest.join(name)).unwrap(),
            "{name} differs from the original"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
