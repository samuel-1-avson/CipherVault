//! Beginner-friendly operator node onboarding: guided setup plus
//! plain-language start/stop/status. Experts keep the raw
//! `ciphervault-operator` flags; this module is the friendly front door.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use rand::RngCore;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::recover::{cmd_invite_join, describe_standing, fetch_self_descriptor, refresh_standing};
use super::update::ReleaseVersion;
use crate::util::DEFAULT_PRODUCTION_OPERATORS;

const TOKEN_FILE: &str = "service.token";
const CONFIG_FILE: &str = "node.json";
const PID_FILE: &str = "node.pid";
const LOG_FILE: &str = "node.log";
const DEFAULT_PORT: u16 = 8101;

fn default_p2p_tcp_port() -> u16 {
    9101
}

fn default_p2p_quic_port() -> u16 {
    9102
}

#[derive(serde::Serialize, serde::Deserialize)]
struct NodeConfig {
    operator_id: String,
    port: u16,
    /// P2P mesh mode (dual HTTP + libp2p). Absent in older node.json
    /// files, which correctly read as disabled.
    #[serde(default)]
    p2p: bool,
    /// Bootstrap peer multiaddrs (mutual exchange with peering partners).
    #[serde(default)]
    p2p_bootstrap: Vec<String>,
    #[serde(default = "default_p2p_tcp_port")]
    p2p_tcp_port: u16,
    #[serde(default = "default_p2p_quic_port")]
    p2p_quic_port: u16,
}

/// Default node data dir, mirroring the account-file precedent:
/// `%APPDATA%\CipherVault\node` on Windows,
/// `$XDG_CONFIG_HOME/ciphervault/node` or `~/.config/ciphervault/node`
/// elsewhere, overridable with `CIPHERVAULT_NODE_DIR`.
fn default_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CIPHERVAULT_NODE_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    if let Some(app_data) = std::env::var_os("APPDATA") {
        return PathBuf::from(app_data).join("CipherVault").join("node");
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("ciphervault").join("node");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("ciphervault")
            .join("node");
    }
    PathBuf::from("operator-data")
}

/// Friendly default node name from the login name, sanitized to the
/// operator-id charset; falls back to `my-node`.
fn default_node_name() -> String {
    let raw = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
        .to_lowercase();
    let clean: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if clean.is_empty() {
        "my-node".to_string()
    } else {
        format!("{clean}-node")
    }
}

/// Locates the operator daemon: next to this executable (how the
/// installer lays out all four binaries), else whatever `PATH` resolves.
fn operator_binary() -> PathBuf {
    let exe_name = if cfg!(windows) {
        "ciphervault-operator.exe"
    } else {
        "ciphervault-operator"
    };
    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            let sibling = dir.join(exe_name);
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from(exe_name)
}

/// Parses the version from `<binary> --version` output (`name x.y.z...`).
fn parse_version_output(output: &str) -> Option<String> {
    output.split_whitespace().nth(1).map(str::to_string)
}

/// Refuses to drive an operator daemon that cannot report its version.
/// Pre-`--version` binaries fail later with confusing errors (unknown
/// `--print-identity`, `/healthz` 404), so catch that here with a
/// plain-language pointer to `ciphervault update`. A version mismatch
/// only warns: mixed installs are legitimate for manual operators.
fn check_operator_binary(binary: &Path) -> Result<()> {
    let output = Command::new(binary).arg("--version").output();
    let output = match output {
        Ok(output) => output,
        Err(error) => bail!(
            "could not run {} ({error}); reinstall with the CipherVault installer so the operator sits next to this CLI",
            binary.display()
        ),
    };
    if !output.status.success() {
        bail!(
            "the operator at {} is too old for this CLI (it cannot even report its version); run `ciphervault update` to refresh every binary",
            binary.display()
        );
    }
    if let Some(reported) = parse_version_output(&String::from_utf8_lossy(&output.stdout)) {
        let ours = env!("CARGO_PKG_VERSION");
        if ReleaseVersion::core_of(&reported) != ReleaseVersion::core_of(ours) {
            eprintln!(
                "{}",
                format!(
                    "Warning: the operator reports {reported} but this CLI is {ours}; mixed versions can behave oddly — run `ciphervault update` to align them."
                )
                .yellow()
            );
        }
    }
    Ok(())
}

fn generate_service_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Writes a secret file, then locks it down to the current user via the
/// shared `ciphervault-file-lock` crate (0600 on Unix, protected DACL on
/// Windows). Best-effort with a loud warning: filesystems without ACLs
/// must not brick setup, but any exposure must be visible.
fn write_secret_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    lock_secret_file_best_effort(path);
    Ok(())
}

/// Shared best-effort wrapper so every secret-file write warns alike.
fn lock_secret_file_best_effort(path: &Path) {
    if let Err(error) = ciphervault_file_lock::lock_secret_file(path) {
        eprintln!(
            "{}",
            format!(
                "Warning: could not lock down {} ({error}); anyone with disk access may read it.",
                path.display()
            )
            .yellow()
        );
    }
}

fn read_config(data_dir: &Path) -> Result<NodeConfig> {
    let raw = std::fs::read_to_string(data_dir.join(CONFIG_FILE)).with_context(|| {
        format!(
            "no node set up in {} yet; run `ciphervault node setup` first",
            data_dir.display()
        )
    })?;
    serde_json::from_str(&raw).context("decode node.json (re-run setup into a fresh folder)")
}

fn read_token(data_dir: &Path) -> Result<String> {
    let token = std::fs::read_to_string(data_dir.join(TOKEN_FILE))
        .context("read service token (was setup interrupted?)")?;
    let token = token.trim().to_string();
    if token.is_empty() {
        bail!("service token file is empty; re-run setup into a fresh folder");
    }
    Ok(token)
}

fn ask(prompt: &str, default: &str) -> Result<String> {
    print!("{prompt} [{default}]: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let trimmed = answer.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn ask_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    loop {
        let answer = ask(prompt, hint)?;
        if answer.eq_ignore_ascii_case(hint) {
            return Ok(default_yes);
        }
        match answer.to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y or n."),
        }
    }
}

/// True when the operator could bind `port`: both the wildcard and the
/// loopback bind must succeed. Either direction alone misses holders on
/// Windows (a loopback bind succeeds over a wildcard listener and vice
/// versa); the operator itself binds the wildcard.
fn port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
        && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Finds a currently free loopback port for P2P listeners.
/// Best-effort: another process could grab it before the daemon binds.
fn find_free_port() -> Option<u16> {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .ok()?
        .local_addr()
        .ok()
        .map(|addr| addr.port())
}

/// Picks two distinct free ports for the P2P TCP and QUIC listeners.
fn pick_p2p_ports() -> Result<(u16, u16)> {
    for _ in 0..10 {
        match (find_free_port(), find_free_port()) {
            (Some(tcp), Some(quic)) if tcp != quic => return Ok((tcp, quic)),
            _ => continue,
        }
    }
    bail!("could not find two free ports for P2P; pass --p2p-tcp-port/--p2p-quic-port explicitly")
}

fn ask_port(default: u16) -> Result<u16> {
    loop {
        let answer = ask(
            "Which network port should it listen on? (only change this if the default is taken)",
            &default.to_string(),
        )?;
        match answer.parse::<u16>() {
            Ok(0) | Err(_) => println!("Please enter a port number between 1 and 65535."),
            Ok(port) if !port_is_free(port) => {
                println!("Port {port} is already in use on this machine; pick another.")
            }
            Ok(port) => return Ok(port),
        }
    }
}

async fn node_is_ready(base_url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .user_agent(concat!("ciphervault/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    match client.get(format!("{base_url}/healthz")).send().await {
        Ok(response) => {
            response.status().is_success()
                && response.text().await.unwrap_or_default().contains("ready")
        }
        Err(_) => false,
    }
}

/// Pure shape check for the `/v1/info` operator-id parse.
fn operator_id_from_info(body: &str) -> Option<String> {
    let info: serde_json::Value = serde_json::from_str(body).ok()?;
    info.get("operator_id")?.as_str().map(str::to_string)
}

/// Live P2P identity served by `/v1/peers/p2p`.
#[derive(serde::Deserialize)]
struct P2pInfo {
    peer_id: String,
    #[serde(default)]
    listen_addrs: Vec<String>,
    #[serde(default)]
    external_addrs: Vec<String>,
}

/// Shareable multiaddrs for peering: AutoNAT external addrs when known,
/// else listen addrs with unspecified hosts rewritten to loopback (good
/// for local drills; replace with your public IP to share widely).
fn p2p_shareable_addrs(info: &P2pInfo) -> Vec<String> {
    let base = if info.external_addrs.is_empty() {
        &info.listen_addrs
    } else {
        &info.external_addrs
    };
    base.iter()
        .map(|addr| {
            let dialable = addr
                .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
                .replace("/ip6/::/", "/ip6/::1/");
            format!("{dialable}/p2p/{}", info.peer_id)
        })
        .collect()
}

/// Reads the operator id a live daemon reports for itself. `None` when the
/// respondent is unreachable or too old to identify via `/v1/info`.
async fn running_operator_id(base_url: &str) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
    let body = client
        .get(format!("{base_url}/v1/info"))
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    operator_id_from_info(&body)
}

async fn wait_for_ready(base_url: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if node_is_ready(base_url).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    node_is_ready(base_url).await
}

fn tail_log(log_path: &Path, lines: usize) -> Vec<String> {
    std::fs::read_to_string(log_path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .take(lines)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn node_summary(config: &NodeConfig, data_dir: &Path) {
    println!();
    println!(
        "{}",
        format!(
            "Your node \"{}\" is running and healthy.",
            config.operator_id
        )
        .bold()
        .green()
    );
    println!("  Health:         http://127.0.0.1:{}/healthz", config.port);
    println!("  Data folder:    {}", data_dir.display());
    println!("  Log file:       {}", data_dir.join(LOG_FILE).display());
    if config.p2p {
        println!("  P2P mesh:       enabled (share addresses via `ciphervault node p2p-info`)");
    }
    println!(
        "  {}",
        "Back up the data folder: it holds your node's identity.".yellow()
    );
}

/// Marks our own stdio handles non-inheritable (Windows only) before a
/// daemon spawn. Shell pipes arrive marked inheritable, and an outliving
/// grandchild would otherwise hold the parent's output pipe open forever,
/// so piped callers never see EOF.
#[cfg(windows)]
fn clear_stdio_inheritability() {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: i32) -> *mut std::ffi::c_void;
        fn SetHandleInformation(handle: *mut std::ffi::c_void, mask: u32, flags: u32) -> i32;
    }
    const STD_INPUT_HANDLE: i32 = -10;
    const STD_OUTPUT_HANDLE: i32 = -11;
    const STD_ERROR_HANDLE: i32 = -12;
    const HANDLE_FLAG_INHERIT: u32 = 1;
    const INVALID_HANDLE_VALUE: isize = -1;
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        unsafe {
            let handle = GetStdHandle(which);
            if handle.is_null() || handle as isize == INVALID_HANDLE_VALUE {
                continue;
            }
            SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
        }
    }
}

/// Adds the P2P mesh flags when this node runs in dual mode.
fn add_p2p_args(cmd: &mut Command, config: &NodeConfig) {
    if !config.p2p {
        return;
    }
    cmd.arg("--enable-p2p")
        .arg("--p2p-tcp-port")
        .arg(config.p2p_tcp_port.to_string())
        .arg("--p2p-quic-port")
        .arg(config.p2p_quic_port.to_string());
    for bootstrap in &config.p2p_bootstrap {
        cmd.arg("--p2p-bootstrap").arg(bootstrap);
    }
}

#[cfg(windows)]
fn spawn_detached(binary: &Path, data_dir: &Path, config: &NodeConfig, token: &str) -> Result<u32> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    clear_stdio_inheritability();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join(LOG_FILE))
        .context("open node log file")?;
    let mut cmd = Command::new(binary);
    cmd.arg("--port")
        .arg(config.port.to_string())
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--operator-id")
        .arg(&config.operator_id);
    add_p2p_args(&mut cmd, config);
    let child = cmd
        .env("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(log.try_clone().context("clone log handle")?)
        .stderr(log)
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .spawn()
        .with_context(|| format!("start {}", binary.display()))?;
    Ok(child.id())
}

#[cfg(not(windows))]
fn spawn_detached(binary: &Path, data_dir: &Path, config: &NodeConfig, token: &str) -> Result<u32> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join(LOG_FILE))
        .context("open node log file")?;
    let mut cmd = Command::new(binary);
    cmd.arg("--port")
        .arg(config.port.to_string())
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--operator-id")
        .arg(&config.operator_id);
    add_p2p_args(&mut cmd, config);
    let child = cmd
        .env("CIPHERVAULT_OPERATOR_SERVICE_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(log.try_clone().context("clone log handle")?)
        .stderr(log)
        .spawn()
        .with_context(|| format!("start {}", binary.display()))?;
    Ok(child.id())
}

#[cfg(windows)]
fn kill_pid(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(windows))]
fn kill_pid(pid: u32) {
    let _ = Command::new("kill")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// True when `pid` looks like our own operator daemon. `node stop` checks
/// this before killing: a stale PID file must never take down a foreign
/// process that reused the number.
#[cfg(windows)]
fn pid_is_our_operator(pid: u32) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .to_ascii_lowercase()
                .contains("ciphervault-operator")
        })
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn pid_is_our_operator(pid: u32) -> bool {
    // `args=` (not `comm=`: comm truncates to 15 chars) works on Linux and macOS.
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "args="])
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .to_ascii_lowercase()
                .contains("ciphervault-operator")
        })
        .unwrap_or(false)
}

async fn start_node(data_dir: &Path) -> Result<()> {
    let config = read_config(data_dir)?;
    let base_url = format!("http://127.0.0.1:{}", config.port);
    if node_is_ready(&base_url).await {
        match running_operator_id(&base_url).await {
            Some(id) if id != config.operator_id => bail!(
                "port {} already serves a different node (\"{id}\"); stop it first, or set this node up on another port",
                config.port
            ),
            None => eprintln!(
                "{}",
                format!(
                    "Warning: the node on port {} is too old to identify itself; assuming it is yours.",
                    config.port
                )
                .yellow()
            ),
            _ => {}
        }
        println!("Your node is already running.");
        node_summary(&config, data_dir);
        return Ok(());
    }
    let token = read_token(data_dir)?;
    let binary = operator_binary();
    check_operator_binary(&binary)?;
    let pid = spawn_detached(&binary, data_dir, &config, &token)?;
    std::fs::write(data_dir.join(PID_FILE), pid.to_string())?;
    if wait_for_ready(&base_url, 15).await {
        node_summary(&config, data_dir);
        Ok(())
    } else {
        eprintln!(
            "{}",
            "The node did not become healthy in time. Recent log lines:"
                .red()
                .bold()
        );
        for line in tail_log(&data_dir.join(LOG_FILE), 5) {
            eprintln!("  {line}");
        }
        bail!(
            "node failed to start; see {}",
            data_dir.join(LOG_FILE).display()
        );
    }
}

/// P2P mesh options for guided setup, kept in one struct so the setup
/// command stays readable as flags grow.
pub(crate) struct NodeP2pOptions {
    pub enabled: bool,
    pub bootstrap: Vec<String>,
    pub tcp_port: Option<u16>,
    pub quic_port: Option<u16>,
}

/// Guided first run: three plain questions, then an admin password is
/// made, the identity is created, and (optionally) the node starts and
/// joins the fleet with a ticket.
pub(crate) async fn cmd_node_setup(
    name: Option<String>,
    data_dir: Option<PathBuf>,
    port: Option<u16>,
    yes: bool,
    join_ticket: Option<PathBuf>,
    no_start: bool,
    p2p: NodeP2pOptions,
) -> Result<()> {
    if !yes && !std::io::stdin().is_terminal() {
        bail!("setup needs answers: re-run in a terminal, or pass --yes to accept every default");
    }
    println!("{}", "Set up your CipherVault node.".bold().green());
    println!("Three quick questions; Enter accepts each default.");
    println!();

    let data_dir = match data_dir {
        Some(dir) => dir,
        None if yes => default_data_dir(),
        None => {
            let answer = ask(
                "Where should it keep its data?",
                &default_data_dir().display().to_string(),
            )?;
            PathBuf::from(answer)
        }
    };
    if data_dir.join(CONFIG_FILE).exists() {
        bail!(
            "{} is already a set-up node folder; pick another folder or delete it to start over",
            data_dir.display()
        );
    }
    let operator_id = match name {
        Some(name) => name,
        None if yes => default_node_name(),
        None => ask(
            "What should your node be called? (its public nickname)",
            &default_node_name(),
        )?,
    };
    let port = match port {
        Some(port) => port,
        None if yes => DEFAULT_PORT,
        None => ask_port(DEFAULT_PORT)?,
    };
    if !port_is_free(port) {
        bail!("port {port} is already in use on this machine; stop whatever holds it or pass another --port");
    }
    let mut p2p_bootstrap = p2p.bootstrap;
    let enable_p2p = if p2p.enabled || !p2p_bootstrap.is_empty() {
        true
    } else if yes {
        false
    } else {
        ask_yes_no(
            "Enable P2P mesh mode (for peering with other nodes)?",
            false,
        )?
    };
    if enable_p2p && p2p_bootstrap.is_empty() && !yes {
        let answer = ask(
            "Bootstrap peer addresses? (space/comma separated; Enter for none — you can peer later)",
            "",
        )?;
        p2p_bootstrap = answer
            .split([',', ' ', ';'])
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_string)
            .collect();
    }
    let (p2p_tcp_port, p2p_quic_port) = if !enable_p2p {
        (default_p2p_tcp_port(), default_p2p_quic_port())
    } else {
        let (auto_tcp, auto_quic) = pick_p2p_ports()?;
        let tcp = p2p.tcp_port.unwrap_or(auto_tcp);
        let mut quic = p2p.quic_port.unwrap_or(auto_quic);
        if quic == tcp {
            // An explicit port collided with the auto-picked one; repick.
            for _ in 0..5 {
                if let Some(free) = find_free_port() {
                    if free != tcp {
                        quic = free;
                        break;
                    }
                }
            }
        }
        (tcp, quic)
    };

    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    let token = generate_service_token();
    write_secret_file(&data_dir.join(TOKEN_FILE), &format!("{token}\n"))?;
    let config = NodeConfig {
        operator_id,
        port,
        p2p: enable_p2p,
        p2p_bootstrap,
        p2p_tcp_port,
        p2p_quic_port,
    };
    std::fs::write(
        data_dir.join(CONFIG_FILE),
        serde_json::to_string_pretty(&config)?,
    )?;
    println!();
    println!(
        "  Admin password saved to {}",
        data_dir.join(TOKEN_FILE).display()
    );
    println!(
        "  {}",
        "Keep it secret: anyone with it can administer your node.".yellow()
    );

    let binary = operator_binary();
    check_operator_binary(&binary)?;
    let identity = Command::new(&binary)
        .arg("--print-identity")
        .arg("--operator-id")
        .arg(&config.operator_id)
        .arg("--data-dir")
        .arg(&data_dir)
        .output()
        .with_context(|| {
            format!(
                "run {} (is the operator installed next to ciphervault?)",
                binary.display()
            )
        })?;
    if !identity.status.success() {
        bail!(
            "could not create the node identity: {}",
            String::from_utf8_lossy(&identity.stderr).trim()
        );
    }
    println!();
    println!("  Your node identity (send this to a fleet admin to get an invite ticket):");
    println!(
        "  {}",
        String::from_utf8_lossy(&identity.stdout).trim().cyan()
    );

    let ticket = match join_ticket {
        Some(path) => Some(path),
        None if yes => None,
        None => {
            let answer = ask(
                "Invite ticket file to join the fleet now? (Enter to skip; you can join later)",
                "",
            )?;
            if answer.is_empty() {
                None
            } else {
                Some(PathBuf::from(answer))
            }
        }
    };
    if let Some(ticket) = ticket {
        let base_url = format!("http://127.0.0.1:{}", config.port);
        if !node_is_ready(&base_url).await {
            println!();
            println!("Starting your node so it can join...");
            start_node(&data_dir).await?;
        }
        let fleet: Vec<String> = DEFAULT_PRODUCTION_OPERATORS
            .iter()
            .map(|s| s.to_string())
            .collect();
        println!();
        println!("Joining the fleet...");
        match cmd_invite_join(ticket, base_url, Some(fleet)).await {
            Ok(()) => println!(
                "{}",
                "Joined: your node is in probation (it stores data; full trust comes after a day of uptime)."
                    .green()
            ),
            Err(error) => eprintln!(
                "{}",
                format!(
                    "Join did not complete ({error:#}). Your node still runs standalone; retry later with `ciphervault invite join`."
                )
                .yellow()
            ),
        }
    }

    let start_now = !no_start && (yes || ask_yes_no("Start the node now?", true)?);
    if start_now {
        println!();
        start_node(&data_dir).await?;
    } else {
        println!();
        println!("All set. Start your node any time with:");
        println!("  ciphervault node start --data-dir {}", data_dir.display());
    }
    if yes {
        println!();
        println!("Back up your node identity any time with:");
        println!(
            "  ciphervault node backup --data-dir {} --to <backup-folder>",
            data_dir.display()
        );
    } else if ask_yes_no("Back up your node's identity files now?", true)? {
        let default = format!("{}-backup", data_dir.display());
        let dest = ask(
            "Back up to which folder? (move it somewhere safe afterwards)",
            &default,
        )?;
        println!();
        cmd_node_backup(Some(data_dir.clone()), PathBuf::from(dest))?;
    }
    Ok(())
}

/// Identity files a backup must carry to restore this exact node.
const BACKUP_FILES: &[&str] = &["operator.key", CONFIG_FILE, TOKEN_FILE];

/// Copies the node identity files into `dest` so this exact node can be
/// restored later. Missing files are reported, not fatal (a node that has
/// never started has no key yet); a folder without `node.json` is refused.
pub(crate) fn cmd_node_backup(data_dir: Option<PathBuf>, dest: PathBuf) -> Result<()> {
    let data_dir = data_dir.unwrap_or_else(default_data_dir);
    if !data_dir.join(CONFIG_FILE).is_file() {
        bail!(
            "no node set up in {} yet; run `ciphervault node setup` first",
            data_dir.display()
        );
    }
    std::fs::create_dir_all(&dest).with_context(|| format!("create {}", dest.display()))?;
    for name in BACKUP_FILES {
        let src = data_dir.join(name);
        if src.is_file() {
            let dest_file = dest.join(name);
            std::fs::copy(&src, &dest_file).with_context(|| format!("copy {}", src.display()))?;
            lock_secret_file_best_effort(&dest_file);
            println!("  saved {name}");
        } else {
            println!("  skipped {name} (not present)");
        }
    }
    println!();
    println!("Backed up to {}.", dest.display());
    println!("To restore: set up a fresh folder, stop the node, then copy these files over it.");
    Ok(())
}

/// Starts the node set up in `data_dir` in the background.
pub(crate) async fn cmd_node_start(data_dir: Option<PathBuf>) -> Result<()> {
    let data_dir = data_dir.unwrap_or_else(default_data_dir);
    start_node(&data_dir).await
}

/// Plain-language health report; exits nonzero when the node is down.
pub(crate) async fn cmd_node_status(data_dir: Option<PathBuf>) -> Result<()> {
    let data_dir = data_dir.unwrap_or_else(default_data_dir);
    let config = read_config(&data_dir)?;
    let base_url = format!("http://127.0.0.1:{}", config.port);
    if node_is_ready(&base_url).await {
        node_summary(&config, &data_dir);
        Ok(())
    } else {
        bail!(
            "Your node is not running. Start it with `ciphervault node start --data-dir {}`.",
            data_dir.display()
        );
    }
}

/// Plain-language fleet standing: checks this node in against the
/// public fleet and reports probation/full/not-joined per endpoint.
pub(crate) async fn cmd_node_standing(data_dir: Option<PathBuf>) -> Result<()> {
    let data_dir = data_dir.unwrap_or_else(default_data_dir);
    let config = read_config(&data_dir)?;
    let base_url = format!("http://127.0.0.1:{}", config.port);
    if !node_is_ready(&base_url).await {
        bail!(
            "Your node is not running. Start it with `ciphervault node start --data-dir {}`.",
            data_dir.display()
        );
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let descriptor = fetch_self_descriptor(&http, &base_url).await?;
    let fleet: Vec<String> = DEFAULT_PRODUCTION_OPERATORS
        .iter()
        .map(|s| s.to_string())
        .collect();
    println!();
    println!(
        "Fleet standing for \"{}\" (public fleet):",
        config.operator_id
    );
    for (target, status) in refresh_standing(&descriptor, &fleet).await? {
        println!("  {target}: {}", describe_standing(&status));
    }
    Ok(())
}

/// Shows this node's P2P identity for peering: the addresses a partner
/// passes as `--p2p-bootstrap` to mesh with us.
pub(crate) async fn cmd_node_p2p_info(data_dir: Option<PathBuf>) -> Result<()> {
    let data_dir = data_dir.unwrap_or_else(default_data_dir);
    let config = read_config(&data_dir)?;
    let base_url = format!("http://127.0.0.1:{}", config.port);
    if !node_is_ready(&base_url).await {
        bail!(
            "Your node is not running. Start it with `ciphervault node start --data-dir {}`.",
            data_dir.display()
        );
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let response = client
        .get(format!("{base_url}/v1/peers/p2p"))
        .send()
        .await
        .context("ask the node for its P2P identity")?;
    if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        bail!(
            "P2P is not enabled for \"{}\" (it was set up without --p2p). Set up a new folder with --p2p to join the mesh.",
            config.operator_id
        );
    }
    let info: P2pInfo = response
        .error_for_status()
        .context("ask the node for its P2P identity")?
        .json()
        .await
        .context("decode the P2P identity")?;
    println!();
    println!("P2P identity for \"{}\":", config.operator_id);
    println!("  Peer ID: {}", info.peer_id.cyan());
    let shareable = p2p_shareable_addrs(&info);
    if shareable.is_empty() {
        println!("  No listen addresses yet; the swarm may still be starting.");
    } else {
        println!("  Share one of these with a peering partner (--p2p-bootstrap):");
        for addr in &shareable {
            println!("    {addr}");
        }
        if info.external_addrs.is_empty() {
            println!(
                "  {}",
                "These point at this machine only; replace 127.0.0.1 with your public IP/hostname to share widely."
                    .yellow()
            );
        }
    }
    Ok(())
}

/// Stops the node set up in `data_dir`.
pub(crate) async fn cmd_node_stop(data_dir: Option<PathBuf>) -> Result<()> {
    let data_dir = data_dir.unwrap_or_else(default_data_dir);
    let config = read_config(&data_dir)?;
    let base_url = format!("http://127.0.0.1:{}", config.port);
    let pid_raw = std::fs::read_to_string(data_dir.join(PID_FILE)).unwrap_or_default();
    match pid_raw.trim().parse::<u32>() {
        Ok(pid) if pid_is_our_operator(pid) => kill_pid(pid),
        Ok(_) => {
            println!("The recorded process is no longer your node; checking the port anyway...")
        }
        Err(_) => println!("No recorded process; checking anyway..."),
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline && node_is_ready(&base_url).await {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = std::fs::remove_file(data_dir.join(PID_FILE));
    if node_is_ready(&base_url).await {
        bail!(
            "The node is still responding; stop process on port {} manually.",
            config.port
        );
    }
    println!("Your node \"{}\" is stopped.", config.operator_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_token_is_64_hex_chars() {
        let token = generate_service_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(token, generate_service_token());
    }

    #[test]
    fn default_name_sanitizes_login() {
        // Whatever the login is, the name stays in the id charset.
        let name = default_node_name();
        assert!(!name.is_empty());
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }

    #[test]
    fn version_output_parses_clap_shape() {
        assert_eq!(
            parse_version_output("ciphervault-operator 1.0.7-beta.7\n"),
            Some("1.0.7-beta.7".to_string())
        );
        assert_eq!(parse_version_output("garbage"), None);
        assert_eq!(parse_version_output(""), None);
    }

    #[test]
    fn missing_operator_binary_points_at_reinstall() {
        let missing = std::env::temp_dir().join(format!(
            "cv-no-such-operator-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let error = check_operator_binary(&missing).unwrap_err();
        assert!(
            format!("{error:#}").contains("reinstall"),
            "unexpected: {error:#}"
        );
    }

    #[test]
    fn port_probe_sees_live_listener() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(!port_is_free(port));
        drop(listener);
        // The suite binds loopback listeners and connections on other
        // threads, so a parallel test may briefly reuse this port before
        // we re-probe. Retry briefly: a genuinely stuck port still fails
        // after the budget.
        let mut free = false;
        for _ in 0..100 {
            if port_is_free(port) {
                free = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(free, "port {port} stayed bound after its listener dropped");
    }

    #[test]
    fn old_node_config_reads_as_http_only() {
        let config: NodeConfig =
            serde_json::from_str(r#"{"operator_id":"x","port":8101}"#).unwrap();
        assert!(!config.p2p);
        assert!(config.p2p_bootstrap.is_empty());
        assert_eq!(config.p2p_tcp_port, 9101);
        assert_eq!(config.p2p_quic_port, 9102);
    }

    #[test]
    fn shareable_addrs_prefer_external_and_rewrite_unspecified() {
        let local = P2pInfo {
            peer_id: "PEER".to_string(),
            listen_addrs: vec![
                "/ip4/0.0.0.0/tcp/9101".to_string(),
                "/ip4/0.0.0.0/udp/9102/quic-v1".to_string(),
            ],
            external_addrs: vec![],
        };
        assert_eq!(
            p2p_shareable_addrs(&local),
            vec![
                "/ip4/127.0.0.1/tcp/9101/p2p/PEER".to_string(),
                "/ip4/127.0.0.1/udp/9102/quic-v1/p2p/PEER".to_string(),
            ]
        );
        let dialable = P2pInfo {
            peer_id: "PEER".to_string(),
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/9101".to_string()],
            external_addrs: vec!["/dns4/node.example.com/tcp/9101".to_string()],
        };
        assert_eq!(
            p2p_shareable_addrs(&dialable),
            vec!["/dns4/node.example.com/tcp/9101/p2p/PEER".to_string()]
        );
        let silent = P2pInfo {
            peer_id: "PEER".to_string(),
            listen_addrs: vec![],
            external_addrs: vec![],
        };
        assert!(p2p_shareable_addrs(&silent).is_empty());
    }

    #[test]
    fn info_parse_reads_operator_id() {
        assert_eq!(
            operator_id_from_info(r#"{"operator_id":"my-node","supported_version":1}"#),
            Some("my-node".to_string())
        );
        assert_eq!(operator_id_from_info("{}"), None);
        assert_eq!(operator_id_from_info("not json"), None);
    }

    #[test]
    fn foreign_pid_is_not_our_operator() {
        // No plausible system runs a PID this high; the probe must fail closed.
        assert!(!pid_is_our_operator(u32::MAX));
    }

    #[test]
    fn backup_copies_identity_files() {
        let root = std::env::temp_dir().join(format!(
            "cv-node-backup-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let dir = root.join("node");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(CONFIG_FILE), r#"{"operator_id":"x","port":1}"#).unwrap();
        std::fs::write(dir.join(TOKEN_FILE), "tok").unwrap();
        let dest = root.join("dest");
        cmd_node_backup(Some(dir.clone()), dest.clone()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join(CONFIG_FILE)).unwrap(),
            r#"{"operator_id":"x","port":1}"#
        );
        assert_eq!(
            std::fs::read_to_string(dest.join(TOKEN_FILE)).unwrap(),
            "tok"
        );
        // operator.key was absent: reported, not fatal.
        assert!(!dest.join("operator.key").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    // The lockdown primitive itself is covered by the
    // ciphervault-file-lock crate tests; this guards the call-site wiring.
    #[cfg(windows)]
    #[test]
    fn write_secret_file_locks_down_to_current_user() {
        let path = std::env::temp_dir().join(format!(
            "cv-restrict-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        write_secret_file(&path, "secret").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
        let query = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        assert!(query.status.success());
        let listing = String::from_utf8_lossy(&query.stdout).to_ascii_lowercase();
        let user = std::env::var("USERNAME").unwrap().to_ascii_lowercase();
        assert!(
            listing.contains(&user),
            "lockdown should grant {user}: {listing}"
        );
        assert!(
            !listing.contains("builtin"),
            "lockdown should strip inherited groups: {listing}"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn backup_refuses_non_node_folder() {
        let root = std::env::temp_dir().join(format!(
            "cv-node-nobackup-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let error = cmd_node_backup(Some(root.clone()), root.join("dest")).unwrap_err();
        assert!(
            format!("{error:#}").contains("no node set up"),
            "unexpected: {error:#}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
