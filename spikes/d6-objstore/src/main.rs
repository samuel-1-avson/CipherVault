//! D6 object-store spike harness.
//!
//! Commands:
//! - `run --backend <file|redb|rocksdb> --dir <path> --n <N>
//!   --value-bytes <B> [--batch <K>] [--sync]`
//!   Puts N objects (keys 0..N), then N random point gets with sampled
//!   value verification. Prints one greppable `RESULT` line.
//! - `crash-child --backend <...> --dir <path> --value-bytes <B>
//!   [--batch <K>] [--sync]`
//!   Writes numbered objects forever (durable commits) until killed. The
//!   parent harness kills it, then runs `crash-check`.
//! - `crash-check --backend <...> --dir <path> --value-bytes <B>`
//!   Verifies the kill left a dense key prefix with correct values and no
//!   corruption. Exit 0 on PASS, 1 on FAIL.
//!
//! Keys are 32 bytes (8-byte big-endian index + deterministic filler);
//! values are `--value-bytes` deterministic bytes of the index, so any
//! read can be verified without storing expectations.

mod file_store;
#[cfg(feature = "redb")]
mod redb_store;
#[cfg(feature = "rocksdb")]
mod rocksdb_store;

use std::path::{Path, PathBuf};
use std::time::Instant;

/// Engine under test. `batch`/`sync` are fixed at open; the run loop just
/// calls `put` and one trailing `flush`.
pub trait ObjStore {
    fn put(&mut self, key: &[u8; 32], value: &[u8]) -> Result<(), String>;
    fn flush(&mut self) -> Result<(), String>;
    fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, String>;
    /// All present key indices, ascending. Crash verification asserts this
    /// is exactly `0..len` (dense prefix, no holes) with correct values.
    fn present_indices(&self) -> Result<Vec<u64>, String>;
    /// Crash debris that is NOT a valid object (e.g. orphaned `.tmp`
    /// files). Informational: engines should report 0.
    fn debris_count(&self) -> u64 {
        0
    }
}

fn key_for(i: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&i.to_be_bytes());
    // Deterministic filler so keys look hash-distributed to LSM/b-tree
    // structures instead of clustering on a counter prefix.
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0xBF58_476D_1CE4_E5B9);
    for byte in key.iter_mut().skip(8) {
        x ^= x >> 29;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 32;
        *byte = (x & 0xFF) as u8;
    }
    key
}

fn value_for(i: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for j in 0..len {
        out.push((i >> (8 * (j % 8))) as u8 ^ (j as u8).wrapping_mul(31));
    }
    out
}

fn verify_value(i: u64, bytes: &[u8], expect_len: usize) -> bool {
    bytes.len() == expect_len && *bytes == *value_for(i, bytes.len())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0xF) as usize] as char);
    }
    out
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    let digits = s.as_bytes();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("bad hex byte {b}")),
    }
}

/// Minimal splitmix64 for the read-phase index stream.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total += meta.len();
            }
        }
    }
    total
}

struct RunConfig {
    backend: String,
    dir: PathBuf,
    n: u64,
    value_bytes: usize,
    batch: usize,
    sync: bool,
    /// Read-phase get count (default: `n`). 0 skips reads.
    gets: Option<u64>,
    /// Skip the put phase (measure reads on an existing store).
    skip_puts: bool,
}

fn arg_value(args: &[String], flag: &str) -> Result<String, String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .ok_or_else(|| format!("missing {flag} <value>"))
}

fn parse_run(args: &[String]) -> Result<RunConfig, String> {
    Ok(RunConfig {
        backend: arg_value(args, "--backend")?,
        dir: PathBuf::from(arg_value(args, "--dir")?),
        n: args
            .windows(2)
            .find(|pair| pair[0] == "--n")
            .map(|pair| pair[1].parse::<u64>())
            .transpose()
            .map_err(|e| format!("bad --n: {e}"))?
            .unwrap_or(0),
        value_bytes: args
            .windows(2)
            .find(|pair| pair[0] == "--value-bytes")
            .map(|pair| pair[1].parse::<usize>())
            .transpose()
            .map_err(|e| format!("bad --value-bytes: {e}"))?
            .unwrap_or(0),
        batch: args
            .windows(2)
            .find(|pair| pair[0] == "--batch")
            .map(|pair| pair[1].parse::<usize>())
            .transpose()
            .map_err(|e| format!("bad --batch: {e}"))?
            .unwrap_or(1),
        sync: args.iter().any(|arg| arg == "--sync"),
        gets: args
            .windows(2)
            .find(|pair| pair[0] == "--gets")
            .map(|pair| pair[1].parse::<u64>())
            .transpose()
            .map_err(|e| format!("bad --gets: {e}"))?,
        skip_puts: args.iter().any(|arg| arg == "--skip-puts"),
    })
}

fn run_store<S: ObjStore>(mut store: S, cfg: &RunConfig, child: bool) -> Result<(), String> {
    // Open happened (and was timed) in the caller.
    let step = (cfg.n / 10).max(1);
    let t_put = Instant::now();
    if child {
        // Crash child: dense durable writes forever, until the parent
        // kills us. No output on the hot path.
        let mut i = 0u64;
        loop {
            let key = key_for(i);
            let value = value_for(i, cfg.value_bytes);
            store.put(&key, &value)?;
            i += 1;
        }
    }
    let mut put_secs = 0.0;
    if !cfg.skip_puts {
        for i in 0..cfg.n {
            let key = key_for(i);
            let value = value_for(i, cfg.value_bytes);
            store.put(&key, &value)?;
            if i % step == 0 {
                eprintln!("put {i}/{}", cfg.n);
            }
        }
        store.flush()?;
        put_secs = t_put.elapsed().as_secs_f64();
    }

    // Read phase: random point gets with replacement, values verified
    // on a 1/1024 sample (recomputing every value would pollute the
    // timing with filler CPU).
    let get_count = cfg.gets.unwrap_or(cfg.n);
    let mut rng = SplitMix64(0x1234_5678_9ABC_DEF0);
    let mut verified = 0u64;
    let mut get_secs = 0.0;
    if get_count > 0 {
        let get_step = (get_count / 10).max(1);
        let t_get = Instant::now();
        for j in 0..get_count {
            let i = rng.next() % cfg.n;
            let got = store
                .get(&key_for(i))?
                .ok_or_else(|| format!("missing key {i} in read phase"))?;
            if j % 1024 == 0 {
                if !verify_value(i, &got, cfg.value_bytes) {
                    return Err(format!("value mismatch at key {i}"));
                }
                verified += 1;
            }
            if j % get_step == 0 {
                eprintln!("get {j}/{get_count}");
            }
        }
        get_secs = t_get.elapsed().as_secs_f64();
    }
    let bytes_on_disk = dir_size(&cfg.dir);
    let puts_per_s = if put_secs > 0.0 {
        cfg.n as f64 / put_secs
    } else {
        0.0
    };
    let gets_per_s = if get_secs > 0.0 {
        get_count as f64 / get_secs
    } else {
        0.0
    };
    println!(
        "RESULT backend={} n={} value_bytes={} batch={} sync={} \
         put_s={put_secs:.3} puts_per_s={puts_per_s:.0} gets={get_count} \
         get_s={get_secs:.3} gets_per_s={gets_per_s:.0} verified={verified} \
         bytes_on_disk={bytes_on_disk}",
        cfg.backend, cfg.n, cfg.value_bytes, cfg.batch, cfg.sync,
    );
    Ok(())
}

fn check_store<S: ObjStore>(store: &S, backend: &str, value_bytes: usize) -> Result<(), String> {
    let present = store.present_indices()?;
    let count = present.len() as u64;
    if count == 0 {
        return Err("no objects present; child made no progress".to_string());
    }
    // Dense-prefix check: exactly 0..count, no holes, no extras.
    for (pos, index) in present.iter().enumerate() {
        if *index != pos as u64 {
            return Err(format!(
                "key hole: position {pos} holds index {index} (count={count})"
            ));
        }
    }
    // Full value verification: a torn write would fail here.
    for i in 0..count {
        let got = store
            .get(&key_for(i))?
            .ok_or_else(|| format!("prefix key {i} unreadable"))?;
        if !verify_value(i, &got, value_bytes) {
            return Err(format!("torn value at key {i}"));
        }
        if i % 50_000 == 0 {
            eprintln!("verify {i}/{count}");
        }
    }
    println!(
        "CRASH backend={backend} present={count} values_ok={count} \
         debris={} verdict=PASS",
        store.debris_count(),
    );
    Ok(())
}

fn open_backend(cfg: &RunConfig) -> Result<Backend, String> {
    match cfg.backend.as_str() {
        "file" => Ok(Backend::File(file_store::FileStore::open(&cfg.dir)?)),
        #[cfg(feature = "redb")]
        "redb" => Ok(Backend::Redb(redb_store::RedbStore::open(&cfg.dir, cfg.batch)?)),
        #[cfg(feature = "rocksdb")]
        "rocksdb" => Ok(Backend::Rocks(rocksdb_store::RocksStore::open(
            &cfg.dir, cfg.batch, cfg.sync,
        )?)),
        other => Err(format!(
            "unknown backend {other:?} (this binary was built without it)"
        )),
    }
}

enum Backend {
    File(file_store::FileStore),
    #[cfg(feature = "redb")]
    Redb(redb_store::RedbStore),
    #[cfg(feature = "rocksdb")]
    Rocks(rocksdb_store::RocksStore),
}

fn run_backend(cfg: &RunConfig, child: bool) -> Result<(), String> {
    match open_backend(cfg)? {
        Backend::File(store) => run_store(store, cfg, child),
        #[cfg(feature = "redb")]
        Backend::Redb(store) => run_store(store, cfg, child),
        #[cfg(feature = "rocksdb")]
        Backend::Rocks(store) => run_store(store, cfg, child),
    }
}

fn check_backend(cfg: &RunConfig) -> Result<(), String> {
    match open_backend(cfg)? {
        Backend::File(store) => check_store(&store, &cfg.backend, cfg.value_bytes),
        #[cfg(feature = "redb")]
        Backend::Redb(store) => check_store(&store, &cfg.backend, cfg.value_bytes),
        #[cfg(feature = "rocksdb")]
        Backend::Rocks(store) => check_store(&store, &cfg.backend, cfg.value_bytes),
    }
}

fn usage() -> String {
    "usage:\n\
     \td6bench run --backend <file|redb|rocksdb> --dir <path> --n <N> \
     --value-bytes <B> [--batch <K>] [--sync] [--gets <M>] [--skip-puts]\n\
     \td6bench crash-child --backend <...> --dir <path> --value-bytes <B> \
     [--batch <K>] [--sync]\n\
     \td6bench crash-check --backend <...> --dir <path> --value-bytes <B>\n\
     \td6bench probe-open --backend <...> --dir <path>"
        .to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    let result = match command {
        "run" => parse_run(&args).and_then(|cfg| {
            if cfg.n == 0 || cfg.value_bytes == 0 {
                return Err("run requires --n <N> and --value-bytes <B>".to_string());
            }
            let t_total = Instant::now();
            let outcome = run_backend(&cfg, false);
            eprintln!("total_s={:.3}", t_total.elapsed().as_secs_f64());
            outcome
        }),
        "probe-open" => parse_run(&args).and_then(|cfg| {
            let t_open = Instant::now();
            let _backend = open_backend(&cfg)?;
            let open_s = t_open.elapsed().as_secs_f64();
            println!("OPEN backend={} open_s={open_s:.3}", cfg.backend);
            Ok(())
        }),
        "crash-child" => parse_run(&args).and_then(|mut cfg| {
            if cfg.value_bytes == 0 {
                return Err("crash-child requires --value-bytes <B>".to_string());
            }
            cfg.n = u64::MAX;
            eprintln!("crash-child ready: backend={}", cfg.backend);
            run_backend(&cfg, true)
        }),
        "crash-check" => parse_run(&args).and_then(|cfg| {
            if cfg.value_bytes == 0 {
                return Err("crash-check requires --value-bytes <B>".to_string());
            }
            check_backend(&cfg)
        }),
        _ => Err(usage()),
    };
    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("d6bench error: {e}");
            std::process::exit(1);
        }
    }
}
