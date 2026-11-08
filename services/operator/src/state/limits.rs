//! Fleet-wide size/timeout limits and env-override parsing.

use std::sync::{Mutex, MutexGuard};

pub const MAX_OBJECT_SIZE: usize = 4 * 1024 * 1024; // 4 MiB max per chunk/manifest object
pub const MAX_RECOVERY_RECORD_SIZE: usize = 64 * 1024; // 64 KiB max per recovery record
pub const MAX_ACTIVE_CHALLENGES: usize = 5_000;
pub const MAX_ACTIVE_SESSIONS: usize = 5_000;
pub const MAX_RECORDS_PER_LOCATOR: usize = 10_000;
pub const MAX_RECOVERY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RECOVERY_LOG_BYTES: u64 = 64 * 1024 * 1024;
pub const RECOVERY_PAGE_BYTES: usize = 1024 * 1024;

pub struct RecoveryPage {
    pub records: Vec<Vec<u8>>,
    /// Byte offset of the next complete frame, scoped to this append-only locator.
    pub next_cursor: Option<u64>,
}
pub const MAX_ACTIVE_PEERS: usize = 128;
/// Peer announces older than this are rejected at registration (replay
/// bound). Matches the routing-table prune window so accepted ⟺ retained.
pub const MAX_PEER_ANNOUNCE_AGE_SECS: u64 = 86400;
/// Peer announces farther in the future than this are rejected (clock
/// bound); without it a future-dated descriptor would never be pruned.
pub const MAX_PEER_ANNOUNCE_SKEW_SECS: u64 = 3600;
/// Number of striped filesystem locks sharding operator disk I/O (R8).
/// Distinct CIDs/locators hash to different stripes so concurrent uploads
/// for different objects no longer serialize on a single global lock.
pub const IO_STRIPE_COUNT: usize = 64;
/// Default probation before a ticket-joined node graduates to full
/// membership: 24 h of fleet-visible life. Override with
/// `CIPHERVAULT_PROBATION_SECS` (floored at 60 s so a typo cannot
/// insta-graduate joiners).
pub const DEFAULT_PROBATION_SECS: u64 = 86400;
/// Default liveness grace at graduation time: the joiner's last proof of
/// life (heartbeat or refresh) must be this recent, or graduation waits
/// for a fresh one. Override with `CIPHERVAULT_JOIN_LIVENESS_GRACE_SECS`
/// (floored at 60 s).
pub const DEFAULT_JOIN_LIVENESS_GRACE_SECS: u64 = 7200;

/// Locks an operator-state mutex, recovering from poisoning with a loud
/// stderr log instead of panicking. Poison is permanent until cleared —
/// every later `lock()` would fail — so recovery is the only stay-alive
/// option; the log keeps it honest. The poison flag is cleared after the
/// single log line so later locks run silently. Recovered state is
/// whatever the panicking holder left behind; every guarded map tolerates
/// that (entries are validated on read and TTL-evicted on write).
pub(crate) fn lock_or_recover<'a, T>(mutex: &'a Mutex<T>, name: &'static str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            eprintln!("operator lock {name} poisoned; recovering with pre-panic state");
            mutex.clear_poison();
            poisoned.into_inner()
        }
    }
}

/// Parses a byte size: plain bytes (`8388608`) or suffixed kilobytes/megabytes
/// (`64KB`, `8MB`, case-insensitive, trailing `B` optional). Else `None`.
pub fn parse_byte_size(value: &str) -> Option<usize> {
    let mut text = value.trim();
    text = text.strip_suffix(['B', 'b']).unwrap_or(text);
    let (digits, multiplier) = if let Some(number) = text.strip_suffix(['M', 'm']) {
        (number, 1024 * 1024)
    } else if let Some(number) = text.strip_suffix(['K', 'k']) {
        (number, 1024)
    } else {
        (text, 1)
    };
    let number: usize = digits.trim().parse().ok()?;
    number.checked_mul(multiplier)
}

/// Reads a byte-size operator limit from the environment. Missing, invalid, or
/// below-`floor` values fall back to `default` with a stderr warning, so a typo
/// can never silently zero a limit.
pub fn operator_limit_from_env(name: &str, default: usize, floor: usize) -> usize {
    let raw = match std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
    {
        Some(value) if !value.is_empty() => value,
        _ => return default,
    };
    match parse_byte_size(&raw) {
        Some(bytes) if bytes >= floor => bytes,
        _ => {
            eprintln!("operator limit {name}={raw} invalid or below floor {floor}; using default {default}");
            default
        }
    }
}

/// Maximum accepted object size. Must fit the largest FastCDC profile chunk
/// (256 KiB) plus encryption/CBOR overhead; the floor enforces that.
pub fn max_object_size() -> usize {
    operator_limit_from_env("CIPHERVAULT_MAX_OBJECT_SIZE", MAX_OBJECT_SIZE, 512 * 1024)
}

pub fn max_recovery_record_size() -> usize {
    operator_limit_from_env(
        "CIPHERVAULT_MAX_RECOVERY_RECORD_SIZE",
        MAX_RECOVERY_RECORD_SIZE,
        4 * 1024,
    )
}

/// Reads a seconds-valued operator knob from the environment. Missing,
/// invalid, or below-`floor` values fall back to `default` with a stderr
/// warning, so a typo can never silently zero a duration.
pub fn operator_secs_from_env(name: &str, default: u64, floor: u64) -> u64 {
    let raw = match std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
    {
        Some(value) if !value.is_empty() => value,
        _ => return default,
    };
    match raw.parse::<u64>() {
        Ok(secs) if secs >= floor => secs,
        _ => {
            eprintln!("operator limit {name}={raw} invalid or below floor {floor}; using default {default}");
            default
        }
    }
}

/// Minimum probation before a ticket-joined node can graduate.
pub fn min_probation_secs() -> u64 {
    operator_secs_from_env("CIPHERVAULT_PROBATION_SECS", DEFAULT_PROBATION_SECS, 60)
}

/// How recent a joiner's last proof of life must be at graduation time.
pub fn join_liveness_grace_secs() -> u64 {
    operator_secs_from_env(
        "CIPHERVAULT_JOIN_LIVENESS_GRACE_SECS",
        DEFAULT_JOIN_LIVENESS_GRACE_SECS,
        60,
    )
}

pub fn max_recovery_response_bytes() -> usize {
    operator_limit_from_env(
        "CIPHERVAULT_MAX_RECOVERY_RESPONSE_BYTES",
        MAX_RECOVERY_RESPONSE_BYTES,
        1024 * 1024,
    )
}
