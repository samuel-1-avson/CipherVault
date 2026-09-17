# CipherVault Platform Support Matrix (R16/R17)

Explicit support statement for hardware-bound factors, OS key protection, and
editor/git integration. Anything marked "Gap" below is specified (with
requirements) rather than silently missing.

## 1. Hardware-bound factors (R16)

| Factor | Windows | macOS | Linux |
|---|---|---|---|
| PIV smartcard / YubiKey (`--hardware-token`) | Supported (WinSCard PC/SC FFI in `crates/crypto/src/piv.rs`) | Gap: clean empty-reader list, `HsmError` on use | Gap: same as macOS |
| OS keyring for epoch/device keys | DPAPI (user-bound) | Gap: 0600 file keystore (see below) | Gap: 0600 file keystore |
| Touch ID / Windows Hello | Gap | Gap | n/a |
| Hosted WebAuthn (account service) | Supported (server-issued options) | Supported | Supported |

Notes:

- The PC/SC transport is `#[cfg(windows)]`-gated by construction: non-Windows
  builds enumerate zero readers and fail token operations with a descriptive
  `HsmError` instead of crashing or misbehaving.
- The non-Windows keystore (`portable_keystore`) is real AEAD, but its key
  lives in a 0600 file next to the vault. Threat model: protects against
  offline casual reads and cross-user snooping on multi-user machines; it does
  NOT bind to OS identity or a TPM the way DPAPI/Hello/Keychain do. Do not
  claim equal device binding across platforms until the gaps below close.

### macOS/Linux PC/SC parity requirements

1. New `#[cfg(target_vendor = "apple")]` / `#[cfg(target_os = "linux")]` FFI
   module mirroring the 7 WinSCard entry points already abstracted
   (`establish/release/list/connect/disconnect/transmit` + IO-request struct),
   bound against pcsclite (`libpcsclite`) on Linux and PCSC.framework on macOS.
2. Reader-enumeration parity: same empty-vs-error semantics as
   `list_pcsc_readers` (context failure yields an empty list, never a panic).
3. PIN entry reuse: the existing `rpassword` prompt + `CIPHERVAULT_PIN` /
   `CIPHERVAULT_READER` env contract, unchanged.
4. CI without hardware: extend the existing `SoftwareHsmSimulator` path
   (`crates/crypto/src/hsm.rs`) so the full init/restore/push token flow runs
   green on all three OS jobs with no reader attached.
5. Manual gate before claiming support: YubiKey 5 sign/unwrap round-trip on
   each OS, recorded in the release notes.

### Touch ID / Windows Hello requirements (alternate factor)

1. Platform crates behind the existing `HardwareSecurityModule` trait so CLI
   call sites (`--hardware-token`) need no changes.
2. Device-bound key attestation flow with a documented fallback when
   biometrics are unavailable (PIN/password, never silent software keys).
3. Explicit matrix update here once any row flips to Supported.

## 2. Editor and git integration (R17)

### Shipped: git hook contract

- `ciphervault hook install` writes `.git/hooks/pre-commit` (`ciphervault hook
  check`); `hook check` exits nonzero when a tracked confidential file is
  staged or a tracked file changed outside a snapshot, blocking the commit.
- Exit codes are the integration contract: `0` clean, nonzero with a
  `CRITICAL SECURITY ALERT` on stderr means blocked. Wrappers must surface
  stderr verbatim.

### Shipped: machine-readable status (gutter feed)

`ciphervault status --json` emits the gutter data contract (field names are
stable; additive changes only):

| Field | Meaning |
|---|---|
| `vault_id_hex`, `device_id_hex` | Identity (hex, 64 chars) |
| `current_epoch`, `device_counter` | Counters |
| `active_head_hex` | Head snapshot id, or `null` when no snapshots exist |
| `tracked_files` | Count of tracked confidential files |
| `operators` | Masked endpoints (`Operator (a.***.***.b):port` / canonical URLs) |
| `pending_uploads` | Unreplicated snapshots (amber gutter state when > 0) |
| `active_epoch_age_days` | Epoch age, or `null` when unknown |
| `active_epoch_stale` | `true` past `--warn-days` (default 90) or when unknown |

### Specified (not built): VS Code extension

Minimum viable gutter, in priority order:

1. Status bar item from `status --json` polling (green/amber/red from
   `pending_uploads`, `active_epoch_stale`, missing head).
2. Activity panel polling the dashboard `/api/activity` feed when
   `ciphervault dashboard` serves locally (watcher `WATCH_*` rows included).
3. Commands: snapshot, push, `prune --dry-run` preview, `rekey --check`.
4. Non-goals: the extension must never display or log decrypted secret values
   (the `run` command's env injection stays terminal-side), and must never
   bypass the pre-commit hook.

## 3. General platform notes (from `cfg` evidence)

- Release self-update, `run` command spawning, and browser opening carry
  explicit Windows/Unix/macOS branches and are covered by CI on all three OSs.
- The file watcher uses OS-native hooks (`ReadDirectoryChangesW`/inotify via
  `notify`) with interval-poll fallback, identical logic on all platforms.
- Line endings: Rust sources are pinned LF (`.gitattributes`); UI files carry
  historical mixed endings and are edited with ending-preserving tooling.
