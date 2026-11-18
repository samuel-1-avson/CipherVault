# CipherVault Platform Support Matrix (R16/R17)

Explicit support statement for hardware-bound factors, OS key protection,
agent network sandboxing, and editor/git integration. Last reviewed for
v1.0.35.

**How to read the status words.** *Supported* means implemented and exercised
on that OS. *Implemented, unverified* means the code path exists and compiles
for that target, but has not been run on a real host of that OS (hosted CI,
the only automated non-Windows coverage, is currently paused). *Gap* means not
built. Do not rely on an *unverified* path for production secrets until it
has been run and recorded in the release notes.

## 1. Hardware-bound factors and OS protections (R16)

| Factor | Windows | macOS | Linux |
|---|---|---|---|
| PIV smartcard / YubiKey (`--hardware-token`) | Supported (WinSCard PC/SC FFI in `crates/crypto/src/piv.rs`) | Implemented, unverified (`PCSC.framework`) | Implemented, unverified (`libpcsclite`, loaded at runtime) |
| OS keyring for epoch/device keys | Supported: DPAPI (user-bound) | Implemented, unverified: Keychain via `/usr/bin/security`; falls back to the 0600 file keystore | Implemented, unverified: Secret Service via `secret-tool`; falls back to the 0600 file keystore |
| `run --no-net` network sandbox | Supported: AppContainer | Implemented, unverified: `sandbox-exec` | Implemented, unverified: `unshare` |
| Touch ID / Windows Hello | Gap | Gap | n/a |
| Hosted WebAuthn (account service) | Supported (server-issued options) | Supported | Supported |

Notes:

- The PC/SC transport is selected per OS. A host without a PC/SC library
  (for example no `libpcsclite.so.1` on Linux) fails token operations with a
  descriptive `HsmError` instead of crashing or misbehaving.
- On non-Windows hosts the key order is: explicit `CIPHERVAULT_MASTER_KEY` /
  `CIPHERVAULT_KEYSTORE_PATH`, then the OS credential store, then the
  `portable_keystore` file. A fresh install provisions a credential-store key
  when it can; set `CIPHERVAULT_REQUIRE_OS_KEYRING=1` to fail instead of
  falling back to the file. The file keystore is real AEAD, but its key lives
  in a 0600 file at `CIPHERVAULT_KEYSTORE_PATH` or
  `$HOME/.config/ciphervault/keystore.key`. Provisioning is exclusive and
  non-destructive; malformed/unreadable existing keys fail closed. Its threat
  model protects against offline casual reads and cross-user snooping on
  multi-user machines; it does NOT bind to OS identity or a TPM. Do not claim
  equal device binding across platforms until the unverified paths are run.
- `run --no-net` fails closed: where no sandbox is available the command is
  refused rather than run with network access. On Windows the child runs in an
  AppContainer, so programs that need files outside its readable locations
  (for example third-party Python packages) can fail to start; use `--proxy`
  or run them without `--no-net`.

### macOS/Linux: gates before claiming support

The macOS and Linux PC/SC FFI modules, the Keychain and Secret Service key
backends, and the `unshare` / `sandbox-exec` sandboxes are implemented. These
gates remain open:

1. CI without hardware: the existing `SoftwareHsmSimulator` path
   (`crates/crypto/src/hsm.rs`) should run the full init/restore/push token
   flow green on all three OS jobs with no reader attached.
2. Manual gate: a YubiKey 5 sign/unwrap round-trip on each OS, recorded in the
   release notes.
3. A live run of the Keychain, Secret Service and `--no-net` paths on real
   macOS and Linux hosts.

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
  explicit Windows/Unix/macOS branches. They are meant to be covered by CI on
  all three OSs, but hosted CI is currently paused, so the non-Windows branches
  are unverified for v1.0.35.
- The file watcher uses OS-native hooks (`ReadDirectoryChangesW`/inotify via
  `notify`) with interval-poll fallback, identical logic on all platforms.
- Line endings: Rust sources are pinned LF (`.gitattributes`); UI files carry
  historical mixed endings and are edited with ending-preserving tooling.
