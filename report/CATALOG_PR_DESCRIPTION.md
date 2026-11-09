# Catalog PR — ready to paste

**PR title:** `Add CipherVault plugin (zero-knowledge secrets for coding agents)`

**File to add:** `plugin-catalog/ciphervault.yaml` (contents in
`report/plugin-catalog-ciphervault.yaml` in the CipherVault repo,
pinned at `71a59408259fbeb7a01671fd3b621c4d13688a8e`).

---

## What it does

CipherVault gives Hermes a zero-knowledge vault for the secrets that pile
up in project directories:

- **6 tools:** vault status, masked secret-sprawl scan, RAM-only
  `run` (secrets injected into the child process environment; captured
  output scrubbed against the injected values themselves before the
  model sees it), encrypted snapshot push, recovery drill, and a
  `redact` stdin filter.
- **`pre_tool_call` leak guard:** blocks tool calls that would read
  secret files (.env, *.pem, id_rsa, credentials.json, recovery kits)
  or make dirty secret-bearing git operations.
- **`transform_tool_result` + `tool_request` middleware:** second and
  third scrubbing layers so values never enter the model context.
- **Secret source:** Hermes' own environment can be sourced from the
  vault via `ciphervault export-env` (machine-only output; refuses a
  terminal).
- **Desktop pane:** live vault status (binary version, tracked files,
  operator reachability) from the plugin's own backend.
- **CLI:** `hermes ciphervault bootstrap|status|doctor`.

## Rule 17 / binary disclosure (rule 13)

The plugin ships **no binary**. On Windows, `hermes ciphervault
bootstrap` downloads `ciphervault.exe` from the CipherVault repo's own
GitHub Release (v1.0.31, pinned in source), verifies it against a
SHA-256 pinned in the plugin source (`d31e7864…a717`) cross-checked
with the release `SHA256SUMS.txt`, and installs it under the plugin's
data dir. Linux/macOS users build from source or set `CIPHERVAULT_BIN`.
Network calls: GitHub Releases only, user-initiated. The plugin shells
out to that CLI for all vault operations; it never reads secret file
contents itself (paths only), and `init` is deliberately not wrapped
(it prints recovery material).

## Validation

- `hermes plugins validate plugins/ciphervault --install-deps` — passed
  (16 checks, no warnings).
- `hermes plugins doctor ciphervault` — 6 tools, 2 hooks registered.
- `pytest plugins/ciphervault/tests` — 25 passed.
- Clean-room proof: fresh `HERMES_HOME`, plugin copied in, bootstrap
  downloaded + checksum-verified the v1.0.31 binary, `doctor` returned
  live vault status.
