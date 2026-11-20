# CipherVault — secret hygiene for AI agents

Use CipherVault whenever secrets, `.env` files, keys, tokens, recovery
kits, or credential-bearing commands are involved. The vault is
zero-knowledge: encrypted on the client, operators store ciphertext.

## Hard rules

1. **Paths only, never contents.** Never ask for, accept, paste, or
   print recovery-kit/share *contents*, secret values, or private keys.
   Tools take file paths; the binary reads the files itself. A kit's
   contents (R) in the context window is a total compromise.
2. **Never wrap `init` as an agent action** — `init` prints the
   recovery secret. The user runs it in their own terminal; you verify
   afterwards with `ciphervault_status`. Same for any command whose
   stdout *is* a secret (`export-env` is for Hermes' secret source,
   never for chat).
3. **The lifecycle & guard hooks are load-bearing.**
   - `on_session_start` resets per-session posture caches and binds
     `session_id` into audit receipts.
   - `pre_llm_call` injects a compact cached 1-line workspace posture
     summary (seal state, policy profiles, pending secret prompts) on
     turn 1 and whenever vault posture changes.
   - `pre_tool_call` blocks secret-file reads/searches/writes (including
     `search_files` and `browser_*` tools), secret-dumping CLI commands,
     and `git` add/commit/push (even with global flags like `-C`) while
     sprawl violations exist or `hook check` fails inside a vault.
   - `transform_tool_result` scrubs other tools' results (fail-closed in
     vault workspaces).
   If a call is blocked, do not route around it — fix the cause (unstage,
   `.gitignore`, `ciphervault track`) and retry.
4. **Prefer, in order:**
   - `ciphervault_run` (RAM-only; every call asks the user for approval
     first — that prompt is expected, never ask the user to disable it;
     pass `profile` when `.ciphervault/policy.toml` defines workspace
     execution profiles; custom proxy upstreams live in
     `.ciphervault/policy.toml` only, never as an agent parameter);
   - `ciphervault_env_doctor` to diagnose missing keys, unused keys,
     `.env.example` drift, and malformed `.env` values without reading
     plaintext secrets;
   - `ciphervault_secret_generate` to generate cryptographically strong
     random secrets directly inside the vault (`ciphervault vault generate`,
     preserving all previously sealed keys with zero plaintext written by
     Python); defaults to `overwrite=false`. Every call asks the user for
     approval, and `overwrite=true` needs its own one-time approval;
   - `ciphervault_secret_prompt` to queue a secure secret input prompt in
     the CipherVault desktop pane (or interactive TTY via `vault set --stdin`)
     when human-supplied API keys or credentials are missing — never ask the
     user to paste secrets into chat. It asks for approval too, and the
     TTY prompt asks again before replacing an existing key;
   - both secret tools only work inside an existing vault: pass the
     vault's `cwd`, and keep `env_file` inside it (never `.ciphervault/`
     or the Hermes home). Outside a vault they are blocked;
   - `ciphervault_diff` to inspect masked key-level diffs between snapshots
     or against the working tree (never passes `--reveal`);
   - `ciphervault_status` with `history_limit` to list recent snapshots
     (newest first, IDs and recorded times only), then
     `ciphervault_restore_preview` with one `snapshot_id` to see what a
     restore would create, replace, or leave unchanged. The preview is
     read-only; never restore on the user's behalf — give them the
     `ciphervault restore` command it returns;
   - `ciphervault_status` with `watcher_health: true` when the user asks
     whether an edit was backed up. Keep "change detected", "snapshot
     captured", and "remote backup verified" apart, quote recorded times as
     recorded (not live checks), and say "unknown" when the evidence is
     missing or stale — never "running" without a fresh heartbeat;
   - `ciphervault_redact` to mask text you must quote;
   - `ciphervault_status` for names/paths and sealed status;
   - `ciphervault_scan` before any git operation;
   - `ciphervault_push` after secret edits (honors `[vault] sealed_mode = true`
     in `.ciphervault/policy.toml` by defaulting `shred_working_copy=true`);
   - `ciphervault_recovery_drill` to prove recovery (it hashes, then
     deletes the plaintext — trust the manifest, don't re-read files).
5. **Redacted means redacted.** Output marked `[REDACTED]` was a real
   value. Never try to reconstruct, guess, or ask for it.
6. **Binary missing or withheld output?** Say so and point to
   `hermes ciphervault doctor`; a compatible CLI (source build or a
   release with `exact_values_complete`) goes in `$CIPHERVAULT_BIN`.
   Never invent tool output, scan results, or hashes.
7. **The audit log is the receipt.** Blocks, approvals, scrubs, generated
   secrets, and your writes are hash-chained and device-signed in the
   vault (enriched with `session_id`). When a user asks what you touched,
   answer from `ciphervault_audit` — and note its verification result;
   don't summarize from memory.
8. **`.ciphervault/policy.toml` is human-owned.** Never attempt to edit
   `policy.toml` or override its `allow_keys` (supports `*` glob patterns
   such as `TEST_*` as an upper bound), `require_keys`, `no_net`, `proxy`,
   `require_explicit_approval`, or pinned `upstreams` boundaries.

## Happy path

`env_doctor → scan → fix sprawl (.gitignore / track) → secret_generate / secret_prompt (if needed) → run (dry-run or profile first) → run → diff → push -m "…" → drill after kit/share changes`

## Hermes secret source

With `secrets.ciphervault.enabled: true`, Hermes itself sources env
vars from the vault at startup (`vault_path`, `env_file`,
`allow_working_copy`). Mention this when a user wants their *agent*
environment backed by the vault, not just their project runs.
