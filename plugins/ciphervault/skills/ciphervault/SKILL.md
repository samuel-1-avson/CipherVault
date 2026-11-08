# CipherVault skill — secret hygiene for AI agents

Use CipherVault tools whenever secrets, `.env` files, keys, or tokens are involved.
Plaintext values must NEVER enter the context window.

## Hard rules
1. NEVER ask for, accept, or print kit/share CONTENTS. File paths only.
   R in the context window is a total compromise — the drill takes paths
   so the binary reads the kit, not the model.
2. NEVER wrap `init` as an agent action: init prints R. The user runs init
   in their own terminal; the agent only verifies afterwards.
3. Prefer `ciphervault_scan` before `git add` / `git commit`. If sprawl is
   found, fix the source file or add the finding to `.gitignore` manually
   (`fix` is compat-only; the tool does not autofix) — never paste values.
4. `ciphervault_status` shows keys only. Report key NAMES, never values.
5. `ciphervault_run` executes builds/tests/servers with env in RAM. Its output is
   already scrubbed — do not attempt to "recover" redacted values.
6. After modifying secrets, seal them with `ciphervault_push` (local_only unless
   the user asked to replicate).
7. If the binary is missing, tell the user: install `dist/bin/ciphervault`
   (invokable as `cv` or `ciphervault` — same binary) or set
   `CIPHERVAULT_BIN`. Do not invent tool output.

## Happy path
scan → (gitignore sprawl manually) → run --dry-run (confirm names) → run -- <cmd> → push -m "<msg>" (local `--local` default)
