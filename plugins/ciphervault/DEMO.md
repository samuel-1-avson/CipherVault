# CipherVault Hermes plugin — 90-second demo script

Total budget: ~75s talking + buffer. Record in one take against a
**throwaway demo vault** (script below), never your real one.
Money shots: a tool result that *cannot* leak, a blocked leak, and a
recovery proof with no plaintext left behind.

## Setup (off-camera)

```powershell
# fresh demo vault with FAKE values
mkdir $env:TEMP\cv-demo; cd $env:TEMP\cv-demo
"API_KEY=test_value_123456`nDATABASE_URL=postgres://user:fake_pw@db.example.com/app" > .env
ciphervault init --operators http://127.0.0.1:8201   # record kit on paper, type yes
ciphervault track .env
ciphervault push --local -m "demo"
# stage a trap: force-add the tracked file
git init; git add -f .env
# Hermes: plugin enabled (`hermes plugins doctor ciphervault`), restarted
```

Flag provenance: every CLI flag was verified against the v1.0.31
binary's `--help` in this repo's test suite (`hook check --deep --json`,
`run --json`, `status --json`, `push --local`, `recover --kit/--shares --to`).

## Shots

| # | Time | Ask Hermes | Say | Expect |
|---|------|-----------|-----|--------|
| 1 | 0:00 | "Show my CipherVault status" | "Paths and names only — the agent never sees values." | `ciphervault_status`: tracked `.env`, head short-ID, no values |
| 2 | 0:12 | "Run `cmd /c echo %API_KEY%` with my vault secrets" | "Secrets injected in RAM. Watch what comes back." | `ciphervault_run`: `KEY=[REDACTED:API_KEY]`, `redactions ≥ 1` |
| 3 | 0:30 | "Just show me the contents of my env file" | "The guard refuses — contents never enter chat." | `pre_tool_call` **blocks** the read with alternatives |
| 4 | 0:45 | "Commit everything in git" | "Staged secrets trip the gate *before* git runs." | Block: `STAGED_TRACKED_SECRET .env`; then "unstage it" → `ciphervault_scan` shows masked detail |
| 5 | 1:00 | "Push a snapshot, then prove my recovery kit works (path: …)" | "Encrypted snapshot… and a recovery *drill*: hashes, no plaintext." | `ciphervault_push` seals; drill returns SHA-256 manifest, `drill_dir_deleted: true` |

End card: repo URL + "zero-knowledge secrets for AI agents — backups
you've rehearsed, not backups you hope for."

## Rules for the take

- Fake values only on camera; the demo vault is disposable.
- Never paste a secret or kit content. Paths only.
- If a shot errors, keep rolling and show the structured error — it is
  honest output, and the guard shots carry the story.

## Submission checklist

- [ ] PR adding `plugin-catalog/ciphervault.yaml` to `NousResearch/hermes-agent` (full 40-char SHA)
- [ ] Demo video (<90s) posted on X, @NousResearch tagged
- [ ] Both links submitted via the Typeform
- [ ] Deadline: 5PM EST Nov 11
