# CipherVault Hermes plugin — 90-second demo script

Total budget: ~70s talking + 20s buffer. Record in one take against the
live repo vault. The money shot is redaction: secrets go in, `***` comes out.

## Setup (before recording, off-camera)

- Hermes restarted with the plugin enabled (`hermes plugins doctor ciphervault` → 5 tools, 1 hook).
- Vault operators reachable (local fleet or persistent fleet).
- One staged trap: `echo "STRIPE_TEST=sk_test_demo123" >> secrets.env` (or stage a scratch `.env`).

## Shots

Flag provenance: every CLI flag named below was verified against
`cv.exe --help` (v1.0.29) — `push -m/--message`, `recover --kit/--to`.
No other CLI flags appear in this script.

| # | Time | Do (in Hermes chat) | Say | Expect |
|---|------|---------------------|-----|--------|
| 1 | 0:00 | "Show my CipherVault status" → `ciphervault_status` | "Keys only. The agent sees names, never values." | Tracked files + head, no values |
| 2 | 0:15 | "Run my tests with secrets in RAM" → `ciphervault_run` with `["npm","test"]` (or any command) | "Secrets are injected in memory. Watch the output." | Command runs; values show `***redacted***` |
| 3 | 0:35 | "Scan for secret sprawl" → `ciphervault_scan` | "It catches the staged file — masked, nothing leaks into context." | Sprawl flagged, values masked |
| 4 | 0:50 | "Snapshot it" → `ciphervault_push` with message `rotate db creds` (`-m`, verified in `push --help`) | "Encrypted snapshot, sealed locally. Operators see ciphertext only." | Local snapshot sealed (replicated only when `local_only=false`) |
| 5 | 1:05 | "Prove my recovery kit works" → `ciphervault_recovery_drill` with the kit **path** (wraps `recover --kit <path> --to <tmpdir>`, both flags verified in `recover --help`) | "Paths only — the kit contents never enter the chat. Clean-machine restore, bit-for-bit." | Restore succeeds into a temp drill dir; diff it against working files, then delete it |

## Rules for the take

- Never paste a secret or kit content on camera. Paths only.
- If any tool errors, keep rolling — the scan/push outputs are the story.
- End card: repo URL + "zero-knowledge secrets for AI agents".

## Submission checklist

- [ ] PR adding `plugin-catalog/ciphervault.yaml` to `NousResearch/hermes-agent` (full 40-char SHA pin)
- [ ] Demo video posted, @NousResearch tagged
- [ ] Both links submitted via the Typeform
- [ ] Deadline: 5PM EST Nov 11
