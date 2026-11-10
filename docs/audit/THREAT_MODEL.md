# CipherVault threat model

Companion to `docs/audit/README.md`. Source-backed against `main`
@ `ea22290` (v1.0.32). This is a model, not audit coverage;
runtime checks are NOT RUN by this document.

## Assets (in priority order)

| Asset | Where it lives | Loss means |
|---|---|---|
| Master recovery secret R (32 B) | Paper kit, guardian shares, passphrase backup | Total vault loss (by design) or total compromise |
| Vault epoch keys | Local store (OS-keyring wrapped), sealed envelopes on operators | Snapshot plaintext for that epoch |
| Device signing key | Local store (keyring-wrapped) or YubiKey PIV 9C | Forged snapshots/heads/audit entries as this device |
| Tracked plaintext files | User workspace | The thing being protected |
| Recovery signing/encryption keys (from R) | Derived on demand | Forged recovery authority |
| Audit chain + fleet checkpoints | Local DB + operator objects | Integrity of the agent-activity record |
| Operator service token | Fleet hosts' env; vault-tracked copy | Fleet admin (enrollment) compromise |
| Operator signing keys | Operator data dirs | Forged receipts/PoS, impersonated operators |

## Actors

- **Model/agent (untrusted with contents):** may issue any tool
  call Hermes exposes; must never receive secret values.
- **Workspace attacker:** can read/write project files (malicious
  repo content, prompt injection in files/issues).
- **Storage operator (honest-but-curious or malicious):** holds
  ciphertext; may drop, replay, or attempt to forge records.
- **Network attacker:** between CLI and operators (TLS + signed
  objects are the controls).
- **Same-OS-user attacker:** out of scope for software keys
  (stated openly); hardware token + OS keyring raise the bar.
- **Fleet admin / service-token holder:** trusted to enroll
  devices; cannot read vault contents.

## Boundaries and controls

1. **Model ↔ vault:** plugin `pre_tool_call` default-denies
   secret-path reads and secret-bearing payloads; `ciphervault_run`
   requires human approval (per-program rule key) and runs the CLI
   with a minimal allow-listed environment; tool results are
   exact-value + shape scrubbed before reaching the model.
2. **CLI ↔ disk:** values move by file path only; kit/share
   contents are never printed by tools; drill restores land in a
   tool-created temp dir deleted in `finally`.
3. **CLI ↔ operators:** device challenge/session auth with
   READ/WRITE scope; signed snapshot/head records; signed PoS
   receipts and lease receipts; operator identity pinned for
   recovery paths.
4. **Present ↔ past:** hash-chained, device-signed audit entries;
   signed content-addressed checkpoints anchored on push and on
   approval grants; `verify-remote` compares local vs anchored
   head.
5. **Device ↔ recovery authority:** device certificates carry
   authority generations signed by the recovery root; captures
   validate authority before advancing local state.

## Key scenarios

- *Agent tries `cat .env`, staged-commit exfiltration, or log
  pasting* → guard blocks / scrubber redacts / audit records.
- *Attacker with DB write access (no device key) edits audit
  history* → chain verification fails on content edits;
  `verify-remote` fails on tail truncation or divergence from the
  fleet anchor. An attacker who can execute code/sign as the same
  OS user can re-forge and re-anchor — out of scope without
  hardware device keys.
- *Malicious operator serves stale/forged objects* → record
  signatures, CID addressing, and head continuity checks reject.
- *Laptop lost* → kit/shares/passphrase restore on a clean
  machine; stale kits are refused by vault-ID mismatch.
- *Operator fleet lost* → local vault + kit re-replicates to a
  new fleet; fleet loss alone cannot decrypt anything.

## Assumptions and unknowns

- The OS keyring/DPAPI protection of at-rest local keys is
  assumed sound; not independently verified.
- Legacy custom KDF soundness is assumed, pending review (audit
  pack C1) — the single largest open cryptographic question.
- Hermes hook coverage bounds the agent boundary: tools or
  channels that bypass Hermes hooks are outside the model.
- Operator availability/independence is a deployment property
  (three VMs, one provider today), not a protocol guarantee.
