# The verifiable agent audit log: proving a model never saw a secret

*A pattern for agent hosts and secret tooling, distilled from
CipherVault's Hermes plugin (open source, MIT/Apache-2.0). Steal
the design; cite the implementation if it helped.*

## The problem

Coding agents leak secrets through ordinary work: reading `.env`
into context, printing keys in command output, staging them into
commits. Tooling that merely *stores* secrets safely does nothing
about the runtime path. And after a run, "the model never saw it"
is normally an assertion nobody can check.

## The pattern (five parts)

1. **Deny by default at the tool boundary.** The agent host's
   pre-tool-call hook rejects reads of known secret paths and
   payloads containing secret material, before the tool runs.
   Legitimate access goes through a dedicated channel (secret
   *names* and masked fingerprints are fine; contents are not).
2. **Gate execution, narrowly.** Any call that will receive secret
   values (e.g. running a command with injected env) requires
   human approval. Make the approval grant *per program*
   (`run:<program>`), so "always allow" never becomes "allow
   everything." Spawn with a minimal allow-listed environment so
   host credentials never leak into children.
3. **Scrub, then log the scrubbed output's hash.** Every tool
   result is redacted (exact injected values + credential shapes)
   before reaching the model. The audit entry records
   `SHA-256(exact_text_that_reached_the_model)`. Later, any output
   can be checked: **hash present in the chain ⇒ it passed the
   scrub; absent ⇒ it didn't.** Log grants and paths, never values.
4. **Chain and sign the log.** Entries are hash-chained
   (`prev_hash` links, SHA-256 over a canonical preimage) and
   signed with the device key (Ed25519). Verification recomputes
   every link and signature and names the first bad entry.
   Appends must be transactional or concurrent writers fork the
   chain.
5. **Anchor off-machine, at the right cadence.** Periodically —
   and *at the moment a high-risk grant is recorded, before the
   approved action runs* — publish a signed, content-addressed
   checkpoint (entry count + head hash) to storage the agent
   doesn't control. Remote verification must **fail**, not warn,
   when the local chain is shorter than the anchor (tail
   truncation) or diverges at the anchored position.

## What the proof does and does not establish

- Establishes: which tools touched which paths, what was blocked,
  what was approved, and whether a given model-bound output
  passed the scrub — with tamper evidence up to the last anchor.
- Does not establish: anything about channels that bypass the
  host's hooks (screenshots, unmanaged processes); nor protection
  against an attacker who can sign as the device (same-OS-user) —
  that needs hardware-backed signing keys.

## Failure modes we hit (so you don't)

- A verify command that *prints* divergence but exits 0 is worse
  than none: automation reads success. Fail closed.
- Substring hash matching lets a forged row "prove" an output;
  require exact field equality on a *verified* chain.
- Anchor cadence matters: anchoring only at the end of a run lets
  a bad run present a tidy, unanchored chain.
- A missing hash means "never scrubbed" only if the scrub path is
  actually mandatory; document the boundary.

## Reference implementation

CipherVault's Hermes plugin + `ciphervault agent-log`
(`show | verify | check | anchor | verify-remote | export`):
https://github.com/samuel-1-avson/CipherVault — design and
adversarial review notes in `docs/audit/`. The pattern itself is
host-agnostic: any agent runtime with tool-call interception and
a signing key can implement it.
