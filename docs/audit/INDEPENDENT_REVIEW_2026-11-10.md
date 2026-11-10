# Independent reviewer pass — crypto core (2026-11-10)

Two fresh reviewers (who did not write this code) reviewed the
v1.0.32 tagged tree (`ea22290`): (A) KDF + chunk encryption +
format/CID; (B) recovery (Shamir/kit/CVKB1) + audit chain +
certificates. Full findings with file:line citations are
summarized here with maintainer dispositions. Method note: this
is an independent *internal* review (separate reviewers, source +
targeted tests), **not** the external audit — that engagement is
still open (`docs/audit/README.md`).

## Fixed in this change

| ID | Sev | Finding | Fix |
|---|---|---|---|
| B-F1 | HIGH | `agent-log verify-remote` printed anchor divergence but exited 0 | Now fails (non-zero) on broken local chain, truncation (fewer local entries than anchored), or divergence at the anchored position; ancestor check via the anchored entry hash. Live-verified both directions against the production fleet, including a truncated scratch copy. |
| B-F2 | HIGH | `agent-log verify` alone cannot detect tail truncation | Documented precisely (invariant 4 rewritten); detection is `verify-remote`'s job and is now enforced (B-F1). |
| B-F4 | MED | `agent-log check` used substring matching and did not verify the chain — a forged row could "prove" an output passed the scrub | Lookup now requires exact `output_sha256` field equality **and** a fully verifying chain before any hit is reported. |
| B-F8 | LOW | Audit append was non-atomic (concurrent appenders could fork the chain) | Prev-read + insert in one transaction. |
| A-F7 | LOW | v2 HKDF helper silently returned a zero key/nonce on (unreachable) expand error | Aborts on the unreachable error instead of emitting predictable key material. |
| A-F8 | LOW | Audit spec misstated the default chunk protocol (code defaults to v2; spec said v1) | Spec corrected (§1, §3); guarantees doc already correct. |
| A-F3 | LOW | Spec diagram claimed v1 file keys are vault-bound; code binds epoch+plaintext only | Diagram corrected; v2 binds vault. Recorded as defence-in-depth gap for v1. |
| B-F9 | LOW | `gf_mul` code comment overstated ("eliminate timing") | Comment now scopes the claim to source-level branchlessness. |

## Accepted / open (recorded, not silently dropped)

| ID | Sev | Item | Position |
|---|---|---|---|
| B-F3 | MED | Same-OS-user attacker can re-forge + re-anchor the audit chain | Accepted risk, already declared out of scope; threat-model wording corrected so it no longer overclaims. Hardware (PIV) audit signing is the real fix — future work. |
| B-F5 | MED | Device certificates: no expiry, revocation, or persisted generation floor; operator withholding can roll recovery back to an older generation | Open design item. Needs a generation-floor pinned in the recovery kit + revocation semantics. Tracked here until designed; auditors please treat as in-scope (pack C6). |
| B-F6 | MED | Kit v2 checksum is optional/strippable, absent from printable kits; kit vault-ID and operator endpoints are unauthenticated (downstream checks blunt this to DoS/stale-rollback, not cross-vault decryption) | Open. Printable-kit v2 + authenticated endpoints need a format revision. |
| A-F1/F2 | HIGH/MED (legacy) | v1 objects: candidate confirmation from a bare file hash (unsalted offline oracle), plus file grouping/structure/change-pattern leakage beyond the previously documented set | Applies only to legacy/opt-out and historical v1 objects — default writes are v2 (keyed IDs, verified by reviewer A to close confirmation for operators without the epoch key). Leakage model now stated completely in the guarantees doc. Recapture migrates objects to v2. |
| A-F5 | MED | Canonical-CBOR *decoding* accepts non-canonical encodings/trailing bytes; two CID notions (re-serialized vs raw bytes) can disagree across paths | Open. No forgery found (AEAD + CID + whole-file checks bind interpreted fields), but content addressing should be one function: strict decode (re-encode-compare) is the planned fix. |
| A-F6/B-F7 | LOW | AAD concatenation relies on caller-enforced 32-byte fields; kit `open_envelope` API verifies no signature (in-flow use is signed via `trust::select_envelope`) | Open hardening items. |

## Verified sound by the reviewers

- Legacy KDF domain separation: injective fixed-width inputs,
  distinct contexts and total lengths per construction; truncation
  safe; masters always CSPRNG-generated. (Still a non-standard
  construction — external review remains the open gate, pack C1.)
- Nonce reuse with distinct plaintext requires SHA-256/HKDF
  collisions in both v1 and v2; identical-chunk reuse is the
  intended dedup.
- Shamir: information-theoretic privacy below threshold, unbiased
  coefficient generation, no reuse; GF(2^8) arithmetic
  exhaustively KAT-verified; no secret-dependent indexing.
- CVKB1: Argon2id 64 MiB/t=3/p=4, authenticated header-as-AAD,
  fail-closed unknown KDF ids, indistinguishable errors.
- Sealed envelopes in-flow: device-signed, bound to
  vault/epoch/device/recipient; low-order points rejected.
- Audit chain vs non-signing attackers: mid-chain edits,
  deletions, reorders detected with first-bad-entry; anchoring
  refuses broken chains; checkpoints are signed and
  content-addressed (the gap was enforcement, now fixed).
