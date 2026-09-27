# CipherVault Mainnet Readiness

**Gate status: `NOT MAINNET READY`** — 3 of 6 blockers verified,
3 blocked on external dependencies.
Evidence date: 2026-09-26. Binaries under test: v1.0.17; live fleet
re-closed same date (~23:07–23:11 UTC).

## Blocker table

| Blocker | Implementation | Tested | Executed | Evidence | External dependency | Status |
|---|---|---|---|---|---|---|
| 1. External audit / pen test | Readiness package written | n/a (external) | No | `docs/SECURITY_AUDIT_READINESS.md` | Auditor engagement + report | `BLOCKED — EXTERNAL AUDIT PENDING` |
| 2. Key rotation drills | Procedures existed | Yes (live + unit) | Yes, 2026-09-26, exit 0 | `docs/KEY_ROTATION_DRILLS.md` | None (live-fleet ceremony is follow-up, not gating the drill) | `VERIFIED` (rehearsal scope) |
| 3. Fleet re-close | Flags + compose on 3/3 nodes | Yes, live per-node | Yes, 2026-09-26 (anon challenge 200→400 all nodes; firewall hold documented) | `docs/FLEET_RE-CLOSE_EVIDENCE.md` §6 | None (firewall deletion is follow-up hardening, not gating) | `VERIFIED` |
| 4. Updater signatures | Ed25519 verification shipped | Yes, 137/137 + CI wiring | Yes — v1.0.18 signed; published sig independently verified (SIG-OK) | `docs/UPDATER_SIGNATURE_VERIFICATION.md` | None | `VERIFIED` |
| 5. Mainnet anchoring | Plan exists | Gates evaluated, red | No (correctly — gates red) | `docs/MAINNET_PROMOTION_EVIDENCE.md` | Blockers 1–3 + ceremony + funds | `BLOCKED — EXTERNAL DEPENDENCY` |
| 6. Legal review | Review package written | n/a (external) | No | `docs/LEGAL_REVIEW_PACKAGE.md` | Owner `legal`: formal sign-off | `BLOCKED — LEGAL REVIEW PENDING` |

## What each status means here

- `VERIFIED`: requirement satisfied with implementation + execution +
  verification + documentation in the repo. Blocker 2's scope is the
  rehearsal drill the ceremony doc demands before federation/mainnet;
  Blocker 4's enforcement goes live with the next signed release (one
  secret-setup step remains; the code refuses unsigned releases).
- `OPEN` (Blocker 3): the remaining step is a concrete operational
  execution, fully specified, with its verification procedure already
  proven on a rehearsal node.
- `BLOCKED — …`: closed only by the named external party; preparation
  packages are complete so no engineering work gates them.

## Remaining actions (ordered)

1. [DONE 2026-09-27] Release secret set, v1.0.18 cut and signed,
   signature independently verified (Blocker 4 `VERIFIED`).
2. [DONE 2026-09-26] Fleet re-closed live (Blocker 3 `VERIFIED`).
3. Engage auditor with `docs/SECURITY_AUDIT_READINESS.md` (Blocker 1);
   run the live soak in parallel (Blocker 5, gate 2).
4. Submit `docs/LEGAL_REVIEW_PACKAGE.md` to `legal` (Blocker 6).
5. With 1–4 green: execute mainnet promotion (Blocker 5).

## Risk classification

- Highest: custom KDF + deterministic nonces unreviewed (audit target #1).
- High: live fleet writable by anonymous keypairs until re-close executes.
- Medium: single offline fleet seed; bearer vouchers; lease-expiry (not
  crypto-erasure) deletion — all documented with mitigations/acceptances.
