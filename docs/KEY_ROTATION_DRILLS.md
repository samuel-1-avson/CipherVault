# Key Rotation Drills (Blocker 2) — Execution Evidence

**Drill date:** 2026-09-26T22:44:30Z – 22:45:xxZ (UTC), script exit 0, 35/35 checks PASS.
**Status:** `VERIFIED` at rehearsal scope. Live-fleet rotation remains a
human step per the ceremony doc; this drill was its required prerequisite.

## Environment

- Binaries: `ciphervault 1.0.17`, `ciphervault-operator 1.0.17` (workspace
  tip, debug build of the exact tree under review).
- Host: Windows rehearsal machine, loopback only, ports 8251–8258.
- Fleet node `drill-fleet-1` (:8251), second fleet node `drill-fleet-2`
  (:8256), joiners `drill-join-1..4` (:8252–8255), strict node
  `drill-strict-1` (:8258, used in the re-close drill), dashboard (:8257).
- Fleet seeds A/B: fresh random 32-byte offline files (drill-only, never
  reused, seeds never leave the drill dir listing — only pubkeys below).
- Operator of the drill: mainnet-readiness reviewer (roles: fleet admin +
  joiner + publisher in one rehearsal).

## Key identifiers (public halves only)

| Key | Pubkey (truncated) |
|---|---|
| Fleet A (pre-rotation) | `f12ea534…fae6` |
| Fleet B (post-rotation) | `0e2d1f6e…da8731` |
| Publisher PA (pre-rotation) | `d7a571e0…540d1e` |
| Publisher PB (post-rotation) | `85b781fc…48cdb` |

Full values are in the drill transcript excerpts below.

## Drill 1 — Fleet-key rotation

Preconditions: F1 pinned to A (`CIPHERVAULT_FLEET_KEY=pubA`), `/healthz`
green, empty membership.

Procedure (real CLI + HTTP, transcripted):

1. `invite pubkey` for seed A → matches expected pubkey (T0).
2. Boot J1; `invite issue <J1-key> --fleet-key-file A` → ticket;
   `invite join ticket --node J1 --via F1` → admitted, probation
   (T1). `GET /v1/peers` shows J1 (T1b).
3. Same-node rejoin with the original ticket → admitted (T2). This is
   the documented grace rejoin (`docs/TESTNET.md`): a spent nonce is
   re-presentable only by the admitted member (`state.rs`
   `spend_invite`; 409 fires only for non-members and is unit-covered
   in `state.rs` + `handlers.rs`).
4. J2 presents J1's ticket → rejected client-side ("different node
   key", exit 1) (T2b). Ticket-to-node binding holds.
5. B-ticket for J2 while pinned to A → rejected, exit 1 (T3); direct
   `POST /v1/peers/join` → HTTP 403 `invite issuer mismatch` (T3b).
6. Rotation: stop F1, restart pinned to B. `/healthz` green, J1 still a
   member (T4/T4b). Membership state before: {J1}; after restart: {J1}.
7. Fresh A-ticket for J3 → rejected (T5). Old key dead.
8. B-ticket for J3 → admitted (T6). New key live. Membership: {J1, J3}.
9. Restart F1 again → {J1, J3} persist (T7). Rotation survives restarts.
10. Partial rotation: F2 boots pinned to A. A-ticket for J4 admitted
    via F2 but rejected via F1 (T8) — mixed fleet is observable per
    node, so rotation must complete on every node. Re-pin F2 to B:
    A-tickets rejected on both nodes (T8b).
11. Lost-seed handling: seed file removed → `invite issue` fails closed
    ("read key file", exit 1) while the fleet keeps serving `/healthz`
    and existing members (T9/T9b). Consequence stands as documented:
    with the seed gone no new tickets can ever be issued, so membership
    would need a re-bootstrap — the drill confirms the failure is a
    clean refusal, not corruption.

Membership before rotation: `{drill-join-1}` (probation).
Membership after rotation: `{drill-join-1, drill-join-3}` (+`drill-join-4`
on F2), all probation, all surviving two restarts.

## Drill 2 — Publisher-key rotation

Preconditions: throwaway vault (`ciphervault init` against F1), publisher
seeds PA/PB as env `CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX`.

Procedure:

1. `publish-public-feed --output feed-A.json` under PA → envelope
   carries `publisher_key_hex = pubPA` (P1).
2. Re-publish under PB → envelope carries `pubPB`, signature differs
   (P1/P2). Publisher state before: PA; after: PB.
3. Stale-feed rule: feed-A key ≠ pin PB is detectable; feed-B key =
   pin PB matches (P3/P4) — the exact-match rule the dashboard
   enforces (`public_checkpoint_publisher_key_pinned`).
4. Live dashboard (`ui --serve`, `CIPHERVAULT_PUBLIC_CHECKPOINT_FEED` +
   `CIPHERVAULT_PUBLIC_CHECKPOINT_PUBLISHER_KEY`): `/api/anchors` with
   matching pin → HTTP 200 (P5). (Feed held 0 checkpoints — fresh
   vault, no anchored evidence — so the check proves pin/file plumbing,
   not a populated `publisher_signed` row; see remaining work.)
5. Committed regression test `publisher_key_rotation_drill`
   (`apps/cli/src/dashboard/finality.rs`, in the 136-test green run):
   PA-signed feed verifies `publisher_signed` under pin PA; after the
   pin rotates to PB the stale PA feed is rejected ("not the pinned
   publisher key"); the PB reissue verifies `publisher_signed`. This
   executes the real sign/verify/pin code path with assertion-level
   evidence.

## Failure/recovery matrix

| Scenario | Result |
|---|---|
| Old key after rotation | Rejected (T5, T8b) |
| New key after rotation | Accepted (T6) |
| Stale credentials (cross-node ticket) | Rejected (T2b) |
| Spent nonce, non-member | 409 by unit-tested code path |
| Partial rotation | Observable mixed state, resolved by completing rotation (T8→T8b) |
| Lost/invalidated key | Issuance fails closed, fleet keeps serving (T9/T9b) |
| Restart/recovery | Membership + pins persist (T4, T7) |

## Unexpected behavior / lessons

1. Grace rejoin initially looked like a replay bug; it is documented
   intended behavior (same admitted member, original ticket). Drill
   asserts it explicitly now (T2).
2. Joiner descriptors report endpoint `http://127.0.0.1:8201` unless
   `CIPHERVAULT_ADVERTISE_ENDPOINT` is set — cosmetic default, not a
   membership defect.
3. A mid-drill partial cleanup once reused stale node data; the harness
   now uses a fresh timestamped dir per run and aborts on dirty state.
   Lesson for fleet ops: rotation runbooks must verify node identity
   (`--print-identity`) after every restart, never assume it.

## Remediation actions from the drill

- None required in product code: every rejection/acceptance behaved as
  designed. The drill's value was confirmation, not bug-finding.
- Committed: `publisher_key_rotation_drill` regression test (deliverable 8).

## Remaining work (out of rehearsal scope)

- Live-fleet fleet-key rotation (human ceremony with the real
  `fleet.seed`; procedure validated here).
- Dashboard `/api/anchors publisher_signed` confirmation with a
  populated feed (needs anchored checkpoints; crypto rotation itself is
  verified above).

## Artifacts

- Full command transcript: drill dir `C:\tmp\cvdrill-20260926-224428\transcript.txt`
  (loopback-only run; contains drill pubkeys, no secrets).
- Per-node logs: same dir (`*.log`). Key excerpts: versions
  `ciphervault 1.0.17`, `ciphervault-operator 1.0.17`;
  `fleet pubA=f12ea534ff996a3ad53bed0343787be5284c1da4a44d998ee1cbed40f796fae6`,
  `fleet pubB=0e2d1f6e2fe708e8f1aad7a0a9d564088c9857c0c3760d7efd075dbf11da8731`;
  final line `=== done: 0 failures: [] ===`, script exit 0.
