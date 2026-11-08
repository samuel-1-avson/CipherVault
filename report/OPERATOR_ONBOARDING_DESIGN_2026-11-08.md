# Operator Onboarding — contributor path design (re-architecture Phase 3, item 1)

**Goal:** a stranger with a server goes from zero to serving replicas with
no SSH into existing nodes and no shared secrets, while the fleet never
trusts an unvetted key with writes.

**What already exists (reuse, don't rebuild):**
- P2P probation: `join_with_invite` (fleet-signed ticket → probation member,
  excluded from repair recipients) + `register_peer` (service-token admin)
  + graduation to full member (`methods_peers.rs`, `swarm` repair filter).
- HTTP device enrollment (`POST /v1/identities`, service-token gated).
- `is_routing_member` gate on repair election (R12) — probationers can never
  win pusher elections even if they announce.
- Join-ticket types (`JoinInvite`/`JoinRequest`, quorum-capable signatures).

**What's missing (the actual work):**
1. **Join request queue.** New endpoint `POST /v1/peers/join-requests`
   (public, rate-limited): contributor submits node descriptor + contact.
   Stored as its own `join-requests.json` inbox (resubmits update in place,
   512-cap, survives restarts), visible via new control-authed
   `GET /v1/peers/join-requests`. No trust
   granted — it's a labeled inbox, not access.
   **Status: IMPLEMENTED + VERIFIED 2026-11-08** (`submit_join_request` /
   `list_join_requests`, handlers, routes, `tests/join_requests.rs` 3/3 green;
   live HTTP: POST 200 pending + control-plane GET returns the record,
   tampered descriptors 400). One-command approval (step 2) still open.
2. **One-command approval.** `POST /v1/peers/join-requests/{id}/resolve`
   (`approved`/`rejected`; 404 unknown, 409 decided) +
   CLI `ciphervault invite requests --via <url>` (inbox review) and
   `ciphervault invite decide <id> approved|rejected --via <url>` (approval
   prints the node key for the existing offline `invite issue` ceremony).
**Status: IMPLEMENTED + VERIFIED 2026-11-08** (`resolve_join_request`, handler,
route, `tests/join_requests.rs` 4/4; full operator suite green; live HTTP:
approve 200, re-resolve 409, unknown 404, bad word 400, auth gate 401/200 —
after fixing the route to Axum `:param` syntax and adding the missing
service-token check the doc audit caught. FULL LOOP proven with real
binaries: request → inbox → approve → offline `invite issue` →
`invite join` → admitted to probation.)
3. **Contributor runbook command.** CLI: `ciphervault invite apply --node
   <own-endpoint> [--contact ...] --via <fleet>` on the *new* node: fetches
   its fresh self-signed descriptor, submits it to every fleet endpoint,
   prints the request id + the three next steps (send id out of band →
   receive ticket → `invite join`). No service token needed; polling was
   deliberately omitted (the ticket arrives out of band, so there is no
   joiner-visible state to poll — approval alone doesn't admit).
**Status: IMPLEMENTED + VERIFIED 2026-11-08** (`cmd_invite_apply`, `invite apply`
subcommand; proven live: real CLI submitted a real joiner descriptor, fleet
returned pending + request id with correct next-step instructions).
4. **Graduation policy (documented defaults).** Probation on ticket-join is
   time-served + liveness-proven, not a human gate:
   - A joined node enters `Probation`. Every verified refresh/heartbeat
     updates `last_seen_utc`; once `now - joined_utc >= CIPHERVAULT_PROBATION_SECS`
     (default compiled in `limits.rs`, floor 60s), the next liveness event
     flips it to `Full` automatically (`note_peer_liveness`,
     `note_peer_heartbeat` — the membership file is written only on the
     transition edge, not per heartbeat).
   - During probation the `POST /v1/peers/join` response reports
     `"probation"`; probationers can serve reads but are excluded from
     repair recipients and can never win pusher election (`R12`
     `retain_eligible_recipients` + `is_routing_member` gate) — a hostile
     or broken newcomer cannot blank or poison repair traffic.
   - `POST /v1/peers/:id/graduate` (control-plane) is the admin override:
     confers `Full` immediately, 404 for unknown ids. Use it when a known
     operator rejoins with a fresh key, not to skip vetting strangers.
   - Repair *eligibility* (trusted-keys set) stays separate from *membership*
     (`Full`): graduation admits a node to the routing table; entrusting it
     with repair traffic is an explicit later decision. Never auto-grant.
   - Liveness has a grace window (`CIPHERVAULT_JOIN_LIVENESS_GRACE_SECS`):
     a node silent past grace is pruned, not graduated — silence never
     promotes.
**Status: POLICY DOCUMENTED 2026-11-08 from implemented mechanics; no code
changes needed.** Remaining hardening (not blocking): dashboard surfacing
of probation counts; alert when a node sits in probation past 2× the
configured window (likely a dead joiner holding a spent ticket).

**Explicit non-goals:** no open enrollment (Sybil + disk-fill), no automatic
promotion (a human or quorum approves every step up), no shared secrets
(service tokens never leave operator hosts; tickets are single-use and bound
to one node key).

**Verification for each step:** existing suites (`dht_records`, `swarm`,
`rendezvous`, `audit_regressions`) + a new `join_flow` integration test:
request → approve → probation (reads OK, repair excluded) → graduate
(writes OK) → revoke (all closed). Reuse the `CIPHERVAULT_ENABLE_RAW_DHT_PUT`
test-only pattern for adversarial cases.

**Order of implementation:** 1 (queue, ~1 endpoint + table rows) → 2 (CLI
approve, reuses ticket issuance) → 3 (join UX, client-side only) → 4 (policy
docs + graduation transitions).
