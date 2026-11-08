# Fleet Re-architecture — make the operator network operable

**Problem (from the 2026-11-08 audit):** the fleet works but cannot be *operated*.
Version drift is invisible (`/v1/info` had no build identity), config is
decorative (TOMLs unread, launcher flags diverge), onboarding is a human
(`POST /v1/identities` needs the service token out-of-band), updates are SSH
snowflakes, and contributors have no path from "I have a server" to "I serve
replicas." Every mystery of the past two days traced to one of these.

**Principle:** make the boring things true — versioned, reproducible, observable —
before adding clever things. No protocol changes in Phase 1.

## Phase 1 — visibility + reproducibility (this week)

1. **Version identity (DONE).** `OperatorInfo` now carries `binary_version`
   (crate version) + `build_sha` (baked via `CIPHERVAULT_BUILD_SHA`, wired
   through `Dockerfile.operator` `ARG GIT_SHA`). Unsigned informational
   fields — descriptors stay verifiable across releases. Dashboard +
   maintenance daemon should alert on fleet version skew (follow-up).
2. **One build pipeline.** `docker compose build` from a pinned commit is the
   *only* supported artifact path. Delete `dist/bin` from the release story
   (keep for dev). Tag images `ciphervault-operator:<short-sha>`, never `latest`
   in production compose.
3. **Config reckoning.** Either wire a real config loader (TOML → CLI flags,
   flags win) or delete every TOML the binary ignores. The `.example` rename
   is the interim state — decide within one cycle. `start-operators.bat` must
   match compose ports or go away.
4. **Drift dashboard.** Maintenance daemon already heartbeats operators: add
   `binary_version`/`build_sha` to the fleet view + SSE telemetry. A red cell
   for "behind HEAD" replaces forensic archaeology.

## Phase 2 — safe rollout (next)

5. **Rolling update as code.** `scripts/fleet-update-node.sh` exists; promote
   it to a compose profile with health-gated progression (next node only
   starts after the previous passes `/healthz` + a canary `push`/`recovery
   test). Rollback = re-tag previous digest, never rebuild old code.
6. **Metrics story.** Decide: loopback-only + in-VPC scraping, or authed
   proxy. Until then, `CIPHERVAULT_METRICS_PUBLIC` stays unset (= open) on the
   public fleet — document that as tech debt with an owner and date, not as
   accepted posture.
7. **Enrollment onboarding.** Today: human with the service token. Minimum
   viable self-service: time-boxed join tickets (`JoinInvite` flow already
   exists for P2P) extended to HTTP enrollment — ticket grants exactly one
   enrollment of stated `(vault, key)` with default perms, single-use, logged.
   Fleet admin stays a separate, explicit, logged action (R6 split already
   landed server-side; this is the UX on top).

## Phase 3 — contributor path (the "compute contribution" story)

8. **Runbook for third-party operators:** hardware floor (disk for 64 MiB/log
   caps + object store, bandwidth for gossip), the exact compose file + env
   template, how to open firewall (443 → Caddy → 820x), how to request fleet
   admission (send operator key + endpoint; admin enrolls + adds to
   `CIPHERVAULT_TRUSTED_PEER_KEYS`).
9. **Trust ladder for new nodes:** join as `probation` (existing mechanism) →
   serve reads only → graduate to writes after N clean audit cycles →
   repair-eligible. Probation exclusion from repair recipients already exists;
   add the read-only middle rung + graduation criteria.
10. **Economics (D4 vouchers) as the anti-spam layer for open enrollment:**
    single-profile enforcement already landed (R7); remaining is UX — how a
    new operator gets its first quota grant without a human signing it.

## Explicit non-goals

- No self-updating binaries (catalog rule 03; the SHA pin *is* the trust model).
- No in-band TLS termination changes until the reverse-proxy story is written.
- No PoS nonce freshness change (wire compat) — next protocol version.
- No GC/expiry for logs/objects until retention policy is a product decision
  with a migration path for existing replicas.

## Acceptance

- `/v1/info` on every fleet node reports a `build_sha` within one deploy of HEAD.
- A new operator goes from bare VM to serving reads with zero SSH into existing nodes.
- `dist/bin` no longer advertised as a deployment artifact.
- This doc's Phase 1 items are done when the drift dashboard shows all green.
