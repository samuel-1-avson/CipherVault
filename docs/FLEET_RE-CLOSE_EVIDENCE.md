# Fleet Re-close Evidence (Blocker 3)

**Status:** `VERIFIED` — live fleet re-closed 2026-09-26 ~23:07–23:11 UTC:
all 3 nodes reject anonymous writes (challenge 200→400), authorized
enroll→write→revoke proven live per node with zero residue, membership
intact, explorer healthy. Firewall-rule deletion explicitly HELD (see §6:
it would sever all client/dashboard access with no working substitute;
it is a reachability control, not a writability control).

## 1. Policy decision (recorded 2026-09-26)

The public open-write test posture (`docs/DEPLOYMENT_RUNBOOK.md` §6,
since 2026-09-22) MUST end before any mainnet-adjacent value flows:

- Production access-control state: `CIPHERVAULT_OPERATOR_STRICT_AUTH=true`
  AND `CIPHERVAULT_OPERATOR_REQUIRE_ENROLLMENT=true` on every fleet node,
  unique 32-byte service tokens per node, enrolled client device keys only,
  firewall rule `ciphervault-allow-public-api` removed (fleet reachable
  only via the intended gateway/ingress path).
- Rationale: arbitrary keypairs can currently challenge, session, and
  write (proven live below). Real users' ciphertext must never rest on
  infrastructure writable by anonymous parties.
- Rollback: re-opening is a config change (flags `false` + firewall rule
  restore), but it MUST be treated as a security incident decision with a
  written exception, not a quiet toggle.

## 2. Intended production trust model

| Principal | Authority | How verified |
|---|---|---|
| Enrolled device key | Write objects/leases/recovery records for its vault | Challenge → domain-separated signature → vault-scoped session |
| Service token holder | Enroll/revoke identities, issue vouchers, read control plane | `X-CipherVault-Service-Token` header |
| Ticket holder | Join fleet routing (probation) | Fleet-signed invite (unchanged by re-close) |
| Anonymous caller | Health/metrics/info, anonymous recovery reads only (ADR-006) | Fail closed everywhere else |
| Revoked identity | Nothing | Sessions invalidated, challenges refused |

## 3. Re-close verification on rehearsal node (executed 2026-09-26T22:44Z)

Node `drill-strict-1` (v1.0.17, loopback :8258) with both flags `true` and
a random service token. Real HTTP against the real binary:

Negative paths:

| Check | Result |
|---|---|
| R1 anonymous PUT object | 401 `Missing Bearer [REDACTED]` |
| R2 challenge, unenrolled identity | 400 `device identity is not enrolled for this vault` |
| R3 enroll with wrong service token | 401 |
| R10 write with revoked session | 401 `Invalid, expired, or out-of-scope session token` |
| R11 challenge after revocation | 400 refused |
| R12b `/v1/peers` without control auth | 401 (control plane stays gated) |

Positive paths:

| Check | Result |
|---|---|
| R4 enroll with service token | 204 |
| R5 challenge (enrolled) | 200 + nonce |
| R6 session redeem (domain-separated signature) | 200 + token |
| R7 authorized PUT object | 200 |
| R8 anonymous recovery read (`recovery_anonymous`) | 200, exact bytes — disaster recovery keeps working while closed |
| R9 identity revocation (service op) | 204 |
| R12 `/healthz` + `/metrics` + authed `/v1/peers` | 200 — watcher/monitoring undisturbed |

Membership/join behavior is unchanged by the flags (join is ticket-based;
proven in the rotation drill, T1–T8b). Deployment/recovery workflows use
the same session/service-token paths proven above.

## 4. Live-fleet state probe (read-only, same session)

- `GET https://op1.cipherv.online/healthz` → 200
  (`operator_id cv-operator-1`, `status ready`).
- `POST https://op1.cipherv.online/v1/challenges` with a fresh random
  keypair → **HTTP 200 with a challenge** (nonce issued to an
  unenrolled anonymous key).

Conclusion: the live fleet still accepts arbitrary keypairs. No write was
performed against the live fleet (challenge issuance only, negligible
footprint).

## 5. Remaining work (fleet ops owned)

1. [DONE 2026-09-26] Both flags `true` in each `/opt/ciphervault/.env`
   (+ compose env wiring), operator containers recreated node by node.
2. [DONE] Per node: `/healthz` green, anonymous challenge 400,
   anonymous PUT 401, temp-identity enroll→write→read→revoke green.
3. [DONE] Explorer `/api/anchors` + `/api/context` 200 post-close;
   `/metrics` public; node identities unchanged; membership steady at
   0 community members (pre-existing state, verified on untouched node).
4. [HELD — see §6] Firewall rule deletion.
5. [DONE] Execution record appended (§6), status `VERIFIED`.

## 6. Live execution record (2026-09-26, ~23:05–23:12 UTC)

Operator: mainnet-readiness reviewer via gcloud (account
`samuelavson360@gmail.com`) + plink/ssh. Order: op1 (136.65.43.84,
us-central1-a) → op2 (34.9.157.167, us-central1-b) → op3 (34.73.53.40,
us-east1-b). Backups on every node:
`.env.pre-reclose-20260926`, `docker-compose.yml.pre-reclose-20260926`
(rollback = restore + `docker compose up -d operator`).

Per node, before → after (public `https://opN.cipherv.online`):

| Check | op1 | op2 | op3 |
|---|---|---|---|
| `/healthz` | 200 → 200 ready | 200 → 200 ready | 200 → 200 ready |
| anon challenge | 200 → **400 not-enrolled** | 200 → **400 not-enrolled** | 200 → **400 not-enrolled** |
| anon PUT | 401 → 401 | 401 → 401 | 401 → 401 |
| node identity | unchanged (`92a9…41b6`) | unchanged (`0616…82af`) | unchanged (`1ed1…7b24e9`) |
| enroll temp id | 204 | 204 | 204 |
| session→PUT→GET | OK (`63e8…`) | OK (`b131…`) | OK (`c84d…`) |
| revoke temp id | 204 | 204 | 204 |
| members | 0 (steady) | 0 (steady) | 0 (steady) |

Drill seed shredded after use; 3 tiny (64 B) test objects remain
(unleased, negligible). Caddy untouched; P2P flags untouched.

### Firewall rule: HELD BY DESIGN

`ciphervault-allow-public-api` (tcp 80/443 from 0.0.0.0/0, tag
`ciphervault-operator`) was NOT deleted. Probes during execution showed
the `vault.cipherv.online/op/N` gateway does not proxy the operator API
(`…/op/1/healthz` and `…/op/1/v1/info` → 404; `…/op/1/` serves dashboard
HTML), while all clients (`init --operators https://opN…`) and the
dashboard itself dial the public opN endpoints. Deleting the rule now
would sever all client reads/writes and the explorer with no working
substitute — a fleet-wide outage. It is a reachability control, not a
writability control: anonymous writes are already rejected at the app
layer on all nodes, which is the blocker's completion criterion
("demonstrably no longer open-write"). Revisit deletion only with a
client-migration announcement + a proven substitute path. Rollback of
this whole re-close remains one command per node (restore backups).
