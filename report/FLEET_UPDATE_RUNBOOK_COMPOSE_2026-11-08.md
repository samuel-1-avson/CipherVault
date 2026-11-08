# Public fleet update runbook (compose) — ship R1–R13 to op1/2/3.ciphervoline

Target state: operator image built from source at/after the remediation
branch (has: identities routes, cursor pagination, rate limiter, healthz,
join plane, quota flags, R3–R13 hardening). Current state: serves
`/v1/identities` but 404s `/v1/chain/publish` and predates every R-fix.

Deployment reality (verified in-repo): each box runs
`deploy/docker-compose.prod.yml` — images build from the repo
(`deploy/docker/Dockerfile.operator`), data lives in named volumes
(`opN_prod_data`), env comes from `/opt/ciphervault/.env` with strict
flags defaulting to `true`. Rollback = re-up the previous image
(keep it tagged).

## 0. Prep (your workstation → each box)

```bash
ssh -i ~/.ssh/google_compute_engine <user>@136.65.43.84   # op1, us-central1-a
# op2: 34.9.157.167 (us-central1-b) | op3: 34.73.53.40 (us-east1-b)
# (gcloud CLI on this machine is broken — bad python path — use ssh -i directly)
```

## 1. Per box, in order op1 → verify → op2 → verify → op3 (quorum holds 2/3)

```bash
cd /opt/ciphervault   # compose project dir (docker-compose.yml + .env live here)

# 1a. snapshot configs (data itself lives in docker volumes, untouched by rebuild)
cp .env .env.pre-r13-$(date +%F)
cp docker-compose.yml docker-compose.yml.pre-r13-$(date +%F)
# 1b. keep the current image for instant rollback
docker tag $(docker images -q ciphervault-operator 2>/dev/null | head -1) ciphervault-operator:pre-r13

# 1c. pull the remediation branch and rebuild ONLY the operator image
git -C /opt/CipherVault fetch origin && git -C /opt/CipherVault checkout <remediation-branch>
docker compose build operator-1   # (operator-2 / operator-3 on their boxes)

# 1d. recreate just that service; the volume (keys, objects, logs) is preserved
docker compose up -d operator-1

# 1e. confirm the new binary is serving (old image answers these differently)
curl -fsS http://localhost:8201/healthz
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8201/v1/chain/publish \
  -H 'Content-Type: application/json' -d '{}'
# ^ expect 422 (route exists, bad body). 404 = old image still running → stop, check.
curl -s "http://localhost:8201/v1/recovery/$(python3 -c 'print("00"*32)')/records?cursor=0"
# ^ expect {"records_hex":[]} — proves cursor pagination works
```

## 2. Fleet-wide verify (from your workstation, no secrets needed)

```bash
for n in 1 2 3; do
  echo "== op$n"
  curl -s -o /dev/null -w "chain:%{http_code} " -X POST https://op$n.cipherv.online/v1/chain/publish \
    -H 'Content-Type: application/json' -d '{}'; echo
  curl -s -o /dev/null -w "metrics:%{http_code}\n" https://op$n.cipherv.online/metrics
  # ^ chain=422 (not 404) and metrics=200 for now — see §3 on why metrics stays public this round
done
# then one client push + one recovery test against the fleet before calling it done
```

Also confirm: `docker logs` shows no `non-strict` warnings on any box
(strict is default-on; any such line means a box is running open).

## 3. Env changes: DELIBERATELY NOTHING in this rollout

Leave `/opt/ciphervault/.env` exactly as-is. Two conscious non-changes:

- **Do NOT gate metrics yet.** Your explorer scrapes public `/metrics` today;
  flipping the loopback gate without moving scraping first would blind
  monitoring. Gate it in a follow-up once scraping moves inside the VPC or
  behind an authed proxy (`CIPHERVAULT_METRICS_PUBLIC` stays unset = open
  until then — code default is deny, env opt-in re-opens).
- **Do NOT set `CIPHERVAULT_OPERATOR_ALLOW_FLEET_ADMIN_GRANT`.** Default
  (unset) strips `FLEET_ADMIN` on *new* enrollments; existing identities keep
  theirs, and the 2026-09-26 drill flow used default READ|WRITE temp
  identities, which are unaffected.

New knobs available when you want them (all default-safe, none required):
`CIPHERVAULT_RECOVERY_READ_LIMIT_PER_MIN` (default 60),
`--max-voucher-quota-bytes` (only matters with `--require-write-vouchers`,
which stays off), `CIPHERVAULT_ENABLE_RAW_DHT_PUT` (leave unset),
`CIPHERVAULT_TRUSTED_PEER_KEYS` (set once P2P repair is enabled fleet-wide).

## 4. Rollback (per box, < 2 min)

```bash
cd /opt/ciphervault
docker tag ciphervault-operator:pre-r13 ciphervault-operator:current
docker compose up -d operator-1
# data dir is append-only; no schema migration shipped, so rollback is image-only
```

## Notes

- The drill fleet's `STRICT_AUTH=false` + open-enrollment config must never be copied to these boxes.
- `start-operators.bat` and `dist/bin` are dev-machine artifacts; fleet truth is compose + repo source.
- `vault.cipherv.online/op/*` gateway 404s the operator API (serves dashboard HTML) — clients must keep dialing `opN.cipherv.online` directly; do not "fix" by proxying until a substitute path is proven.
- Supersedes the systemd variant (fleet runs compose per `docs/FLEET_RE-CLOSE_EVIDENCE.md`).
