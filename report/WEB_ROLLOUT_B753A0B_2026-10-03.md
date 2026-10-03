# Web rollout evidence: edge main-b753a0b (2026-10-03)

PR #25 (audit-export paging OOM fix) merged 17:49 UTC; edge build
37141936318 SUCCESS. Promoted in one move: OOM fix + explorer guidance
(recovery notice + session summary, c883acc) now live.

## Promoted digests (attested to b753a0b, cosign-verified pre-promotion)

- Dashboard: `ghcr.io/samuel-1-avson/ciphervault-dashboard@sha256:ebf9b0760524ca266bac09f10099ddee01365142950680bdb5a42bdbf786fbe2`
- Account: `ghcr.io/samuel-1-avson/ciphervault-account@sha256:738352bb2930a76443ce1bb8175a306235818b91bc6cefd2ccf20a0db9c0a75b`
- Identity: `edge-images.yml@refs/heads/main`, cert `githubWorkflowSha`
  `b753a0bfb8801b2017c6f52967817c5dce64ccab`, both exit 0.

## Rollback digests (release-signed, verified under release identity)

- Dashboard: `ghcr.io/samuel-1-avson/ciphervault-dashboard@sha256:a2cee5149746462d20b16f26c792964f66211c491d2833cd8301caac7598c123`
- Account: `ghcr.io/samuel-1-avson/ciphervault-account@sha256:92a7d03ea7772c08192ebf5d423dc531ca6aa7a97b8f0abf4d7e296bac33836d`
- Identity: `release.yml@refs/tags/v1.0.28`, both exit 0.
- Rollback: re-run the driver with these as the new images (staged
  automatically by the script).

## Procedure

- Dry run (`promote-immutable-web.ps1` without `-Apply`, pins read raw
  from live metadata): exit 0 — attestations verified, VM pulled
  candidates, Caddyfile `Valid configuration` (pre-existing header_up /
  formatting warnings only).
- Apply: exit 0 — config staged, VM stopped, runtime identity +
  metadata switched, VM restarted, health endpoint responding, live
  deployment verified by the script's own probes.

## Post-rollout verification (independent)

- Instance metadata images == promoted digests (both).
- Running containers: `ciphervault-ui-ciphervault-ui-1 ebf9b0760524`,
  `ciphervault-ui-account-1 738352bb2930` (prefix match).
- `GET https://vault.cipherv.online/api/context` → `build_version`
  `1.0.28`, `mode` `public_explorer`.
- `GET /` serves both new markers: `hosted-session-summary`,
  `recovery-public-note`.
- `GET /api/operators` and `GET /api/explorer/overview` → 200.
- Paged export: live image attested to b753a0b (contains
  `verify_and_export_audit_page` + cursor paging); the 3 new export
  tests passed in CI on the merged commit. An authed live page-walk
  needs Alice credentials + dual-control step-up (owner-only, optional).

## Notes

- Driver used: `C:\tmp\rollout-b753a0b.ps1` (scratch, not committed).
- Token scope gap: `gh` token lacks `read:packages`, so digests were
  resolved via `docker buildx imagetools inspect` on the public
  `main-b753a0b` tags instead of the packages API.
