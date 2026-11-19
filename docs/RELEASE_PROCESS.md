# Release Process

Short version: `main` is always validated by CI; a **tag** is what spends
money. Tag only to ship something real.

## When to cut a release

- A cloud promotion needs new GHCR images, or
- Users need new installables (installer, packages, updater payload).
- Ordinary merges, hardening batches, and docs ride on CI alone — no tag.

## Versioning

- Stable semver: `1.0.7`, then `1.0.8`, … for each shipped release.
- Pre-release suffixes (`-beta.N`, `-rc.N`) only while a version is still
  settling; graduate to stable instead of stacking endless betas.
- The updater treats a final release as newer than any prerelease with the
  same core, so beta users upgrade cleanly to stable.

## What a tag costs

Each `v*` tag runs the full release matrix: 6 binary targets (Windows,
Linux glibc, Linux ARM64, musl, 2× macOS) plus 4 multi-arch container
images with SBOM, SLSA provenance, and cosign signatures. This is a
private repo, so minutes are billable — macOS legs cost 10x Linux.

Cost controls already in the workflows:

- `Swatinem/rust-cache` on every Rust job (per-target keys on the matrix),
  so repeat builds reuse dependencies instead of recompiling from scratch.
- `cross` installs from a pinned prebuilt binary, not git source.
- `cancel-in-progress` on CI and releases: a newer push kills the stale run.
- Docs-only pushes (`docs/**`, `report/**`, `*.md`) skip CI entirely.
- Container builds use registry-layer caching (`type=gha`).

## Edge images (cloud deploys without a release)
`edge-images.yml` builds the dashboard + account images from `main` (server/container changes only, plus manual dispatch) and pushes `edge` and `main-<sha>` tags with SLSA provenance and keyless cosign signatures - no version bump, no 6-target matrix. Promote an edge digest with the usual script, overriding the signature identity and asserting the base Cargo version:
`scripts/gcp/promote-immutable-web.ps1 ... -ExpectedBuildVersion <cargo-version> -CosignCertificateIdentityRegex 'https://github.com/samuel-1-avson/CipherVault/.github/workflows/edge-images.yml@refs/heads/main'`
Caveat: edge images share the base version string, so the live version assertion cannot distinguish two edge builds - record the promoted digest. Prefer edge for urgent cloud-only fixes; cut a release for anything user-facing.

## Cutting a release

Preconditions — check before anything else, and record the result in the
release-prep PR:

- `gh workflow list` shows the CI workflows **enabled** (not
  `disabled_manually`), and a recent `gh run list` shows jobs actually
  starting. "Job was not started because your account is locked due to a
  billing issue" means hosted CI is down: either restore it, or ship
  local-only with that limitation stated in `dist/RELEASE_NOTES.md`
  (the v1.0.31–v1.0.35 pattern) — never claim CI validation that did
  not run.
- Release prep lands by **pull request**, so the required status checks
  gate it. If a direct push bypasses branch protection in an emergency,
  record that fact and the reason in the PR/notes that follows.

Checklist:

1. Bump the version on the release track: workspace `Cargo.toml`, then
   run `node scripts/sync-version.cjs` and confirm
   `node scripts/sync-version.cjs --check` passes (covers
   `apps/ui/index.html`, `apps/ui/app.js`, and the README badge; landing
   strings are updated at deploy time via
   `scripts/deploy-web.sh --expect vX.Y.Z`). Update
   `dist/scripts/install.*` and the scoop/homebrew/winget manifests, and
   write the `dist/RELEASE_NOTES.md` entry **before** tagging, marked
   "in preparation" until the tag exists.
2. Run the full local battery and record the observed counts in the PR:
   `cargo test --workspace --locked --no-fail-fast`,
   `python -m pytest plugins/ciphervault/tests/test_plugin.py -q`,
   `python -m pytest tests/mcp/test_mcp_server.py -q`,
   `node --test plugins/ciphervault/tests/desktop_plugin.test.mjs`, and
   `node apps/ui/audit.test.cjs`. Numbers copied from an earlier run or
   a handoff brief are not verification.
3. Merge the release-prep PR; wait for CI green on `main` (or record the
   local-only exception per the preconditions).
4. Tag (`git tag vX.Y.Z`) and push the tag; confirm the release workflow
   and the published release + GHCR digests. The workflow's
   `fill-manifest-hashes` job commits the winget/scoop/brew hashes to
   `main` automatically — verify that commit landed before announcing.
5. **Hermes re-pin (follow-up PR, after assets exist).** The plugin pins
   per-platform SHA-256 values in `plugins/ciphervault/binary.py`, so it
   cannot move in the same commit as the version bump. Once the release
   assets and `SHA256SUMS.txt` are published, update `RELEASE_VERSION`
   and `RELEASE_ASSETS`, the pin assertions in
   `plugins/ciphervault/tests/test_plugin.py`, and the plugin README;
   re-run the plugin suite. Until that PR merges,
   `hermes ciphervault doctor` warns that a current CLI differs from the
   pinned target — expected, not a defect.
6. Promote to the cloud per `docs/DEPLOYMENT_RUNBOOK.md` §10/R4.
6b. Within 24 h of the tag, promote that tag's dashboard+account
    digests to the web VM (`scripts/gcp/promote-immutable-web.ps1`
    with `-ExpectedBuildVersion X.Y.Z`, rollback images set to the
    currently live digests), or record an exception below with an
    owner and a new deadline. Rationale: releases that never reach
    the web UI strand users on stale builds (1.0.9 served while
    1.0.14 was current, Sep 2026).
7. Staleness check: `GET https://vault.cipherv.online/api/context`
   `build_version` MUST equal the just-cut tag before announcing.
   If it does not, either run step 6b now or record the exception;
   never announce a release the web UI does not serve.
8. Clean up: remove merged release/swarm worktrees
   (`git worktree remove <path>`, then `git worktree prune` — prune
   alone does not remove worktrees that still exist on disk) and delete
   merged branches (`git branch -d`).

## Release exceptions (rule 6b log)

| Tag | Exception | Owner | Deadline | Status |
|-----|-----------|-------|----------|--------|
| v1.0.14 | Web still serves 1.0.9; promote deferred to DON production-push Unit 4 | fleet ops | Unit 4 execution | closed 2026-09-24 (`/api/context` = 1.0.14, digests verified) |
