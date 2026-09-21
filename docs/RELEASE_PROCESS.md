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

## Cutting a release

1. Bump the version on the release track (workspace `Cargo.toml`,
   `dist/scripts/install.*`, scoop/homebrew/winget manifests, docs).
2. Commit and push; wait for CI green on `main`.
3. Tag (`git tag vX.Y.Z`) and push the tag; confirm the release workflow
   and the published release + GHCR digests.
4. Promote to the cloud per `docs/DEPLOYMENT_RUNBOOK.md` §10/R4.
