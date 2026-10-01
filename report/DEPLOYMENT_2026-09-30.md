# CipherVault 1.0.26 release and deployment ledger

Date: 30 September 2026 (UTC/Africa/Accra)

The authorized remediation was merged, released, and deployed to the operator fleet and hosted web service. This ledger records the release, production verification, and recovery evidence; it does not imply that the remaining assurance work is complete.

## Starting state

- Repository audit baseline: a9df97dfee9ae64f9c82ce48d9c4ddc67176dc78.
- Dashboard and account service were on v1.0.25. The three storage operators were on v1.0.21.
- The hosted account database contained 4 accounts, 3 devices, 1 TOTP credential, and 2 sessions, with no secrets or scoped-secret versions.
- Four pre-change VM disk snapshots reached READY: cv-audit-20260930-web, cv-audit-20260930-op1, cv-audit-20260930-op2, and cv-audit-20260930-op3. These remain available as infrastructure rollback points; disk snapshots are not application-consistent backups.

## Code, test, and release evidence

PR [#13](https://github.com/samuel-1-avson/CipherVault/pull/13) merged as 4966a5ce057b81ac0ee8795881133cad91f8c3ac. Its code and release tag v1.0.26 passed the main-branch checks. The release workflow [36779365526](https://github.com/samuel-1-avson/CipherVault/actions/runs/36779365526) completed successfully: the full pre-release gate, six supported binary archive builds, all four container builds, vulnerability scans, Cosign signing, GitHub release publication, and package-manager hash generation.

The [v1.0.26 release](https://github.com/samuel-1-avson/CipherVault/releases/tag/v1.0.26) contains the six platform bundles and a V2-authenticated SHA256SUMS file. The signed image identities were verified against the exact release workflow at refs/tags/v1.0.26. The scan gate rejects fixable High and Critical findings.

The package-manager hash update PR [#14](https://github.com/samuel-1-avson/CipherVault/pull/14) merged as 30acd4a210ef73a2c29a4e08c494783088d63fb4 after DCO, GitGuardian, and Sourcery review checks passed.

Local verification passed 826 tests with 0 failures and 3 existing ignored tests across 81 result blocks. Formatting, strict all-target Clippy, Rust 1.89 checks, browser CSP, DOM/landing/container checks, installer signature cases, cloud key-bootstrap cases, and release packaging regressions passed. The dependency audit found no known vulnerabilities apart from the explicit time-limited paste maintenance exception. The hosted browser CI job uses a CI-only Chrome sandbox flag because the hosted runner cannot start Chrome’s zygote sandbox.

## Production deployment

The operator fleet was promoted sequentially, with pre-health checks, pinned digest pulls, post-restart readiness checks, and version assertions. Each node reports v1.0.26, and each VM’s RepoDigests was independently checked against the release digest:

| Service | Production digest | Result |
| --- | --- | --- |
| Operator fleet | sha256:3ddc93805a69799d9d476a4698101afacbc0daf8b95d735c1fd5223643792bc2 | All three nodes report v1.0.26 and pass health checks |
| Dashboard | sha256:49ea0d281066f6e07df086177264fa603331f5254be33d53ccc7ab74c874ab9d | Running healthy as the non-root ciphervault user |
| Account service | sha256:8737d5f5dc04d6b9aa3966cfb3a34189d044f3edc82568fe2617ec46a5cc3da2 | Running healthy as the non-root ciphervault user |

The prior signed rollback images are retained: operator sha256:524ae05ef2bab9abce8f00f625c39bd71c5ba37bf5869fd2a665f7fd09ab1155, dashboard sha256:72e4c78a3e74f41670c2d0d838600b302f05a04a73514d605a3c4059e4f1d548, and account sha256:9b218c124de3b872ac72405a2797d94af7828b170a4e48b434414eae99742f03. The web promotion script verified candidate and rollback signatures, validated Caddy configuration, switched the VM to cv-web-runtime@gen-lang-client-0022105784.iam.gserviceaccount.com, and asserted the live build version. Caddy emitted existing non-fatal header and formatting warnings; configuration validation succeeded.

Post-deploy checks confirmed build_version 1.0.26, successful /api/vault, /api/operators, and /api/account/capabilities routes, and HTTP 401 for an anonymous /api/account/session request. All three operator endpoints returned ready with storage_ready true. The web containers report the expected immutable digests, run as ciphervault, and are healthy.

Secret Manager scope-token key version 2 was added and is enabled; version 1 remains enabled for rollback. Rotation invalidates any previously issued stateless scoped-token bearers, so clients retaining one must obtain a fresh token. The live database contained no scoped-secret versions at deployment.

## Account backup and restore evidence

Before promotion and again after the v1.0.26 restart, the signed account image created an online SQLite backup with the live data volume mounted read-only. Offline restore rehearsals used the existing protected KEK and TOTP key files. Both rehearsals returned verified_isolated_restore, decrypted the one retained TOTP seed, revoked the two sessions in the copied database, and reported production_modified false. No key material was included in either backup.

The post-deploy archive is 14,485 bytes, with archive SHA-256 6de2f16a5ffb36c2fd427b3ae2ec998429acefce10c9513425e58050505f03fd and database SHA-256 fcd5db795a7461de26a5dc62f16ee62a6265a5cb8959dfa0c2d75932fed1389b. Its private GCS object is:

gs://ciphervault-account-backups-108687509435/releases/v1.0.26/post-v1.0.26-20260930T2317Z/account-backup.tar.gz

The object was downloaded after upload and its SHA-256 matched the protected workstation copy. The pre-deployment archive was 14,451 bytes, with archive SHA-256 bf87ff0d9dadcb135418c396e7838a4f1906d004705aa132ecd79417bf9aef93 and database SHA-256 cff7852a5de0a0bc33ff89cf54d44833f955d78151eba11efa19323345965e66. Its GCS object is releases/v1.0.26/pre-v1.0.26-20260930T2210Z/account-backup.tar.gz. Workstation copies are in the user-restricted local folder C:\Users\samue\AppData\Local\CipherVault\Recovery-20260930, outside OneDrive.

The bucket enforces uniform bucket-level access and public-access prevention, with object versioning and a seven-day soft-delete window. It is in the same GCP project, so it does not provide independent organizational custody. The backup command’s receipt is a corruption check, not a signature or authenticity proof.

## Remaining assurance work and process risks

Production writes remain on the v1 capture format. Independent cryptographic review is required before enabling v2 writes; F13/F21 remain open for existing v1 captures and history. The live database had no scoped-secret versions, so the production restore rehearsal could not exercise decryption of retained secret values; synthetic regressions cover those paths. No external cryptographic audit or physical-token ceremony is claimed.

TOTP is available but is not enforced as a second factor. Independent cloud/key custody, provider/KMS adapters, retention and compaction policy, and production capacity characterization remain open work. The recovery bucket is in the same project and the seven-day soft-delete policy is not a substitute for an independent retention custodian.

Repository policy blocked ordinary merges for PRs #13 and #14. PR #13 had no qualifying human peer review available; PR #14 had Sourcery approval and its required checks passed. Administrator merges were used to complete the user-authorized release. Restore an available human review path and avoid routine policy bypasses before the next release.

One synthetic failed-test fixture remains in a local temporary folder because automatic approval review rejected its cleanup as “blocked by policy.” An operator identity inspection also created an unused nested identity; only that newly created file and empty directory were removed after checking their path, timestamp, and contents. The active production identity remained unchanged.

See the [remediation report](AUDIT_REMEDIATION_2026-09-30.md), [original project audit](PROJECT_AUDIT_2026-09-30.md), and [release notes](../dist/RELEASE_NOTES.md).
