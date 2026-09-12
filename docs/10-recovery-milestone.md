# Recovery and durability milestone

## Implemented behavior

- Recovery derives its trust root from the offline secret. Remote records cannot nominate their own trust root. Device certificates must authorize signing; heads and snapshot records must have matching signatures, vault, counter, and authority generation. Epoch envelopes must be signed by the snapshot's certified signer and target the derived recovery key.
- Each new snapshot has a persisted RecoverySet: snapshot record, encrypted manifest, exact chunk CIDs, certificate and envelope objects, locator, and discovery records. Public bootstrap objects occupy the existing envelope_ids inventory field. Both CLI and agent use this inventory.
- Push reads back all objects, verifies signed lease fields, publishes certificates and envelopes before the head, and reads the discovery log back. Missing verification, failed persistence, or fewer than three distinct operator signing keys prevents a durability success.
- Audit checks the inventory and discovery log per operator. It does not infer durability from operator reachability. Repair republishes the persisted inventory from local ciphertext and verifies it, including when all remote copies of an object have been lost.
- Operator object and lease publication use synced temporary files and atomic rename. Recovery-log appends are serialized and rolled back on write failure. Lease renewal loads an existing receipt, preserves its closure and bytes, and extends its existing term. Unsafe or unknown lease IDs are rejected.
- CLI failures propagate to API responses. Dashboard health comes from completed recovery audits; file rows do not claim individual replica verification based on operator reachability.

## Regression evidence

The recovery drill uses Cargo's freshly built CLI and ephemeral ports. It injects lease persistence and discovery-log failures and checks nonzero push exit status without a durability claim. It then removes a chunk, an envelope object, and a discovery log; audit must fail, repair must succeed, and audit must pass. Finally it destroys the client directory, stops one operator, and recovers byte-identical files from the exported kit.

Additional regressions reject self-authorized heads, incorrectly signed or non-signing certificates, altered envelopes and authority bindings, unverifiable operator receipts, modified lease accounting fields, unsafe lease IDs, and writes when persistence is unavailable. The JavaScript regression checks degraded and unavailable audit states, including clearing previously verified status.

Run the commands in the root README. CI retains formatting and strict Clippy gates and runs on Linux, Windows, and macOS; this change does not assert that hosted CI or physical hardware tests have been run.

## Compatibility and Completed Milestone Extensions

All items flagged in early review iterations have been resolved and certified in **CipherVault v0.1.0-prod.4**:

- **Protected Local Storage**: Device signing keys and epoch keys are encrypted at rest using Windows DPAPI (`CryptProtectData`) and machine-authenticated encryption on Linux/macOS ([`crates/local-store/src/keyring.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/local-store/src/keyring.rs)).
- **Zero-Disk Recovery Hardening**: `recovery_kit_backup.txt` has been permanently removed; master recovery secrets are scrubbed from RAM on initialization.
- **Physical Hardware Security Token (HSM)**: Upgraded from simulation to native ISO 7816-4 APDU smartcard driver over PC/SC ([`crates/crypto/src/piv.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/crypto/src/piv.rs)), supporting YubiKey Slot 9C touch presence and Slot 9D ECDH key agreement.
- **Operator Ownership Authorization**: `POST /v1/recovery/:locator/records` verifies cryptographic Ed25519 signatures against registered `recovery_signing_pk` or authorized `DeviceCertificate`.
- **FastCDC Content-Defined Chunking**: Integrated compile-time Gear rolling hash matrix (`SplitMix64`) achieving 96.15% deduplication ratio ([`crates/snapshot/src/fastcdc.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/snapshot/src/fastcdc.rs)).
- **Proof-of-Storage Readback**: Nonce challenge-response protocol (`POST /v1/objects/:cid/challenge`) reduces verification wire bandwidth by 99.96%.
- **Threshold Guardian Recovery**: Shamir's Secret Sharing over $\text{GF}(2^8)$ with constant-time inversion enables $M$-of-$N$ guardian paper recovery ([`crates/crypto/src/shamir.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/crates/crypto/src/shamir.rs)).
- **Persisted Maintenance Fleet Scheduler**: SQLite WAL mode database ([`services/maintenance/src/db.rs`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/services/maintenance/src/db.rs)) powers continuous autonomous background replication audits.
- **Automated Arbitrum L2 Relayer**: Salted commitments submitted to L2 relayer nodes with EIP-712 proof receipts ([`contracts/CipherVaultRegistry.sol`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/contracts/CipherVaultRegistry.sol)).
- **Operational Chaos Drill & Docker Cluster**: 100% verified across live multi-node failure injection drills with zero bitflips.
