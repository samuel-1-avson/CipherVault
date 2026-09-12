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

## Compatibility and remaining work

- Existing inventories and lease signatures are not retroactively upgraded. Create a new snapshot and receipts with upgraded clients and operators; retain old backups.
- Local signing/epoch keys and the local recovery-kit copy still need protected storage. The HSM backend remains a simulator.
- Operator sessions still need ownership authorization and pinned operator identities. Distinct keys and URLs do not establish independent infrastructure.
- A withheld newest certified head cannot be detected without a trusted freshness checkpoint. Multi-device fork resolution and revocation require a fuller policy; this milestone rejects observed same-generation, same-counter conflicts.
- Restore path checks still need handle-based race resistance. This milestone does not certify the filesystem boundary.
- The background maintenance daemon still needs a persisted job scheduler; the CLI repair path is implemented.
- Blockchain finality and deployment environments need separate validation. No production-readiness certification is made.
