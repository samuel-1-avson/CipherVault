# 01 — Product and requirements

## Product contract

Give an individual developer a Git-like workflow for confidential files, with independently retained encrypted versions and a tested path back after complete original-device loss. The product is a backup system, not a source-control replacement, blockchain wallet, password manager, or runtime secret delivery service.

The word “recoverable” means that an authorized person has enough independent recovery material, at least one intact ciphertext replica and its metadata remain reachable, retention/payment obligations are still met, and a compatible trustworthy client can execute the documented format. It does not mean unconditional recovery forever.

## Initial assumptions

| Area | Provisional assumption |
|---|---|
| Audience | Individual developers; one human owner, up to three devices later |
| Files | Explicitly selected regular files such as `.env`, configuration, certificates and exportable development keys |
| Capacity | 100 MiB typical active vault; MVP limits 1 GiB total active content and 256 MiB per file |
| Versions | All snapshots retained for at least 90 days; optional manually selected long-lived checkpoints |
| Connectivity | Intermittent laptops; operators and maintenance services continuously online |
| Platforms | Windows first to reproduce the motivating incident, then macOS and Linux |
| Durability | Three full replicas across verified independent administration and infrastructure domains |
| Recovery | Random offline recovery secret and printed bootstrap information, two separate physical locations |
| Service model | Paid retention with prepaid runway; no free-permanent-storage premise |

These limits constrain the first demonstration, not an architectural maximum. Larger-file chunking, throughput, cost, and filesystem semantics require new measurements before limits change.

## Requirements and acceptance evidence

| ID | Requirement | Evidence required before beta |
|---|---|---|
| R01 | Encrypt on the client before any outbound upload | Packet/body inspection with synthetic canaries; adapters accept only encrypted object types |
| R02 | Restore after total original-device loss | Clean-machine drill with original disks, OS key store and local database unavailable |
| R03 | Continue recovery after coordinator loss | Block its DNS/API/database; restore directly through kit-listed independent operators |
| R04 | Independent remote retention | Three operator receipts, dependency inventory and successful readback from each |
| R05 | Immutable versions and rollback | Restore an older signed snapshot after a compromised device submits corrupt newer content |
| R06 | Detect corruption, wrong keys and substitution | Tamper/truncation/reordering tests fail without final output publication |
| R07 | Usable coding loop | Explicit push, optional debounce watch, status command, offline queue, no plaintext diff by default |
| R08 | Safe filesystem restore | Reject traversal, symlinks, device paths and collisions; stage then atomically publish files where supported |
| R09 | Separate auth and decryption | Wallet-only and billing-admin accounts cannot decrypt; recovery works without old wallet |
| R10 | Visible retention and repair | Earliest expiry, quorum deficit, retrieval age and funding runway are shown |
| R11 | Bounded revocation claims | Test old-copy access and document that retained old keys still decrypt old ciphertext |
| R12 | No secret leakage from product observability | Logs, crash handling, update paths and support export reviewed using synthetic canaries |
| R13 | Open exit path | Offline format specification, verification vectors, encrypted export and standalone restore tool |
| R14 | Explicit freshness confidence | Old valid snapshots displayed as valid-but-possibly-stale when current independent head cannot be established |

## Non-goals

No new consensus protocol, custom blockchain, product token, plaintext validator inspection, autonomous trading, novel threshold cryptosystem, guaranteed erasure from third-party disks, guaranteed recovery without keys, or unattended escrow of decryption keys. No live injection into production applications, collaborative editing, enterprise SSO, arbitrary recursive home-directory backup, or automatic import of hardware-wallet seeds in the MVP. A hardware-bound non-exportable key cannot be backed up as a file; users need the issuing system's supported recovery process.

## Onboarding

1. Explain that Git and this vault protect different files. Start from an explicit file selection, never a blanket scan of the user's home directory. Preview names and sizes locally; do not print values.
2. Create the vault, recovery authority, and first device authority. Show that the account wallet is optional billing/authentication convenience and is not the decryption key.
3. Generate the recovery kit locally. Require a short offline verification exercise that proves the user recorded it. Explain where to keep two copies; saving the only copy inside the vault or on the same laptop does not count.
4. Review selected paths, retention policy and expected charges. Refuse private-key material in a shared/public demo vault. For actual use, provide clear key-category guidance and require intentional selection rather than silently collecting key stores.
5. Push a synthetic test snapshot, then complete a kit-based recovery test into a separate directory before showing “recovery setup verified.” Real secret enrollment follows the release gates in document 07.

The recovery kit contains secret material and public/bootstrap information. Provide printed text with checksums and a machine-readable offline export. Do not use an online QR generator, website, clipboard sync, analytics event, screenshot uploader, or command-line argument to handle its secret. Avoid promising secure deletion from SSDs or OS-managed print spools.

## Everyday workflow

`init`, `track`, `status`, `push`, `history`, `restore`, and `verify` should feel familiar. The planned executable is `ciphervault`, matching the selected CipherVault project name. A local config maps tracked paths to random internal file IDs. That mapping is confidential. An optional non-secret example config may be committed only after explicit review.

The default `push` waits for all three required replicas to accept and read back the complete recovery closure, or returns a clear pending/degraded result. `push --background` returns after a durable local queue write and explicitly says it is not yet remotely protected. A Git hook can warn on unbacked changes but does not upload silently or block Git indefinitely. The CLI should never imply that a source-code push included ignored files.

Watcher mode is opt-in. Debounce for a proposed five seconds, capture coherent file bytes with read-before/read-after stat checks, and retry if a file changes during capture. Ordinary file reads do not provide an application-consistent database snapshot; databases and active credential stores need documented export procedures. Snapshot capture should be independent of Git branch names; a branch label is optional encrypted metadata.

## Restore and recovery experience

On a clean machine, verify the restore client's release signature, enter the recovery secret through a protected local prompt, and use the kit to discover the vault. Fetch head candidates from independent operators, compare signed history and available checkpoint evidence, then choose a snapshot. Download, authenticate and stage every file before publishing it to a new destination. Show names only in the local UI and require explicit overwrite consent. Do not execute restored scripts or automatically load `.env` contents into a shell.

A recovered private key may still need rotation at its issuer after a theft or compromise. Restoring its bytes does not prove nobody else copied it. A lost but uncompromised disk and a malware-compromised machine have different incident responses.

## Error language

Use actionable messages: “Queued locally; original-device loss would lose this snapshot,” “2 of 3 replicas verified; protection degraded,” “Retention expires in 18 days,” “Snapshot authentic; latest version could not be confirmed,” and “Recovery secret does not unlock this kit.” Avoid “safe forever,” “unhackable,” or a single green check hiding missing metadata or unpaid retention.
