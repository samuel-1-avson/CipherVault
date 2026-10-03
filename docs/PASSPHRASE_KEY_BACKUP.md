# Passphrase-wrapped vault-key backup (Step 2, ADR-012)

Opt-in disaster recovery: the offline recovery kit, sealed client-side
with a passphrase-derived key and stored as an ordinary content-addressed
operator object. New device + account login + passphrase recovers the
vault. Operators learn nothing.

## Non-goals

- No server-side unwrap endpoint, now or later. Any proposal to add one
  must supersede ADR-012 explicitly.
- No passphrase rules enforced anywhere except the local CLI prompt.
- No change to `recover`, guardians, or the paper kit. Restore writes a
  standard kit file; the drilled `recovery test` / `recover` path runs
  unchanged from there.

## Envelope v1 (`CVKB1`)

Byte layout, all integers fixed-width big-endian:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 5 | magic `CVKB1` |
| 5 | 1 | kdf_id (`0x01`) |
| 6 | 16 | Argon2id salt |
| 22 | 24 | XChaCha20-Poly1305 nonce |
| 46 | N | ciphertext + 16-byte tag |

- `kdf_id 0x01` == `derive_key_from_password` (Argon2id, 64 MiB, 3
  iterations, 4 lanes, 32-byte output). Future IDs add new parameter
  sets; v1 parsing rejects unknown IDs fail-closed.
- Plaintext is the canonical kit text (`format_printable`, UTF-8).
- AAD is the 46-byte header: magic, version, KDF parameters, salt, and
  nonce are all authenticated. Tampering with any of them fails
  decryption indistinguishably from a wrong passphrase.
- The implementation lives in `crates/crypto` (`seal`/`open` over
  opaque bytes) so the format is reusable and unit-testable without
  network or vault state.

## Ceremonies

Backup (`ciphervault recovery key-backup`):

1. Load key material: `--kit PATH` (printable kit, parsed and checksum/
   descriptor-validated before use) or `--share PATH...` (threshold
   guardian sheets combined into a kit). Never reads secrets from disk
   stores; R exists only in process memory during sealing.
2. Prompt the passphrase twice over hidden TTY input (`rpassword`).
   Minimum 12 characters; the prompt recommends 6+ random words and
   says plainly that a weak passphrase is the weak link. Debug builds
   only accept `CIPHERVAULT_TEST_PASSPHRASE` as a drill hatch (loud
   warning, compiled out of release); shipped binaries never read it.
3. Seal the canonical kit text, upload the envelope to every configured
   operator until `--replicas` (default: `resolve_required_replicas`)
   confirm, read each replica back, and print the locator
   (`sha256(envelope)` hex).
4. Record a `KEYBACKUP_OK` activity row (locator, replicas, no secrets).

Restore (`ciphervault recovery key-restore --locator HEX --output kit.txt`):

1. Fetch the envelope from any operator (anonymous recovery read).
2. Prompt the passphrase once over hidden input, open the envelope.
3. Validate the result by parsing it as a kit (checksum + descriptor
   match) before writing anything.
4. Write the kit file with owner-only permissions and print the exact
   `recovery test --kit` follow-up. Then `recover` as drilled.

Rotation: backups are immutable content-addressed blobs; rotation means
a new backup (new locator) after rekey or suspected passphrase exposure.
Old envelopes persist on operators and stay safe exactly as long as the
passphrase stays strong and unique to this backup — document the locator
handoff, not deletion.

Verify drill: `key-restore` into a temp dir on a schedule (or before any
risky operation) and diff the descriptors against the live kit. A backup
counts only after a restore drill reads it back.

## Locator handling

The locator is public: it identifies random-looking ciphertext that is
useless without the passphrase. Preferred home: the account vault-link
record — after `key-backup`, open the dashboard (Account → Linked
Vaults & Key Backups) and record the locator against the vault. Any
later login, on any machine, shows it again plus a ready-to-paste
restore command. Until it is recorded (or as a second copy), keep the
64 hex characters somewhere durable and copy-pasteable: a
password-manager notes field, an email draft, or a printed sheet next
to the passphrase hint — never next to the passphrase itself.

## Threat model

- Operator (or breach) reads the blob: learns envelope metadata
  (version, KDF params, salt, length) and nothing about R. Offline
  passphrase guessing costs one 64 MiB Argon2id evaluation per guess
  by construction.
- Operator withholds the blob: mitigated by N-operator replicas and
  readback verification at backup time; restore tries every configured
  operator.
- Wrong/tampered blob: digest check on fetch plus AEAD failure on
  open, both fail closed with no partial output.
- Weak/reused passphrase: the residual risk, owned by the user and
  stated in the prompt. Minimum length plus honest copy; no server
  visibility by design.
- Malware on the backup/restore machine: out of scope (same as the
  paper kit ceremony — a compromised endpoint sees R either way).
