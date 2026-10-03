# ADR-012: Account/vault unification — one login UX over a preserved crypto split

Date: 2026-10-03 · Status: Accepted

## Context

The explorer hides private vault features from hosted logins (ADR scope:
`apps/cli/src/dashboard/{server,router,session}.rs`, `apps/ui/app.js`
`applyAccessContext`). The account (`cvacct_…`: identity, devices, MFA)
and the vault (`vault_id`: encrypted files, snapshots, device keys) are
separate entities, and private routes mount only on loopback (`--local`).

The owner asked why they are separate, whether device loss means total
loss, and proposed merging account+vault into one entity held by the
operators — fully decentralized, operators unable to read the data.

Facts bounding the answer:

- Pushed vault ciphertext already lives on the operators
  (`ciphervault push` replicates encrypted snapshots to the operator
  pool). What is device-only is unpushed work and the keys.
- Key recovery exists and is drilled (guardian Shamir shares / paper
  kit rebuild files and a working store; wipe-to-pull chaos drill
  passes). But it is ceremony-heavy, so the practical risk stands:
  a user who never pushes and never completes a ceremony loses
  everything with the device.
- The account record never contains vault plaintext or recovery
  secrets, and the account key never replaces the vault key
  (`docs/ACCOUNT_IDENTITY_DESIGN.md`). That split is the whole basis
  of the untrusted-operator promise.
- The account service is centralized SQLite today; "100%
  decentralized" is not achieved by any change that keeps it as the
  sole control plane.

Requirements: (1) device loss must not mean data loss for ordinary
users; (2) login-anywhere UX comparable to hosted forges; (3) operators
stay blind to vault content; (4) no single-server decryption oracle.

## Decision

Unify the experience, keep the cryptographic split. Four steps, in
order:

1. **Auto-push + backup-health indicator.** Close the "forgot to push"
   hole: scheduled/triggered push plus a visible health signal (last
   push time, unpushed change count, replica confirmation) in the CLI
   and dashboard. Ciphertext on operators is already unreadable to
   them; more of it, more often, strictly reduces loss risk.
2. **Opt-in passphrase-wrapped vault-key backup on operators.** The
   vault keys are sealed client-side with a key derived from a user
   passphrase (memory-hard KDF, random salt, AEAD, versioned envelope)
   and the wrapped blob is stored as an ordinary operator object under
   the vault namespace. No server-side unwrap endpoint ever exists:
   the client downloads the blob and unwraps locally. New device +
   login + passphrase recovers the vault; operators learn nothing.
   Opt-in, because a weak passphrase becomes the weak link, and the
   UI must say so plainly.
3. **Unified login/dashboard.** One login shows account, linked vaults,
   and backup health together. Vault metadata already in the account
   record (linked IDs, aliases, roles) extends to push/replica health.
   Private data routes stay loopback-only: the hosted view reports
   status, enrolled devices perform data operations. Mode remains a
   server bind-time property, never a per-session flag.
4. **Decentralize the account control plane (direction, not design).**
   Replicate/anchor account metadata across the operator set so no
   single SQLite file is the crown jewels. Sequenced after 1–3; no
   protocol commitment in this record.

## Consequences

- Device loss for a pushed + wrapped-key user becomes an inconvenience
  (new device, login, passphrase, pull), not a catastrophe — without
  operators ever holding usable keys.
- The crypto boundary does not move: no server endpoint accepts a
  passphrase, unwraps keys, or resets vault access alone. Any future
  proposal to add one must supersede this record explicitly.
- Residual risks, owned: passphrase strength (mitigate with strength
  meter + honest copy, never with server-side rules that see the
  passphrase); wrapped-blob/user confusion (label opt-in state in the
  backup-health indicator); account plane centralization until step 4.
- Rejected: literal merge with server-held vault keys (account DB
  breach becomes total breach; contradicts the untrusted-operator
  promise); status quo guardians-only as the sole story (drilled but
  ceremony-heavy — most users will not complete it); per-session
  private mode on the public router (mounted routes gated only by
  session checks can leak across users on a single bug).
