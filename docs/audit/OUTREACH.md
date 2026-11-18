# Audit outreach — drafts (send from the maintainer's address)

Status: ready to send. The engagement pack is public at
`docs/audit/`; link it, don't attach the repo.

## Targets, in order

1. **Firms with Rust + applied-crypto practices** (quote C1–C8,
   staged if needed): Trail of Bits, Cure53, Quarkslab,
   Least Authority, NCC Group, Kudelski Security.
2. **Independent cryptographers** (fixed-fee protocol review of
   C1–C4 is a good fit): approach via their public consulting
   pages/blogs; offer the pack + a seeded demo environment.
3. **Community review venues** (slower, cheaper, public):
   a public "request for review" issue on the repo linking the
   pack; OSTIF (Open Source Technology Improvement Fund) audit
   facilitation for open-source projects.

## Draft — firm / consultancy

Subject: Request for quote — cryptographic audit of CipherVault (Rust, client-side encrypted backup)

Hello,

CipherVault is an open-source, client-side encrypted secret-backup
system (Rust workspace; XChaCha20-Poly1305, Ed25519/X25519, Shamir
threshold recovery, replicated ciphertext storage, plus a signed
agent-audit log). We are preparing for wider release and want an
independent cryptographic audit before we claim more than we have
proven.

We've published an engagement pack that scopes the work precisely:
protocol questions C1–C8 (legacy custom KDF soundness and v1
deterministic-chunk leakage analysis are our top concerns), code
scope, claimed invariants, reproduction commands, and known
limitations we do not need rediscovered:
https://github.com/samuel-1-avson/CipherVault/blob/main/docs/audit/README.md

Design spec and threat model are linked from the pack. Snapshot is
tagged v1.0.32; 1,100+ tests reproduce our current evidence.

Could you quote scope (full C1–C8 or staged starting with C1–C4),
fee model, earliest start, and re-test terms? We require the right
to publish the final report.

Thanks,
Samuel Avson — CipherVault maintainer

## Draft — independent reviewer (short)

Subject: Paid review — custom KDF + deterministic chunk encryption (Rust)

Hi — CipherVault (open-source encrypted secret backup) needs
outside eyes on two things before wider release: a legacy custom
Blake2b KDF's domain separation, and the exact leakage of
deterministic file-key/chunk-nonce derivation (plus its HKDF-based
v2 replacement). Scoped pack with invariants and reproduction
commands: https://github.com/samuel-1-avson/CipherVault/blob/main/docs/audit/README.md
(items C1–C3). Fixed-fee, publishable report. Interested? I'll send
the tagged snapshot and a demo environment.

— Samuel

## Draft — public review request (GitHub issue / forum post)

Title: Request for independent cryptographic review — audit pack published

CipherVault has not had an external audit, and we'd rather fix
that than imply otherwise. We've published a scoped engagement
pack (protocol questions, invariants, reproduction commands,
known limitations): docs/audit/. Top concerns: legacy custom
Blake2b KDF (C1), v1 deterministic-chunk leakage (C2), and the
opt-in HKDF v2 protocol that replaces it (C3). Quotes from firms
and fixed-fee offers from independent reviewers are both welcome;
the final report will be published. Security contact and status:
SECURITY.md → "Audit status".
