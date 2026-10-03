# What Is CipherVault? (Plain-English Guide)

*For anyone who uses GitHub normally and wants to understand — and start
using — CipherVault. No cryptography background required.*

## The one-paragraph version

**Git tracks your source code. CipherVault protects everything Git
leaves behind.** Every project has confidential files that must never
go into Git: `.env` files, API keys, database passwords, TLS
certificates, signing keys. CipherVault is a tool that encrypts those
files on your own machine, backs them up across a network of storage
nodes, versions them like Git versions code, and restores them onto any
machine — including a brand-new laptop after yours is lost or stolen.
The storage nodes only ever see scrambled ciphertext; they cannot read
your secrets.

## The problem it solves

If you build software, you already know rule #1: **never commit
secrets to Git**. So you add `.env` to `.gitignore`… and then four
problems appear:

1. **One slip leaks everything.** A single careless `git add .` can
   push credentials into history forever, including public mirrors.
2. **New machine, no secrets.** When a laptop dies, is stolen, or gets
   wiped, Git restores your code — but every API key, certificate, and
   environment config that lived only on that disk is gone. Recovery
   means days of resetting passwords and reissuing keys.
3. **Cloud vaults own you.** Services like 1Password or AWS Secrets
   Manager work, but your secrets live on someone else's servers, under
   their subscription, their outages, and their access policies.
4. **Plaintext lying around.** Unencrypted `.env` files on disk can be
   read by malware, by anyone glancing at your screen, or by a
   compromised build script.

CipherVault exists to fix all four at once: Git-style versioning for
secrets, clean-machine recovery, no central custodian that can read
your data, and encryption everywhere outside your own machine's memory.

## How it works (no jargon)

Think of it as a **safety deposit box combined with a time machine**:

1. **You pick which files to protect.** Typically `.env`,
   certificates, and private keys. CipherVault also updates your
   `.gitignore` automatically so Git never touches them.
2. **Your machine encrypts everything first.** Before anything leaves
   your laptop, file contents are scrambled with strong modern
   encryption (XChaCha20-Poly1305 — the same class of algorithm that
   protects your messaging apps). This happens locally; no server is
   involved.
3. **Copies are spread across storage nodes ("operators").** The
   encrypted blobs are replicated to several independent nodes. The
   nodes can prove they still hold your data, but they cannot read it
   — they see only opaque chunks, sizes, and counts.
4. **History is kept.** Every backup is a versioned snapshot, so you
   can diff, roll back, and see what changed — just like `git log`
   for your secrets.
5. **Recovery works from nothing.** If your machine is gone, an
   offline recovery kit (a printed/written-down secret you made at
   setup) or a set of guardian shares held by people you trust can
   rebuild everything onto a fresh machine — as long as the storage
   network still holds your encrypted copies.

The golden rule of the design: **your secrets are readable in exactly
two places — your machine's memory while you use them, and inside your
encrypted backups that only your keys can open.** Everything in
between is ciphertext.

## The pieces (what's what)

- **The CLI (`ciphervault`)** — the main tool. Commands feel
  Git-like: `init`, `track`, `push`, `pull`, `run`, `diff`. A
  beginner-friendly fullscreen menu (TUI) opens if you just type
  `ciphervault` with no arguments.
- **Storage operators** — the nodes holding encrypted chunks. The
  project runs a small fleet; anyone can also run a node and earn
  standing in the network.
- **The web dashboard / explorer** — a public window into the
  network's health (operator status, checkpoints) plus hosted
  sign-in for account holders. It never sees your secret values.
- **Accounts + MFA** — hosted sign-in (devices/passkeys plus TOTP
  authenticator codes) guards the management plane. MFA enrollment
  is per-account and owner-controlled.
- **Recovery kits & guardians** — two clean-machine recovery
  methods: a single offline paper kit, or M-of-N split shares
  (e.g. any 2 of 3 guardians) so no one person alone can recover.
- **Anchoring** — periodic checkpoints are anchored to a public
  ledger so history can't be silently rewritten.

## How to use it (the 5-minute path)

**Install** (Windows PowerShell):

```powershell
irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex
```

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash
```

Then open a **new** terminal and go to your project folder:

| Step | Command | What it does |
|------|---------|--------------|
| 1. Start | `ciphervault init` | Creates your vault. **Save the offline recovery kit it shows you** — this is the only way back if all your machines die. |
| 2. Protect | `ciphervault track .env` | Marks files as secrets (and auto-updates `.gitignore`). |
| 3. Back up | `ciphervault push -m "Backup"` | Encrypts and replicates to the storage network. |
| 4. Run safely | `ciphervault run -- npm start` | Starts your app with secrets fed from memory — no plaintext file needed. |
| 5. New machine | `ciphervault pull` / `restore` | Downloads and decrypts your secrets onto this machine. |

Prefer menus over commands? Just run `ciphervault` alone and the
guided TUI walks you through the same steps.

Want to **run a storage node** instead? `ciphervault node setup`
starts a short wizard — see
[OPERATOR_PLAYBOOKS.md](./OPERATOR_PLAYBOOKS.md).

## Questions GitHub users always ask

**Is it like Git?**
The workflow rhymes with Git (track, push, pull, diff, history), but
it stores *encrypted secrets*, not code — and there is no
GitHub-equivalent that can read your data.

**Does it replace 1Password / AWS Secrets Manager?**
For *development* secrets (`.env`, keys, certs tied to your
projects), yes — with no subscription and no central party that can
read them. It's not a password manager for website logins.

**What if my laptop is stolen?**
Your secrets on the network are encrypted blobs the thief can't read
without your keys. Get a new machine, use your recovery kit (or
guardians), and `restore`. Then rotate anything the stolen disk held
in plaintext.

**What if the storage nodes disappear?**
Replication across independent nodes plus health audits make quiet
loss unlikely — but no network is magic. Keep your recovery material
offline, run a `recovery-drill` occasionally, and keep your own
encrypted backups of anything irreplaceable.

**Who can read my secrets?**
Your machines (while in use) and whoever holds your recovery
material. Operators cannot. Dashboard visitors cannot. There is no
master key and no support desk that can peek.

## Honest limits (read before trusting it with your life)

- **Default captures use the battle-tested v1 format**; the newer v2
  format (better privacy against chunk-guessing) is opt-in pending
  independent cryptographic review.
- **Operators see shapes, not contents**: chunk sizes, counts, and
  access patterns are visible to them even though file contents are
  not.
- **Restore writes real files**: during recovery, decrypted files
  exist on your disk (with strict permissions) — that's the point,
  but be aware of it on shared machines.
- **Back up your local keys separately**: on Windows they're in the
  OS keyring; elsewhere in a keystore file. Lose them *and* your
  recovery kit and your backups are unreadable.
- **No independent audit yet**: the cryptography follows standard
  practice and the test suite is extensive, but no outside firm has
  certified it. The full, precise picture lives in
  [CURRENT_SECURITY_GUARANTEES.md](./CURRENT_SECURITY_GUARANTEES.md)
  — read it before production use.

## Where to go next

- [SETUP_GUIDE.md](./SETUP_GUIDE.md) — the two role paths in detail
- [WORKFLOW_GUIDE.md](./WORKFLOW_GUIDE.md) — daily developer workflow
- [CURRENT_SECURITY_GUARANTEES.md](./CURRENT_SECURITY_GUARANTEES.md) — exact promises and limits
- [CICD_INTEGRATION.md](./CICD_INTEGRATION.md) — using CipherVault in pipelines
- [OPERATOR_PLAYBOOKS.md](./OPERATOR_PLAYBOOKS.md) — running a storage node
- [MFA_ROLLOUT.md](./MFA_ROLLOUT.md) / [ENFORCED_MFA.md](./ENFORCED_MFA.md) — account second-factor details
