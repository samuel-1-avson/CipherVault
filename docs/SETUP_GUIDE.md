# CipherVault Setup Guide

Two roles, two paths. Pick yours and ignore the other one — the tooling,
binaries, and docs are separated on purpose.

| | **Developers** (day-to-day secrets) | **Node runners** (contribute storage) |
|---|---|---|
| Goal | Back up `.env` files, keys, and certs; restore them on any machine | Run a storage node that holds others' encrypted chunks |
| Main commands | `init`, `track`, `push`, `pull`, `run`, `diff` | `node setup`, `node status`, `node standing` |
| Guided start | Bare `ciphervault` opens the TUI | `ciphervault node setup` wizard |
| Deep docs | [WORKFLOW_GUIDE.md](./WORKFLOW_GUIDE.md), [CICD_INTEGRATION.md](./CICD_INTEGRATION.md) | [OPERATOR_PLAYBOOKS.md](./OPERATOR_PLAYBOOKS.md), [DEPLOYMENT_RUNBOOK.md](./DEPLOYMENT_RUNBOOK.md) |

`ciphervault --help` lists every command under these same headings.

---

## Installing (both roles)

### Easy: one-liner (recommended)

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.ps1 | iex
```

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/samuel-1-avson/CipherVault/main/dist/scripts/install.sh | bash
```

The installer verifies the SHA-256 checksum, installs to a user directory,
and adds it to `PATH`. Open a **new** terminal afterwards.

Smaller footprint? Set the role before installing:

```powershell
$env:CIPHERVAULT_ROLE = "developer"  # or "node"; default "full"
```

```bash
CIPHERVAULT_ROLE=node curl -fsSL ... | bash
```

- `developer` → `ciphervault` + `ciphervault-agent` (file watcher)
- `node` → `ciphervault` + `ciphervault-operator` + `ciphervault-maintenance`
  (the CLI ships here too: `ciphervault node setup` is the onboarding wizard)
- `full` → all four binaries (default; both paths work)

Private-repo note: if the installer cannot read the release feed, export a
token with Contents-read first: `CIPHERVAULT_GITHUB_TOKEN=<token>`.

### Alternative: release bundles

Each GitHub release ships three archives per platform: the full
`ciphervault-<tag>-<target>` bundle plus slim `ciphervault-dev-*` and
`ciphervault-node-*` bundles. Verify against the release `SHA256SUMS.txt`.

### Alternative: package managers

Scoop, Homebrew, and winget manifests live in
[`dist/package-managers/`](../dist/package-managers/README.md).

### Updating

```sh
ciphervault update          # install the latest signed release
ciphervault update --check  # just check
```

---

## Path A: developers

### Easy start (5 commands)

```sh
cd your-project
ciphervault init            # creates the vault, prints the recovery kit: save it!
ciphervault track .env      # or: ciphervault track -i   (find secrets via .gitignore)
ciphervault hook install    # block accidental secret commits
ciphervault push -m "first backup"
ciphervault status
```

Prefer clicking? Run bare `ciphervault` for the guided terminal UI.

### Daily loop

```sh
ciphervault push -m "rotate stripe key"   # snapshot + replicate to operators
ciphervault pull                          # fetch a teammate's latest snapshot
ciphervault diff                          # what changed (values masked by default)
ciphervault run -- npm start              # secrets into memory, never onto disk
ciphervault doctor                        # self-check when something feels off
```

### Going further

- `ciphervault watch --sync` (or the `ciphervault-agent` service) snapshots
  on every save.
- `ciphervault recovery split` + `recover` cover clean-machine disaster
  recovery; rehearse with `ciphervault recovery test --to ./restore-drill`.
- CI pipelines: zero-disk injection is covered in
  [CICD_INTEGRATION.md](./CICD_INTEGRATION.md).
- YubiKey owners: `ciphervault token status`, then `init --hardware-token`.

---

## Path B: node runners

You store only opaque ciphertext chunks. You cannot read anyone's files,
names, or folder structure.

### Easy start (guided wizard)

```sh
ciphervault node setup
```

The wizard asks three questions (node name, data folder, port), starts the
node in the background, and prints a health summary. No flags, no config
files. (Downloaded the zip instead of installing? Double-click
`scripts/setup-node.bat` on Windows or run `scripts/setup-node.sh`.)

```sh
ciphervault node status     # plain-language health report
ciphervault node standing   # fleet standing: probation / full / not-joined
ciphervault node backup --to ./node-backup   # back up node identity files
ciphervault node stop       # stop; `ciphervault node start` to resume
```

Back up the identity files (`node backup`) somewhere safe: they prove your
node is yours. Joining the shared fleet additionally needs a fleet invite;
see the playbooks below.

### Going further (technical operators)

- Raw daemon with every knob: `ciphervault-operator --help`
  (ports, data dir, key rotation, `--print-identity`, P2P mesh flags).
- [OPERATOR_PLAYBOOKS.md](./OPERATOR_PLAYBOOKS.md): restarts, meshing,
  vouchers, repair, fleet invites.
- [DEPLOYMENT_RUNBOOK.md](./DEPLOYMENT_RUNBOOK.md): Docker Compose,
  systemd, Caddy, and multi-region VPS provisioning.
- [TESTNET.md](./TESTNET.md): joining the testnet fleet end to end.

---

## Troubleshooting (both roles)

- `ciphervault doctor` (developers) and `ciphervault node status`
  (node runners) are the first stop; both exit nonzero when unhealthy.
- Node logs live next to the data folder (`node.log`); re-run the failing
  command with more context before asking for help.
- Version skew between the CLI and the operator daemon prints an explicit
  warning — resolve it with `ciphervault update`.
