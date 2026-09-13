# CipherVault CI/CD Integration & Developer Ergonomics Guide

This guide details how to integrate **CipherVault** into continuous integration and automated deployment pipelines (GitHub Actions, GitLab CI, CircleCI, Jenkins), as well as utilizing the Developer Ergonomics suite: **Encrypted Secret Diffing (`ciphervault diff`)**, **Multi-Workstation Synchronization (`ciphervault pull`)**, and **Shell Tab Autocompletions (`ciphervault completions`)**.

---

## 1. The Zero-Disk CI/CD Paradigm

### The Problem With Traditional CI Secret Ingestion
In typical CI/CD pipelines, secrets are managed through repository or organization secret stores and written to disk before running build tools:
```bash
# ⚠️ INSECURE ANTI-PATTERN: Secrets touch the runner filesystem
echo "$PROD_ENV_FILE" > .env
docker build -t myapp .
rm .env # Too late: block allocation, swap file, and container overlays retain secrets!
```
1. **Runner Disk Persistence**: Residual plaintext remains in unallocated blocks, swap files, and container storage drivers.
2. **Container Layer Leaks**: Files placed into the workspace during `docker build` can be accidentally committed into intermediate layers.
3. **Log Exposure**: Misconfigured build scripts dump environment variables into public CI build logs.

### The CipherVault Zero-Disk Solution
With `ciphervault run -- <command>`, secrets are:
1. **Decrypted in RAM only**: The AES-256-GCM / XChaCha20-Poly1305 ciphertext is decrypted strictly in volatile process heap memory.
2. **Injected Ephemerally**: Secrets are passed directly to the spawned child process via its inherited operating system process environment block (`CreateProcessW` on Windows, `execve` on Linux/macOS).
3. **Zero Secrets on Disk**: Not a single byte of plaintext is ever written to any temporary file, disk buffer, or pipe.
4. **Scrubbed on Exit**: As soon as the command completes, memory buffers are explicitly overwritten with zeroes using cryptographic zeroization (`zeroize::Zeroize`).

```
+-----------------------------------------------------------------------+
| CI/CD Runner Volatile Memory                                          |
|                                                                       |
|  +--------------------+        +-----------------------------------+  |
|  | CipherVault CLI    |        | Child Process (e.g. npm test)    |  |
|  | - In-memory decrypt| =====> | - In-memory environment block    |  |
|  | - Scrub on exit    |        | - Zero disk access to credentials|  |
|  +--------------------+        +-----------------------------------+  |
|           |                                                           |
+-----------|-----------------------------------------------------------+
            |
            X  <-- [ZERO DISK WRITE ENFORCEMENT]
            |
+-----------------------------------------------------------------------+
| Runner Filesystem / Disk (No Plaintext Secrets Ever Written)         |
+-----------------------------------------------------------------------+
```

---

## 2. GitHub Actions Integration

### Using the Official Composite Action (`ciphervault-run`)
CipherVault provides a composite GitHub Action located at `.github/actions/ciphervault-run`:

```yaml
name: Production Deployment

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Deploy Under Zero-Disk Secret Injection
        uses: ./.github/actions/ciphervault-run
        with:
          command: "npm run deploy"
          env-file: ".env.production"
          quiet: "true"
```

### Action Input Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `command` | `string` | *(Required)* | The shell command, script, or binary to execute under secret injection. |
| `snapshot` | `string` | `""` | Optional 32-byte hex snapshot ID. Defaults to the active local head. |
| `env-file` | `string` | `""` | Filter injection to a specific secret file (e.g., `.env.production`). |
| `no-inherit`| `boolean` | `false` | Run in clean-room isolation without inheriting host environment variables. |
| `dry-run` | `boolean` | `false` | Verify injection variables and syntax without executing command. |
| `quiet` | `boolean` | `false` | Suppress CipherVault startup banner logs in CI output. |
| `install-binary` | `boolean` | `true` | Compile/install CipherVault if not present on `$PATH`. |

---

## 3. GitLab CI Integration

In `.gitlab-ci.yml`, invoke `ciphervault run` directly within job scripts:

```yaml
stages:
  - build
  - release

build-and-deploy:
  stage: release
  image: ubuntu:24.04
  only:
    - main
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl
    - curl -sSL https://releases.ciphervault.io/install.sh | bash
  script:
    # Verify zero secrets on disk before execution
    - test ! -f .env
    # Execute build step with zero-disk secret injection
    - ciphervault run --quiet -- ./scripts/deploy_production.sh
```

---

## 4. Encrypted Secret Diffing (`ciphervault diff`)

The `ciphervault diff` command enables encrypted secret comparison and revision history inspection while actively guarding against shoulder-surfing and log leakage.

### Shoulder-Surfing Defense
By default, all secret values are masked with `***`:
```bash
$ ciphervault diff
Comparing: head:9e4f21a0 -> working tree

File: .env (dotenv format)
  ~ DATABASE_URL: postgres://app:***...a8f -> postgres://app:***...91c
  + NEW_API_KEY: sk_live_***...4b1
  - RETIRED_KEY: (removed)
  = PORT: 8080 (unchanged)

Summary: 1 file(s) changed, 1 added, 1 removed, 1 modified
```

### Commands & Flags
- `ciphervault diff`: Compare uncommitted working tree secrets against active head.
- `ciphervault diff <snapshot_id>`: Compare working tree against specific snapshot revision.
- `ciphervault diff <snapshot_a> <snapshot_b>`: Compare two historical snapshot revisions.
- `ciphervault diff --reveal`: Unmask plaintext values (restricted to secure private terminals).
- `ciphervault diff --file <path>`: Restrict diff output to a single confidential file.
- `ciphervault diff --json`: Output machine-readable JSON for audit logs or CI pipelines.

---

## 5. Multi-Workstation Synchronization (`ciphervault pull`)

When working across multiple laptops, build servers, or developer workstations, `ciphervault pull` synchronizes confidential state from the storage operator federation:

```bash
$ ciphervault pull
Connecting to 3 independent storage operator(s)...
Found newer remote snapshot: b41a9c8e1029
Applying updated confidential files into workspace...
✓ Successfully synchronized with operator cluster (Head: b41a9c8e1029)
  - Updated: .env
  - Updated: certs/server.key
```

### Safety Guards
1. **Uncommitted Modification Protection**: If local files have uncommitted edits, `pull` aborts to prevent accidental data loss:
   ```text
   Error: Local tracked file(s) have uncommitted modifications: .env
   Commit changes with 'ciphervault push' or discard with 'ciphervault pull --force'
   ```
2. **Cryptographic Head Authentication**: Pull verifies the Ed25519 signatures of the operator cluster and device certificate chain against registered recovery keys before applying any snapshot.
3. **Dry-Run Inspection**: Use `ciphervault pull --dry-run` to query remote operator heads without altering any local files.

---

## 6. Shell Tab Autocompletions (`ciphervault completions`)

Generate native, high-performance autocompletion scripts for your preferred shell:

### Bash
```bash
ciphervault completions bash > ~/.local/share/bash-completion/completions/ciphervault
# Or source directly in ~/.bashrc:
eval "$(ciphervault completions bash)"
```

### Zsh
```zsh
ciphervault completions zsh > "${fpath[1]}/_ciphervault"
# Or source directly in ~/.zshrc:
eval "$(ciphervault completions zsh)"
```

### PowerShell (Windows / macOS / Linux)
```powershell
ciphervault completions powershell | Out-String | Invoke-Expression
# To persist across sessions, add to $PROFILE:
Add-Content -Path $PROFILE -Value 'ciphervault completions powershell | Out-String | Invoke-Expression'
```

### Fish
```fish
ciphervault completions fish > ~/.config/fish/completions/ciphervault.fish
```

### Elvish
```elvish
eval (ciphervault completions elvish | slurp)
```
