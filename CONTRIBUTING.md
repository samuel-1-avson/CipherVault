# Contributing to CipherVault

Thank you for your interest in contributing to **CipherVault**! We are committed to building an open, secure, and decentralized multi-party secret governance network, and we welcome contributions from developers, cryptographers, security researchers, and technical writers.

To protect the integrity of the project, its users, and all contributors, we maintain clear guidelines on code quality, security provenance, and intellectual property.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
3. [Getting Started & Local Setup](#getting-started--local-setup)
4. [Development Workflow](#development-workflow)
5. [Code Quality & Testing Standards](#code-quality--testing-standards)
6. [Commit Message Standards](#commit-message-standards)
7. [Licensing and Inbound Rights](#licensing-and-inbound-rights)
8. [Reporting Security Issues](#reporting-security-issues)

---

## Code of Conduct

All contributors and community participants are expected to adhere to our [Code of Conduct](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/CODE_OF_CONDUCT.md). We are committed to providing a welcoming, inclusive, and harassment-free environment for everyone.

---

## Developer Certificate of Origin (DCO)

To guarantee that all code in CipherVault is legitimate, original, and free of proprietary or stolen intellectual property, **CipherVault uses the Developer Certificate of Origin (DCO Version 1.1)**, the same standard adopted by the Linux Kernel and Git projects.

### What Does the DCO Mean?

By signing off on a commit, you certify that:
1. You wrote the contribution yourself, or you have the legal right to submit it under CipherVault's open-source licenses.
2. The contribution is based on previous open-source work with compatible licensing terms.
3. You understand that your contribution is public and cannot be withdrawn retroactively.

### How to Sign Your Commits

Every commit submitted to CipherVault **must contain a `Signed-off-by:` line** with your real name and email address.

You can automate this easily using Git's `-s` flag:

```bash
git commit -s -m "feat(crypto): implement threshold signature verification"
```

This appends a signature to your commit message:
```text
feat(crypto): implement threshold signature verification

Signed-off-by: Jane Contributor <jane.contributor@example.com>
```

> [!IMPORTANT]
> Pull requests containing commits without a valid DCO sign-off will be blocked by automated GitHub status checks until signed off.

---

## Getting Started & Local Setup

### Prerequisites

Ensure you have the following installed locally:
* **Rust**: `1.80.0` or later (installed via [rustup](https://rustup.rs))
* **Foundry**: (`forge`, `cast`) for smart contract testing (installed via [getfoundry.sh](https://getfoundry.sh))
* **Git**: with a configured identity (`git config user.name` and `git config user.email`)
* **Docker / Docker Compose**: for local multi-node operator cluster integration tests

### Repository Setup

1. Fork the official repository on GitHub: `https://github.com/samuel-1-avson/CipherVault`
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/CipherVault.git
   cd CipherVault
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/samuel-1-avson/CipherVault.git
   ```
4. Verify your local build:
   ```bash
   cargo check --workspace
   ```

### Disk Space & Build Artifacts

Full workspace builds keep several gigabytes of incremental artifacts under the cargo target directory (debug + test profiles across 13 crates). On small system drives (notably Windows `C:`), a build can fail with `ENOSPC` during linking. This project has hit that: the fix is reclaiming build outputs, never touching source files.

- Point `CARGO_TARGET_DIR` at a roomy volume before your first build (e.g. `$env:CARGO_TARGET_DIR = 'D:\cargo-target'` on Windows, `export CARGO_TARGET_DIR=/data/cargo-target` on Unix).
- To reclaim space later, delete the target directory contents or run `cargo clean -p <crate>`; both are regenerable. Never delete `src/`, `Cargo.toml`, or `Cargo.lock` to free space.
- CI runners are unaffected (each job provisions a fresh disk), so this guidance is for local development only.

---

## Development Workflow

1. **Create an Issue:** For major architectural changes or new crates, please open a GitHub Issue or Discussion first so we can align on design before you write large amounts of code.
2. **Branch from `main`:**
   ```bash
   git checkout main
   git pull upstream main
   git checkout -b feat/frost-threshold-resync
   ```
3. **Keep Branches Focused:** One feature or bug fix per Pull Request. Avoid grouping unrelated refactorings into a single PR.
4. **Sign Commits:** Always use `git commit -s`. We also strongly encourage cryptographically signing commits using GPG or SSH keys (`git commit -S -s`).

---

## Code Quality & Testing Standards

All code submitted to CipherVault must pass our automated quality gates:

### 1. Formatting
```bash
cargo fmt --all -- --check
```

### 2. Linting
CipherVault maintains strict Clippy lints with zero warnings allowed:
```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### 3. Unit and Integration Tests
```bash
cargo test --workspace --all-features
```

### 4. Smart Contract Tests (Foundry)
If you modify contracts in [`contracts/`](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/contracts/):
```bash
forge test -vvv
```

### 5. SPDX Headers
Every new `.rs` or `.sol` source file should include the project's standard SPDX header at the top:
```rust
// Copyright (c) 2026 Samuel Avornyoh and CipherVault Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
```

---

## Commit Message Standards

We follow the **Conventional Commits** specification:

```text
<type>(<scope>): <short description in present tense>

[optional detailed body explaining why this change was made]

Signed-off-by: Your Name <your.email@example.com>
```

### Allowed Types:
* `feat`: A new user-facing feature or API capability
* `fix`: A bug fix
* `perf`: Performance optimization
* `refactor`: Code reorganization with no functional change
* `docs`: Documentation updates
* `test`: Adding or modifying test suites
* `chore`: Build system, CI/CD, or maintenance changes

### Example:
```text
feat(protocol): add nonce replay guard for operator state transitions

Operators now track monotonic sequence IDs across epoch handshakes, preventing
replay attacks during rapid network partitions.

Signed-off-by: Samuel Avornyoh <samuel@example.com>
```

---

## Licensing and Inbound Rights

By contributing to CipherVault, you agree that your contributions will be licensed under the project's dual-license:
* **[MIT License](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/LICENSE-MIT)**
* **[Apache License 2.0](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/LICENSE-APACHE)**

You retain copyright over your individual contributions, but grant the project, maintainers, and all downstream users a perpetual, irrevocable, royalty-free license to use, modify, redistribute, and compile your work under these terms.

---

## Reporting Security Issues

Please **do not disclose security vulnerabilities publicly** on GitHub issues or community channels. 

Refer to our [Security Policy](file:///c:/Users/samue/OneDrive/Desktop/projects/CipherVault/SECURITY.md) for instructions on confidential disclosure and our coordinated vulnerability disclosure timeline.
