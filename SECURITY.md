# Security Policy

CipherVault is a security-first cryptographic infrastructure project providing multi-party secret governance, threshold key derivation, and decentralized identity management. The integrity, confidentiality, and reliability of our cryptographic primitives and network services are of the utmost priority.

We actively welcome and value vulnerability reports from independent security researchers, cryptographers, and the open-source community.

---

## Supported Versions

Only the latest release on the primary development branch and explicitly tagged stable releases receive security patches:

| Version / Branch | Supported | Security Patch Policy |
| :--- | :--- | :--- |
| `main` (active development) | :white_check_mark: Yes | Immediate hotfix / rolling patch |
| Latest tagged `v1.0.x` release (currently `v1.0.25`) | :white_check_mark: Yes | Fixes ship in the next tagged release; local remediation changes require verification and release |
| Earlier tags, including `v0.1.x` | :x: No | Upgrade to the latest supported release |

---

## Reporting a Vulnerability

> [!CAUTION]
> **DO NOT file public GitHub Issues or discuss vulnerabilities on public chat channels, social media, or forums.** Doing so puts all users of the network at immediate risk.

### 1. Preferred Method: GitHub Private Vulnerability Reporting
Submit your report directly through GitHub's encrypted advisory workflow:
1. Navigate to the **[Security Tab](https://github.com/samuel-1-avson/CipherVault/security)** of the official repository.
2. Click **"Report a vulnerability"** under the Advisories section.
3. Complete the confidential advisory form with all relevant details.

### 2. Direct Security Contact
If GitHub Private Reporting is unavailable, contact the lead maintainer directly:
* **Contact:** Samuel Avornyoh
* **Email:** [security@ciphervault.org](mailto:security@ciphervault.org) (or maintainer GitHub direct contact)
* **Subject Line:** `[SECURITY] Potential Vulnerability in CipherVault: <Brief Summary>`

---

## What to Include in Your Report

To help us investigate, reproduce, and resolve the issue quickly, please provide:
* **Type of Vulnerability:** (e.g., Cryptographic flaw, threshold signature bypass, replay attack, memory safety, privilege escalation, smart contract reentrancy).
* **Affected Component:** Specific crate or contract path (e.g., `crates/crypto`, `contracts/CipherVaultRegistry.sol`, `services/account`).
* **Environment:** Operating system, Rust compiler version, and node configuration.
* **Proof of Concept (PoC):** Minimal reproduction code, test script, or exact CLI commands demonstrating the flaw.
* **Potential Impact:** An assessment of what an attacker could achieve (e.g., secret recovery, unauthorized quorum bypass, denial of service).

---

## Response & Disclosure SLA

We commit to the following response timeline for all legitimate security reports:

| Phase | Target Timeline | Details |
| :--- | :--- | :--- |
| **Initial Acknowledgment** | **Within 48 hours** | We confirm receipt of your report and assign a triage lead. |
| **Triage & Validation** | **Within 5 business days** | We analyze the report, attempt reproduction, and determine CVSS severity. |
| **Remediation & Patch** | **14 to 30 days** | We prepare, test, and audit a patch in a private repository. |
| **Coordinated Disclosure** | **Upon patch release** | We release the patch, publish a GitHub Security Advisory, and credit the researcher. |

---

## Safe Harbor for Researchers

We consider security research conducted under this policy to be authorized. We will **not** pursue legal action or criminal complaints against researchers who:
* Act in good faith to avoid privacy violations, data destruction, and interruption or degradation of services.
* Do not exploit a security issue beyond the minimum necessary to prove the vulnerability's existence.
* Give the CipherVault team a reasonable amount of time to remediate the vulnerability before publicly sharing details.
* Do not access, modify, or compromise any private cryptographic keys, shares, or data belonging to other users or network operators.
