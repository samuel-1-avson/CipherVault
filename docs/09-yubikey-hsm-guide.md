# CipherVault Hardware Security Module (HSM) & YubiKey PIV Guide

This guide describes how to integrate physical **YubiKey 5 Series** hardware tokens and **PKCS#11 HSMs** with **CipherVault** to achieve hardware-isolated cryptographic key protection.

---

## 1. Security Architecture & Threat Model

In standard software vaults, cryptographic private keys reside in host memory (RAM) while the vault is unlocked. If the host operating system is compromised with kernel-level malware, memory scraping, or cold-boot attacks, ephemeral keys could potentially be extracted.

With **Hardware Security Module (HSM)** integration:
1. **Private Keys Never Leave Silicon**: Private keys are generated directly inside the tamper-resistant secure element (CC EAL6+) of the YubiKey and cannot be exported.
2. **Physical Touch-Policy Protection**: Cryptographic operations (signing snapshot commits, decrypting epoch envelopes) require physical user presence (touching the golden contact on the YubiKey).
3. **Hardware PIN/PUK Defense**: 3 consecutive failed PIN attempts brick the PIV applet until unlocked with the administrative PUK.

```text
┌─────────────────────────────────────────────────────────────┐
│                    Host Machine (Untrusted)                 │
│                                                             │
│   ciphervault commit / restore                              │
│              │                                              │
│              ▼ (PC/SC / PKCS#11 Interface)                  │
└──────────────┼──────────────────────────────────────────────┘
               │  Protected USB / NFC Bus
┌──────────────▼──────────────────────────────────────────────┐
│                    YubiKey 5 Series / HSM                   │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │ PIV Secure Element (CC EAL6+)                       │   │
│   │                                                     │   │
│   │  [Slot 9A] Authentication   (Ed25519)               │   │
│   │            Operator mTLS & Session Auth             │   │
│   │                                                     │   │
│   │  [Slot 9C] Digital Signature (Ed25519)              │   │
│   │            Snapshot Head & Assertion Signing        │   │
│   │            * Requires Physical Touch                │   │
│   │                                                     │   │
│   │  [Slot 9D] Key Management   (X25519 / P-256)        │   │
│   │            Epoch Envelope Key Unwrapping / ECDH     │   │
│   │            * Requires Physical Touch + PIN          │   │
│   └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Hardware Slot Mapping

CipherVault maps its key hierarchy to standard NIST SP 800-73-4 PIV slots:

| PIV Slot | Slot Name | CipherVault Function | Algorithm | Touch Policy | PIN Policy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **9A** | Authentication | Mutual TLS (mTLS) to Operators | Ed25519 | Cached (15s) | Once per session |
| **9C** | Digital Signature | Device Snapshot Commits | Ed25519 | **Always** | Always |
| **9D** | Key Management | Vault Epoch Envelope ECDH | X25519 / P-256 | **Always** | Always |
| **9E** | Card Authentication | Physical Presence Verification | Ed25519 | Never | Never |

---

## 3. Provisioning Your YubiKey

### Prerequisites
Install **YubiKey Manager CLI** (`ykman`):
- **macOS**: `brew install ykman`
- **Linux (Ubuntu/Debian)**: `sudo apt-get install yubikey-manager`
- **Windows**: `winget install Yubico.YubiKeyManager`

### Step 1: Change Default PIN, PUK, and Management Key
```bash
# Set new User PIN (default: 123456)
ykman piv access change-pin

# Set new PUK (default: 12345678)
ykman piv access change-puk

# Set new Management Key (protects slot generation)
ykman piv access change-management-key --generate --protect
```

### Step 2: Generate Device Signing Key (Slot 9C)
Generate an Ed25519 signing key inside hardware requiring physical touch:
```bash
ykman piv keys generate \
    --algorithm ED25519 \
    --pin-policy ALWAYS \
    --touch-policy ALWAYS \
    9C device_signing.pub

# Create self-signed X.509 attestation certificate for slot 9C
ykman piv certificates generate \
    --subject "CN=CipherVault Device Signing Key" \
    9C device_signing.pub
```

### Step 3: Generate Key Management Key (Slot 9D)
Generate an encryption/key agreement key requiring physical touch:
```bash
ykman piv keys generate \
    --algorithm X25519 \
    --pin-policy ALWAYS \
    --touch-policy ALWAYS \
    9D epoch_mgmt.pub

ykman piv certificates generate \
    --subject "CN=CipherVault Epoch Key Management" \
    9D epoch_mgmt.pub
```

---

## 4. PKCS#11 Library Paths

CipherVault links dynamically to the PKCS#11 provider installed on the system:

- **Linux**: `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` (or `libykcs11.so`)
- **macOS**: `/usr/local/lib/libykcs11.dylib` or `/opt/homebrew/lib/libykcs11.dylib`
- **Windows**: `C:\Program Files\Yubico\Yubico PIV Tool\bin\libykpiv.dll`

Set the library path in your configuration:
```toml
# .ciphervault/config.toml
[hsm]
enabled = true
driver = "pkcs11"
module_path = "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykpiv.dll"
pin = "prompt"
touch_timeout_secs = 15
```

---

## 5. Software Simulator & CI Fallback

For environments without physical USB keys (such as headless servers and GitHub Actions CI pipelines), CipherVault provides `ciphervault_crypto::SoftwareHsmSimulator`.

It implements the identical `HardwareSecurityModule` trait in memory using zeroized Dalek primitives:
```rust
use ciphervault_crypto::{HardwareSecurityModule, HsmSlot, SoftwareHsmSimulator};

let hsm = SoftwareHsmSimulator::generate();
let public_key = hsm.get_public_key(HsmSlot::DigitalSignature)?;
let signature = hsm.sign_digest(HsmSlot::DigitalSignature, b"CIPHERVAULT-DOMAIN", &digest)?;
```

---

## 6. Verification Commands

Check whether your YubiKey slots are properly provisioned:
```bash
# List all PIV keys and certificates on the connected token
ykman piv info

# Test signing a test digest
ciphervault hsm test-signature --slot 9C
```
