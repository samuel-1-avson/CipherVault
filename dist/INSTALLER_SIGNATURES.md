# Bootstrap release verification

Both installers require an independently installed OpenSSL 3 with Ed25519 support on `PATH`. Obtain it through a trusted operating-system package source. They never execute a downloaded CipherVault executable to verify that download.

Current releases must publish `SHA256SUMS.txt` and `SHA256SUMS.txt.sig`. Signature verification against the public key embedded in the installer runs before checksum comparison, extraction, or executable replacement. The pinned public keys must match the updater's trust roots when a release key is rotated.

The four-line signature envelope is:

```text
CIPHERVAULT-RELEASE-SIG-V2
tag: vVERSION
key-id: FIRST_16_LOWERCASE_HEX_CHARACTERS_OF_PUBLIC_KEY
signature: LOWERCASE_HEX_ED25519_SIGNATURE
```

The exact Ed25519 message is the UTF-8 bytes `CIPHERVAULT-RELEASE-SIG-V2\ntag: vVERSION\n`, followed by the unchanged bytes of `SHA256SUMS.txt`. The tag permits 1–128 ASCII letters, digits, dots, underscores, and hyphens. Checksum lines bind the archive's exact version and target filename.

Automatic latest installation uses strict V2 verification. Historical V1 signatures authenticate the checksums without cryptographically binding the tag and are rejected by default. Deliberate historical compatibility requires **both** `CIPHERVAULT_ALLOW_LEGACY_RELEASE_SIGNATURE=1` and `CIPHERVAULT_VERSION=vEXACT_TAG`. This switch does not permit unsigned releases, untrusted signing keys, or checksum mismatches. The updater refuses downgrades; an explicitly requested `update --reinstall` can repair the same signed release.

Run `node tests/release_installer_signatures.cjs` to exercise the shell and PowerShell verifiers with isolated synthetic keys and the existing public V1 fixture. The test performs no download or installation. Rust updater tests separately exercise V2 tag rewriting, checksum tampering, untrusted keys, unsigned envelopes, and explicit V1 policy.
