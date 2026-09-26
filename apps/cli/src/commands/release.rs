//! Release-engineering commands: sign and verify `SHA256SUMS.txt` release
//! signatures (`ciphervault release sign|verify`).
//!
//! The release workflow signs the published checksums with the offline
//! release seed and uploads the detached `SHA256SUMS.txt.sig` asset next
//! to them; the updater (`commands::update`) verifies that signature
//! against its pinned trust roots before any checksum or install step.
//! The seed lives in CI secrets / offline ceremony media and never in the
//! repo; the corresponding pubkey is pinned in `update.rs`.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::PathBuf;

use super::update::{
    is_pinned_release_key, release_key_id_of_pubkey, render_release_signature,
    verify_release_signature,
};

/// Loads the 32-byte release signing seed: explicit key file first (offline
/// ceremony), `CIPHERVAULT_RELEASE_SIGNING_KEY` env otherwise (CI secret).
/// The value is hex, `0x`-prefixed or bare. Never logged.
fn load_release_signing_seed(key_file: Option<&PathBuf>) -> Result<[u8; 32]> {
    let raw = match key_file {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("reading release key file {}", path.display()))?,
        None => std::env::var("CIPHERVAULT_RELEASE_SIGNING_KEY").context(
            "CIPHERVAULT_RELEASE_SIGNING_KEY is required (or --key-file for an offline ceremony)",
        )?,
    };
    let trimmed = raw.trim().trim_start_matches("0x").trim();
    let decoded = hex::decode(trimmed).context("release signing seed is not valid hex")?;
    if decoded.len() != 32 {
        bail!("release signing seed must be exactly 32 bytes");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

/// Signs `sums` for `tag` and writes the detached envelope to `out` (or
/// stdout). Refuses to sign with a seed whose pubkey is not pinned: such a
/// release would be uninstallable, so the ceremony fails here, not at the
/// user's updater. The envelope is self-verified before it is emitted.
pub(crate) fn cmd_release_sign(
    tag: String,
    sums: PathBuf,
    out: Option<PathBuf>,
    key_file: Option<PathBuf>,
) -> Result<()> {
    if tag.trim().is_empty() {
        bail!("release tag must not be empty");
    }
    let seed = load_release_signing_seed(key_file.as_ref())?;
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    if !is_pinned_release_key(&pubkey_hex) {
        bail!(
            "signing key {} is not a pinned release key; pin its pubkey in the updater before signing",
            release_key_id_of_pubkey(&pubkey_hex)
        );
    }
    let sums_bytes =
        fs::read(&sums).with_context(|| format!("reading checksum file {}", sums.display()))?;
    let signature_hex = hex::encode(signing_key.sign(&sums_bytes).to_bytes());
    let envelope = render_release_signature(
        tag.trim(),
        &release_key_id_of_pubkey(&pubkey_hex),
        &signature_hex,
    );
    // Fail closed on any rendering bug: the emitted envelope must verify.
    verify_release_signature(&sums_bytes, &envelope, tag.trim())
        .context("self-verification of the emitted release signature failed")?;
    match &out {
        Some(path) => fs::write(path, &envelope)
            .with_context(|| format!("writing signature file {}", path.display()))?,
        None => print!("{envelope}"),
    }
    println!(
        "Signed {} for tag {} with release key {}.",
        sums.display(),
        tag.trim(),
        release_key_id_of_pubkey(&pubkey_hex)
    );
    Ok(())
}

/// Verifies a detached release signature against the pinned trust roots
/// (ceremony / CI double-check; same predicate the updater enforces).
pub(crate) fn cmd_release_verify(tag: String, sums: PathBuf, sig: PathBuf) -> Result<()> {
    let sums_bytes =
        fs::read(&sums).with_context(|| format!("reading checksum file {}", sums.display()))?;
    let sig_text =
        fs::read_to_string(&sig).with_context(|| format!("reading signature {}", sig.display()))?;
    let key_id = verify_release_signature(&sums_bytes, &sig_text, tag.trim())?;
    println!(
        "Release signature valid (tag {}, key {}).",
        tag.trim(),
        key_id
    );
    Ok(())
}

#[cfg(test)]
mod release_command_tests {
    use super::*;

    #[test]
    fn seed_loader_rejects_wrong_lengths() {
        let dir = std::env::temp_dir().join(format!("cv_relsig_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let short = dir.join("short.hex");
        fs::write(&short, "ab12").unwrap();
        assert!(load_release_signing_seed(Some(&short)).is_err());
        let nonhex = dir.join("nonhex.hex");
        fs::write(&nonhex, "zz".repeat(32)).unwrap();
        assert!(load_release_signing_seed(Some(&nonhex)).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unpinned_seed_refuses_to_sign() {
        let dir = std::env::temp_dir().join(format!("cv_relsign_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sums = dir.join("SHA256SUMS.txt");
        fs::write(&sums, "aa  x\n").unwrap();
        // Fixed non-pinned seed: deterministic, and certainly not the
        // pinned release key (asserted, so the test fails loudly if the
        // trust roots ever change to include it).
        let seed = [0x77u8; 32];
        let pubkey_hex = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        assert!(!is_pinned_release_key(&pubkey_hex));
        let key_file = dir.join("attacker.hex");
        fs::write(&key_file, hex::encode(seed)).unwrap();
        let err = cmd_release_sign(
            "v0.0.0-test".into(),
            sums,
            Some(dir.join("SHA256SUMS.txt.sig")),
            Some(key_file),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not a pinned release key"),
            "{err:#}"
        );
        assert!(!dir.join("SHA256SUMS.txt.sig").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
