//! Multi-party genesis ceremony for the sovereign CipherChain.
//!
//! The fleet agrees out-of-band on (chain id, member keys, genesis
//! timestamp). One party runs `genesis propose` to build the deterministic
//! unsigned proposal; every member runs `genesis sign` with their device
//! key; the founder runs `genesis assemble` to combine quorum signatures
//! into a chain dir. Late joiners need no files: they adopt the gossiped
//! tip and backfill history over the catch-up RPC.

use anyhow::{bail, Context, Result};

/// Unsigned ceremony proposal file: the deterministic height-0 header plus
/// the agreed member set it must be certified by.
#[derive(serde::Serialize, serde::Deserialize)]
struct GenesisProposalFile {
    chain_id: String,
    validators: Vec<String>,
    header: ciphervault_chain::BlockHeader,
}

/// Parses a comma/space/semicolon-separated list of hex validator keys:
/// trims `0x`, requires 32 bytes each, sorts, dedups, rejects empties.
pub(crate) fn parse_pubkey_list(raw: &str) -> Result<Vec<[u8; 32]>> {
    let mut keys = Vec::new();
    for (i, part) in raw
        .split([',', ';', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let bytes = hex::decode(part.trim().trim_start_matches("0x"))
            .with_context(|| format!("key {i} is not hex"))?;
        if bytes.len() != 32 {
            bail!("key {i} must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        keys.push(arr);
    }
    if keys.is_empty() {
        bail!("no validator keys supplied");
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(keys)
}

pub(crate) fn cmd_genesis_propose(
    validators_raw: &str,
    timestamp_ms: u64,
    chain_id: &str,
    out_path: &str,
) -> Result<()> {
    let keys = parse_pubkey_list(validators_raw)?;
    let set = ciphervault_chain::ValidatorSet::new(keys.clone())?;
    if set.quorum_threshold() > keys.len() {
        bail!("quorum unreachable for this set");
    }
    let header = ciphervault_chain::BlockHeader {
        version: ciphervault_chain::PROTOCOL_VERSION,
        chain_id: chain_id.to_string(),
        height: 0,
        prev_block_hash: [0u8; 32],
        state_root: ciphervault_chain::EMPTY_TREE_ROOT,
        tx_root: ciphervault_chain::EMPTY_TREE_ROOT,
        timestamp_ms,
        proposer: keys[0],
        next_validators: None,
        signatures: Vec::new(),
    };
    let file = GenesisProposalFile {
        chain_id: chain_id.to_string(),
        validators: keys.iter().map(hex::encode).collect(),
        header,
    };
    let json = serde_json::to_string_pretty(&file)?;
    std::fs::write(out_path, &json)
        .with_context(|| format!("failed to write proposal to {out_path}"))?;
    println!("Genesis proposal written to {out_path}");
    println!("  Chain ID:      {chain_id}");
    println!(
        "  Members:       {} (quorum {})",
        keys.len(),
        set.quorum_threshold()
    );
    println!("  Timestamp:     {timestamp_ms}");
    println!("  Proposer:      {}", hex::encode(keys[0]));
    println!("  Unsigned hash: {}", hex::encode(file.header.block_hash()));
    println!("Share this file out-of-band; every member verifies the terms, signs, and returns a signature file.");
    Ok(())
}

pub(crate) fn cmd_genesis_sign(proposal_path: &str, out_path: &str) -> Result<()> {
    let raw = std::fs::read_to_string(proposal_path)
        .with_context(|| format!("failed to read proposal {proposal_path}"))?;
    let file: GenesisProposalFile =
        serde_json::from_str(&raw).context("proposal file is not a genesis proposal")?;
    if file.header.height != 0 {
        bail!("proposal is not a height-0 genesis");
    }
    if file.header.version != ciphervault_chain::PROTOCOL_VERSION {
        bail!(
            "proposal version {} != local protocol {} (upgrade first)",
            file.header.version,
            ciphervault_chain::PROTOCOL_VERSION
        );
    }
    if !file.header.signatures.is_empty() {
        bail!("proposal already carries signatures; sign the unsigned proposal");
    }
    // Load (creating if needed) this member's persistent device key.
    let (_chain_dir, device_signer, _set) = super::anchor::load_device_and_validators()?;
    if !file
        .validators
        .iter()
        .any(|h| h.eq_ignore_ascii_case(&hex::encode(device_signer.public_key())))
    {
        bail!("local device key is not a member of this ceremony set");
    }
    let sig = device_signer.sign_header(&file.header);
    let json = serde_json::to_string_pretty(&sig)?;
    std::fs::write(out_path, &json)
        .with_context(|| format!("failed to write signature to {out_path}"))?;
    println!("Signature written to {out_path}");
    println!("  Validator: {}", hex::encode(sig.validator));
    println!("Return this file to the founder for assembly.");
    Ok(())
}

pub(crate) fn cmd_genesis_assemble(
    proposal_path: &str,
    signature_paths: &[String],
    chain_dir: &str,
) -> Result<()> {
    let raw = std::fs::read_to_string(proposal_path)
        .with_context(|| format!("failed to read proposal {proposal_path}"))?;
    let file: GenesisProposalFile =
        serde_json::from_str(&raw).context("proposal file is not a genesis proposal")?;
    if file.header.height != 0 {
        bail!("proposal is not a height-0 genesis");
    }
    let mut keys = Vec::with_capacity(file.validators.len());
    for (i, h) in file.validators.iter().enumerate() {
        let bytes = hex::decode(h.trim().trim_start_matches("0x"))
            .with_context(|| format!("proposal validator {i} is not hex"))?;
        if bytes.len() != 32 {
            bail!("proposal validator {i} must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        keys.push(arr);
    }
    let set = ciphervault_chain::ValidatorSet::new(keys)?;
    let mut signatures = Vec::with_capacity(signature_paths.len());
    for path in signature_paths {
        let sig_raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read signature {path}"))?;
        let sig: ciphervault_chain::BlockSignature =
            serde_json::from_str(&sig_raw).context("signature file is not a block signature")?;
        signatures.push(sig);
    }
    let GenesisProposalFile {
        chain_id,
        validators: file_validators,
        header,
    } = file;
    let dir = std::path::PathBuf::from(chain_dir);
    if dir.join("blocks").exists() {
        bail!("chain dir {chain_dir} already holds blocks; assemble into an empty dir");
    }
    let ledger = ciphervault_chain::SovereignLedger::assemble_genesis(
        &chain_id,
        set,
        header,
        signatures,
        Some(dir.clone()),
    )?;
    // Operator convenience: the ceremony set doubles as the initial
    // configured file (admission + open seed until the first rotation).
    let validators_json =
        serde_json::to_string_pretty(&file_validators).context("encode validators")?;
    if let Err(e) = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::write(dir.join("validators.json"), validators_json))
    {
        eprintln!("warning: could not write validators.json: {e}");
    }
    println!("Genesis assembled in {chain_dir}");
    println!("  Height:        {}", ledger.height());
    println!(
        "  Members:       {} (quorum {})",
        ledger.validator_set().validators().len(),
        ledger.validator_set().quorum_threshold()
    );
    println!(
        "  Genesis hash:  {}",
        hex::encode(ledger.latest_block().header.block_hash())
    );
    println!("Share the hash out-of-band: every member must see the same value. Others join via gossip + backfill.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_propose_is_deterministic_and_sorted() {
        let out = std::env::temp_dir().join(format!(
            "cv-genesis-propose-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let keys = format!(
            "{},{}",
            hex::encode([0x02u8; 32]),
            hex::encode([0x01u8; 32])
        );
        cmd_genesis_propose(&keys, 1_000, "test-chain", &out.to_string_lossy()).unwrap();
        let first = std::fs::read_to_string(&out).unwrap();
        cmd_genesis_propose(&keys, 1_000, "test-chain", &out.to_string_lossy()).unwrap();
        let second = std::fs::read_to_string(&out).unwrap();
        assert_eq!(first, second);
        // Sorted ascending regardless of input order.
        let file: GenesisProposalFile = serde_json::from_str(&first).unwrap();
        assert_eq!(file.validators[0], hex::encode([0x01u8; 32]));
        assert_eq!(file.header.proposer, [0x01u8; 32]);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn test_parse_pubkey_list_rejects_garbage() {
        assert!(parse_pubkey_list("").is_err());
        assert!(parse_pubkey_list("zzzz").is_err());
        assert!(parse_pubkey_list(&hex::encode([0x01u8; 31])).is_err());
        // Duplicates collapse.
        let one = hex::encode([0x01u8; 32]);
        let keys = parse_pubkey_list(&format!("{one},{one}")).unwrap();
        assert_eq!(keys, vec![[0x01u8; 32]]);
    }

    #[test]
    fn test_assemble_combines_quorum_and_persists() {
        use ciphervault_chain::{ConsensusSigner, ValidatorSet};
        let dir = std::env::temp_dir().join(format!(
            "cv-genesis-assemble-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let signers: Vec<ConsensusSigner> = (0..3).map(|_| ConsensusSigner::generate()).collect();
        let keys: Vec<[u8; 32]> = signers.iter().map(|s| s.public_key()).collect();
        let keys_csv = keys.iter().map(hex::encode).collect::<Vec<_>>().join(",");
        let proposal_path = dir.join("proposal.json");
        let chain_dir = dir.join("chain");
        std::fs::create_dir_all(&dir).unwrap();
        cmd_genesis_propose(
            &keys_csv,
            1_000,
            "test-chain",
            &proposal_path.to_string_lossy(),
        )
        .unwrap();

        // Two of three sign: quorum for a 3-member set is 3, so assembly
        // must fail...
        let mut sig_paths = Vec::new();
        for (i, signer) in signers.iter().take(2).enumerate() {
            let raw = std::fs::read_to_string(&proposal_path).unwrap();
            let file: GenesisProposalFile = serde_json::from_str(&raw).unwrap();
            let sig = signer.sign_header(&file.header);
            let path = dir.join(format!("sig{i}.json"));
            std::fs::write(&path, serde_json::to_string_pretty(&sig).unwrap()).unwrap();
            sig_paths.push(path.to_string_lossy().to_string());
        }
        assert!(cmd_genesis_assemble(
            &proposal_path.to_string_lossy(),
            &sig_paths,
            &chain_dir.to_string_lossy()
        )
        .is_err());

        // ...and the third signature completes quorum.
        let raw = std::fs::read_to_string(&proposal_path).unwrap();
        let file: GenesisProposalFile = serde_json::from_str(&raw).unwrap();
        let sig = signers[2].sign_header(&file.header);
        let path = dir.join("sig2.json");
        std::fs::write(&path, serde_json::to_string_pretty(&sig).unwrap()).unwrap();
        sig_paths.push(path.to_string_lossy().to_string());
        cmd_genesis_assemble(
            &proposal_path.to_string_lossy(),
            &sig_paths,
            &chain_dir.to_string_lossy(),
        )
        .unwrap();

        // Reopen from disk: height 0, ceremony set active.
        let set = ValidatorSet::new(keys.clone()).unwrap();
        let ledger =
            ciphervault_chain::SovereignLedger::open("test-chain", set, &chain_dir).unwrap();
        assert_eq!(ledger.height(), 0);
        // The ceremony sorts members; compare in ceremony order.
        let mut expected = keys.clone();
        expected.sort_unstable();
        assert_eq!(ledger.validator_set().validators(), expected);
        assert!(chain_dir.join("genesis_validators.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `genesis sign` uses the member's persistent device key and refuses
    /// proposals the local key is not a member of.
    #[tokio::test]
    async fn test_sign_uses_device_key_and_enforces_membership() {
        use crate::util::{VaultContext, REQUEST_VAULT_CONTEXT};

        let ws = std::env::temp_dir().join(format!(
            "cv-genesis-sign-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let vault_dir = ws.join(".ciphervault");
        std::fs::create_dir_all(&vault_dir).unwrap();
        let db_path = vault_dir.join("vault.db");
        std::fs::write(&db_path, []).unwrap();
        let ctx = VaultContext::from_db_path(&db_path).unwrap();

        REQUEST_VAULT_CONTEXT
            .scope(ctx, async {
                // Device key is created on first load; include it in the set.
                let (_, device_signer, _) =
                    crate::commands::anchor::load_device_and_validators().unwrap();
                let member = hex::encode(device_signer.public_key());
                let outsider = hex::encode([0xabu8; 32]);

                let proposal = ws.join("proposal.json");
                cmd_genesis_propose(&member, 1_000, "test-chain", &proposal.to_string_lossy())
                    .unwrap();
                let sig_path = ws.join("sig.json");
                cmd_genesis_sign(&proposal.to_string_lossy(), &sig_path.to_string_lossy()).unwrap();
                let sig: ciphervault_chain::BlockSignature =
                    serde_json::from_str(&std::fs::read_to_string(&sig_path).unwrap()).unwrap();
                assert_eq!(sig.validator, device_signer.public_key());
                // The signature verifies against the proposal header.
                let file: GenesisProposalFile =
                    serde_json::from_str(&std::fs::read_to_string(&proposal).unwrap()).unwrap();
                let mut signed = file.header.clone();
                signed.signatures.push(sig.clone());
                ciphervault_chain::ValidatorSet::new(vec![device_signer.public_key()])
                    .unwrap()
                    .verify_header_signatures(&signed)
                    .unwrap();

                // A proposal without the local key is refused.
                let foreign = ws.join("foreign.json");
                cmd_genesis_propose(&outsider, 1_000, "test-chain", &foreign.to_string_lossy())
                    .unwrap();
                assert!(cmd_genesis_sign(
                    &foreign.to_string_lossy(),
                    &ws.join("foreign_sig.json").to_string_lossy(),
                )
                .is_err());
            })
            .await;
        let _ = std::fs::remove_dir_all(&ws);
    }
}
