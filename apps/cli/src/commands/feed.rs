//! Public checkpoint-feed build and publish commands.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;

use crate::util::get_vault_store;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PublicCheckpointFeedEntry {
    pub(crate) network: String,
    pub(crate) chain_id: u64,
    pub(crate) contract_address_hex: String,
    pub(crate) commitment_hex: String,
    pub(crate) head_record_cid_hex: String,
    #[serde(default)]
    pub(crate) tx_hash_hex: Option<String>,
    #[serde(default)]
    pub(crate) block_number: Option<u64>,
    pub(crate) published_at_utc: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PublicCheckpointFeedUnsigned {
    pub(crate) version: u32,
    pub(crate) issued_at_utc: u64,
    pub(crate) checkpoints: Vec<PublicCheckpointFeedEntry>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PublicCheckpointFeedEnvelope {
    pub(crate) version: u32,
    pub(crate) issued_at_utc: u64,
    pub(crate) checkpoints: Vec<PublicCheckpointFeedEntry>,
    pub(crate) publisher_key_hex: String,
    pub(crate) signature_hex: String,
}

pub(crate) fn load_public_feed_signing_key() -> Result<SigningKey> {
    let raw = std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX").map_err(|_| {
        anyhow::anyhow!(
            "CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX is required to publish the public feed"
        )
    })?;
    let decoded = hex::decode(raw.trim().trim_start_matches("0x"))
        .context("Public checkpoint signing key is not valid hex")?;
    if decoded.len() != 32 {
        bail!("Public checkpoint signing key must be exactly 32 bytes");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded);
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn build_public_checkpoint_feed(
    evidence: Vec<ciphervault_format::CheckpointEvidence>,
    network: String,
    signing_key: &SigningKey,
    issued_at_utc: u64,
) -> Result<PublicCheckpointFeedEnvelope> {
    if network.trim().is_empty() {
        bail!("Public checkpoint feed network label cannot be empty");
    }
    if evidence.len() > 1_000 {
        bail!("Public checkpoint feed cannot contain more than 1,000 records");
    }

    let checkpoints = evidence
        .into_iter()
        .map(|record| {
            if record.version != ciphervault_format::PROTOCOL_VERSION {
                bail!("Checkpoint evidence uses an unsupported protocol version");
            }
            if !record.verify_commitment() {
                bail!("Checkpoint evidence contains an invalid commitment preimage");
            }
            if record.chain_id == 0
                || record.contract_address.len() != 20
                || record.commitment.len() != 32
                || record.head_record_cid.len() != 32
            {
                bail!("Checkpoint evidence contains invalid chain or digest lengths");
            }

            let tx_present =
                record.tx_hash.len() == 32 && record.tx_hash.iter().any(|byte| *byte != 0);
            if !record.tx_hash.is_empty() && record.tx_hash.len() != 32 {
                bail!("Checkpoint evidence contains an invalid transaction hash");
            }

            Ok(PublicCheckpointFeedEntry {
                network: network.clone(),
                chain_id: record.chain_id,
                contract_address_hex: hex::encode(record.contract_address),
                commitment_hex: hex::encode(record.commitment),
                head_record_cid_hex: hex::encode(record.head_record_cid),
                tx_hash_hex: tx_present.then(|| format!("0x{}", hex::encode(record.tx_hash))),
                block_number: (record.block_number > 0).then_some(record.block_number),
                published_at_utc: record.timestamp_utc,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let unsigned = PublicCheckpointFeedUnsigned {
        version: 1,
        issued_at_utc,
        checkpoints,
    };
    let message = ciphervault_format::to_canonical_cbor(&unsigned)
        .context("Unable to canonicalize public checkpoint feed")?;
    let signature = ciphervault_crypto::signatures::sign_with_domain(
        signing_key,
        b"public_checkpoint_feed",
        &message,
    );
    Ok(PublicCheckpointFeedEnvelope {
        version: unsigned.version,
        issued_at_utc: unsigned.issued_at_utc,
        checkpoints: unsigned.checkpoints,
        publisher_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
        signature_hex: hex::encode(signature),
    })
}

pub(crate) fn cmd_publish_public_feed(output: PathBuf, network: String) -> Result<()> {
    let signing_key = load_public_feed_signing_key()?;
    let store = get_vault_store()?;
    let evidence = store
        .list_checkpoint_evidence()
        .context("Unable to read checkpoint evidence from the active vault")?;
    let feed = build_public_checkpoint_feed(
        evidence,
        network,
        &signing_key,
        Utc::now().timestamp().max(0) as u64,
    )?;
    let encoded = serde_json::to_vec_pretty(&feed).context("Unable to encode public feed JSON")?;

    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temp_path = output.with_file_name(format!(
        ".{}.tmp-{}",
        output
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("public-checkpoint-feed.json"),
        std::process::id()
    ));
    fs::write(&temp_path, &encoded)?;
    let write_result = (|| -> Result<()> {
        if output.exists() {
            fs::remove_file(&output)?;
        }
        fs::rename(&temp_path, &output)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result?;

    println!(
        "Published {} signed checkpoint record(s) to {}",
        feed.checkpoints.len(),
        output.display()
    );
    println!(
        "Publisher verification key: {}",
        feed.publisher_key_hex.cyan()
    );
    println!(
        "Receipt and finality fields remain independently unverified until a chain verifier confirms them."
    );
    Ok(())
}
