//! Out-of-band approval commands.

use anyhow::{bail, Context, Result};
use colored::Colorize;

use crate::util::{get_configured_operators, get_vault_store, operator_service_request};

pub(crate) async fn cmd_approve_list() -> Result<()> {
    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured.");
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    println!(
        "{}",
        "Pending Out-of-Band Cryptographic Authorization Challenges".bold()
    );
    println!("---------------------------------------------------------------------------------");

    let mut all_challenges = Vec::new();
    for op in &operators {
        let url = format!("{}/v1/auth/challenges/pending", op.trim_end_matches('/'));
        if let Ok(resp) = operator_service_request(http.get(&url)).send().await {
            if let Ok(challenges) = resp
                .json::<Vec<ciphervault_recovery::ApprovalChallenge>>()
                .await
            {
                for c in challenges {
                    if !all_challenges
                        .iter()
                        .any(|x: &ciphervault_recovery::ApprovalChallenge| {
                            x.challenge_id == c.challenge_id
                        })
                    {
                        all_challenges.push(c);
                    }
                }
            }
        }
    }

    if all_challenges.is_empty() {
        println!(
            "{}",
            "  (No pending authorization challenges found across cluster)".dimmed()
        );
        return Ok(());
    }

    println!(
        "{:<20} {:<18} {:<14} {:<10} {:<24}",
        "CHALLENGE ID", "ACTION", "VAULT ID", "TTL", "DETAILS"
    );
    println!(
        "{:<20} {:<18} {:<14} {:<10} {:<24}",
        "------------------",
        "----------------",
        "------------",
        "--------",
        "----------------------"
    );

    let now = chrono::Utc::now().timestamp() as u64;
    for c in &all_challenges {
        let remaining_secs = c.expires_at_utc.saturating_sub(now);
        let ttl_str = format!("{}s", remaining_secs);
        let short_vault = if c.vault_id_hex.len() >= 8 {
            &c.vault_id_hex[..8]
        } else {
            &c.vault_id_hex
        };
        let action_str = format!("{:?}", c.action);
        println!(
            "{:<20} {:<18} {:<14} {:<10} {:<24}",
            c.challenge_id.cyan().bold(),
            action_str.yellow(),
            short_vault.dimmed(),
            ttl_str.green(),
            c.details
        );
    }

    println!();
    println!(
        "To approve a challenge, run: {}",
        "ciphervault approve sign <CHALLENGE_ID>".cyan()
    );
    Ok(())
}

pub(crate) async fn cmd_approve_sign(
    challenge_id: String,
    approver_name: Option<String>,
) -> Result<()> {
    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured.");
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // 1. Fetch challenge details from operator cluster
    let mut found_challenge: Option<ciphervault_recovery::ApprovalChallenge> = None;
    for op in &operators {
        let url = format!(
            "{}/v1/auth/challenges/{}",
            op.trim_end_matches('/'),
            challenge_id
        );
        if let Ok(resp) = operator_service_request(http.get(&url)).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Ok(c) = serde_json::from_value::<ciphervault_recovery::ApprovalChallenge>(
                    json["challenge"].clone(),
                ) {
                    found_challenge = Some(c);
                    break;
                }
            }
        }
    }

    let challenge = found_challenge.context(format!(
        "Challenge '{}' not found or already expired on operator cluster",
        challenge_id
    ))?;

    println!("{}", "Authorize Cryptographic Approval Challenge".bold());
    println!("--------------------------------------------------");
    println!(
        "  Challenge ID:     {}",
        challenge.challenge_id.cyan().bold()
    );
    println!("  Action:           {:?}", challenge.action);
    println!("  Vault ID:         {}", challenge.vault_id_hex.yellow());
    println!("  Details:          {}", challenge.details);
    println!(
        "  Expires in:       {}s",
        challenge
            .expires_at_utc
            .saturating_sub(chrono::Utc::now().timestamp() as u64)
    );

    // Sign using device key from local store, or create an ad-hoc guardian key
    let store = get_vault_store();
    let signing_key = if let Ok(ref s) = store {
        let (_, key, _, _) = s.get_device_state()?;
        key
    } else {
        ciphervault_crypto::generate_signing_key()
    };

    let name = approver_name.unwrap_or_else(|| {
        std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "Authorized Approver".into())
    });

    let receipt =
        ciphervault_recovery::SignedApprovalReceipt::sign(&challenge, name.clone(), &signing_key);

    // Broadcast receipt to operators
    let mut accepted_count = 0;
    for op in &operators {
        let url = format!(
            "{}/v1/auth/challenges/{}/approve",
            op.trim_end_matches('/'),
            challenge_id
        );
        if let Ok(resp) = operator_service_request(http.post(&url))
            .json(&receipt)
            .send()
            .await
        {
            if resp.status().is_success() {
                accepted_count += 1;
            }
        }
    }

    if accepted_count == 0 {
        bail!("Failed to submit approval receipt to any operator");
    }

    println!(
        "{}",
        format!(
            "✓ Cryptographic approval signature by '{}' submitted and accepted by {} operator(s)!",
            name, accepted_count
        )
        .green()
        .bold()
    );

    Ok(())
}

pub(crate) async fn cmd_approve_status(challenge_id: String) -> Result<()> {
    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured.");
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    for op in &operators {
        let url = format!(
            "{}/v1/auth/challenges/{}",
            op.trim_end_matches('/'),
            challenge_id
        );
        if let Ok(resp) = operator_service_request(http.get(&url)).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Ok(challenge) = serde_json::from_value::<
                    ciphervault_recovery::ApprovalChallenge,
                >(json["challenge"].clone())
                {
                    println!("{}", "Approval Challenge Status".bold());
                    println!("--------------------------------------------------");
                    println!("  Challenge ID:  {}", challenge.challenge_id.cyan().bold());
                    println!("  Action:        {:?}", challenge.action);
                    println!("  Details:       {}", challenge.details);
                    let approved = json["approved"].as_bool().unwrap_or(false);
                    let count = json["receipt_count"].as_u64().unwrap_or(0);
                    println!(
                        "  Status:        {}",
                        if approved {
                            "APPROVED".green().bold()
                        } else {
                            "PENDING".yellow().bold()
                        }
                    );
                    println!("  Signatures:    {}", count);

                    if let Some(receipts) = json["receipts"].as_array() {
                        for r in receipts {
                            let name = r["approver_name"].as_str().unwrap_or("Unknown");
                            let pk = r["approver_pk_hex"].as_str().unwrap_or("");
                            let short_pk = if pk.len() >= 12 { &pk[..12] } else { pk };
                            // Display-only, but never assert validity unchecked:
                            // verify each receipt against the fetched challenge.
                            let valid = serde_json::from_value::<
                                ciphervault_recovery::SignedApprovalReceipt,
                            >(r.clone())
                            .map(|receipt| receipt.verify(&challenge).is_ok())
                            .unwrap_or(false);
                            println!(
                                "    - Signed by: {} (Key: {}...) [{}]",
                                name.cyan(),
                                short_pk.dimmed(),
                                if valid {
                                    "VALID".green()
                                } else {
                                    "INVALID".red().bold()
                                }
                            );
                        }
                    }
                    return Ok(());
                }
            }
        }
    }

    bail!("Challenge '{}' not found on any operator", challenge_id);
}
