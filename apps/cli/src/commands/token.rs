//! Hardware-token subcommands.

use anyhow::{bail, Result};
use colored::Colorize;
use std::io::{IsTerminal, Write};

use ciphervault_crypto::HardwareSecurityModule;

use crate::util::{get_saved_token_reader, resolve_hardware_token, save_token_reader_preference};
use crate::TokenSubcommand;

pub(crate) async fn cmd_token(sub: TokenSubcommand) -> Result<()> {
    match sub {
        TokenSubcommand::Status { reader } => {
            println!(
                "{}",
                "=== CIPHERVAULT HARDWARE SECURITY MODULE & YUBIKEY STATUS ==="
                    .bold()
                    .cyan()
            );
            let readers = ciphervault_crypto::list_readers()?;
            if readers.is_empty() {
                println!("  PC/SC Subsystem:  Active");
                println!("  Attached Readers: None detected");
                println!("\n{}", "To use a hardware token:".yellow());
                println!("  1. Insert a YubiKey 5 Series or PIV-compliant smartcard.");
                println!("  2. Ensure the PC/SC SmartCard service is running.");
                println!("  3. Run 'ciphervault token status' again.");
                return Ok(());
            }

            println!("  Attached Readers ({}):", readers.len());
            for r in &readers {
                println!("    - {}", r.green().bold());
            }

            println!("\n{}", "Probing PIV Applet on attached tokens...".dimmed());
            match ciphervault_crypto::probe_with_reader(reader.as_deref())? {
                Some(token) => {
                    println!(
                        "  Hardware Token:   Connected ({})",
                        token.reader_name().yellow().bold()
                    );
                    if let Ok(info_9c) =
                        token.get_slot_info(ciphervault_crypto::HsmSlot::DigitalSignature)
                    {
                        println!(
                            "  Slot 9C (Sign):   {} | Touch: {}",
                            info_9c.algorithm.green(),
                            info_9c.touch_policy.cyan()
                        );
                        println!("                    PK: {}", info_9c.public_key_hex);
                    }
                    if let Ok(info_9d) =
                        token.get_slot_info(ciphervault_crypto::HsmSlot::KeyManagement)
                    {
                        println!(
                            "  Slot 9D (ECDH):   {} | Touch: {}",
                            info_9d.algorithm.green(),
                            info_9d.touch_policy.cyan()
                        );
                        println!("                    PK: {}", info_9d.public_key_hex);
                    }
                    println!("\n  Status:           Ready for '--hardware-token' and '--touch' operations.");
                }
                None => {
                    println!(
                        "  Hardware Token:   Reader present, but no responsive PIV smartcard applet found."
                    );
                }
            }
        }
        TokenSubcommand::Probe { reader } => {
            match ciphervault_crypto::probe_with_reader(reader.as_deref())? {
                Some(token) => {
                    let info_9c =
                        token.get_slot_info(ciphervault_crypto::HsmSlot::DigitalSignature)?;
                    let info_9d =
                        token.get_slot_info(ciphervault_crypto::HsmSlot::KeyManagement)?;
                    let payload = serde_json::json!({
                        "detected": true,
                        "reader": token.reader_name(),
                        "slot_9c": info_9c,
                        "slot_9d": info_9d,
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                }
                None => {
                    let readers = ciphervault_crypto::list_readers()?;
                    let payload = serde_json::json!({
                        "detected": false,
                        "readers": readers,
                        "message": "No PIV smartcard token detected in PC/SC readers",
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                }
            }
        }
        TokenSubcommand::List => {
            println!(
                "{}",
                "=== CIPHERVAULT PC/SC READERS & TOKENS ===".bold().cyan()
            );
            let readers = ciphervault_crypto::list_readers()?;
            if readers.is_empty() {
                println!("  No PC/SC card readers detected on system.");
                return Ok(());
            }
            let active_tokens = ciphervault_crypto::probe_all()?;
            let active_reader_names: std::collections::HashSet<String> = active_tokens
                .iter()
                .map(|t| t.reader_name().to_string())
                .collect();

            let preferred = get_saved_token_reader();

            for (i, r) in readers.iter().enumerate() {
                let has_piv = active_reader_names.contains(r);
                let is_pref = preferred.as_deref() == Some(r.as_str());
                let pref_str = if is_pref {
                    " [Default]".cyan().bold()
                } else {
                    "".normal()
                };
                if has_piv {
                    println!(
                        "  [{}] {} {} {}",
                        i + 1,
                        r.green().bold(),
                        "✓ PIV Ready".green(),
                        pref_str
                    );
                } else {
                    println!(
                        "  [{}] {} {} {}",
                        i + 1,
                        r.dimmed(),
                        "(No PIV card inserted)".dimmed(),
                        pref_str
                    );
                }
            }
            println!(
                "\n  Total Readers: {} | Active PIV Tokens: {}",
                readers.len(),
                active_tokens.len()
            );
        }
        TokenSubcommand::Slots { reader } => {
            println!(
                "{}",
                "=== CIPHERVAULT HARDWARE TOKEN SLOT INSPECTOR ==="
                    .bold()
                    .cyan()
            );
            let token =
                resolve_hardware_token(reader.as_deref(), None, !std::io::stdin().is_terminal())?;
            println!(
                "  Hardware Token: {}\n",
                token.reader_name().yellow().bold()
            );

            let slots = [
                (
                    ciphervault_crypto::HsmSlot::DigitalSignature,
                    "9C",
                    "Digital Signature",
                ),
                (
                    ciphervault_crypto::HsmSlot::KeyManagement,
                    "9D",
                    "Key Management / ECDH",
                ),
                (
                    ciphervault_crypto::HsmSlot::Authentication,
                    "9A",
                    "Authentication",
                ),
                (
                    ciphervault_crypto::HsmSlot::CardAuthentication,
                    "9E",
                    "Card Authentication",
                ),
            ];

            for (slot, hex_code, label) in slots {
                print!("  Slot {} ({}): ", hex_code.bold(), label);
                match token.get_slot_info(slot) {
                    Ok(info) => {
                        println!("{}", "Active".green().bold());
                        println!("    Algorithm:    {}", info.algorithm.cyan());
                        println!("    Touch Policy: {}", info.touch_policy);
                        println!("    PIN Policy:   {}", info.pin_policy);
                        println!("    Public Key:   {}", info.public_key_hex.dimmed());
                    }
                    Err(e) => {
                        println!("{} ({})", "Unprovisioned / Inaccessible".dimmed(), e);
                    }
                }
                println!();
            }
        }
        TokenSubcommand::Pin { pin, test, clear } => {
            if clear {
                ciphervault_crypto::clear_cached_pin();
                println!(
                    "{}",
                    "✓ Cleared cached hardware token PIN from session memory.".green()
                );
                return Ok(());
            }

            let pin_val = if let Some(p) = pin {
                p
            } else if std::io::stdin().is_terminal() {
                rpassword::prompt_password("Enter hardware token PIN: ")?
            } else {
                bail!("Must specify --pin <PIN> in headless/non-interactive mode");
            };

            let pin_bytes = pin_val.trim().as_bytes();
            if test {
                match ciphervault_crypto::PcscHardwareToken::probe()? {
                    Some(token) => {
                        token.verify_pin(pin_bytes)?;
                        println!(
                            "{}",
                            "✓ PIN verified successfully with attached hardware token!"
                                .bold()
                                .green()
                        );
                        ciphervault_crypto::set_cached_pin(pin_bytes);
                    }
                    None => {
                        bail!("Cannot test PIN: No PIV hardware token detected in PC/SC readers.");
                    }
                }
            } else {
                ciphervault_crypto::set_cached_pin(pin_bytes);
                println!(
                    "{}",
                    "✓ Hardware token PIN cached in volatile session memory.".green()
                );
            }
        }
        TokenSubcommand::Select { reader } => {
            let readers = ciphervault_crypto::list_readers()?;
            if readers.is_empty() {
                bail!("No PC/SC smartcard readers detected on system.");
            }

            let target = if let Some(r) = reader {
                let r_lower = r.to_lowercase();
                readers
                    .into_iter()
                    .find(|name| name.to_lowercase().contains(&r_lower))
                    .ok_or_else(|| anyhow::anyhow!("Reader matching '{}' not found", r))?
            } else if std::io::stdin().is_terminal() {
                println!(
                    "\n{}",
                    "Select default hardware token reader:".bold().cyan()
                );
                for (i, r) in readers.iter().enumerate() {
                    println!("  [{}] {}", i + 1, r.green());
                }
                print!("Selection [1-{}]: ", readers.len());
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let choice: usize = input.trim().parse().unwrap_or(1);
                let idx = if choice >= 1 && choice <= readers.len() {
                    choice - 1
                } else {
                    0
                };
                readers[idx].clone()
            } else {
                bail!("Must provide reader name in headless mode. Usage: ciphervault token select --reader <NAME>");
            };

            save_token_reader_preference(&target)?;
            println!(
                "{} Default hardware token reader set to '{}'",
                "✓".green().bold(),
                target.yellow()
            );
        }
    }
    Ok(())
}
