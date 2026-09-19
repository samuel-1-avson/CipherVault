use super::app::{StatusLevel, TuiApp, TuiTab};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;

pub async fn handle_key_event(app: &mut TuiApp, key: KeyEvent) {
    // If Help modal is open, any key closes it
    if app.show_help {
        if let KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter = key.code {
            app.show_help = false;
        }
        return;
    }

    // If Track modal is open, handle text input
    if app.show_track_modal {
        match key.code {
            KeyCode::Esc => {
                app.show_track_modal = false;
                app.track_input_buffer.clear();
            }
            KeyCode::Enter => {
                let path_str = app.track_input_buffer.trim().to_string();
                if !path_str.is_empty() {
                    let path = PathBuf::from(&path_str);
                    if path.exists() {
                        match crate::get_vault_store() {
                            Ok(store) => match store.track_file(&path_str) {
                                Ok(_) => {
                                    app.set_status(
                                        format!("✓ Tracked '{}' into vault database", path_str),
                                        StatusLevel::Success,
                                    );
                                    app.refresh_local_state();
                                }
                                Err(e) => {
                                    app.set_status(
                                        format!("Error tracking file: {e}"),
                                        StatusLevel::Error,
                                    );
                                }
                            },
                            Err(e) => {
                                app.set_status(
                                    format!("Failed to open vault store: {e}"),
                                    StatusLevel::Error,
                                );
                            }
                        }
                    } else {
                        app.set_status(
                            format!("File not found: '{}'", path_str),
                            StatusLevel::Warning,
                        );
                    }
                }
                app.show_track_modal = false;
                app.track_input_buffer.clear();
            }
            KeyCode::Backspace => {
                app.track_input_buffer.pop();
            }
            KeyCode::Char(c) => {
                app.track_input_buffer.push(c);
            }
            _ => {}
        }
        return;
    }

    // Global Keybindings
    match key.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }

        // Help
        KeyCode::Char('?') => {
            app.show_help = true;
        }

        // Tabs direct jump
        KeyCode::Char('1') => app.switch_tab(TuiTab::Overview),
        KeyCode::Char('2') => app.switch_tab(TuiTab::Files),
        KeyCode::Char('3') => app.switch_tab(TuiTab::Snapshots),
        KeyCode::Char('4') => app.switch_tab(TuiTab::Operators),
        KeyCode::Char('5') => app.switch_tab(TuiTab::FastCdc),
        KeyCode::Char('6') => app.switch_tab(TuiTab::HardwareToken),

        // Tab cycling
        KeyCode::Tab | KeyCode::Right => app.next_tab(),
        KeyCode::BackTab | KeyCode::Left => app.previous_tab(),

        // Table / List Navigation
        KeyCode::Down | KeyCode::Char('j') => match app.active_tab {
            TuiTab::Files => {
                if !app.tracked_files.is_empty() {
                    app.file_table_index = (app.file_table_index + 1) % app.tracked_files.len();
                    app.run_fastcdc_inspection();
                }
            }
            TuiTab::Snapshots if !app.snapshots.is_empty() => {
                app.snapshot_table_index = (app.snapshot_table_index + 1) % app.snapshots.len();
            }
            TuiTab::FastCdc if !app.fastcdc_chunks.is_empty() => {
                app.chunk_table_index = (app.chunk_table_index + 1) % app.fastcdc_chunks.len();
            }
            _ => {}
        },

        KeyCode::Up | KeyCode::Char('k') => match app.active_tab {
            TuiTab::Files => {
                if !app.tracked_files.is_empty() {
                    app.file_table_index = if app.file_table_index == 0 {
                        app.tracked_files.len() - 1
                    } else {
                        app.file_table_index - 1
                    };
                    app.run_fastcdc_inspection();
                }
            }
            TuiTab::Snapshots if !app.snapshots.is_empty() => {
                app.snapshot_table_index = if app.snapshot_table_index == 0 {
                    app.snapshots.len() - 1
                } else {
                    app.snapshot_table_index - 1
                };
            }
            TuiTab::FastCdc if !app.fastcdc_chunks.is_empty() => {
                app.chunk_table_index = if app.chunk_table_index == 0 {
                    app.fastcdc_chunks.len() - 1
                } else {
                    app.chunk_table_index - 1
                };
            }
            _ => {}
        },

        // Action: Force Refresh
        KeyCode::Char('r') => {
            app.set_status(
                "Refreshing local state and pinging storage operators...",
                StatusLevel::Info,
            );
            app.refresh_local_state();
            app.poll_operators_async().await;
            app.set_status("✓ Local state and operators updated.", StatusLevel::Success);
        }

        // Account session actions. Hosted TOTP login remains a browser
        // ceremony; the TUI uses the local OS-protected account key so it can
        // never require users to paste vault secrets into the terminal.
        KeyCode::Char('l') => app.login_local_account(),
        KeyCode::Char('o') => app.logout_local_account(),

        // Action: Track Modal
        KeyCode::Char('t') => {
            app.show_track_modal = true;
            app.track_input_buffer.clear();
        }

        // Action: Push snapshot
        KeyCode::Char('p') => {
            app.set_status(
                "Pushing encrypted snapshot across operators...",
                StatusLevel::Info,
            );
            match execute_quick_push().await {
                Ok(msg) => {
                    app.set_status(msg, StatusLevel::Success);
                    app.refresh_local_state();
                }
                Err(e) => {
                    app.set_status(format!("Snapshot push failed: {e}"), StatusLevel::Error);
                }
            }
        }

        // Action: Anchor to Arbitrum L2
        KeyCode::Char('a') => {
            app.set_status(
                "Submitting state commitment to Arbitrum L2 relayer...",
                StatusLevel::Info,
            );
            match execute_quick_anchor().await {
                Ok(msg) => {
                    app.set_status(msg, StatusLevel::Success);
                    app.refresh_local_state();
                }
                Err(e) => {
                    app.set_status(format!("L2 anchor failed: {e}"), StatusLevel::Error);
                }
            }
        }

        _ => {}
    }
}

async fn execute_quick_push() -> anyhow::Result<String> {
    crate::cmd_push(
        Some("TUI Snapshot commit".into()),
        false,
        false,
        false,
        None,
        None,
        None,
        None,
    )
    .await?;
    Ok("✓ Encrypted snapshot created and confirmed across operator quorum.".into())
}

async fn execute_quick_anchor() -> anyhow::Result<String> {
    let store = crate::get_vault_store()?;
    let head = store.get_active_head()?;
    let head_record = match head {
        Some(h) => h,
        None => {
            anyhow::bail!(
                "Vault has no snapshots committed yet. Press [p] to create a snapshot first."
            );
        }
    };
    let head_hex = hex::encode(&head_record.snapshot_id);
    let relayer_url = crate::get_configured_operators().first().cloned();

    match crate::cmd_anchor(
        Some(head_hex),
        None,
        None,
        None,
        None,
        None,
        true,
        relayer_url,
    )
    .await
    {
        Ok(_) => Ok("✓ Checkpoint registered with Arbitrum L2 relayer (QueuedForRelay).".into()),
        Err(e) => {
            anyhow::bail!("{e}");
        }
    }
}
