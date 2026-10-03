use super::app::{StatusLevel, TuiApp, TuiTab, TuiTable};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;

pub async fn handle_key_event(app: &mut TuiApp, key: KeyEvent) {
    // If Help modal is open, Esc / ? / Enter closes it (other keys ignored).
    if app.show_help {
        if let KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter = key.code {
            app.show_help = false;
        }
        return;
    }

    // Snapshot inspector is display-only: any dismiss key closes it.
    if app.show_snapshot_modal {
        if let KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') = key.code {
            app.show_snapshot_modal = false;
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
                                        format!("✓ Tracked '{path_str}' into vault database"),
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
                            format!("File not found: '{path_str}'"),
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

    // If the explorer search modal is open, handle CID input
    if app.show_explorer_search_modal {
        match key.code {
            KeyCode::Esc => {
                app.show_explorer_search_modal = false;
                app.explorer_search_buffer.clear();
            }
            KeyCode::Enter => {
                app.show_explorer_search_modal = false;
                // The probe runs in a background task; the status line and the
                // object panel update when it completes.
                app.spawn_object_probe();
                app.explorer_search_buffer.clear();
            }
            KeyCode::Backspace => {
                app.explorer_search_buffer.pop();
            }
            KeyCode::Char(c) => {
                app.explorer_search_buffer.push(c);
            }
            _ => {}
        }
        return;
    }

    // If the update modal is open, apply or dismiss it. Locked to read-only
    // while an install is in flight.
    if app.show_update_modal {
        if !app.update_in_progress {
            match key.code {
                KeyCode::Esc | KeyCode::Char('l') | KeyCode::Char('L') => {
                    app.show_update_modal = false;
                }
                KeyCode::Enter | KeyCode::Char('u') | KeyCode::Char('U') => {
                    app.spawn_update_apply();
                }
                _ => {}
            }
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
        KeyCode::Char('6') => {
            app.switch_tab(TuiTab::HardwareToken);
            app.spawn_token_probe();
        }
        KeyCode::Char('7') => {
            app.switch_tab(TuiTab::Explorer);
            app.spawn_explorer_refresh();
        }

        // Explorer object lookup
        KeyCode::Char('/') => {
            app.switch_tab(TuiTab::Explorer);
            app.spawn_explorer_refresh();
            app.show_explorer_search_modal = true;
            app.explorer_search_buffer.clear();
        }

        // Tab cycling
        KeyCode::Tab | KeyCode::Right => app.next_tab(),
        KeyCode::BackTab | KeyCode::Left => app.previous_tab(),

        // Table / List Navigation
        KeyCode::Down | KeyCode::Char('j') => match app.active_tab {
            TuiTab::Files => app.select_next(TuiTable::Files),
            TuiTab::Snapshots => app.select_next(TuiTable::Snapshots),
            TuiTab::FastCdc => app.select_next(TuiTable::Chunks),
            TuiTab::Explorer => app.select_next(TuiTable::Checkpoints),
            TuiTab::Operators => app.select_next(TuiTable::Operators),
            _ => {}
        },

        KeyCode::Up | KeyCode::Char('k') => match app.active_tab {
            TuiTab::Files => app.select_prev(TuiTable::Files),
            TuiTab::Snapshots => app.select_prev(TuiTable::Snapshots),
            TuiTab::FastCdc => app.select_prev(TuiTable::Chunks),
            TuiTab::Explorer => app.select_prev(TuiTable::Checkpoints),
            TuiTab::Operators => app.select_prev(TuiTable::Operators),
            _ => {}
        },

        // Page and edge jumps follow the active table's visible window.
        KeyCode::PageDown => match app.active_tab {
            TuiTab::Files => app.select_page(TuiTable::Files, true),
            TuiTab::Snapshots => app.select_page(TuiTable::Snapshots, true),
            TuiTab::FastCdc => app.select_page(TuiTable::Chunks, true),
            TuiTab::Explorer => app.select_page(TuiTable::Checkpoints, true),
            TuiTab::Operators => app.select_page(TuiTable::Operators, true),
            _ => {}
        },

        KeyCode::PageUp => match app.active_tab {
            TuiTab::Files => app.select_page(TuiTable::Files, false),
            TuiTab::Snapshots => app.select_page(TuiTable::Snapshots, false),
            TuiTab::FastCdc => app.select_page(TuiTable::Chunks, false),
            TuiTab::Explorer => app.select_page(TuiTable::Checkpoints, false),
            TuiTab::Operators => app.select_page(TuiTable::Operators, false),
            _ => {}
        },

        KeyCode::Home => match app.active_tab {
            TuiTab::Files => app.select_edge(TuiTable::Files, true),
            TuiTab::Snapshots => app.select_edge(TuiTable::Snapshots, true),
            TuiTab::FastCdc => app.select_edge(TuiTable::Chunks, true),
            TuiTab::Explorer => app.select_edge(TuiTable::Checkpoints, true),
            TuiTab::Operators => app.select_edge(TuiTable::Operators, true),
            _ => {}
        },

        KeyCode::End => match app.active_tab {
            TuiTab::Files => app.select_edge(TuiTable::Files, false),
            TuiTab::Snapshots => app.select_edge(TuiTable::Snapshots, false),
            TuiTab::FastCdc => app.select_edge(TuiTable::Chunks, false),
            TuiTab::Explorer => app.select_edge(TuiTable::Checkpoints, false),
            TuiTab::Operators => app.select_edge(TuiTable::Operators, false),
            _ => {}
        },

        // Row actions: inspect a snapshot, or jump from a file to its chunks.
        KeyCode::Enter => match app.active_tab {
            TuiTab::Snapshots => {
                if app.snapshots.is_empty() {
                    app.set_status("No snapshots to inspect.", StatusLevel::Warning);
                } else {
                    app.show_snapshot_modal = true;
                }
            }
            TuiTab::Files => {
                if app.tracked_files.is_empty() {
                    app.set_status("No tracked files to inspect.", StatusLevel::Warning);
                } else {
                    app.switch_tab(TuiTab::FastCdc);
                    app.request_inspection();
                }
            }
            _ => {}
        },

        // Action: Force Refresh
        KeyCode::Char('r') => {
            app.set_status("Refreshing local state and operators...", StatusLevel::Info);
            app.refresh_local_state();
            app.spawn_operator_poll();
            app.spawn_explorer_refresh();
            app.refresh_echo = app.poll_in_flight;
            if !app.poll_in_flight && app.operators.is_empty() {
                app.set_status(
                    "Local state refreshed; no operators configured to poll.",
                    StatusLevel::Warning,
                );
            }
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

        // Action: Untrack the selected file (Files tab only).
        KeyCode::Char('x') => {
            if app.active_tab == TuiTab::Files {
                app.untrack_selected_file();
            } else {
                app.set_status(
                    "Switch to the Files tab to untrack a file.",
                    StatusLevel::Info,
                );
            }
        }

        // Action: Push snapshot (background task; completion lands on the
        // status line without freezing input).
        KeyCode::Char('p') => app.spawn_push(),

        // Action: Check for updates
        KeyCode::Char('u') => app.spawn_update_check(true),

        // Action: Anchor to Arbitrum L2 (background task).
        KeyCode::Char('a') => app.spawn_anchor(),

        _ => {}
    }
}
