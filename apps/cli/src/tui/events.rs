use super::app::{StatusLevel, TuiApp, TuiTab, TuiTable};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub async fn handle_key_event(app: &mut TuiApp, key: KeyEvent) {
    // If Help modal is open, Esc / ? / Enter closes it (other keys ignored).
    if app.show_help {
        if let KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter = key.code {
            app.show_help = false;
        }
        return;
    }

    // Snapshot inspector is display-only, except for its action shortcuts:
    // [R] stages a restore confirmation, [F] diffs the selected snapshot.
    if app.show_snapshot_modal {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                app.show_snapshot_modal = false;
            }
            KeyCode::Char('R') => {
                app.show_snapshot_modal = false;
                app.request_restore_confirm();
            }
            KeyCode::Char('F') => {
                app.show_snapshot_modal = false;
                app.spawn_diff_for_context();
            }
            _ => {}
        }
        return;
    }

    // Diff viewer: scroll the masked report, any dismiss key closes it.
    // It sits below the confirm modal so a staged [y]/[Enter] still resolves
    // even with a diff open underneath.
    if app.show_diff_modal && app.confirm_action.is_none() {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                app.show_diff_modal = false;
            }
            KeyCode::Down | KeyCode::Char('j') => app.select_next(TuiTable::DiffLines),
            KeyCode::Up | KeyCode::Char('k') => app.select_prev(TuiTable::DiffLines),
            KeyCode::PageDown => app.select_page(TuiTable::DiffLines, true),
            KeyCode::PageUp => app.select_page(TuiTable::DiffLines, false),
            KeyCode::Home => app.select_edge(TuiTable::DiffLines, true),
            KeyCode::End => app.select_edge(TuiTable::DiffLines, false),
            _ => {}
        }
        return;
    }

    // Confirm modal owns its keys: [y]/[Enter] executes the staged action
    // exactly once, [n]/[Esc] drops it. No other binding runs while staged.
    if app.confirm_action.is_some() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                app.cancel_confirm();
            }
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.confirm_pending();
            }
            _ => {}
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
                app.show_track_modal = false;
                app.track_input_buffer.clear();
                // Store I/O runs in a background task; the status line and
                // the file table update when it completes.
                if !path_str.is_empty() {
                    app.spawn_track(path_str);
                }
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
        // Quit. Bare Esc never quits: it only dismisses modals (handled
        // above), so mashing Esc on a table cannot exit the TUI. While a
        // mutating task runs, the first [q] arms a two-stroke guard.
        KeyCode::Char('q') => {
            app.request_quit();
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
        // Sign-out is confirm-gated ([y]/[Enter] confirms) so a typo on the
        // key next to push ([p]) cannot revoke the session mid-shift.
        KeyCode::Char('l') => app.login_local_account(),
        KeyCode::Char('o') => app.request_logout_confirm(),

        // Action: Track Modal
        KeyCode::Char('t') => {
            app.show_track_modal = true;
            app.track_input_buffer.clear();
        }

        // Action: stage untrack confirmation (Files tab only; the modal
        // executes on [y]/[Enter] so a stray [x] cannot drop tracking).
        KeyCode::Char('x') => {
            app.untrack_selected_file();
        }

        // Action: Push snapshot (background task; completion lands on the
        // status line without freezing input).
        KeyCode::Char('p') => app.spawn_push(),

        // Action: stage restore confirmation (Snapshots tab or inspector;
        // the modal executes on [y]/[Enter] because restore overwrites
        // uncommitted working-tree changes).
        KeyCode::Char('R') => {
            app.request_restore_confirm();
        }

        // Action: masked diff (Snapshots tab: selected vs head, head vs
        // working tree; Files tab: selected file, head vs working tree).
        // Read-only, so no confirmation is staged.
        KeyCode::Char('F') => app.spawn_diff_for_context(),

        // Pull: [d] runs the read-only dry-run check (no confirm needed —
        // it writes nothing); [D] stages the real pull behind the confirm
        // modal (applies the remote snapshot with force=false, so dirty
        // files abort instead of being overwritten).
        KeyCode::Char('d') => app.spawn_pull(true),
        KeyCode::Char('D') => app.request_pull_confirm(),

        // Action: Check for updates
        KeyCode::Char('u') => app.spawn_update_check(true),

        // Action: stage anchor confirmation (Arbitrum L2 cost).
        KeyCode::Char('a') => app.request_anchor_confirm(),

        _ => {}
    }
}
