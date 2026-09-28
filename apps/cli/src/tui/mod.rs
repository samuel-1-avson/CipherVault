pub mod app;
pub mod events;
pub mod ui;

use anyhow::Result;
use app::{TuiApp, TuiTab};
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{stdout, IsTerminal};
use std::time::{Duration, Instant};

/// Runs the interactive CipherVault Terminal User Interface (TUI)
pub async fn run_tui(poll_interval_ms: u64) -> Result<()> {
    // Check if running in a terminal
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("Cannot run CipherVault TUI: standard input is not a terminal (TTY).");
    }

    // Initialize terminal into raw mode and alternate screen
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;

    // Install panic hook to ensure terminal is restored on unexpected panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    let mut app = TuiApp::new(Duration::from_millis(poll_interval_ms));

    // Kick off the initial background work. Nothing here awaits: the first
    // frame renders immediately and results land as tasks complete.
    app.spawn_operator_poll();
    app.spawn_token_probe();
    app.spawn_update_check(false);

    let res = run_loop(&mut terminal, &mut app).await;

    // Restore terminal cleanly
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

async fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut TuiApp,
) -> Result<()> {
    let tick_rate = Duration::from_millis(50);
    let mut last_tick = Instant::now();

    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                events::handle_key_event(app, key).await;
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }

        // Apply finished background tasks. This never blocks: input stays
        // live no matter how slow the network or smartcard is.
        app.drain_tasks();

        // One-shot self-update check on the first tick. Silent unless an
        // update is pending, which opens the update modal.
        if !app.update_check_done {
            app.spawn_update_check(false);
        }

        // Periodic background polling for operator health. The timestamp
        // advances when the poll is *started* (each spawn is also guarded
        // against duplicates), so a slow operator can never stack ticks.
        if app.last_poll.elapsed() >= app.poll_interval {
            app.spawn_operator_poll();
            // Explorer telemetry is cache-backed (30 s) and the checkpoint
            // feed is cache-backed (60 s), so refreshing while visible is
            // cheap and keeps the tab live without a manual keypress.
            if app.active_tab == TuiTab::Explorer {
                app.spawn_explorer_refresh();
            }
            app.last_poll = Instant::now();
        }
    }

    Ok(())
}
