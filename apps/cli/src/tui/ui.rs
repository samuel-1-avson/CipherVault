use super::app::{StatusLevel, TuiApp, TuiTab};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, HighlightSpacing, Paragraph,
        Row, Table, Tabs, Wrap,
    },
    Frame,
};

pub fn draw(frame: &mut Frame, app: &mut TuiApp) {
    let size = frame.area();

    // Main layout: Header (3 rows), Content (flex), Footer (3 rows)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(size);

    render_header(frame, app, chunks[0]);

    match app.active_tab {
        TuiTab::Overview => render_overview_tab(frame, app, chunks[1]),
        TuiTab::Files => render_files_tab(frame, app, chunks[1]),
        TuiTab::Snapshots => render_snapshots_tab(frame, app, chunks[1]),
        TuiTab::Operators => render_operators_tab(frame, app, chunks[1]),
        TuiTab::FastCdc => render_fastcdc_tab(frame, app, chunks[1]),
        TuiTab::HardwareToken => render_token_tab(frame, app, chunks[1]),
    }

    render_footer(frame, app, chunks[2]);

    // Render modals if active
    if app.show_track_modal {
        render_track_modal(frame, app);
    } else if app.show_help {
        render_help_modal(frame);
    }
}

fn render_header(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let header_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(22),
            Constraint::Min(40),
            Constraint::Length(26),
        ])
        .split(area);

    // 1. Logo / Title
    let logo = Paragraph::new(Line::from(vec![
        Span::styled("CIPHER", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled("VAULT ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("v0.1", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::Cyan)));
    frame.render_widget(logo, header_layout[0]);

    // 2. Tab Navigation
    let titles: Vec<Line> = TuiTab::ALL
        .iter()
        .map(|t| Line::from(t.title()))
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)))
        .select(app.active_tab as usize)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, header_layout[1]);

    // 3. Durability / Status Badge
    let online_count = app.operators.iter().filter(|o| o.online).count();
    let total_count = app.operators.len();

    let (badge_text, badge_color) = if online_count == total_count && total_count > 0 {
        (format!(" {online_count}/{total_count} QUORUM OK "), Color::Green)
    } else if online_count > 0 {
        (format!(" {online_count}/{total_count} DEGRADED "), Color::Yellow)
    } else {
        (" ALL OFFLINE ".into(), Color::Red)
    };

    let badge = Paragraph::new(Line::from(vec![
        Span::styled(
            badge_text,
            Style::default()
                .fg(Color::Black)
                .bg(badge_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(badge_color)));
    frame.render_widget(badge, header_layout[2]);
}

fn render_overview_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(8)])
        .split(area);

    let top_cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(main_layout[0]);

    // Left Card: Vault Identity & Cryptographic Roots
    let vid_snippet = if app.vault_id_hex.len() > 16 {
        format!("{}...{}", &app.vault_id_hex[..8], &app.vault_id_hex[app.vault_id_hex.len() - 8..])
    } else {
        app.vault_id_hex.clone()
    };

    let head_snippet = if app.head_cid_hex.len() > 16 {
        format!("{}...{}", &app.head_cid_hex[..8], &app.head_cid_hex[app.head_cid_hex.len() - 8..])
    } else {
        app.head_cid_hex.clone()
    };

    let locator_snippet = if app.recovery_locator_hex.len() > 16 {
        format!("{}...", &app.recovery_locator_hex[..12])
    } else {
        app.recovery_locator_hex.clone()
    };

    let info_text = vec![
        Line::from(vec![
            Span::styled("Vault ID:        ", Style::default().fg(Color::Gray)),
            Span::styled(vid_snippet, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Active Epoch:    ", Style::default().fg(Color::Gray)),
            Span::styled(format!("Epoch #{}", app.active_epoch), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Latest Head:     ", Style::default().fg(Color::Gray)),
            Span::styled(head_snippet, Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled("Public Locator:  ", Style::default().fg(Color::Gray)),
            Span::styled(locator_snippet, Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled("Store Mode:      ", Style::default().fg(Color::Gray)),
            Span::styled("SQLite WAL (DPAPI Protected at rest)", Style::default().fg(Color::LightGreen)),
        ]),
    ];

    let info_block = Paragraph::new(info_text)
        .block(
            Block::default()
                .title(" Vault Cryptographic Identity ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(info_block, top_cards[0]);

    // Right Card: Quick Health & Capacity
    let total_size: u64 = app.tracked_files.iter().map(|f| f.size_bytes).sum();
    let online_ops = app.operators.iter().filter(|o| o.online).count();

    let health_text = vec![
        Line::from(vec![
            Span::styled("Tracked Files:    ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{} confidential files", app.tracked_files.len()), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Protected Volume: ", Style::default().fg(Color::Gray)),
            Span::styled(format_bytes(total_size), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Total Snapshots:  ", Style::default().fg(Color::Gray)),
            Span::styled(format!("{} commits in DAG", app.snapshots.len()), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Federation Quorum:", Style::default().fg(Color::Gray)),
            Span::styled(format!("{online_ops} of {} nodes online", app.operators.len()), Style::default().fg(if online_ops == app.operators.len() { Color::Green } else { Color::Yellow })),
        ]),
        Line::from(vec![
            Span::styled("Hardware Token:   ", Style::default().fg(Color::Gray)),
            Span::styled(
                if app.token_status.token_attached { "YubiKey PIV Slot 9C Active" } else { "No Physical Token" },
                Style::default().fg(if app.token_status.token_attached { Color::Green } else { Color::DarkGray }),
            ),
        ]),
    ];

    let health_block = Paragraph::new(health_text)
        .block(
            Block::default()
                .title(" Federation & Storage Metrics ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Green)),
        );
    frame.render_widget(health_block, top_cards[1]);

    // Bottom Section: Core Security Axioms & Operational Guidelines
    let axioms = vec![
        Line::from(vec![
            Span::styled("• Zero Plaintext At Rest: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Device keys and epoch secrets are locked via OS keyring (Windows DPAPI) and never stored unencrypted."),
        ]),
        Line::from(vec![
            Span::styled("• Zero-Disk Recovery Kit: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Master secret R is wiped from RAM immediately upon vault initialization with zero plain disk footprint."),
        ]),
        Line::from(vec![
            Span::styled("• FastCDC Content Deduplication: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Dual-mask Gear rolling hash slices files; unchanged chunks are skipped using 461-byte PoS challenges."),
        ]),
        Line::from(vec![
            Span::styled("• Arbitrum L2 Settlement: ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("Head commitments can be anchored on-chain with sequencer receipt verification against CipherVaultRegistry."),
        ]),
    ];

    let bottom_block = Paragraph::new(axioms)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .title(" Zero-Knowledge System Invariants ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    frame.render_widget(bottom_block, main_layout[1]);
}

fn render_files_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    if app.tracked_files.is_empty() {
        let p = Paragraph::new("No files tracked yet. Press [t] to track a file (e.g. .env or secrets/dev.key)")
            .alignment(Alignment::Center)
            .block(Block::default().title(" Tracked Files ").borders(Borders::ALL).border_type(BorderType::Rounded));
        frame.render_widget(p, area);
        return;
    }

    let rows: Vec<Row> = app
        .tracked_files
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let status_span = if f.exists_on_disk {
                Span::styled("✓ Present", Style::default().fg(Color::Green))
            } else {
                Span::styled("✗ Missing", Style::default().fg(Color::Red))
            };

            let row_style = if i == app.file_table_index {
                Style::default().bg(Color::Rgb(30, 58, 138)).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                Span::raw(format!("{}", i + 1)),
                Span::styled(&f.path, Style::default().fg(Color::White)),
                Span::styled(format_bytes(f.size_bytes), Style::default().fg(Color::Cyan)),
                Span::styled(&f.file_id_hex, Style::default().fg(Color::Yellow)),
                status_span,
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Percentage(45),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Length(14),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["#", "File Path", "Size", "File ID", "Disk Status"])
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(format!(" Tracked Confidential Files ({} files) - Press [t] to track new ", app.tracked_files.len()))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_spacing(HighlightSpacing::Always);

    frame.render_widget(table, area);
}

fn render_snapshots_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    if app.snapshots.is_empty() {
        let p = Paragraph::new("No snapshots committed yet. Press [p] to create and replicate your first snapshot!")
            .alignment(Alignment::Center)
            .block(Block::default().title(" Snapshot History DAG ").borders(Borders::ALL).border_type(BorderType::Rounded));
        frame.render_widget(p, area);
        return;
    }

    let rows: Vec<Row> = app
        .snapshots
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let cid_snippet = format!("{}...", &s.snapshot_id_hex[..8]);
            let parent_snippet = if s.parent_id_hex == "Genesis" {
                "Genesis".into()
            } else {
                format!("{}...", &s.parent_id_hex[..8])
            };

            let head_badge = if s.is_head {
                Span::styled(" [HEAD] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
            } else {
                Span::styled(" commit ", Style::default().fg(Color::DarkGray))
            };

            let row_style = if i == app.snapshot_table_index {
                Style::default().bg(Color::Rgb(30, 58, 138)).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                Span::raw(format!("{}", i + 1)),
                Span::styled(cid_snippet, Style::default().fg(Color::Cyan)),
                Span::styled(parent_snippet, Style::default().fg(Color::Gray)),
                Span::styled(&s.message, Style::default().fg(Color::White)),
                Span::styled(&s.timestamp_rfc3339, Style::default().fg(Color::Yellow)),
                Span::styled(format!("{} files", s.files_count), Style::default().fg(Color::White)),
                head_badge,
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Percentage(35),
        Constraint::Length(22),
        Constraint::Length(10),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["#", "CID", "Parent", "Commit Message", "Timestamp", "Files", "Status"])
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(" Immutable Snapshot History DAG (Replicated across Operators) ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    frame.render_widget(table, area);
}

fn render_operators_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let rows: Vec<Row> = app
        .operators
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let (status_span, latency_span) = if op.online {
                let lat_color = if op.latency_ms < 50 {
                    Color::Green
                } else if op.latency_ms < 200 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                (
                    Span::styled("ONLINE", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    Span::styled(format!("{} ms", op.latency_ms), Style::default().fg(lat_color)),
                )
            } else {
                (
                    Span::styled("OFFLINE", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                    Span::styled("Timeout", Style::default().fg(Color::DarkGray)),
                )
            };

            Row::new(vec![
                Span::raw(format!("{}", i + 1)),
                Span::styled(&op.operator_id, Style::default().fg(Color::White)),
                Span::styled(&op.endpoint, Style::default().fg(Color::Cyan)),
                status_span,
                latency_span,
                Span::styled("90-day immutable lease", Style::default().fg(Color::Gray)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(4),
        Constraint::Length(14),
        Constraint::Length(30),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["#", "Operator ID", "Endpoint URI", "Status", "Latency", "Retention Policy"])
                .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(" Storage Operator Quorum & Live Latency Telemetry ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Green)),
        );

    frame.render_widget(table, area);
}

fn render_fastcdc_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(8)])
        .split(area);

    if let Some(ref m) = app.fastcdc_metrics {
        let metrics_text = vec![
            Line::from(vec![
                Span::styled("Analyzing File: ", Style::default().fg(Color::Gray)),
                Span::styled(&m.source_name, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(format!("  ({} total)", format_bytes(m.total_bytes as u64)), Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled("Chunks Produced: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", m.total_chunks), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" ({} unique, {} duplicate)", m.unique_chunks, m.duplicate_chunks), Style::default().fg(Color::White)),
                Span::styled("  |  Deduplication Savings: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{:.1}% ({} pruned)", m.dedup_savings_pct, format_bytes(m.saved_bytes as u64)), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]),
        ];

        let p = Paragraph::new(metrics_text).block(
            Block::default()
                .title(" FastCDC Dual-Mask Normalization Metrics ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        frame.render_widget(p, chunks[0]);

        // Table of chunks
        let rows: Vec<Row> = app
            .fastcdc_chunks
            .iter()
            .take(20) // Show first 20 chunks
            .map(|c| {
                let dup_span = if c.is_duplicate {
                    Span::styled("Duplicate", Style::default().fg(Color::Yellow))
                } else {
                    Span::styled("Unique", Style::default().fg(Color::Green))
                };

                Row::new(vec![
                    Span::raw(format!("{}", c.index)),
                    Span::styled(format!("{}", c.offset), Style::default().fg(Color::Gray)),
                    Span::styled(format_bytes(c.length as u64), Style::default().fg(Color::Cyan)),
                    Span::styled(&c.gear_fingerprint, Style::default().fg(Color::Magenta)),
                    Span::styled(format!("{:.2}", c.entropy), Style::default().fg(Color::White)),
                    dup_span,
                    Span::styled(&c.preview, Style::default().fg(Color::DarkGray)),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Min(20),
        ];

        let table = Table::new(rows, widths)
            .header(
                Row::new(vec!["#", "Offset", "Length", "Gear Rolling Hash", "Entropy", "Deduplication", "Plaintext Preview"])
                    .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                    .bottom_margin(1),
            )
            .block(
                Block::default()
                    .title(" Content-Defined Chunk Slices (Gear SplitMix64) ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
        frame.render_widget(table, chunks[1]);
    } else {
        let p = Paragraph::new("No confidential files tracked or available to inspect. Press [t] to track a file.")
            .alignment(Alignment::Center)
            .block(Block::default().title(" FastCDC Inspector ").borders(Borders::ALL).border_type(BorderType::Rounded));
        frame.render_widget(p, area);
    }
}

fn render_token_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(area);

    let (token_title, token_color) = if app.token_status.token_attached {
        (" Physical Smartcard / YubiKey Detected (Slot 9C/9D Ready) ", Color::Green)
    } else {
        (" No Physical Smartcard Detected (PC/SC Bus Active) ", Color::Yellow)
    };

    let readers_str = if app.token_status.readers.is_empty() {
        "None detected".into()
    } else {
        app.token_status.readers.join(", ")
    };

    let token_text = vec![
        Line::from(vec![
            Span::styled("PC/SC Readers:    ", Style::default().fg(Color::Gray)),
            Span::styled(readers_str, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Hardware Status:  ", Style::default().fg(Color::Gray)),
            Span::styled(
                if app.token_status.token_attached { "YubiKey PIV Token Attached" } else { "Waiting for hardware insertion" },
                Style::default().fg(if app.token_status.token_attached { Color::Green } else { Color::Yellow }).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Slot 9C (Sign):   ", Style::default().fg(Color::Gray)),
            Span::styled("Digital Signature with User Presence Touch Enforcement", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Slot 9D (KeyMgmt):", Style::default().fg(Color::Gray)),
            Span::styled("Hardware-isolated ECDH Key Agreement for clean recovery", Style::default().fg(Color::Cyan)),
        ]),
    ];

    let p = Paragraph::new(token_text).block(
        Block::default()
            .title(token_title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(token_color)),
    );
    frame.render_widget(p, main_layout[0]);

    // Instructions Box
    let guide_text = vec![
        Line::from(vec![
            Span::styled("PIV Touch Ceremony Instructions:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("1. To bind your device identity to physical hardware, run:"),
        Line::from(Span::styled("   ciphervault init --hardware-token", Style::default().fg(Color::Yellow))),
        Line::from("2. To require touch confirmation before replicating a snapshot commit:"),
        Line::from(Span::styled("   ciphervault push --touch", Style::default().fg(Color::Yellow))),
        Line::from("3. The YubiKey LED will flash; host execution pauses until the capacitive sensor is physically touched."),
        Line::from("4. Private keys never touch host RAM or swap memory."),
    ];

    let guide = Paragraph::new(guide_text).block(
        Block::default()
            .title(" Hardware Security Guide ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(guide, main_layout[1]);
}

fn render_footer(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let footer_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let level_color = match app.status_level {
        StatusLevel::Info => Color::Cyan,
        StatusLevel::Success => Color::Green,
        StatusLevel::Warning => Color::Yellow,
        StatusLevel::Error => Color::Red,
    };

    let status_p = Paragraph::new(Line::from(vec![
        Span::styled(" Status: ", Style::default().fg(Color::DarkGray)),
        Span::styled(&app.status_message, Style::default().fg(level_color)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)));
    frame.render_widget(status_p, footer_layout[0]);

    let hints = Paragraph::new(Line::from(vec![
        Span::styled("[1-6/Tab]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Tabs  ", Style::default().fg(Color::Gray)),
        Span::styled("[p]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Push  ", Style::default().fg(Color::Gray)),
        Span::styled("[a]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Anchor  ", Style::default().fg(Color::Gray)),
        Span::styled("[r]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Refresh  ", Style::default().fg(Color::Gray)),
        Span::styled("[t]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Track  ", Style::default().fg(Color::Gray)),
        Span::styled("[q]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(" Quit", Style::default().fg(Color::Gray)),
    ]))
    .alignment(Alignment::Right)
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(Style::default().fg(Color::DarkGray)));
    frame.render_widget(hints, footer_layout[1]);
}

fn render_track_modal(frame: &mut Frame, app: &TuiApp) {
    let area = centered_rect(60, 20, frame.area());
    frame.render_widget(Clear, area);

    let modal_block = Block::default()
        .title(" Track New Confidential File ")
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .margin(1)
        .split(area);

    frame.render_widget(modal_block, area);

    let label = Paragraph::new("Enter relative or absolute path of file to add to vault tracking:");
    frame.render_widget(label, inner[0]);

    let input = Paragraph::new(Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Yellow)),
        Span::styled(&app.track_input_buffer, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled("█", Style::default().fg(Color::Yellow)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::White)));
    frame.render_widget(input, inner[1]);

    let help = Paragraph::new("[Enter] Confirm Tracking    [Esc] Cancel")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    frame.render_widget(help, inner[2]);
}

fn render_help_modal(frame: &mut Frame) {
    let area = centered_rect(65, 55, frame.area());
    frame.render_widget(Clear, area);

    let help_text = vec![
        Line::from(Span::styled("CipherVault TUI Keyboard Shortcuts", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("1 - 6      ", Style::default().fg(Color::Yellow)),
            Span::raw("Switch directly to tabs 1 through 6"),
        ]),
        Line::from(vec![
            Span::styled("Tab        ", Style::default().fg(Color::Yellow)),
            Span::raw("Cycle to the next tab"),
        ]),
        Line::from(vec![
            Span::styled("BackTab    ", Style::default().fg(Color::Yellow)),
            Span::raw("Cycle to the previous tab"),
        ]),
        Line::from(vec![
            Span::styled("p          ", Style::default().fg(Color::Yellow)),
            Span::raw("Push new encrypted snapshot across storage operators"),
        ]),
        Line::from(vec![
            Span::styled("a          ", Style::default().fg(Color::Yellow)),
            Span::raw("Anchor active head commitment to Arbitrum L2"),
        ]),
        Line::from(vec![
            Span::styled("t          ", Style::default().fg(Color::Yellow)),
            Span::raw("Open modal to track a new confidential file"),
        ]),
        Line::from(vec![
            Span::styled("r          ", Style::default().fg(Color::Yellow)),
            Span::raw("Force immediate refresh of local state & operator pings"),
        ]),
        Line::from(vec![
            Span::styled("Up / Down  ", Style::default().fg(Color::Yellow)),
            Span::raw("Select previous / next row in tables"),
        ]),
        Line::from(vec![
            Span::styled("?          ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle this help overlay"),
        ]),
        Line::from(vec![
            Span::styled("q / Esc    ", Style::default().fg(Color::Red)),
            Span::raw("Quit TUI and restore terminal cleanly"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Press [Esc] or [?] to close this help overlay", Style::default().fg(Color::Gray))),
    ];

    let p = Paragraph::new(help_text).block(
        Block::default()
            .title(" Help & Keyboard Reference ")
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(p, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}
