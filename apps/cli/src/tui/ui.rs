use super::app::{BoundaryKind, StatusLevel, TuiApp, TuiTab};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, Clear, HighlightSpacing, Paragraph, Row, Table, Tabs, Wrap,
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
        TuiTab::Explorer => render_explorer_tab(frame, app, chunks[1]),
    }

    render_footer(frame, app, chunks[2]);

    // Render modals if active
    if app.show_track_modal {
        render_track_modal(frame, app);
    } else if app.show_explorer_search_modal {
        render_explorer_search_modal(frame, app);
    } else if app.show_update_modal {
        render_update_modal(frame, app);
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
        Span::styled(
            "CIPHER",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "VAULT ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            concat!("v", env!("CARGO_PKG_VERSION")),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(logo, header_layout[0]);

    // 2. Tab Navigation
    let titles: Vec<Line> = TuiTab::ALL.iter().map(|t| Line::from(t.title())).collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
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
        (
            format!(" {online_count}/{total_count} RESPONDING "),
            Color::Green,
        )
    } else if online_count > 0 {
        (
            format!(" {online_count}/{total_count} RESPONDING "),
            Color::Yellow,
        )
    } else {
        (
            format!(" {online_count}/{total_count} RESPONDING "),
            Color::Red,
        )
    };

    let badge = Paragraph::new(Line::from(vec![Span::styled(
        badge_text,
        Style::default()
            .fg(Color::Black)
            .bg(badge_color)
            .add_modifier(Modifier::BOLD),
    )]))
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(badge_color)),
    );
    frame.render_widget(badge, header_layout[2]);
}

fn render_overview_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(8)])
        .split(area);

    let top_cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_layout[0]);

    // Left Card: Vault Identity & Cryptographic Roots
    let vid_snippet = if app.vault_id_hex.len() > 16 {
        format!(
            "{}...{}",
            &app.vault_id_hex[..8],
            &app.vault_id_hex[app.vault_id_hex.len() - 8..]
        )
    } else {
        app.vault_id_hex.clone()
    };

    let head_snippet = if app.head_cid_hex.len() > 16 {
        format!(
            "{}...{}",
            &app.head_cid_hex[..8],
            &app.head_cid_hex[app.head_cid_hex.len() - 8..]
        )
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
            Span::styled(
                vid_snippet,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Active Epoch:    ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("Epoch #{}", app.active_epoch),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
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
            Span::styled(store_mode_label(), Style::default().fg(Color::LightGreen)),
        ]),
    ];

    let info_block = Paragraph::new(info_text).block(
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
    let total_ops = app.operators.len();
    let (operator_text, operator_color) = if total_ops == 0 {
        ("No operators configured".to_string(), Color::DarkGray)
    } else if online_ops == total_ops {
        (format!("All {total_ops} responding"), Color::Green)
    } else if online_ops == 0 {
        (format!("0 of {total_ops} responding (dark)"), Color::Red)
    } else {
        (
            format!("{online_ops} of {total_ops} responding (degraded)"),
            Color::Yellow,
        )
    };
    let (token_text, token_color) = if app.token_status.probing {
        ("Probing…".to_string(), Color::Yellow)
    } else if app.token_status.token_attached {
        ("PIV token attached".to_string(), Color::Green)
    } else {
        ("No PIV token".to_string(), Color::DarkGray)
    };

    let health_text = vec![
        Line::from(vec![
            Span::styled("Tracked Files:    ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} confidential files", app.tracked_files.len()),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Protected Volume: ", Style::default().fg(Color::Gray)),
            Span::styled(format_bytes(total_size), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Total Snapshots:  ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} commits in DAG", app.snapshots.len()),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("Operator Responses:", Style::default().fg(Color::Gray)),
            Span::styled(operator_text, Style::default().fg(operator_color)),
        ]),
        Line::from(vec![
            Span::styled("Hardware Token:   ", Style::default().fg(Color::Gray)),
            Span::styled(token_text, Style::default().fg(token_color)),
        ]),
        Line::from(vec![
            Span::styled("Account Session:  ", Style::default().fg(Color::Gray)),
            Span::styled(
                if !app.account_configured {
                    "Not configured"
                } else if app.account_authenticated {
                    if app.account_session_device_id.is_some() {
                        "Authenticated (device-bound)"
                    } else {
                        "Authenticated (account-only)"
                    }
                } else {
                    "Signed out"
                },
                Style::default().fg(if app.account_authenticated {
                    Color::Green
                } else if app.account_configured {
                    Color::Yellow
                } else {
                    Color::DarkGray
                }),
            ),
        ]),
    ];

    let health_block = Paragraph::new(health_text).block(
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
            Span::raw(format!(
                "Device keys and epoch secrets are locked via {} and never stored unencrypted.",
                os_keyring_label()
            )),
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

    let bottom_block = Paragraph::new(axioms).wrap(Wrap { trim: true }).block(
        Block::default()
            .title(" Zero-Knowledge System Invariants ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(bottom_block, main_layout[1]);
}

fn render_files_tab(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    if app.tracked_files.is_empty() {
        let p = Paragraph::new(
            "No files tracked yet. Press [t] to track a file (e.g. .env or secrets/dev.key)",
        )
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .title(" Tracked Files ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
        frame.render_widget(p, area);
        return;
    }

    app.file_visible = table_page_height(area);
    let (start, end) = window_range(app.file_scroll, app.tracked_files.len(), app.file_visible);

    let rows: Vec<Row> = app
        .tracked_files
        .iter()
        .enumerate()
        .skip(start)
        .take(end - start)
        .map(|(i, f)| {
            let status_span = if f.exists_on_disk {
                Span::styled("✓ Present", Style::default().fg(Color::Green))
            } else {
                Span::styled("✗ Missing", Style::default().fg(Color::Red))
            };

            let row_style = if i == app.file_table_index {
                Style::default()
                    .bg(Color::Rgb(30, 58, 138))
                    .add_modifier(Modifier::BOLD)
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
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(format!(
                    " Tracked Confidential Files ({} files{}) - [t] track new ",
                    app.tracked_files.len(),
                    window_label(start, end, app.tracked_files.len())
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_spacing(HighlightSpacing::Always);

    frame.render_widget(table, area);
}

fn render_snapshots_tab(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    if app.snapshots.is_empty() {
        let p = Paragraph::new(
            "No snapshots committed yet. Press [p] to create and replicate your first snapshot!",
        )
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .title(" Snapshot History DAG ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
        frame.render_widget(p, area);
        return;
    }

    app.snapshot_visible = table_page_height(area);
    let (start, end) = window_range(
        app.snapshot_scroll,
        app.snapshots.len(),
        app.snapshot_visible,
    );

    let rows: Vec<Row> = app
        .snapshots
        .iter()
        .enumerate()
        .skip(start)
        .take(end - start)
        .map(|(i, s)| {
            let cid_snippet = format!("{}...", hex_head(&s.snapshot_id_hex, 8));
            let parent_snippet = if s.parent_id_hex == "Genesis" {
                "Genesis".into()
            } else {
                format!("{}...", hex_head(&s.parent_id_hex, 8))
            };

            let head_badge = if s.is_head {
                Span::styled(
                    " [HEAD] ",
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(" commit ", Style::default().fg(Color::DarkGray))
            };

            let row_style = if i == app.snapshot_table_index {
                Style::default()
                    .bg(Color::Rgb(30, 58, 138))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                Span::raw(format!("{}", i + 1)),
                Span::styled(cid_snippet, Style::default().fg(Color::Cyan)),
                Span::styled(parent_snippet, Style::default().fg(Color::Gray)),
                Span::styled(&s.message, Style::default().fg(Color::White)),
                Span::styled(&s.timestamp_rfc3339, Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{} files", s.files_count),
                    Style::default().fg(Color::White),
                ),
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
            Row::new(vec![
                "#",
                "CID",
                "Parent",
                "Commit Message",
                "Timestamp",
                "Files",
                "Status",
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(format!(
                    " Immutable Snapshot History DAG ({} commits{}) ",
                    app.snapshots.len(),
                    window_label(start, end, app.snapshots.len())
                ))
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
                    Span::styled(
                        "ONLINE",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{} ms", op.latency_ms),
                        Style::default().fg(lat_color),
                    ),
                )
            } else {
                (
                    Span::styled(
                        "OFFLINE",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        op.last_error.as_deref().unwrap_or("Unavailable"),
                        Style::default().fg(Color::DarkGray),
                    ),
                )
            };

            Row::new(vec![
                Span::raw(format!("{}", i + 1)),
                Span::styled(&op.operator_id, Style::default().fg(Color::White)),
                Span::styled(&op.endpoint, Style::default().fg(Color::Cyan)),
                status_span,
                latency_span,
                Span::styled(
                    op.retention_policy.as_deref().unwrap_or("Not observed"),
                    Style::default().fg(Color::Gray),
                ),
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
            Row::new(vec![
                "#",
                "Operator ID",
                "Endpoint URI",
                "Status",
                "Latency",
                "Retention Policy",
            ])
            .style(
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )
            .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(" Storage Operator Responses & Live Latency ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Green)),
        );

    frame.render_widget(table, area);
}

fn render_fastcdc_tab(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(8)])
        .split(area);

    app.chunk_visible = table_page_height(chunks[1]);
    let (start, end) = window_range(
        app.chunk_scroll,
        app.fastcdc_chunks.len(),
        app.chunk_visible,
    );

    if let Some(ref m) = app.fastcdc_metrics {
        let metrics_text = vec![
            Line::from(vec![
                Span::styled("Analyzing File: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    &m.source_name,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "  ({} total · {} profile)",
                        format_bytes(m.total_bytes as u64),
                        m.profile
                    ),
                    Style::default().fg(Color::Gray),
                ),
            ]),
            Line::from(vec![
                Span::styled("Chunks Produced: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{}", m.total_chunks),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        " ({} unique, {} duplicate)",
                        m.unique_chunks, m.duplicate_chunks
                    ),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    "  |  Deduplication Savings: ",
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(
                    format!(
                        "{:.1}% ({} pruned)",
                        m.dedup_savings_pct,
                        format_bytes(m.saved_bytes as u64)
                    ),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
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

        // Table of chunks (scrollable window into the full chunk list)
        let rows: Vec<Row> = app
            .fastcdc_chunks
            .iter()
            .enumerate()
            .skip(start)
            .take(end - start)
            .map(|(i, c)| {
                let dup_span = if c.is_duplicate {
                    Span::styled("Duplicate", Style::default().fg(Color::Yellow))
                } else {
                    Span::styled("Unique", Style::default().fg(Color::Green))
                };

                let row_style = if i == app.chunk_table_index {
                    Style::default()
                        .bg(Color::Rgb(30, 58, 138))
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                Row::new(vec![
                    Span::raw(format!("{}", c.index)),
                    Span::styled(format!("{}", c.offset), Style::default().fg(Color::Gray)),
                    Span::styled(
                        format_bytes(c.length as u64),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(&c.gear_fingerprint, Style::default().fg(Color::Magenta)),
                    Span::styled(
                        c.boundary.label(),
                        Style::default().fg(boundary_color(c.boundary)),
                    ),
                    Span::styled(
                        format!("{:.2}", c.entropy),
                        Style::default().fg(Color::White),
                    ),
                    dup_span,
                    Span::styled("Masked", Style::default().fg(Color::DarkGray)),
                ])
                .style(row_style)
            })
            .collect();

        let widths = [
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(8),
        ];

        let table = Table::new(rows, widths)
            .header(
                Row::new(vec![
                    "#",
                    "Offset",
                    "Length",
                    "Boundary Hash",
                    "Cut",
                    "Entropy",
                    "Dedup",
                    "Content",
                ])
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(1),
            )
            .block(
                Block::default()
                    .title(format!(
                        " Content-Defined Chunk Slices (Gear SplitMix64{}) ",
                        window_label(start, end, app.fastcdc_chunks.len())
                    ))
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
        frame.render_widget(table, chunks[1]);
    } else {
        let hint = app.fastcdc_notice.as_deref().unwrap_or(
            "No confidential files tracked or available to inspect. Press [t] to track a file.",
        );
        let p = Paragraph::new(hint).alignment(Alignment::Center).block(
            Block::default()
                .title(" FastCDC Inspector ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
        frame.render_widget(p, area);
    }
}

fn render_token_tab(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(8)])
        .split(area);

    let status = &app.token_status;
    let (token_title, token_color) = if status.token_attached {
        (
            " PIV Hardware Token Attached (slots probed live) ",
            Color::Green,
        )
    } else if status.probing {
        (" Probing PC/SC bus… ", Color::Yellow)
    } else if status.last_error.is_some() {
        (" Token Probe Failed ", Color::Red)
    } else {
        (" No PIV Token Detected ", Color::Yellow)
    };

    let readers_str = if status.readers.is_empty() {
        "None detected".to_string()
    } else {
        status.readers.join(", ")
    };

    let hardware_line: String = if status.token_attached {
        status
            .token_label
            .clone()
            .unwrap_or_else(|| "PIV token attached".into())
    } else if status.probing {
        "Probing readers for a responsive PIV applet…".into()
    } else if let Some(error) = status.last_error.as_deref() {
        format!("Probe error: {error}")
    } else if status.readers.is_empty() {
        "Waiting for hardware insertion".into()
    } else {
        "Readers present; no responsive PIV applet".into()
    };
    let hardware_color = if status.token_attached {
        Color::Green
    } else if status.last_error.is_some() {
        Color::Red
    } else {
        Color::Yellow
    };

    let slot_line = |ready: bool, detail: Option<&str>, purpose: &str| -> (String, Color) {
        match (ready, detail) {
            (true, Some(detail)) => (format!("✓ Ready ({detail})"), Color::Green),
            (true, None) => ("✓ Ready".to_string(), Color::Green),
            (false, Some(detail)) => (format!("✗ Not ready ({detail})"), Color::Yellow),
            (false, None) => (format!("· {purpose} (not probed)"), Color::DarkGray),
        }
    };
    let (slot_9c_text, slot_9c_color) = if status.token_attached || status.slot_9c_detail.is_some()
    {
        slot_line(
            status.slot_9c_ready,
            status.slot_9c_detail.as_deref(),
            "Digital Signature",
        )
    } else {
        (
            "· Digital Signature (no token)".to_string(),
            Color::DarkGray,
        )
    };
    let (slot_9d_text, slot_9d_color) = if status.token_attached || status.slot_9d_detail.is_some()
    {
        slot_line(
            status.slot_9d_ready,
            status.slot_9d_detail.as_deref(),
            "ECDH Key Management",
        )
    } else {
        (
            "· ECDH Key Management (no token)".to_string(),
            Color::DarkGray,
        )
    };

    let token_text = vec![
        Line::from(vec![
            Span::styled("PC/SC Readers:    ", Style::default().fg(Color::Gray)),
            Span::styled(readers_str, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Hardware Status:  ", Style::default().fg(Color::Gray)),
            Span::styled(
                hardware_line,
                Style::default()
                    .fg(hardware_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Slot 9C (Sign):   ", Style::default().fg(Color::Gray)),
            Span::styled(slot_9c_text, Style::default().fg(slot_9c_color)),
        ]),
        Line::from(vec![
            Span::styled("Slot 9D (KeyMgmt):", Style::default().fg(Color::Gray)),
            Span::styled(slot_9d_text, Style::default().fg(slot_9d_color)),
        ]),
        Line::from(vec![
            Span::styled("Refresh:          ", Style::default().fg(Color::Gray)),
            Span::styled(
                "probed on this tab + every [r] refresh",
                Style::default().fg(Color::DarkGray),
            ),
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
        Line::from("3. The token's touch indicator lights up; host execution pauses until the sensor is physically touched."),
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

fn render_explorer_tab(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(11),
            Constraint::Min(8),
        ])
        .split(area);

    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);
    render_explorer_cluster_card(frame, app, cards[0]);
    render_explorer_feed_card(frame, app, cards[1]);

    render_explorer_object_panel(frame, app, rows[1]);

    let tables = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(rows[2]);
    render_explorer_operators_table(frame, app, tables[0]);
    render_explorer_checkpoints_table(frame, app, tables[1]);
}

fn render_explorer_cluster_card(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let total = app.explorer_operators.len();
    let reachable = app
        .explorer_operators
        .iter()
        .filter(|operator| operator.reachable)
        .count();
    let health_color = if total > 0 && reachable == total {
        Color::Green
    } else if reachable > 0 {
        Color::Yellow
    } else {
        Color::Red
    };
    let required = ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS;

    let text = vec![
        Line::from(vec![
            Span::styled("Operators:     ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{reachable}/{total} reachable"),
                Style::default()
                    .fg(health_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Observed:      ", Style::default().fg(Color::Gray)),
            Span::styled(&app.explorer_observed_at, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Quorum policy: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{required} replicas"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            "Presence-only lookups; bytes never leave operators.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let card = Paragraph::new(text).block(
        Block::default()
            .title(" Cluster Health ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(card, area);
}

fn explorer_tx_snippet(tx_hash_hex: Option<&str>) -> String {
    match tx_hash_hex {
        Some(tx) if tx.len() > 18 => format!("{}...", &tx[..18]),
        Some(tx) => tx.to_string(),
        None => "not submitted".to_string(),
    }
}

fn explorer_finality_color(status: &str) -> Color {
    match status {
        "deeply_confirmed" | "publisher_signed" => Color::Green,
        "unverified" => Color::Yellow,
        "reorg_suspected" | "invalid" | "not_submitted" => Color::Red,
        _ => Color::Gray,
    }
}

fn render_explorer_feed_card(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let mut lines = vec![Line::from(vec![
        Span::styled("Checkpoints: ", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{}", app.explorer_checkpoints.len()),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ])];

    if !app.explorer_feed_configured {
        lines.push(Line::from(Span::styled(
            "No signed checkpoint feed configured.",
            Style::default().fg(Color::Yellow),
        )));
        lines.push(Line::from(Span::styled(
            "Set CIPHERVAULT_PUBLIC_CHECKPOINT_FEED.",
            Style::default().fg(Color::DarkGray),
        )));
    } else if let Some(head) = app.explorer_checkpoints.first() {
        lines.push(Line::from(vec![
            Span::styled("Head: ", Style::default().fg(Color::Gray)),
            Span::styled(head.network.clone(), Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("  {}", explorer_tx_snippet(head.tx_hash_hex.as_deref())),
                Style::default().fg(Color::Yellow),
            ),
        ]));
        let confirmations = head
            .confirmations
            .map(|count| format!(" ({count} conf)"))
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled("Finality: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}{}", head.finality_status, confirmations),
                Style::default()
                    .fg(explorer_finality_color(&head.finality_status))
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::styled(
            "Feed configured; no checkpoints published yet.",
            Style::default().fg(Color::Gray),
        )));
    }

    let card = Paragraph::new(lines).block(
        Block::default()
            .title(" Anchor Feed Head ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Magenta)),
    );
    frame.render_widget(card, area);
}

fn render_explorer_object_panel(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let block = Block::default()
        .title(" Object Quorum Lookup — [/] to search ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Green));

    let Some(result) = app.explorer_object.as_ref() else {
        let hint = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "Press [/] to look up a 64-hex content ID across every operator.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "Operators prove possession with a PoS challenge; object bytes are never fetched.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .alignment(Alignment::Center)
        .block(block);
        frame.render_widget(hint, area);
        return;
    };

    let (badge, badge_color) = if result.satisfied {
        (" SATISFIED ", Color::Green)
    } else {
        (" QUORUM MISSING ", Color::Red)
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled("CID: ", Style::default().fg(Color::Gray)),
            Span::styled(result.cid_hex.clone(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Quorum: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!(
                    "{}/{} present (required {}) ",
                    result.present, result.checked, result.required
                ),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                badge,
                Style::default()
                    .fg(Color::Black)
                    .bg(badge_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    for replica in result.replicas.iter().take(6) {
        let (marker, marker_color) = match replica.status.as_str() {
            "present" => ("●", Color::Green),
            "absent" => ("○", Color::Yellow),
            _ => ("?", Color::Red),
        };
        let detail = match replica.status.as_str() {
            "present" => {
                let size = replica
                    .size_bytes
                    .map(format_bytes)
                    .unwrap_or_else(|| "size unknown".to_string());
                format!("{} ms · {}", replica.latency_ms, size)
            }
            _ => replica
                .error
                .clone()
                .unwrap_or_else(|| format!("{} ms", replica.latency_ms)),
        };
        lines.push(Line::from(vec![
            Span::styled(
                marker,
                Style::default()
                    .fg(marker_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(replica.endpoint.clone(), Style::default().fg(Color::Cyan)),
            Span::styled(
                format!(" → {} · {}", replica.status, detail),
                Style::default().fg(Color::Gray),
            ),
        ]));
    }
    if result.replicas.len() > 6 {
        lines.push(Line::from(Span::styled(
            format!("…and {} more replicas", result.replicas.len() - 6),
            Style::default().fg(Color::DarkGray),
        )));
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_explorer_operators_table(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let rows: Vec<Row> = app
        .explorer_operators
        .iter()
        .map(|operator| {
            let (status_span, latency_span) = if operator.reachable {
                (
                    Span::styled(
                        "REACHABLE",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        operator
                            .latency_ms
                            .map(|latency| format!("{latency} ms"))
                            .unwrap_or_else(|| "--".to_string()),
                        Style::default().fg(Color::White),
                    ),
                )
            } else {
                (
                    Span::styled(
                        "UNREACHABLE",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("--", Style::default().fg(Color::DarkGray)),
                )
            };
            Row::new(vec![
                Span::styled(&operator.display_name, Style::default().fg(Color::White)),
                Span::styled(&operator.region, Style::default().fg(Color::Gray)),
                status_span,
                latency_span,
                Span::styled(&operator.identity, Style::default().fg(Color::Cyan)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Min(10),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["Operator", "Region", "Status", "Latency", "Identity"])
                .style(
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(" Cluster Operators ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Green)),
        );
    frame.render_widget(table, area);
}

fn render_explorer_checkpoints_table(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    if app.explorer_checkpoints.is_empty() {
        let message = if app.explorer_feed_configured {
            "Feed configured; no checkpoints published yet."
        } else {
            "No signed checkpoint feed (CIPHERVAULT_PUBLIC_CHECKPOINT_FEED)."
        };
        let hint = Paragraph::new(message).alignment(Alignment::Center).block(
            Block::default()
                .title(" Published Checkpoints ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        );
        frame.render_widget(hint, area);
        return;
    }

    app.explorer_checkpoint_visible = table_page_height(area);
    let (start, end) = window_range(
        app.explorer_checkpoint_scroll,
        app.explorer_checkpoints.len(),
        app.explorer_checkpoint_visible,
    );

    let rows: Vec<Row> = app
        .explorer_checkpoints
        .iter()
        .enumerate()
        .skip(start)
        .take(end - start)
        .map(|(i, checkpoint)| {
            let row_style = if i == app.explorer_checkpoint_index {
                Style::default()
                    .bg(Color::Rgb(30, 58, 138))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let published = if checkpoint.published_at_utc > 0 {
                chrono::DateTime::from_timestamp(checkpoint.published_at_utc as i64, 0)
                    .map(|moment| moment.format("%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "--".to_string())
            } else {
                "--".to_string()
            };
            Row::new(vec![
                Span::styled(
                    explorer_tx_snippet(checkpoint.tx_hash_hex.as_deref()),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(&checkpoint.network, Style::default().fg(Color::Cyan)),
                Span::styled(
                    checkpoint.finality_status.clone(),
                    Style::default().fg(explorer_finality_color(&checkpoint.finality_status)),
                ),
                Span::styled(
                    checkpoint
                        .confirmations
                        .map(|count| count.to_string())
                        .unwrap_or_else(|| "--".to_string()),
                    Style::default().fg(Color::White),
                ),
                Span::styled(published, Style::default().fg(Color::Gray)),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(21),
        Constraint::Length(14),
        Constraint::Length(14),
        Constraint::Length(6),
        Constraint::Min(10),
    ];

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["Tx Hash", "Network", "Finality", "Conf", "Published"])
                .style(
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(format!(
                    " Published Checkpoints ({} total{}) ",
                    app.explorer_checkpoints.len(),
                    window_label(start, end, app.explorer_checkpoints.len())
                ))
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Magenta)),
        )
        .highlight_spacing(HighlightSpacing::Always);
    frame.render_widget(table, area);
}

fn render_explorer_search_modal(frame: &mut Frame, app: &TuiApp) {
    let area = centered_rect(60, 24, frame.area());
    frame.render_widget(Clear, area);

    let modal_block = Block::default()
        .title(" Inspect Object by Content ID ")
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Green));

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

    let label = Paragraph::new("Enter 64-character hex content ID (presence-only lookup):");
    frame.render_widget(label, inner[0]);

    let input = Paragraph::new(Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Green)),
        Span::styled(
            &app.explorer_search_buffer,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("█", Style::default().fg(Color::Green)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White)),
    );
    frame.render_widget(input, inner[1]);

    let help = Paragraph::new("[Enter] Probe Quorum    [Esc] Cancel")
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    frame.render_widget(help, inner[2]);
}

fn render_update_modal(frame: &mut Frame, app: &TuiApp) {
    let area = centered_rect(62, 28, frame.area());
    frame.render_widget(Clear, area);

    let (title, border_color) = if app.update_in_progress {
        (" Installing Update… ", Color::Yellow)
    } else {
        (" Update Available ", Color::Green)
    };
    let modal_block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(border_color));

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Length(2)])
        .margin(1)
        .split(area);

    frame.render_widget(modal_block, area);

    let latest = app
        .update_pending
        .as_ref()
        .map(|pending| pending.tag.as_str())
        .unwrap_or("…");
    let info = if app.update_in_progress {
        vec![
            Line::from(Span::styled(
                "Downloading, verifying, and installing…",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "Watch the status line for the result. The running TUI",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "keeps the old version until you quit and relaunch.",
                Style::default().fg(Color::Gray),
            )),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::raw("A new CipherVault release is ready: "),
                Span::styled(
                    format!("v{} → {latest}", env!("CARGO_PKG_VERSION")),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(Span::styled(
                "The release archive is checksum-verified before install.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "Updating replaces this binary; relaunch afterwards to use it.",
                Style::default().fg(Color::Gray),
            )),
        ]
    };
    frame.render_widget(Paragraph::new(info), inner[0]);

    let keys = if app.update_in_progress {
        "Installing… please wait"
    } else {
        "[U]pdate Now    [L]ater"
    };
    let help = Paragraph::new(keys)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Gray));
    frame.render_widget(help, inner[1]);
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
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(status_p, footer_layout[0]);

    let hints = Paragraph::new(Line::from(vec![
        Span::styled(
            "[1-7/Tab]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Tabs  ", Style::default().fg(Color::Gray)),
        Span::styled(
            "[p]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Push  ", Style::default().fg(Color::Gray)),
        Span::styled(
            "[a]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Anchor  ", Style::default().fg(Color::Gray)),
        Span::styled(
            "[r]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Refresh  ", Style::default().fg(Color::Gray)),
        Span::styled(
            "[t]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Track  ", Style::default().fg(Color::Gray)),
        Span::styled(
            "[?]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Help  ", Style::default().fg(Color::Gray)),
        Span::styled(
            "[q]",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Quit", Style::default().fg(Color::Gray)),
    ]))
    .alignment(Alignment::Right)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
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
        Span::styled(
            &app.track_input_buffer,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("█", Style::default().fg(Color::Yellow)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White)),
    );
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
        Line::from(Span::styled(
            "CipherVault TUI Keyboard Shortcuts",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("1 - 7      ", Style::default().fg(Color::Yellow)),
            Span::raw("Switch directly to tabs 1 through 7"),
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
            Span::styled("/          ", Style::default().fg(Color::Yellow)),
            Span::raw("Open the explorer object lookup (64-hex CID, presence-only)"),
        ]),
        Line::from(vec![
            Span::styled("u          ", Style::default().fg(Color::Yellow)),
            Span::raw("Check for CipherVault updates (popup when one is ready)"),
        ]),
        Line::from(vec![
            Span::styled("l          ", Style::default().fg(Color::Yellow)),
            Span::raw("Sign in to the local account with the OS-protected account key"),
        ]),
        Line::from(vec![
            Span::styled("o          ", Style::default().fg(Color::Yellow)),
            Span::raw("Sign out of the local account session"),
        ]),
        Line::from(vec![
            Span::styled("Up / Down  ", Style::default().fg(Color::Yellow)),
            Span::raw("Select previous / next row in tables (j / k work too)"),
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
        Line::from(Span::styled(
            "Network, token, and inspection work runs in the background; input never blocks on it.\nHosted authenticator sign-in is available in the web dashboard; it does not unlock vault keys in the TUI.\nPress [Esc] or [?] to close this help overlay",
            Style::default().fg(Color::Gray),
        )),
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

/// Data rows that fit in a bordered table with a one-line header row and a
/// one-line header margin.
fn table_page_height(area: Rect) -> usize {
    area.height.saturating_sub(4) as usize
}

/// Clamps a scroll offset into a renderable `[start, end)` window.
fn window_range(offset: usize, len: usize, visible: usize) -> (usize, usize) {
    if len == 0 {
        return (0, 0);
    }
    let start = offset.min(len - 1);
    let end = (start + visible.max(1)).min(len);
    (start, end)
}

/// Appends "rows a–b of N" to a table title only when scrolling hides rows.
fn window_label(start: usize, end: usize, len: usize) -> String {
    if len > end - start {
        format!(", rows {}–{} of {}", start + 1, end, len)
    } else {
        String::new()
    }
}

/// First `n` bytes of an ASCII hex string without panicking on short input.
fn hex_head(value: &str, n: usize) -> &str {
    value.get(..n.min(value.len())).unwrap_or(value)
}

fn boundary_color(boundary: BoundaryKind) -> Color {
    match boundary {
        BoundaryKind::MaskS => Color::Cyan,
        BoundaryKind::MaskL => Color::Blue,
        BoundaryKind::ForcedMax => Color::Yellow,
        BoundaryKind::Tail => Color::DarkGray,
    }
}

fn store_mode_label() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "SQLite WAL (DPAPI protected at rest)"
    }
    #[cfg(target_os = "macos")]
    {
        "SQLite WAL (Keychain protected at rest)"
    }
    #[cfg(target_os = "linux")]
    {
        "SQLite WAL (OS keyring protected at rest)"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        "SQLite WAL (OS keyring protected at rest)"
    }
}

fn os_keyring_label() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Windows DPAPI"
    }
    #[cfg(target_os = "macos")]
    {
        "macOS Keychain"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "the OS keyring"
    }
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

#[cfg(test)]
mod tests {
    use super::super::app::{
        BoundaryKind, ExplorerCheckpointRow, ExplorerObjectResult, ExplorerOperatorRow,
        ExplorerReplicaRow, FastCdcTuiChunk, FastCdcTuiMetrics, TrackedFileItem,
    };
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn drawn_text(app: &mut TuiApp, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn seeded_explorer_app() -> TuiApp {
        let mut app = TuiApp::new(std::time::Duration::from_secs(30));
        app.switch_tab(TuiTab::Explorer);
        app.explorer_observed_at = "2026-09-19 12:00:00 UTC".into();
        app.explorer_operators = vec![
            ExplorerOperatorRow {
                display_name: "Operator 1".into(),
                operator_id: "op-1".into(),
                region: "us-central1".into(),
                reachable: true,
                latency_ms: Some(42),
                identity: "verified".into(),
            },
            ExplorerOperatorRow {
                display_name: "Operator 2".into(),
                reachable: false,
                ..Default::default()
            },
        ];
        app.explorer_feed_configured = true;
        app.explorer_checkpoints = vec![ExplorerCheckpointRow {
            network: "arbitrum-one".into(),
            commitment_hex: "ab12".into(),
            tx_hash_hex: Some("0x99".into()),
            finality_status: "deeply_confirmed".into(),
            confirmations: Some(20),
            published_at_utc: 1_757_000_000,
        }];
        app.explorer_object = Some(ExplorerObjectResult {
            cid_hex: "ab".repeat(32),
            present: 2,
            checked: 3,
            required: 2,
            satisfied: true,
            replicas: vec![ExplorerReplicaRow {
                endpoint: "https://op.example".into(),
                operator_id: Some("op-1".into()),
                status: "present".into(),
                latency_ms: 12,
                size_bytes: Some(128),
                error: None,
            }],
        });
        app
    }

    #[test]
    fn explorer_tab_renders_telemetry_quorum_and_checkpoints() {
        let mut app = seeded_explorer_app();
        let text = drawn_text(&mut app, 140, 44);
        for needle in [
            "7: Explorer",
            "Cluster Health",
            "1/2 reachable",
            "Anchor Feed Head",
            "arbitrum-one",
            "deeply_confirmed",
            "Object Quorum Lookup",
            "SATISFIED",
            "2/3 present",
            "Cluster Operators",
            "Operator 1",
            "Published Checkpoints",
            "0x99",
        ] {
            assert!(text.contains(needle), "missing {needle:?}");
        }
    }

    #[test]
    fn explorer_search_modal_renders_input() {
        let mut app = seeded_explorer_app();
        app.show_explorer_search_modal = true;
        app.explorer_search_buffer = "ab12".into();
        let text = drawn_text(&mut app, 140, 44);
        assert!(text.contains("Inspect Object by Content ID"));
        assert!(text.contains("ab12"));
    }

    #[test]
    fn update_modal_renders_pending_release() {
        let mut app = TuiApp::new(std::time::Duration::from_secs(30));
        app.update_pending = Some(crate::PendingUpdate {
            tag: "v9.9.9".into(),
            target: "x86_64-pc-windows-msvc",
            archive_suffix: "zip",
        });
        app.show_update_modal = true;
        let text = drawn_text(&mut app, 120, 40);
        assert!(text.contains("Update Available"));
        assert!(text.contains("v9.9.9"));
        assert!(text.contains("[U]pdate Now"));
    }

    #[test]
    fn update_modal_locks_while_installing() {
        let mut app = TuiApp::new(std::time::Duration::from_secs(30));
        app.show_update_modal = true;
        app.update_in_progress = true;
        let text = drawn_text(&mut app, 120, 40);
        assert!(text.contains("Installing Update"));
        assert!(text.contains("please wait"));
    }

    #[test]
    fn files_table_scrolls_window_to_selection() {
        let mut app = TuiApp::new(std::time::Duration::from_secs(30));
        app.switch_tab(TuiTab::Files);
        app.tracked_files = (0..30)
            .map(|i| TrackedFileItem {
                path: format!("tracked-file-{i:02}"),
                size_bytes: 100,
                file_id_hex: "aa".into(),
                exists_on_disk: true,
            })
            .collect();
        app.file_table_index = 25;
        app.file_scroll = 20;
        let text = drawn_text(&mut app, 120, 16);
        assert!(text.contains("tracked-file-25"), "selected row visible");
        assert!(text.contains("rows 21–26 of 30"), "window label shown");
        assert!(!text.contains("tracked-file-00"), "off-window rows hidden");
        assert!(!text.contains("tracked-file-29"), "trailing rows hidden");
    }

    #[test]
    fn token_tab_reports_absent_token_honestly() {
        let mut app = TuiApp::new(std::time::Duration::from_secs(30));
        app.switch_tab(TuiTab::HardwareToken);
        let text = drawn_text(&mut app, 140, 44);
        assert!(text.contains("No PIV Token"));
        assert!(text.contains("not probed") || text.contains("no token"));
        app.token_status.probing = true;
        let text = drawn_text(&mut app, 140, 44);
        assert!(text.contains("Probing PC/SC bus"));
    }

    #[test]
    fn fastcdc_tab_renders_boundary_cut_column() {
        let mut app = TuiApp::new(std::time::Duration::from_secs(30));
        app.switch_tab(TuiTab::FastCdc);
        app.fastcdc_metrics = Some(FastCdcTuiMetrics {
            source_name: "demo.bin".into(),
            profile: "default".into(),
            total_bytes: 5000,
            total_chunks: 1,
            unique_chunks: 1,
            duplicate_chunks: 0,
            saved_bytes: 0,
            dedup_savings_pct: 0.0,
        });
        app.fastcdc_chunks = vec![FastCdcTuiChunk {
            index: 0,
            offset: 0,
            length: 5000,
            cid_hex: "ab".repeat(32),
            gear_fingerprint: "0x0123456789abcdef".into(),
            boundary: BoundaryKind::MaskS,
            entropy: 7.99,
            is_duplicate: false,
        }];
        let text = drawn_text(&mut app, 140, 44);
        for needle in [
            "Boundary Hash",
            "Cut",
            "0x0123456789abcdef",
            "default profile",
        ] {
            assert!(text.contains(needle), "missing {needle:?}");
        }
    }

    #[test]
    fn fastcdc_tab_explains_inspector_cap_skip() {
        let mut app = TuiApp::new(std::time::Duration::from_secs(30));
        app.switch_tab(TuiTab::FastCdc);
        app.fastcdc_notice = Some("Selected file is big (inspector cap 64): not loaded.".into());
        let text = drawn_text(&mut app, 140, 44);
        assert!(text.contains("inspector cap"));
    }

    #[test]
    fn overview_reports_operator_health_honestly() {
        let mut app = TuiApp::new(std::time::Duration::from_secs(30));
        app.switch_tab(TuiTab::Overview);
        app.operators.clear();
        let text = drawn_text(&mut app, 140, 44);
        assert!(text.contains("No operators configured"));
        assert!(text.contains("No PIV token"));
    }
}
