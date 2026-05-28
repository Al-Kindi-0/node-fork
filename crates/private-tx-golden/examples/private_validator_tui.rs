//! Interactive TUI for the private validator PoC.
//!
//! Splits client, RPC/operator, validator, and auditor state into separate panes so the privacy
//! boundary is visible while the demo steps forward. Scenario changes re-render the audit outcome
//! from one real happy-path crypto run; they do not re-run the ceremony.

use std::env;
use std::io::{self, Stdout};
use std::time::Instant;

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use miden_node_private_tx::{
    ArchiveAssociatedData, ArchiveRecordKey, ChainId, EncryptedPrivateTxPayload,
    EncryptedPrivateTxRecord, PRIVATE_TX_VERSION, PrivateTxRecord, PrivateTxRecordMetadata,
    SubmissionEncryptionAssociatedData, SubmissionPayloadAssociatedData, ThresholdRecordEncryptor,
    ValidatorId, ViewingGroupPublicKey, ViewingGroupSetup, ViewingKeyShare, ViewingPartyId,
    ViewingPartyPublicShare, ViewingPolicy, archive_associated_data, decrypt_submission_payload,
    encrypt_submission_payload, private_tx_record_identity, seal_private_tx_record,
    submission_associated_data_for_encryption, submission_associated_data_for_payload,
};
use miden_node_private_tx_golden::{
    GOLDEN_THRESHOLD_SCHEME_ID, GoldenThresholdAdapter, decrypt_private_tx_archive_record,
};
use miden_protocol::crypto::dsa::eddsa_25519_sha512::SecretKey;
use miden_protocol::crypto::ies::{SealingKey, UnsealingKey};
use miden_protocol::transaction::TransactionId;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{Hasher, Word};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

const PRIVATE_NOTE: &str =
    "private note: invoice INV-042, account A -> account B, amount 42, memo medical supplies";
const BOND_AMOUNT: u64 = 100;
const SLASH_AMOUNT: u64 = 10;
const MIN_TERMINAL_WIDTH: u16 = 132;
const MIN_TERMINAL_HEIGHT: u16 = 40;
const SIDEBAR_WIDTH: u16 = 34;
const TOP_ROW_HEIGHT: u16 = 13;

type DemoResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> DemoResult<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    let mut app = App::new(build_demo_snapshot()?, &args)?;

    let mut stdout = io::stdout();
    let _terminal_mode = TerminalMode::enter(&mut stdout)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let run_result = run_app(&mut terminal, &mut app);
    terminal.show_cursor()?;

    run_result
}

struct TerminalMode;

impl TerminalMode {
    fn enter(stdout: &mut Stdout) -> io::Result<Self> {
        enable_raw_mode()?;
        if let Err(err) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(err);
        }

        Ok(Self)
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    }
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> DemoResult<()> {
    loop {
        terminal.draw(|frame| render(frame, app))?;
        if let Event::Key(key) = event::read()? {
            if app.handle_key(key) {
                return Ok(());
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Setup,
    ClientSeal,
    ValidatorArchive,
    AuditRequest,
    AuditRecover,
    Coordination,
}

impl Stage {
    const ALL: [Self; 6] = [
        Self::Setup,
        Self::ClientSeal,
        Self::ValidatorArchive,
        Self::AuditRequest,
        Self::AuditRecover,
        Self::Coordination,
    ];

    const fn title(self) -> &'static str {
        match self {
            Self::Setup => "1. Viewing group",
            Self::ClientSeal => "2. Client seals payload",
            Self::ValidatorArchive => "3. Validator archives",
            Self::AuditRequest => "4. Auditor requests tx",
            Self::AuditRecover => "5. Threshold unlock",
            Self::Coordination => "6. Coordination outcome",
        }
    }

    const fn narrative(self) -> &'static str {
        match self {
            Self::Setup => {
                "Viewing parties create a threshold key before any private transaction is archived."
            },
            Self::ClientSeal => {
                "The client seals private fields so RPC can forward without reading them."
            },
            Self::ValidatorArchive => {
                "The validator opens inside its trust boundary, validates, then reseals an audit record."
            },
            Self::AuditRequest => {
                "The auditor requests one tx_id and publishes a one-time reply key."
            },
            Self::AuditRecover => {
                "Enough party responses recover only this transaction's archive key."
            },
            Self::Coordination => "Settlement slashes parties that missed the audit deadline.",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Setup => 0,
            Self::ClientSeal => 1,
            Self::ValidatorArchive => 2,
            Self::AuditRequest => 3,
            Self::AuditRecover => 4,
            Self::Coordination => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Pane {
    Client,
    Rpc,
    Validator,
    Auditor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    AllRespond,
    OneMissing,
    BelowThreshold,
}

impl Scenario {
    const fn title(self) -> &'static str {
        match self {
            Self::AllRespond => "everyone responds",
            Self::OneMissing => "party-3 misses, quorum survives",
            Self::BelowThreshold => "below threshold",
        }
    }

    const fn responders(self) -> &'static [usize] {
        match self {
            Self::AllRespond => &[0, 1, 2],
            Self::OneMissing => &[0, 1],
            Self::BelowThreshold => &[0],
        }
    }
}

struct App {
    snapshot: DemoSnapshot,
    stage: Stage,
    scenario: Scenario,
}

impl App {
    fn new(snapshot: DemoSnapshot, args: &[String]) -> DemoResult<Self> {
        let scenario = match args.first().map(String::as_str) {
            Some("--below-threshold") => Scenario::BelowThreshold,
            Some("--one-missing") => Scenario::OneMissing,
            Some("--all") => Scenario::AllRespond,
            None => Scenario::OneMissing,
            Some(other) => return Err(format!("unknown argument: {other}").into()),
        };

        Ok(Self { snapshot, stage: Stage::Setup, scenario })
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Right | KeyCode::Down | KeyCode::Char(' ') => self.next_stage(),
            KeyCode::Left | KeyCode::Up => self.previous_stage(),
            KeyCode::Char('r') => self.stage = Stage::Setup,
            KeyCode::Char('1') => self.scenario = Scenario::AllRespond,
            KeyCode::Char('2') => self.scenario = Scenario::OneMissing,
            KeyCode::Char('3') => self.scenario = Scenario::BelowThreshold,
            _ => {},
        }

        false
    }

    fn next_stage(&mut self) {
        let index = self.stage.index().saturating_add(1).min(Stage::ALL.len() - 1);
        self.stage = Stage::ALL[index];
    }

    fn previous_stage(&mut self) {
        let index = self.stage.index().saturating_sub(1);
        self.stage = Stage::ALL[index];
    }

    fn stage_reached(&self, stage: Stage) -> bool {
        self.stage.index() >= stage.index()
    }

    fn active_responders(&self) -> &'static [usize] {
        self.scenario.responders()
    }

    fn audit_unlocked(&self) -> bool {
        self.active_responders().len() >= usize::from(self.snapshot.threshold)
    }

    const fn active_pane(&self, pane: Pane) -> bool {
        match self.stage {
            Stage::Setup => false,
            Stage::ClientSeal => matches!(pane, Pane::Client),
            Stage::ValidatorArchive => matches!(pane, Pane::Validator),
            Stage::AuditRequest | Stage::AuditRecover | Stage::Coordination => {
                matches!(pane, Pane::Auditor)
            },
        }
    }

    const fn highlights_enabled(&self) -> bool {
        !matches!(self.stage, Stage::Setup)
    }
}

fn print_help() {
    println!("private_validator_tui");
    println!("usage: cargo run -p miden-node-private-tx-golden --example private_validator_tui");
    println!("optional scenario arg: --all | --one-missing | --below-threshold");
    println!("keys: 1/2/3 select scenario, arrows/space move, r reset, q quit");
    println!("terminal: {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT} minimum");
}

struct DemoSnapshot {
    tx_id: String,
    participants: usize,
    threshold: u16,
    private_fields: PrivateFields,
    private_payload_bytes: usize,
    submission_payload_bytes: usize,
    archive_record_bytes: usize,
    archive_ciphertext_bytes: usize,
    wrapped_key_bytes: usize,
    audit_response_bytes_total: usize,
    dkg_ms: u128,
    client_encrypt_ms: u128,
    validator_archive_ms: u128,
    audit_decrypt_ms: u128,
}

struct PrivateFields {
    note: String,
    amount: String,
    memo: String,
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        render_too_small(frame, area);
        return;
    }

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(12), Constraint::Length(3)])
        .split(area);

    render_header(frame, root[0], app);
    render_footer(frame, root[2]);
    render_body(frame, root[1], app);
}

fn render_body(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(76), Constraint::Length(SIDEBAR_WIDTH)])
        .split(area);
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(TOP_ROW_HEIGHT), Constraint::Min(15)])
        .split(body[0]);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(panes[0]);
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(panes[1]);

    render_client(frame, top[0], app);
    render_rpc(frame, top[1], app);
    render_validator(frame, bottom[0], app);
    render_auditor(frame, bottom[1], app);
    render_sidebar(frame, body[1], app);
}

fn render_too_small(frame: &mut Frame<'_>, area: Rect) {
    let paragraph = Paragraph::new(vec![
        Line::from("Terminal too small for the private validator TUI."),
        Line::from(format!(
            "Resize to at least {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT}, or run private_validator_demo --narrated.",
        )),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title("private validator TUI"));
    frame.render_widget(Clear, area);
    frame.render_widget(paragraph, area);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let progress = (app.stage.index() as f64 + 1.0) / Stage::ALL.len() as f64;
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "Private Validator PoC",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                app.stage.title(),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("scenario: "),
            Span::styled(app.scenario.title(), Style::default().fg(Color::Yellow)),
            Span::raw("  tx_id: "),
            Span::styled(&app.snapshot.tx_id, Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![Span::styled(app.stage.narrative(), Style::default().fg(Color::Gray))]),
    ]);
    frame.render_widget(header, area);

    let gauge_area = Rect {
        x: area.x,
        y: area.y + 4,
        width: area.width,
        height: 1,
    };
    frame.render_widget(
        Gauge::default().gauge_style(Style::default().fg(Color::Cyan)).ratio(progress),
        gauge_area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect) {
    let footer = Paragraph::new(vec![
        Line::from("1 all respond  2 one misses  3 below threshold    Space/Right next  Left previous  r reset  q quit"),
        Line::from("K_tx = per-tx archive key | RPC never sees private fields | demo uses real DKG/AEAD/IES crypto"),
    ])
    .style(Style::default().fg(Color::Gray))
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::TOP));
    frame.render_widget(footer, area);
}

fn render_client(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines = vec![
        Line::from("Private fields, client view:"),
        private_field("note", app.snapshot.private_fields.note.clone(), Color::White),
        private_field("amount", app.snapshot.private_fields.amount.clone(), Color::White),
        private_field("memo", app.snapshot.private_fields.memo.clone(), Color::White),
        Line::from(""),
        Line::from("Seal to validator key:"),
    ];

    if app.stage_reached(Stage::ClientSeal) {
        lines.push(status_line("encrypted payload", "sealed", Color::Green));
        lines.push(label_value("payload bytes", app.snapshot.submission_payload_bytes.to_string()));
        lines.push(label_value("binding", "chain + tx + validator + key id"));
    } else {
        lines.push(status_line("waiting to submit", "not sealed yet", Color::Gray));
    }

    render_panel(
        frame,
        area,
        "Client",
        Color::Green,
        app.active_pane(Pane::Client),
        app.highlights_enabled(),
        lines,
    );
}

fn render_rpc(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines = vec![Line::from("Same private fields at RPC:"), Line::from("")];

    if app.stage_reached(Stage::ClientSeal) {
        lines.push(private_field(
            "note",
            format!("[sealed, {} B opaque]", app.snapshot.submission_payload_bytes),
            Color::Cyan,
        ));
        lines.push(private_field("amount", "[sealed]", Color::Cyan));
        lines.push(private_field("memo", "[sealed]", Color::Cyan));
        lines.push(Line::from(""));
        lines.push(label_value("sees", "ProvenTransaction + opaque blob"));
        lines.push(status_line("can decrypt", "no", Color::Green));
    } else {
        lines.push(status_line("transaction", "not submitted", Color::Gray));
    }

    render_panel(
        frame,
        area,
        "RPC / Operator",
        Color::Blue,
        app.active_pane(Pane::Rpc),
        app.highlights_enabled(),
        lines,
    );
}

fn render_validator(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines = vec![Line::from("Trust boundary: validator / TEE")];

    if app.stage_reached(Stage::ValidatorArchive) {
        lines.extend([
            Line::from(""),
            status_line("open payload", "ok", Color::Green),
            Line::from("Opened fields:"),
            private_field("note", app.snapshot.private_fields.note.clone(), Color::White),
            private_field("amount", app.snapshot.private_fields.amount.clone(), Color::White),
            private_field("memo", app.snapshot.private_fields.memo.clone(), Color::White),
            status_line("validate", "ok", Color::Green),
            status_line("seal archive", "ok", Color::Green),
            label_value(
                "archive ct",
                format!("{} B sealed PrivateTxRecord", app.snapshot.archive_ciphertext_bytes),
            ),
            label_value("contains", "private note + metadata; no ZK proof"),
            label_value(
                "K_tx wrap",
                format!("{} B fixed threshold crypto", app.snapshot.wrapped_key_bytes),
            ),
        ]);
    } else if app.stage_reached(Stage::ClientSeal) {
        lines.extend([
            Line::from(""),
            status_line("received encrypted payload", "waiting", Color::Yellow),
            private_field("note", "[sealed until validator opens]", Color::Gray),
        ]);
    } else {
        lines.extend([Line::from(""), status_line("validator", "idle", Color::Gray)]);
    }

    render_panel(
        frame,
        area,
        "Validator",
        Color::Magenta,
        app.active_pane(Pane::Validator),
        app.highlights_enabled(),
        lines,
    );
}

fn render_auditor(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines = vec![Line::from("Audits are explicit per-tx requests.")];

    if matches!(app.stage, Stage::AuditRequest) {
        lines.extend([
            Line::from(""),
            status_line("archive request", "sent", Color::Yellow),
            label_value("auditor key", "fresh public key for this audit"),
            label_value("why fresh", "old key leak stays scoped"),
            label_value("responses", "encrypted to auditor key"),
            label_value(
                "archive record",
                format!("{} sealed bytes", app.snapshot.archive_record_bytes),
            ),
        ]);
        lines.extend(archive_store_lines(app));
    }

    if app.stage_reached(Stage::AuditRecover) {
        lines.push(Line::from(""));
        lines.push(status_line("archive lookup", "found tx", Color::Yellow));
        lines.push(label_value("other archive txs", "still sealed"));
        lines.push(Line::from(""));
        lines.extend(threshold_lines(app));
        if app.audit_unlocked() {
            lines.push(label_value(
                "response bytes",
                app.snapshot.audit_response_bytes_total.to_string(),
            ));
            lines.push(status_line("recover K_tx", "quorum reached", Color::Green));
            lines.push(private_field(
                "opened note",
                app.snapshot.private_fields.note.clone(),
                Color::White,
            ));
            lines.push(private_field(
                "opened details",
                format!(
                    "{} | {}",
                    app.snapshot.private_fields.amount, app.snapshot.private_fields.memo
                ),
                Color::White,
            ));
        } else {
            lines.push(status_line("recover K_tx", "below threshold", Color::Red));
            lines.push(private_field("opened record", "[still sealed]", Color::Gray));
        }
    }

    render_panel(
        frame,
        area,
        "Auditor / Coordinator",
        Color::Yellow,
        app.active_pane(Pane::Auditor),
        app.highlights_enabled(),
        lines,
    );
}

fn render_sidebar(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let sidebar = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Min(10),
            Constraint::Min(8),
        ])
        .split(area);

    let stage_items = Stage::ALL
        .iter()
        .map(|stage| {
            let marker = if *stage == app.stage {
                ">"
            } else if app.stage_reached(*stage) {
                "*"
            } else {
                " "
            };
            ListItem::new(Line::from(vec![
                Span::styled(marker, Style::default().fg(Color::Cyan)),
                Span::raw(" "),
                Span::raw(stage.title()),
            ]))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(stage_items).block(Block::default().borders(Borders::ALL).title("Flow")),
        sidebar[0],
    );

    let scenario_lines = vec![
        scenario_option("1", Scenario::AllRespond, app.scenario),
        scenario_option("2", Scenario::OneMissing, app.scenario),
        scenario_option("3", Scenario::BelowThreshold, app.scenario),
    ];
    frame.render_widget(
        Paragraph::new(scenario_lines)
            .block(Block::default().borders(Borders::ALL).title("Scenario"))
            .wrap(Wrap { trim: false }),
        sidebar[1],
    );

    render_tracker(frame, sidebar[2], app);

    let bonds = party_bonds(app)
        .into_iter()
        .map(|(party, balance)| {
            let style = if balance < BOND_AMOUNT {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{party}: ")),
                Span::styled(balance.to_string(), style),
            ]))
        })
        .collect::<Vec<_>>();
    let bond_style = if matches!(app.stage, Stage::Coordination) {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    frame.render_widget(
        List::new(bonds).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(bond_style)
                .title("Mock Bonds"),
        ),
        sidebar[3],
    );
}

fn render_tracker(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let lines = secrets_public_lines(app);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Secrets / Public"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    title: &'static str,
    border_color: Color,
    active: bool,
    highlights_enabled: bool,
    lines: Vec<Line<'static>>,
) {
    let border_style = if !highlights_enabled {
        Style::default().fg(border_color)
    } else if active {
        Style::default().fg(border_color).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(title, border_style.add_modifier(Modifier::BOLD)));
    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

fn status_line(label: &'static str, value: &'static str, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{label}: ")),
        Span::styled(value, Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ])
}

fn label_value(label: impl Into<String>, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{}: ", label.into()), Style::default().fg(Color::Gray)),
        Span::raw(value.into()),
    ])
}

fn private_field(
    label: &'static str,
    value: impl Into<String>,
    value_color: Color,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::Gray)),
        Span::styled(value.into(), Style::default().fg(value_color)),
    ])
}

fn threshold_lines(app: &App) -> Vec<Line<'static>> {
    let responded = app.active_responders();
    let mut lines = vec![label_value(
        "threshold needed",
        format!("{} of {}", app.snapshot.threshold, app.snapshot.participants),
    )];

    for index in 0..app.snapshot.participants {
        let marker = if responded.contains(&index) { "[x]" } else { "[ ]" };
        let status = if responded.contains(&index) {
            "responded"
        } else if app.audit_unlocked() {
            "missed; quorum still reached"
        } else {
            "missed"
        };
        let color = if responded.contains(&index) {
            Color::Green
        } else if app.audit_unlocked() {
            Color::Yellow
        } else {
            Color::Red
        };
        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" party-{} {status}", index + 1)),
        ]));
    }

    if app.audit_unlocked() {
        lines.push(status_line("status", "QUORUM REACHED -> K_tx recovered", Color::Green));
    } else {
        lines.push(status_line("status", "BELOW THRESHOLD -> archive sealed", Color::Red));
    }

    lines
}

fn archive_store_lines(app: &App) -> Vec<Line<'static>> {
    let current_status = if app.stage_reached(Stage::AuditRecover) {
        if app.audit_unlocked() {
            "opened by current audit"
        } else {
            "still sealed; below threshold"
        }
    } else {
        "selected; sealed"
    };

    vec![
        Line::from(""),
        Line::from(Span::styled("Archive store:", Style::default().fg(Color::Gray))),
        Line::from(vec![
            Span::styled("  ", Style::default().fg(Color::Gray)),
            Span::styled(app.snapshot.tx_id.clone(), Style::default().fg(Color::Yellow)),
            Span::raw(format!("  {current_status}")),
        ]),
        Line::from("  tx_0x9a120000...  still sealed"),
        Line::from("  tx_0xb38c0000...  still sealed"),
    ]
}

fn secrets_public_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            "SECRETS (held by)",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        private_field("private note", secret_holder(app), Color::White),
    ];

    if app.stage_reached(Stage::ValidatorArchive) {
        lines.push(private_field("K_tx", secret_key_holder(app), Color::White));
    }

    lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "PUBLIC / OPAQUE",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        label_value("proof", "ProvenTransaction"),
    ]);

    if app.stage_reached(Stage::ClientSeal) {
        lines.push(label_value(
            "payload",
            format!("encrypted ({} B)", app.snapshot.submission_payload_bytes),
        ));
    }
    if app.stage_reached(Stage::ValidatorArchive) {
        lines.push(label_value(
            "archive",
            format!("ciphertext ({} B)", app.snapshot.archive_ciphertext_bytes),
        ));
        lines.push(label_value(
            "K_tx wrap",
            format!("threshold IBE ({} B)", app.snapshot.wrapped_key_bytes),
        ));
    }
    if app.stage_reached(Stage::AuditRequest) {
        lines.push(label_value("audit", "tx_id + transport key"));
    }

    lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "MEASURED",
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        )),
        label_value(
            "setup",
            format!("DKG {} ms | seal {} ms", app.snapshot.dkg_ms, app.snapshot.client_encrypt_ms),
        ),
        label_value("runtime", runtime_measurement(app)),
        label_value(
            "sizes",
            format!(
                "note {} B | archive {} B | K_tx wrap {} B",
                app.snapshot.private_payload_bytes,
                app.snapshot.archive_ciphertext_bytes,
                app.snapshot.wrapped_key_bytes
            ),
        ),
        label_value("why larger", "metadata, tags, fixed threshold crypto"),
    ]);

    lines
}

fn secret_holder(app: &App) -> &'static str {
    if app.stage_reached(Stage::AuditRecover) && app.audit_unlocked() {
        "Auditor, after quorum"
    } else if app.stage_reached(Stage::ValidatorArchive) {
        "Validator trust boundary"
    } else {
        "Client only"
    }
}

fn secret_key_holder(app: &App) -> &'static str {
    if app.stage_reached(Stage::AuditRecover) && app.audit_unlocked() {
        "Auditor, for this tx"
    } else {
        "sealed in archive"
    }
}

fn runtime_measurement(app: &App) -> String {
    if app.scenario == Scenario::BelowThreshold && app.stage_reached(Stage::AuditRecover) {
        format!("archive {} ms | audit not run", app.snapshot.validator_archive_ms)
    } else {
        format!(
            "archive {} ms | audit {} ms",
            app.snapshot.validator_archive_ms, app.snapshot.audit_decrypt_ms
        )
    }
}

fn scenario_option(key: &'static str, scenario: Scenario, active: Scenario) -> Line<'static> {
    let style = if scenario == active {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    Line::from(vec![
        Span::styled(format!("{key} "), style),
        Span::styled(scenario.title(), style),
    ])
}

fn party_bonds(app: &App) -> Vec<(String, u64)> {
    (0..app.snapshot.participants)
        .map(|index| {
            let balance = if app.stage_reached(Stage::Coordination)
                && !app.active_responders().contains(&index)
            {
                BOND_AMOUNT.saturating_sub(SLASH_AMOUNT)
            } else {
                BOND_AMOUNT
            };
            (format!("party-{}", index + 1), balance)
        })
        .collect()
}

fn build_demo_snapshot() -> DemoResult<DemoSnapshot> {
    let fixture = Fixture::new()?;
    let adapter = GoldenThresholdAdapter;

    let dkg_started = Instant::now();
    let viewing_group = ViewingGroup::setup(&adapter, &fixture.viewing_policy)?;
    let dkg_ms = dkg_started.elapsed().as_millis();

    let client_started = Instant::now();
    let wire_payload = client_encrypts_private_payload(&fixture)?;
    let client_encrypt_ms = client_started.elapsed().as_millis();

    let validator_started = Instant::now();
    let archive = validator_decrypts_and_archives(
        &fixture,
        &adapter,
        &viewing_group.group_public_key,
        &wire_payload,
    )?;
    let validator_archive_ms = validator_started.elapsed().as_millis();

    let audit_started = Instant::now();
    let audit = decrypt_private_tx_archive_record(
        &archive.record,
        viewing_group.threshold,
        &viewing_group.key_shares,
        &viewing_group.public_shares,
    )?;
    let audit_decrypt_ms = audit_started.elapsed().as_millis();
    let expected = expected_private_tx_record(&fixture, private_payload().to_vec());
    assert_eq!(audit.record, expected);

    Ok(DemoSnapshot {
        tx_id: short_id(&fixture.tx_id.to_string()),
        participants: viewing_group.key_shares.len(),
        threshold: viewing_group.threshold,
        private_fields: parse_private_fields(audit.record.transaction_inputs())?,
        private_payload_bytes: private_payload().len(),
        submission_payload_bytes: wire_payload.len(),
        archive_record_bytes: archive.record.to_bytes().len(),
        archive_ciphertext_bytes: archive.record.record_ciphertext.len(),
        wrapped_key_bytes: archive.wrapped_key_bytes,
        audit_response_bytes_total: audit.response_bytes_total,
        dkg_ms,
        client_encrypt_ms,
        validator_archive_ms,
        audit_decrypt_ms,
    })
}

fn private_payload() -> &'static [u8] {
    PRIVATE_NOTE.as_bytes()
}

fn parse_private_fields(bytes: &[u8]) -> DemoResult<PrivateFields> {
    let text = std::str::from_utf8(bytes)?;
    let fields = text
        .strip_prefix("private note: invoice ")
        .and_then(|value| value.split_once(", account "))
        .and_then(|(invoice, rest)| {
            let (account_path, rest) = rest.split_once(", amount ")?;
            let (amount, memo) = rest.split_once(", memo ")?;
            Some((invoice, account_path, amount, memo))
        })
        .ok_or_else(|| format!("unexpected demo private payload format: {text}"))?;
    let (invoice, account_path, amount, memo) = fields;

    Ok(PrivateFields {
        note: format!("{invoice} | {}", account_path.replace("account ", "")),
        amount: amount.to_string(),
        memo: memo.to_string(),
    })
}

fn short_id(id: &str) -> String {
    const PREFIX_LEN: usize = 18;
    if id.len() <= PREFIX_LEN {
        id.to_string()
    } else {
        format!("{}...", &id[..PREFIX_LEN])
    }
}

struct Fixture {
    chain_id: ChainId,
    tx_id: TransactionId,
    validator_id: ValidatorId,
    validator_encryption_key_id: Word,
    tee_attestation_id: Word,
    public_tx_hash: Word,
    sealing_key: SealingKey,
    unsealing_key: UnsealingKey,
    viewing_policy: ViewingPolicy,
}

impl Fixture {
    fn new() -> DemoResult<Self> {
        let validator_secret_key = SecretKey::new();
        let validator_public_key = validator_secret_key.public_key();
        let validator_public_key_bytes = validator_public_key.to_bytes();
        let mut attestation_bytes = Vec::new();
        attestation_bytes.extend_from_slice(b"demo-attestation");
        attestation_bytes.extend_from_slice(&validator_public_key_bytes);

        Ok(Self {
            chain_id: ChainId::new("miden-devnet")?,
            tx_id: tx_id(100)?,
            validator_id: ValidatorId::new("validator-1")?,
            validator_encryption_key_id: word(20),
            tee_attestation_id: Hasher::hash(&attestation_bytes),
            public_tx_hash: Hasher::hash(b"demo-public-proven-transaction"),
            sealing_key: SealingKey::X25519XChaCha20Poly1305(validator_public_key),
            unsealing_key: UnsealingKey::X25519XChaCha20Poly1305(validator_secret_key),
            viewing_policy: ViewingPolicy {
                version: PRIVATE_TX_VERSION,
                viewing_group_id: word(200),
                threshold: 2,
                parties: vec![
                    ViewingPartyId::new("party-1")?,
                    ViewingPartyId::new("party-2")?,
                    ViewingPartyId::new("party-3")?,
                ],
                scheme_id: GOLDEN_THRESHOLD_SCHEME_ID,
            },
        })
    }
}

struct ViewingGroup {
    threshold: u16,
    group_public_key: ViewingGroupPublicKey,
    key_shares: Vec<ViewingKeyShare>,
    public_shares: Vec<ViewingPartyPublicShare>,
}

impl ViewingGroup {
    fn setup(adapter: &GoldenThresholdAdapter, policy: &ViewingPolicy) -> DemoResult<Self> {
        let local_participants = policy
            .parties
            .iter()
            .enumerate()
            .map(|(index, party_id)| {
                GoldenThresholdAdapter::generate_local_participant(
                    party_id.clone(),
                    u32::try_from(index + 1).expect("demo participant index fits in u32"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let session = GoldenThresholdAdapter::dkg_session(
            policy.viewing_group_id,
            policy.threshold,
            local_participants
                .iter()
                .map(|participant| participant.public.clone())
                .collect(),
        )?;
        let dealings = local_participants
            .iter()
            .map(|participant| adapter.create_dkg_dealing(&session, participant))
            .collect::<Result<Vec<_>, _>>()?;

        for dealing in &dealings {
            adapter.verify_dkg_dealing(&session, &dealing.public)?;
        }

        let key_shares = local_participants
            .iter()
            .enumerate()
            .map(|(index, participant)| {
                let peer_dealings = dealings
                    .iter()
                    .enumerate()
                    .filter(|(peer_index, _)| *peer_index != index)
                    .map(|(_, dealing)| dealing.public.clone())
                    .collect::<Vec<_>>();
                adapter.complete_dkg(
                    &session,
                    participant,
                    &dealings[index].private,
                    &peer_dealings,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let group_public_key = GoldenThresholdAdapter::viewing_group_public_key(&key_shares[0])?;
        let public_shares = key_shares
            .iter()
            .map(GoldenThresholdAdapter::viewing_party_public_share)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            threshold: policy.threshold,
            group_public_key,
            key_shares,
            public_shares,
        })
    }
}

struct ArchiveOutput {
    record: EncryptedPrivateTxRecord,
    wrapped_key_bytes: usize,
}

fn client_encrypts_private_payload(fixture: &Fixture) -> DemoResult<Vec<u8>> {
    let submission_ad =
        submission_associated_data_for_encryption(SubmissionEncryptionAssociatedData {
            chain_id: &fixture.chain_id,
            tx_id: fixture.tx_id,
            validator_id: &fixture.validator_id,
            validator_encryption_key_id: fixture.validator_encryption_key_id,
        });

    Ok(encrypt_submission_payload(
        &fixture.sealing_key,
        fixture.validator_encryption_key_id,
        private_payload(),
        &submission_ad,
    )?
    .to_bytes())
}

fn validator_decrypts_and_archives(
    fixture: &Fixture,
    adapter: &GoldenThresholdAdapter,
    group_public_key: &ViewingGroupPublicKey,
    wire_payload: &[u8],
) -> DemoResult<ArchiveOutput> {
    let payload = EncryptedPrivateTxPayload::read_from_bytes(wire_payload)?;
    let submission_ad = submission_associated_data_for_payload(SubmissionPayloadAssociatedData {
        chain_id: &fixture.chain_id,
        tx_id: fixture.tx_id,
        validator_id: &fixture.validator_id,
        payload: &payload,
    });
    let private_payload =
        decrypt_submission_payload(&fixture.unsealing_key, &payload, &submission_ad)?;
    let record = expected_private_tx_record(fixture, private_payload);
    let identity = private_tx_record_identity(&fixture.chain_id, fixture.tx_id);
    let archive_ad = archive_associated_data(ArchiveAssociatedData {
        chain_id: &fixture.chain_id,
        tx_id: fixture.tx_id,
        viewing_group_id: group_public_key.viewing_group_id,
        identity: &identity,
        validator_id: &fixture.validator_id,
        validator_encryption_key_id: fixture.validator_encryption_key_id,
        tee_attestation_id: fixture.tee_attestation_id,
    });
    let record_key = ArchiveRecordKey::generate();
    let record_key_bytes = record_key.to_bytes();
    let record_ciphertext = seal_private_tx_record(&record_key, &record.to_bytes(), &archive_ad)?;
    let data_key_protection =
        adapter.encrypt_record_key(group_public_key, &identity, &archive_ad, &record_key_bytes)?;
    let wrapped_key_bytes = data_key_protection.to_bytes().len();

    Ok(ArchiveOutput {
        record: EncryptedPrivateTxRecord {
            version: PRIVATE_TX_VERSION,
            chain_id: fixture.chain_id.clone(),
            tx_id: fixture.tx_id,
            viewing_group_id: group_public_key.viewing_group_id,
            identity,
            validator_id: fixture.validator_id.clone(),
            validator_encryption_key_id: fixture.validator_encryption_key_id,
            tee_attestation_id: fixture.tee_attestation_id,
            record_ciphertext,
            data_key_protection,
        },
        wrapped_key_bytes,
    })
}

fn expected_private_tx_record(fixture: &Fixture, transaction_inputs: Vec<u8>) -> PrivateTxRecord {
    PrivateTxRecord::new(
        PrivateTxRecordMetadata {
            version: PRIVATE_TX_VERSION,
            chain_id: fixture.chain_id.clone(),
            tx_id: fixture.tx_id,
            validator_id: fixture.validator_id.clone(),
            validator_encryption_key_id: fixture.validator_encryption_key_id,
            tee_attestation_id: fixture.tee_attestation_id,
            public_tx_hash: fixture.public_tx_hash,
        },
        transaction_inputs,
    )
}

fn word(seed: u32) -> Word {
    Word::from([seed, seed + 1, seed + 2, seed + 3])
}

fn tx_id(seed: u32) -> DemoResult<TransactionId> {
    TransactionId::read_from_bytes(&word(seed).to_bytes()).map_err(Into::into)
}
