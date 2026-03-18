use std::{
    collections::{BTreeMap, VecDeque},
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use cityg_stress::metrics::MetricsSnapshot;

#[derive(Debug, Clone)]
pub(crate) struct WorkerView {
    pub(crate) id: usize,
    pub(crate) current_round: usize,
    pub(crate) completed_rounds: usize,
    pub(crate) failed_rounds: usize,
    pub(crate) status: String,
    pub(crate) mode: String,
    pub(crate) room_id: String,
    pub(crate) count: usize,
    pub(crate) last_error: Option<String>,
}

impl WorkerView {
    pub(crate) fn new(id: usize) -> Self {
        Self {
            id,
            current_round: 0,
            completed_rounds: 0,
            failed_rounds: 0,
            status: "idle".to_string(),
            mode: "-".to_string(),
            room_id: "-".to_string(),
            count: 0,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    pub(crate) started_at: Instant,
    pub(crate) artifact_dir: PathBuf,
    pub(crate) server_url: String,
    pub(crate) manage_server: bool,
    pub(crate) total_rounds: usize,
    pub(crate) completed_rounds: usize,
    pub(crate) failed_rounds: usize,
    pub(crate) worker_passes: usize,
    pub(crate) worker_failures: usize,
    pub(crate) restarts: usize,
    pub(crate) capacity_check_status: String,
    pub(crate) capacity_check_failed: bool,
    pub(crate) server_ready: bool,
    pub(crate) server_alive: bool,
    pub(crate) metrics: MetricsSnapshot,
    pub(crate) workers: BTreeMap<usize, WorkerView>,
    pub(crate) recent_events: VecDeque<String>,
    pub(crate) finished: bool,
}

impl AppState {
    pub(crate) fn new(
        worker_count: usize,
        rounds_per_worker: usize,
        artifact_dir: PathBuf,
        server_url: String,
        manage_server: bool,
        final_capacity_check: bool,
    ) -> Self {
        let mut workers = BTreeMap::new();
        for id in 1..=worker_count {
            workers.insert(id, WorkerView::new(id));
        }
        Self {
            started_at: Instant::now(),
            artifact_dir,
            server_url,
            manage_server,
            total_rounds: worker_count.saturating_mul(rounds_per_worker),
            completed_rounds: 0,
            failed_rounds: 0,
            worker_passes: 0,
            worker_failures: 0,
            restarts: 0,
            capacity_check_status: if final_capacity_check {
                "pending".to_string()
            } else {
                "skipped".to_string()
            },
            capacity_check_failed: false,
            server_ready: false,
            server_alive: false,
            metrics: MetricsSnapshot::default(),
            workers,
            recent_events: VecDeque::with_capacity(64),
            finished: false,
        }
    }

    pub(crate) fn push_event(&mut self, line: impl Into<String>) {
        let line = line.into();
        if self.recent_events.len() >= 20 {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back(line.clone());
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.artifact_dir.join("events.log"))
        {
            let _ = writeln!(file, "{line}");
        }
    }

    pub(crate) fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

fn human_elapsed(duration: Duration) -> String {
    let secs = duration.as_secs();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let rem = secs % 60;
    if hours > 0 {
        format!("{hours:02}:{mins:02}:{rem:02}")
    } else {
        format!("{mins:02}:{rem:02}")
    }
}

fn metric_text(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.1} ms"))
        .unwrap_or_else(|| "-".to_string())
}

fn chunk_layout(area: Rect) -> [Rect; 4] {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(8),
        ])
        .split(area);
    [chunks[0], chunks[1], chunks[2], chunks[3]]
}

pub(crate) fn draw(frame: &mut Frame<'_>, app: &AppState) {
    let [header, metrics, workers, events] = chunk_layout(frame.area());
    draw_header(frame, header, app);
    draw_metrics(frame, metrics, app);
    draw_workers(frame, workers, app);
    draw_events(frame, events, app);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let server_style = if app.server_ready {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Yellow)
    };
    let title = if app.finished {
        "CityG Stress (finished)"
    } else {
        "CityG Stress"
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(title, Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::raw(format!("elapsed={}  ", human_elapsed(app.elapsed()))),
            Span::styled(
                format!(
                    "server={} ",
                    if app.server_ready { "ready" } else { "warming" }
                ),
                server_style,
            ),
            Span::raw(format!("restarts={}  ", app.restarts)),
            Span::raw(format!(
                "workers={}/{}",
                app.worker_passes + app.worker_failures,
                app.workers.len()
            )),
        ]),
        Line::from(vec![
            Span::raw(format!("url={}  ", app.server_url)),
            Span::raw(format!(
                "mode={}  ",
                if app.manage_server {
                    "managed-server"
                } else {
                    "external-server"
                }
            )),
            Span::raw(format!("capacity={}  ", app.capacity_check_status)),
            Span::raw(format!("artifacts={}", app.artifact_dir.display())),
        ]),
        Line::from(if app.finished {
            vec![Span::styled(
                "Finished. Press Enter, q, or Esc to exit.",
                Style::default().fg(Color::Cyan),
            )]
        } else {
            vec![Span::raw("Press q or Esc to request a graceful stop.")]
        }),
    ];
    let block = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Run"));
    frame.render_widget(block, area);
}

fn draw_metrics(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let rows = vec![
        Row::new(vec![
            Cell::from("Rounds"),
            Cell::from(format!("{}/{}", app.completed_rounds, app.total_rounds)),
            Cell::from("Failed rounds"),
            Cell::from(app.failed_rounds.to_string()),
            Cell::from("Accept ok"),
            Cell::from(app.metrics.accept_epoch_ok.to_string()),
        ]),
        Row::new(vec![
            Cell::from("Accept p50"),
            Cell::from(metric_text(app.metrics.accept_p50_ms)),
            Cell::from("Accept p95"),
            Cell::from(metric_text(app.metrics.accept_p95_ms)),
            Cell::from("Accept p99"),
            Cell::from(metric_text(app.metrics.accept_p99_ms)),
        ]),
        Row::new(vec![
            Cell::from("Refresh conflicts"),
            Cell::from(app.metrics.refresh_conflicts.to_string()),
            Cell::from("Capacity"),
            Cell::from(app.capacity_check_status.clone()),
            Cell::from("Metrics age"),
            Cell::from(
                app.metrics
                    .updated_at
                    .map(|updated| human_elapsed(updated.elapsed()))
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]),
    ];
    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Length(16),
            Constraint::Min(12),
        ],
    )
    .block(Block::default().borders(Borders::ALL).title("Metrics"));
    frame.render_widget(table, area);
}

fn draw_workers(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let rows = app.workers.values().map(|worker| {
        let room = if worker.room_id.len() > 12 {
            format!("{}...", &worker.room_id[..12])
        } else {
            worker.room_id.clone()
        };
        let status_style = if worker.failed_rounds > 0 {
            Style::default().fg(Color::Red)
        } else if worker.status == "running" {
            Style::default().fg(Color::Yellow)
        } else if worker.completed_rounds > 0 {
            Style::default().fg(Color::Green)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(worker.id.to_string()),
            Cell::from(worker.current_round.to_string()),
            Cell::from(worker.completed_rounds.to_string()),
            Cell::from(worker.failed_rounds.to_string()),
            Cell::from(worker.mode.clone()),
            Cell::from(worker.count.to_string()),
            Cell::from(room),
            Cell::from(worker.status.clone()).style(status_style),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(18),
            Constraint::Min(12),
        ],
    )
    .header(
        Row::new([
            "Worker", "Round", "Done", "Failed", "Mode", "Count", "Room", "Status",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title("Workers"));
    frame.render_widget(table, area);
}

fn draw_events(frame: &mut Frame<'_>, area: Rect, app: &AppState) {
    let lines: Vec<Line<'static>> = if app.recent_events.is_empty() {
        vec![Line::from("No events yet")]
    } else {
        app.recent_events
            .iter()
            .rev()
            .map(|line| Line::from(line.clone()))
            .collect()
    };
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Recent Events"),
    );
    frame.render_widget(paragraph, area);
}
