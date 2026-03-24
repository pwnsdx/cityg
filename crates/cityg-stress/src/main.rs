mod ui;

use std::{
    env,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{IsTerminal, Stdout, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use cityg_api_client::{
    CitygApiClient, RoomAdminOperation, build_room_admin_proof, generate_room_admin_keypair,
};
use cityg_client::demo;
use cityg_stress::metrics::{MetricsSnapshot, parse_metrics_snapshot};
use clap::{ArgAction, Parser};
use crossterm::{
    event::{self, Event as CEvent, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use hex::encode as hex_encode;
use rand::seq::SliceRandom;
use rand::{RngExt, rng};
use ratatui::{Terminal, backend::CrosstermBackend};
use serde::{Deserialize, Serialize};
use tokio::{
    process::{Child, Command},
    sync::{Mutex, mpsc, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing_subscriber::EnvFilter;
use ui::{AppState, draw};

const DEFAULT_SERVER_BIND: &str = "127.0.0.1:18080";
const DEFAULT_ADMIN_TOKEN: &str = "join-leave-admin-token";
const DEFAULT_MESSAGE_TOKEN: &str = "join-leave-message-token";
const DEFAULT_WINDOW_TTL_SECS: u64 = 120;
const DEFAULT_MAX_CONCURRENT_HEADS: u64 = 4;
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
const DEFAULT_SERVER_READY_TIMEOUT_SECS: u64 = 180;
const RESTART_RETRY_ATTEMPTS: usize = 3;
const RESTART_SETTLE_GRACE: Duration = Duration::from_secs(2);
const CLIENT_RESTART_INJECTED_ERROR: &str = "managed client restart injected";

#[derive(Debug, Parser)]
#[command(name = "cityg-stress")]
#[command(about = "Live stress harness for CityG with ratatui dashboard")]
struct Cli {
    #[arg(long, env = "CITYG_STRESS_SERVER_BIND", default_value = DEFAULT_SERVER_BIND)]
    server_bind: String,
    #[arg(long, env = "CITYG_STRESS_SERVER_URL")]
    server_url: Option<String>,
    #[arg(long, env = "CITYG_STRESS_NO_MANAGE_SERVER", action = ArgAction::SetTrue)]
    no_manage_server: bool,
    #[arg(long, env = "CITYG_STRESS_WORKERS", default_value_t = 4)]
    workers: usize,
    #[arg(long, env = "CITYG_STRESS_ROUNDS_PER_WORKER", default_value_t = 5)]
    rounds_per_worker: usize,
    #[arg(long, env = "CITYG_STRESS_MIN_COUNT", default_value_t = 2)]
    min_count: usize,
    #[arg(long, env = "CITYG_STRESS_MAX_COUNT", default_value_t = 4)]
    max_count: usize,
    #[arg(long, env = "CITYG_STRESS_LEAVES_PER_ROOM", default_value_t = 1)]
    leaves_per_room: usize,
    #[arg(long, env = "CITYG_STRESS_WATCH_PERCENT", default_value_t = 60)]
    watch_percent: u8,
    #[arg(long, env = "CITYG_STRESS_JITTER_MAX_SECS", default_value_t = 3)]
    jitter_max_secs: u64,
    #[arg(long, env = "CITYG_STRESS_ROUND_DELAY_SECS", default_value_t = 0)]
    round_delay_secs: u64,
    #[arg(long, env = "CITYG_STRESS_DURATION_SECS")]
    duration_secs: Option<u64>,
    #[arg(long, env = "CITYG_STRESS_MESSAGE_BURST_COUNT", default_value_t = 3)]
    message_burst_count: usize,
    #[arg(
        long,
        env = "CITYG_STRESS_MESSAGE_BURST_INTERVAL_MS",
        default_value_t = 100
    )]
    message_burst_interval_ms: u64,
    #[arg(long, env = "CITYG_STRESS_FINAL_CAPACITY_CHECK", action = ArgAction::SetTrue)]
    final_capacity_check: bool,
    #[arg(long, env = "CITYG_STRESS_REQUIRE_METRICS", action = ArgAction::SetTrue)]
    require_metrics: bool,
    #[arg(long, env = "CITYG_STRESS_RESTART_EVERY_SECS", default_value_t = 0)]
    restart_every_secs: u64,
    #[arg(
        long,
        env = "CITYG_STRESS_CLIENT_RESTART_EVERY_SECS",
        default_value_t = 0
    )]
    client_restart_every_secs: u64,
    #[arg(long, env = "CITYG_STRESS_CAPTURE_CLIENT_STATE_ARTIFACTS", action = ArgAction::SetTrue)]
    capture_client_state_artifacts: bool,
    #[arg(long, env = "CITYG_STRESS_WINDOW_TTL_SECS", default_value_t = DEFAULT_WINDOW_TTL_SECS)]
    window_ttl_secs: u64,
    #[arg(long, env = "CITYG_STRESS_MAX_CONCURRENT_HEADS", default_value_t = DEFAULT_MAX_CONCURRENT_HEADS)]
    max_concurrent_heads: u64,
    #[arg(long, env = "CITYG_STRESS_POLL_INTERVAL_MS", default_value_t = DEFAULT_POLL_INTERVAL_MS)]
    poll_interval_ms: u64,
    #[arg(
        long,
        env = "CITYG_STRESS_SERVER_READY_TIMEOUT_SECS",
        default_value_t = DEFAULT_SERVER_READY_TIMEOUT_SECS
    )]
    server_ready_timeout_secs: u64,
    #[arg(long, env = "CITYG_STRESS_ADMIN_TOKEN")]
    admin_token: Option<String>,
    #[arg(long, env = "CITYG_STRESS_MESSAGE_TOKEN")]
    message_token: Option<String>,
    #[arg(long, env = "CITYG_STRESS_SERVER_STATE_PATH")]
    server_state_path: Option<PathBuf>,
    #[arg(long, env = "CITYG_STRESS_API_BIN")]
    api_bin: Option<PathBuf>,
    #[arg(long, env = "CITYG_STRESS_JOIN_LEAVE_BIN")]
    join_leave_bin: Option<PathBuf>,
    #[arg(long, env = "CITYG_STRESS_ARTIFACT_DIR")]
    artifact_dir: Option<PathBuf>,
    #[arg(long, action = ArgAction::SetTrue)]
    plain: bool,
}

#[derive(Debug, Clone)]
struct Config {
    server_bind: String,
    server_url: String,
    manage_server: bool,
    workers: usize,
    rounds_per_worker: usize,
    min_count: usize,
    max_count: usize,
    leaves_per_room: usize,
    watch_percent: u8,
    jitter_max_secs: u64,
    round_delay_secs: u64,
    duration: Option<Duration>,
    message_burst_count: usize,
    message_burst_interval_ms: u64,
    final_capacity_check: bool,
    require_metrics: bool,
    restart_every_secs: u64,
    client_restart_every_secs: u64,
    capture_client_state_artifacts: bool,
    window_ttl_secs: u64,
    max_concurrent_heads: u64,
    poll_interval: Duration,
    server_ready_timeout: Duration,
    admin_token: String,
    message_token: String,
    server_state_path: Option<PathBuf>,
    api_bin: PathBuf,
    join_leave_bin: PathBuf,
    artifact_dir: PathBuf,
    plain: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HealthStatus {
    #[serde(default)]
    alive: Option<bool>,
    #[serde(default)]
    ready: Option<bool>,
    #[serde(default)]
    status: Option<String>,
}

impl HealthStatus {
    fn alive(&self) -> bool {
        self.alive.unwrap_or_else(|| {
            self.status
                .as_deref()
                .map(|status| status == "healthy")
                .unwrap_or(false)
        })
    }

    fn ready(&self) -> bool {
        self.ready.unwrap_or_else(|| {
            self.status
                .as_deref()
                .map(|status| status == "healthy")
                .unwrap_or(false)
        })
    }
}

#[derive(Debug)]
enum AppEvent {
    WorkerRoundStarted {
        worker_id: usize,
        round: usize,
        room_id: String,
        mode: &'static str,
        count: usize,
    },
    WorkerRoundCompleted {
        worker_id: usize,
        round: usize,
        elapsed: Duration,
    },
    WorkerRoundFailed {
        worker_id: usize,
        round: usize,
        error: String,
    },
    WorkerFinished {
        worker_id: usize,
        ok: bool,
    },
    ServerReady {
        alive: bool,
        ready: bool,
    },
    ServerRestarting,
    ServerRestarted {
        pid: Option<u32>,
    },
    MetricsUpdated(MetricsSnapshot),
    Info(String),
    CapacityCheckStarted,
    CapacityCheckFinished {
        ok: bool,
        log_path: PathBuf,
    },
    RunComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartState {
    generation: u64,
    restarting: bool,
    changed_at: Instant,
}

impl Default for RestartState {
    fn default() -> Self {
        Self {
            generation: 0,
            restarting: false,
            changed_at: Instant::now(),
        }
    }
}

#[derive(Debug)]
struct ManagedServer {
    config: Config,
    log_path: PathBuf,
    child: Option<Child>,
}

impl ManagedServer {
    fn new(config: Config) -> Self {
        let log_path = config.artifact_dir.join("server.log");
        Self {
            config,
            log_path,
            child: None,
        }
    }

    async fn start(&mut self) -> Result<Option<u32>> {
        let stdout = open_append(&self.log_path)?;
        let stderr = stdout.try_clone().context("clone server log file")?;
        let mut command = Command::new(&self.config.api_bin);
        command
            .env("CITYG_SERVER_ADDRESS", &self.config.server_bind)
            .env("CITYG_SERVER_ROOMS_ADMIN_TOKEN", &self.config.admin_token)
            .env("CITYG_SERVER_WINDOW_ADMIN_TOKEN", &self.config.admin_token)
            .env(
                "CITYG_SERVER_MESSAGE_AUTH_TOKEN",
                &self.config.message_token,
            )
            .env(
                "CITYG_PROTOCOL_WINDOW_DURATION_SECS",
                self.config.window_ttl_secs.to_string(),
            )
            .env(
                "CITYG_SERVER_WINDOW_TTL_SECS",
                self.config.window_ttl_secs.to_string(),
            )
            .env(
                "CITYG_PROTOCOL_MAX_CONCURRENT_HEADS",
                self.config.max_concurrent_heads.to_string(),
            )
            .env("RUST_LOG", "warn")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some(state_path) = self.config.server_state_path.as_ref() {
            command.env("CITYG_SERVER_STATE_PATH", state_path);
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("spawn {}", self.config.api_bin.display()))?;
        let pid = child.id();
        if let Err(err) = wait_for_ready(
            &self.config.server_url,
            Some(&mut child),
            &self.log_path,
            self.config.server_ready_timeout,
        )
        .await
        {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(err);
        }
        self.child = Some(child);
        Ok(pid)
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            timeout(Duration::from_secs(15), child.kill())
                .await
                .context("timed out stopping managed server")?
                .context("kill managed server")?;
        }
        Ok(())
    }

    async fn restart(&mut self) -> Result<Option<u32>> {
        self.stop().await?;
        self.start().await
    }
}

#[derive(Debug)]
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enable raw mode")?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen).context("enter alternate screen")?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).context("create terminal")?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let config = Config::resolve(Cli::parse())?;
    fs::create_dir_all(&config.artifact_dir)
        .with_context(|| format!("create {}", config.artifact_dir.display()))?;

    let mut startup_events = Vec::new();
    let mut server = if config.manage_server {
        let mut managed = ManagedServer::new(config.clone());
        let pid = managed.start().await?;
        startup_events.push(format!(
            "managed server started pid={}",
            pid.map(|id| id.to_string())
                .unwrap_or_else(|| "-".to_string())
        ));
        Some(Arc::new(Mutex::new(managed)))
    } else {
        None
    };

    let interactive = !config.plain && std::io::stdout().is_terminal();
    let mut app = AppState::new(
        config.workers,
        config.rounds_per_worker,
        config.artifact_dir.clone(),
        config.server_url.clone(),
        config.manage_server,
        config.final_capacity_check,
    );
    app.push_event(format!("artifact dir: {}", config.artifact_dir.display()));
    if config.client_restart_every_secs > 0 {
        app.push_event(format!(
            "client restart chaos enabled every {}s",
            config.client_restart_every_secs
        ));
    }
    if config.capture_client_state_artifacts {
        app.push_event("client state artifacts enabled".to_string());
    }
    for line in startup_events {
        app.push_event(line);
    }
    if let Err(err) =
        capture_observability_snapshot(&config.server_url, &config.artifact_dir, "initial").await
    {
        app.push_event(format!("initial observability snapshot failed: {err}"));
        if config.require_metrics {
            if let Some(server_ref) = server.as_mut() {
                let _ = server_ref.lock().await.stop().await;
            }
            write_summary(&config.artifact_dir, &app)?;
            print_final_summary(&app);
            return Err(anyhow!("initial observability snapshot failed: {err}"));
        }
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();
    let (stop_tx, stop_rx) = watch::channel(false);
    let (restart_state_tx, restart_state_rx) = watch::channel(RestartState::default());
    let active_rounds = Arc::new(AtomicUsize::new(0));

    let metrics_handle = tokio::spawn(poll_metrics_loop(
        config.server_url.clone(),
        config.artifact_dir.clone(),
        config.poll_interval,
        event_tx.clone(),
        stop_rx.clone(),
    ));

    let restart_handle = if config.manage_server && config.restart_every_secs > 0 {
        if let Some(server_ref) = server.as_ref().cloned() {
            Some(tokio::spawn(restart_loop(
                server_ref,
                Duration::from_secs(config.restart_every_secs),
                config.artifact_dir.clone(),
                event_tx.clone(),
                restart_state_tx,
                active_rounds.clone(),
                stop_rx.clone(),
            )))
        } else {
            None
        }
    } else {
        None
    };

    let supervisor_handle = tokio::spawn(run_workers(
        config.clone(),
        event_tx.clone(),
        restart_state_rx.clone(),
        active_rounds.clone(),
        stop_rx.clone(),
    ));

    let mut failed = if interactive {
        run_tui(&mut app, &mut event_rx, stop_tx.clone(), config.duration).await?
    } else {
        run_plain(&mut app, &mut event_rx, stop_tx.clone(), config.duration).await?
    };

    let _ = stop_tx.send(true);
    let _ = supervisor_handle.await;
    let _ = metrics_handle.await;
    if let Some(handle) = restart_handle {
        let _ = handle.await;
    }
    drain_events(&mut app, &mut event_rx);
    if let Err(err) =
        capture_observability_snapshot(&config.server_url, &config.artifact_dir, "final").await
    {
        app.push_event(format!("final observability snapshot failed: {err}"));
        if config.require_metrics {
            failed = true;
        }
    }
    drain_events(&mut app, &mut event_rx);
    if let Some(server_ref) = server.as_mut()
        && let Err(err) = server_ref.lock().await.stop().await
    {
        app.push_event(format!("managed server stop failed: {err}"));
        failed = true;
    }

    write_summary(&config.artifact_dir, &app)?;
    print_final_summary(&app);

    if failed {
        Err(anyhow!(
            "one or more workers failed; inspect {}",
            config.artifact_dir.display()
        ))
    } else {
        Ok(())
    }
}

impl Config {
    fn resolve(cli: Cli) -> Result<Self> {
        if cli.workers == 0 || cli.rounds_per_worker == 0 {
            return Err(anyhow!("workers and rounds-per-worker must be >= 1"));
        }
        if cli.min_count == 0 || cli.max_count < cli.min_count {
            return Err(anyhow!("min-count/max-count are inconsistent"));
        }
        if cli.watch_percent > 100 {
            return Err(anyhow!("watch-percent must be between 0 and 100"));
        }
        let repo_root = repo_root()?;
        let server_url = cli
            .server_url
            .unwrap_or_else(|| format!("http://{}", cli.server_bind));
        let admin_token = cli
            .admin_token
            .or_else(|| read_env("CITYG_CLIENT_ADMIN_TOKEN"))
            .or_else(|| read_env("CITYG_SERVER_ROOMS_ADMIN_TOKEN"))
            .or_else(|| read_env("CITYG_SERVER_WINDOW_ADMIN_TOKEN"))
            .unwrap_or_else(|| DEFAULT_ADMIN_TOKEN.to_string());
        let message_token = cli
            .message_token
            .or_else(|| read_env("CITYG_CLIENT_MESSAGE_AUTH_TOKEN"))
            .or_else(|| read_env("CITYG_SERVER_MESSAGE_AUTH_TOKEN"))
            .unwrap_or_else(|| DEFAULT_MESSAGE_TOKEN.to_string());
        let api_bin = resolve_binary(
            cli.api_bin,
            repo_root.join("target/debug/cityg-api"),
            "cityg-api",
        )?;
        let join_leave_bin = resolve_binary(
            cli.join_leave_bin,
            repo_root.join("target/debug/join_leave"),
            "join_leave",
        )?;
        let artifact_dir = cli.artifact_dir.unwrap_or_else(default_artifact_dir);
        let server_state_path = cli
            .server_state_path
            .or_else(|| (!cli.no_manage_server).then(|| artifact_dir.join("server.journal")));

        Ok(Self {
            server_bind: cli.server_bind,
            server_url,
            manage_server: !cli.no_manage_server,
            workers: cli.workers,
            rounds_per_worker: cli.rounds_per_worker,
            min_count: cli.min_count,
            max_count: cli.max_count,
            leaves_per_room: cli.leaves_per_room.min(cli.max_count),
            watch_percent: cli.watch_percent,
            jitter_max_secs: cli.jitter_max_secs,
            round_delay_secs: cli.round_delay_secs,
            duration: cli.duration_secs.map(Duration::from_secs),
            message_burst_count: cli.message_burst_count,
            message_burst_interval_ms: cli.message_burst_interval_ms,
            final_capacity_check: cli.final_capacity_check,
            require_metrics: cli.require_metrics,
            restart_every_secs: cli.restart_every_secs,
            client_restart_every_secs: cli.client_restart_every_secs,
            capture_client_state_artifacts: cli.capture_client_state_artifacts,
            window_ttl_secs: cli.window_ttl_secs,
            max_concurrent_heads: cli.max_concurrent_heads,
            poll_interval: Duration::from_millis(cli.poll_interval_ms),
            server_ready_timeout: Duration::from_secs(cli.server_ready_timeout_secs),
            admin_token,
            message_token,
            server_state_path,
            api_bin,
            join_leave_bin,
            artifact_dir,
            plain: cli.plain,
        })
    }
}

fn repo_root() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("failed to resolve workspace root"))
}

fn binary_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn resolve_binary(
    candidate: Option<PathBuf>,
    default_path: PathBuf,
    label: &str,
) -> Result<PathBuf> {
    let cli_flag = match label {
        "cityg-api" => "--api-bin",
        "join_leave" => "--join-leave-bin",
        _ => "--<binary>-bin",
    };
    if let Some(path) = candidate {
        if path.exists() {
            return Ok(path);
        }
        return Err(anyhow!(
            "{label} binary not found at {}; build it first or pass a valid path",
            path.display()
        ));
    }

    let name = binary_name(label);
    if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
        let cargo_target_path = PathBuf::from(target_dir).join("debug").join(&name);
        if cargo_target_path.exists() {
            return Ok(cargo_target_path);
        }
        return Err(anyhow!(
            "{label} binary not found at {}; build it in the same CARGO_TARGET_DIR or pass {}",
            cargo_target_path.display(),
            cli_flag
        ));
    }

    if let Ok(current_exe) = env::current_exe()
        && let Some(runtime_dir) = current_exe.parent()
    {
        let sibling = runtime_dir.join(&name);
        if sibling.exists() {
            return Ok(sibling);
        }
        if runtime_dir != default_path.parent().unwrap_or_else(|| Path::new("")) {
            return Err(anyhow!(
                "{label} binary not found next to {}; build it in the same target dir or pass {}",
                current_exe.display(),
                cli_flag
            ));
        }
    }

    if default_path.exists() {
        Ok(default_path)
    } else {
        Err(anyhow!(
            "{label} binary not found at {}; build it first",
            default_path.display()
        ))
    }
}

fn default_artifact_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    env::temp_dir().join(format!("cityg-stress-{stamp}"))
}

fn read_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

fn random_room_id() -> String {
    let mut bytes = [0u8; 32];
    rng().fill(&mut bytes);
    hex_encode(bytes)
}

fn random_leave_order(count: usize, limit: usize) -> String {
    let mut values: Vec<usize> = (1..=count).collect();
    values.shuffle(&mut rng());
    values
        .into_iter()
        .take(limit.min(count))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

async fn wait_for_ready(
    server_url: &str,
    mut child: Option<&mut Child>,
    log_path: &Path,
    timeout: Duration,
) -> Result<()> {
    let client = reqwest::Client::new();
    let started = Instant::now();
    let url = format!("{}/health/ready", server_url.trim_end_matches('/'));
    loop {
        if started.elapsed() > timeout {
            return Err(anyhow!("server did not become ready within {:?}", timeout));
        }

        if let Some(child) = child.as_deref_mut()
            && let Some(status) = child.try_wait().context("poll managed server")?
        {
            return Err(anyhow!(
                "managed server exited before readiness with status {}; check {}",
                status,
                log_path.display()
            ));
        }

        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                if let Some(child) = child.as_deref_mut()
                    && let Some(status) = child.try_wait().context("poll managed server")?
                {
                    return Err(anyhow!(
                        "managed server exited before readiness with status {}; check {}",
                        status,
                        log_path.display()
                    ));
                }
                return Ok(());
            }
            _ => sleep(Duration::from_secs(1)).await,
        }
    }
}

async fn fetch_health(server_url: &str) -> Result<HealthStatus> {
    let client = reqwest::Client::new();
    let url = format!("{}/health/detailed", server_url.trim_end_matches('/'));
    let response = client.get(url).send().await.context("request health")?;
    let response = response.error_for_status().context("health status")?;
    response
        .json::<HealthStatus>()
        .await
        .context("decode health json")
}

async fn fetch_metrics_text(server_url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let url = format!("{}/metrics", server_url.trim_end_matches('/'));
    let response = client.get(url).send().await.context("request metrics")?;
    let response = response.error_for_status().context("metrics status")?;
    response.text().await.context("read metrics body")
}

async fn poll_metrics_loop(
    server_url: String,
    artifact_dir: PathBuf,
    interval: Duration,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    mut stop_rx: watch::Receiver<bool>,
) {
    loop {
        if *stop_rx.borrow() {
            break;
        }

        match fetch_health(&server_url).await {
            Ok(health) => {
                let _ = event_tx.send(AppEvent::ServerReady {
                    alive: health.alive(),
                    ready: health.ready(),
                });
                let _ = fs::write(
                    artifact_dir.join("final-health.json"),
                    serde_json::to_vec_pretty(&health).unwrap_or_default(),
                );
            }
            Err(err) => {
                let _ = event_tx.send(AppEvent::Info(format!("health poll failed: {err}")));
                let _ = event_tx.send(AppEvent::ServerReady {
                    alive: false,
                    ready: false,
                });
            }
        }

        match fetch_metrics_text(&server_url).await {
            Ok(text) => {
                let snapshot = parse_metrics_snapshot(&text, Instant::now());
                let _ = fs::write(artifact_dir.join("final-metrics.txt"), text.as_bytes());
                let _ = event_tx.send(AppEvent::MetricsUpdated(snapshot));
            }
            Err(err) => {
                let _ = event_tx.send(AppEvent::Info(format!("metrics poll failed: {err}")));
            }
        }

        tokio::select! {
            _ = sleep(interval) => {}
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn capture_observability_snapshot(
    server_url: &str,
    artifact_dir: &Path,
    prefix: &str,
) -> Result<()> {
    let health = fetch_health(server_url).await?;
    fs::write(
        artifact_dir.join(format!("{prefix}-health.json")),
        serde_json::to_vec_pretty(&health).unwrap_or_default(),
    )
    .with_context(|| format!("write {prefix}-health.json"))?;

    let metrics = fetch_metrics_text(server_url).await?;
    fs::write(
        artifact_dir.join(format!("{prefix}-metrics.txt")),
        metrics.as_bytes(),
    )
    .with_context(|| format!("write {prefix}-metrics.txt"))?;
    Ok(())
}

async fn restart_loop(
    server: Arc<Mutex<ManagedServer>>,
    interval: Duration,
    artifact_dir: PathBuf,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    restart_state_tx: watch::Sender<RestartState>,
    active_rounds: Arc<AtomicUsize>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let restart_log_path = artifact_dir.join("restarts.log");
    loop {
        tokio::select! {
            _ = sleep(interval) => {}
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    break;
                }
                continue;
            }
        }
        if *stop_rx.borrow() {
            break;
        }
        if let Ok(mut file) = open_append(&restart_log_path) {
            let _ = writeln!(
                file,
                "{} restart-begin",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            );
        }
        let next_generation = restart_state_tx.borrow().generation.saturating_add(1);
        let _ = restart_state_tx.send(RestartState {
            generation: next_generation,
            restarting: true,
            changed_at: Instant::now(),
        });
        let _ = event_tx.send(AppEvent::ServerRestarting);
        while active_rounds.load(Ordering::SeqCst) > 0 {
            tokio::select! {
                _ = sleep(Duration::from_millis(100)) => {}
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        return;
                    }
                }
            }
        }
        let restart_result = {
            let mut guard = server.lock().await;
            guard.restart().await
        };
        match restart_result {
            Ok(pid) => {
                let _ = restart_state_tx.send(RestartState {
                    generation: next_generation,
                    restarting: false,
                    changed_at: Instant::now(),
                });
                let _ = event_tx.send(AppEvent::ServerRestarted { pid });
            }
            Err(err) => {
                let _ = restart_state_tx.send(RestartState {
                    generation: next_generation,
                    restarting: false,
                    changed_at: Instant::now(),
                });
                let _ = event_tx.send(AppEvent::Info(format!("restart failed: {err}")));
                break;
            }
        }
    }
}

async fn run_workers(
    config: Config,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    restart_rx: watch::Receiver<RestartState>,
    active_rounds: Arc<AtomicUsize>,
    stop_rx: watch::Receiver<bool>,
) {
    let mut set = JoinSet::new();
    for worker_id in 1..=config.workers {
        set.spawn(run_worker(
            worker_id,
            config.clone(),
            event_tx.clone(),
            restart_rx.clone(),
            active_rounds.clone(),
            stop_rx.clone(),
        ));
    }
    while let Some(result) = set.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let _ = event_tx.send(AppEvent::Info(format!("worker task error: {err:#}")));
            }
            Err(err) => {
                let _ = event_tx.send(AppEvent::Info(format!("worker task join error: {err}")));
            }
        }
    }
    if config.final_capacity_check && !*stop_rx.borrow() {
        let _ = event_tx.send(AppEvent::CapacityCheckStarted);
        let log_path = config.artifact_dir.join("final-capacity.log");
        let result = run_final_capacity_check(&config, &log_path).await;
        match result {
            Ok(()) => {
                let _ = event_tx.send(AppEvent::CapacityCheckFinished { ok: true, log_path });
            }
            Err(err) => {
                let _ = open_append(&log_path).and_then(|mut file| {
                    writeln!(file, "capacity-check-error={err}")?;
                    Ok(file)
                });
                let _ = event_tx.send(AppEvent::Info(format!(
                    "final capacity check failed: {err}"
                )));
                let _ = event_tx.send(AppEvent::CapacityCheckFinished {
                    ok: false,
                    log_path,
                });
            }
        }
    }
    let _ = event_tx.send(AppEvent::RunComplete);
}

async fn run_final_capacity_check(_config: &Config, log_path: &Path) -> Result<()> {
    let repo_root = repo_root()?;
    let output = Command::new("cargo")
        .arg("test")
        .arg("-p")
        .arg("cityg-api")
        .arg("window_full_rest_api_freeze")
        .arg("--")
        .arg("--exact")
        .current_dir(repo_root)
        .output()
        .await
        .context("run final capacity check")?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&output.stdout);
    bytes.extend_from_slice(&output.stderr);
    fs::write(log_path, bytes).with_context(|| format!("write {}", log_path.display()))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "capacity check exited with status {}",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".to_string())
        ))
    }
}

async fn run_worker(
    worker_id: usize,
    config: Config,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    mut restart_rx: watch::Receiver<RestartState>,
    active_rounds: Arc<AtomicUsize>,
    stop_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut api_client =
        CitygApiClient::new(&config.server_url).with_admin_token(config.admin_token.clone());
    api_client = api_client.with_message_auth_token(config.message_token.clone());
    let worker_log = config
        .artifact_dir
        .join(format!("worker-{worker_id:02}.log"));
    let worker_status = config
        .artifact_dir
        .join(format!("worker-{worker_id:02}.status"));

    'rounds: for round in 1..=config.rounds_per_worker {
        if *stop_rx.borrow() {
            break;
        }
        let started = Instant::now();
        let mut count = rng().random_range(config.min_count..=config.max_count);
        let watch_mode = rng().random_range(0..100) < config.watch_percent;
        if watch_mode && count < 2 {
            count = 2;
        }
        let mode = if watch_mode { "watch" } else { "batch" };
        let leave_order = random_leave_order(count, config.leaves_per_room);

        let max_attempts = if (config.manage_server && config.restart_every_secs > 0)
            || config.client_restart_every_secs > 0
        {
            RESTART_RETRY_ATTEMPTS
        } else {
            1
        };
        let mut attempt = 0usize;
        loop {
            attempt = attempt.saturating_add(1);
            let restart_before = wait_for_restart_quiescence(&mut restart_rx).await;
            if *stop_rx.borrow() {
                break 'rounds;
            }
            let room_id = random_room_id();
            let round_started_at = Instant::now();
            let _ = event_tx.send(AppEvent::WorkerRoundStarted {
                worker_id,
                round,
                room_id: room_id.clone(),
                mode,
                count,
            });
            active_rounds.fetch_add(1, Ordering::SeqCst);

            let result = run_worker_round_attempt(
                &api_client,
                &config,
                WorkerRoundAttempt {
                    worker_log: &worker_log,
                    worker_id,
                    round,
                    room_id: &room_id,
                    count,
                    watch_mode,
                    leave_order: &leave_order,
                },
            )
            .await;
            active_rounds.fetch_sub(1, Ordering::SeqCst);
            let restart_after = *restart_rx.borrow();

            match result {
                Ok(()) => break,
                Err(err) => {
                    let client_restart_injected =
                        err.to_string().contains(CLIENT_RESTART_INJECTED_ERROR);
                    let overlapped_restart = restart_after.restarting
                        || restart_after.generation != restart_before.generation
                        || round_started_at.saturating_duration_since(restart_before.changed_at)
                            <= RESTART_SETTLE_GRACE
                        || Instant::now().saturating_duration_since(restart_after.changed_at)
                            <= RESTART_SETTLE_GRACE;
                    let retryable = attempt < max_attempts
                        && ((config.manage_server && config.restart_every_secs > 0)
                            || client_restart_injected);
                    if retryable {
                        let _ = event_tx.send(AppEvent::Info(format!(
                            "worker {worker_id} round {round} failed{}{}; retrying on fresh room",
                            if overlapped_restart {
                                format!(
                                    " near managed restart gen={} -> {}",
                                    restart_before.generation, restart_after.generation
                                )
                            } else {
                                String::new()
                            },
                            if client_restart_injected {
                                " after injected client restart".to_string()
                            } else {
                                String::new()
                            }
                        )));
                        let _ = event_tx.send(AppEvent::Info(format!(
                            "worker {worker_id} round {round} waiting for managed server readiness before retry"
                        )));
                        if let Err(err) = wait_for_ready(
                            &config.server_url,
                            None,
                            &config.artifact_dir.join("server.log"),
                            config.server_ready_timeout,
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "worker {worker_id} wait for server ready before retrying round {round}"
                            )
                        }) {
                            fs::write(&worker_status, b"status=failed\n").ok();
                            let error = err.to_string();
                            let _ = event_tx.send(AppEvent::WorkerRoundFailed {
                                worker_id,
                                round,
                                error: error.clone(),
                            });
                            let _ = event_tx.send(AppEvent::WorkerFinished {
                                worker_id,
                                ok: false,
                            });
                            return Err(err);
                        }
                        continue;
                    }

                    let _ = event_tx.send(AppEvent::Info(format!(
                        "worker {worker_id} round {round} failed without retry after {} attempts",
                        attempt
                    )));
                    fs::write(&worker_status, b"status=failed\n").ok();
                    if let Err(snapshot_err) = capture_observability_snapshot(
                        &config.server_url,
                        &config.artifact_dir,
                        &format!("worker-{worker_id:02}-round-{round:03}-failure"),
                    )
                    .await
                    {
                        let _ = event_tx.send(AppEvent::Info(format!(
                            "round {round} failure observability capture failed: {snapshot_err}"
                        )));
                    }
                    let error = format!("round {round} failed: {err}");
                    let _ = event_tx.send(AppEvent::WorkerRoundFailed {
                        worker_id,
                        round,
                        error: error.clone(),
                    });
                    let _ = event_tx.send(AppEvent::WorkerFinished {
                        worker_id,
                        ok: false,
                    });
                    return Err(anyhow!(error));
                }
            }
        }

        if config.manage_server && config.restart_every_secs > 0 {
            let _ = wait_for_restart_quiescence(&mut restart_rx).await;
            if let Err(err) = wait_for_ready(
                &config.server_url,
                None,
                &config.artifact_dir.join("server.log"),
                config.server_ready_timeout,
            )
            .await
            .with_context(|| {
                format!("worker {worker_id} wait for server ready before capturing round {round}")
            }) {
                fs::write(&worker_status, b"status=failed\n").ok();
                let error = err.to_string();
                let _ = event_tx.send(AppEvent::WorkerRoundFailed {
                    worker_id,
                    round,
                    error: error.clone(),
                });
                let _ = event_tx.send(AppEvent::WorkerFinished {
                    worker_id,
                    ok: false,
                });
                return Err(err);
            }
        }
        if let Err(err) = capture_observability_snapshot(
            &config.server_url,
            &config.artifact_dir,
            &format!("worker-{worker_id:02}-round-{round:03}"),
        )
        .await
        {
            if config.require_metrics {
                fs::write(&worker_status, b"status=failed\n").ok();
                let error = format!("round {round} observability snapshot failed: {err}");
                let _ = event_tx.send(AppEvent::WorkerRoundFailed {
                    worker_id,
                    round,
                    error: error.clone(),
                });
                let _ = event_tx.send(AppEvent::WorkerFinished {
                    worker_id,
                    ok: false,
                });
                return Err(anyhow!(error));
            }
            let _ = event_tx.send(AppEvent::Info(format!(
                "round {round} observability capture failed: {err}"
            )));
        }
        let _ = event_tx.send(AppEvent::WorkerRoundCompleted {
            worker_id,
            round,
            elapsed: started.elapsed(),
        });
        if config.round_delay_secs > 0 && round < config.rounds_per_worker && !*stop_rx.borrow() {
            sleep(Duration::from_secs(config.round_delay_secs)).await;
        }
    }

    fs::write(&worker_status, b"status=ok\n").ok();
    let _ = event_tx.send(AppEvent::WorkerFinished {
        worker_id,
        ok: true,
    });
    Ok(())
}

async fn wait_for_restart_quiescence(
    restart_rx: &mut watch::Receiver<RestartState>,
) -> RestartState {
    loop {
        let state = *restart_rx.borrow();
        if !state.restarting && state.changed_at.elapsed() >= RESTART_SETTLE_GRACE {
            return state;
        }
        if state.restarting {
            if restart_rx.changed().await.is_err() {
                return state;
            }
            continue;
        }
        let remaining = RESTART_SETTLE_GRACE.saturating_sub(state.changed_at.elapsed());
        if remaining.is_zero() {
            return state;
        }
        sleep(remaining).await;
    }
}

struct WorkerRoundAttempt<'a> {
    worker_log: &'a Path,
    worker_id: usize,
    round: usize,
    room_id: &'a str,
    count: usize,
    watch_mode: bool,
    leave_order: &'a str,
}

async fn run_worker_round_attempt(
    api_client: &CitygApiClient,
    config: &Config,
    attempt: WorkerRoundAttempt<'_>,
) -> Result<()> {
    api_client
        .bootstrap_room_as_admin(attempt.room_id, demo::kbroad_public(), {
            let (pop_public_key, pop_secret_key) = generate_room_admin_keypair();
            build_room_admin_proof(
                RoomAdminOperation::Bootstrap,
                attempt.room_id,
                demo::kbroad_public(),
                &pop_public_key,
                &pop_secret_key,
            )?
        })
        .await
        .with_context(|| format!("bootstrap room {}", attempt.room_id))?;

    if config.jitter_max_secs > 0 {
        let jitter = rng().random_range(0..=config.jitter_max_secs);
        if jitter > 0 {
            sleep(Duration::from_secs(jitter)).await;
        }
    }

    let log_file = open_append(attempt.worker_log)?;
    let err_file = log_file.try_clone().context("clone worker log file")?;
    let alias_base = format!("stress-w{}-r{}", attempt.worker_id, attempt.round);
    let session_artifact_dir = config.capture_client_state_artifacts.then(|| {
        config.artifact_dir.join(format!(
            "worker-{worker:02}-round-{round:03}-client-state",
            worker = attempt.worker_id,
            round = attempt.round
        ))
    });
    let mut command = Command::new(&config.join_leave_bin);
    command
        .arg(&config.server_url)
        .arg(attempt.room_id)
        .arg(&alias_base)
        .arg(format!("--count={}", attempt.count))
        .arg(format!("--leave-order={}", attempt.leave_order))
        .arg(format!(
            "--message-burst-count={}",
            config.message_burst_count
        ))
        .arg(format!(
            "--message-burst-interval-ms={}",
            config.message_burst_interval_ms
        ))
        .arg("--verbose")
        .env("CITYG_CLIENT_ADMIN_TOKEN", &config.admin_token)
        .env("CITYG_CLIENT_MESSAGE_AUTH_TOKEN", &config.message_token)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(err_file));
    if let Some(artifact_dir) = session_artifact_dir.as_ref() {
        command.arg(format!("--session-artifact-dir={}", artifact_dir.display()));
    }
    if attempt.watch_mode {
        command.arg("--watch");
    } else {
        command.arg("--batch");
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("run {}", config.join_leave_bin.display()))?;
    let status = if config.client_restart_every_secs > 0 {
        tokio::select! {
            status = child.wait() => {
                status.with_context(|| format!("run {}", config.join_leave_bin.display()))?
            }
            _ = sleep(Duration::from_secs(config.client_restart_every_secs)) => {
                let pid = child.id();
                let _ = child.start_kill();
                let _ = timeout(Duration::from_secs(15), child.wait()).await;
                if let Ok(mut file) = open_append(&config.artifact_dir.join("client-restarts.log")) {
                    let _ = writeln!(
                        file,
                        "{} worker={} round={} pid={:?} room={} client-restart-injected",
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        attempt.worker_id,
                        attempt.round,
                        pid,
                        attempt.room_id
                    );
                }
                if config.require_metrics {
                    let _ = capture_observability_snapshot(
                        &config.server_url,
                        &config.artifact_dir,
                        &format!(
                            "worker-{worker:02}-round-{round:03}-client-restart",
                            worker = attempt.worker_id,
                            round = attempt.round
                        ),
                    )
                    .await;
                }
                return Err(anyhow!(
                    "{CLIENT_RESTART_INJECTED_ERROR} worker={} round={}",
                    attempt.worker_id,
                    attempt.round
                ));
            }
        }
    } else {
        child
            .wait()
            .await
            .with_context(|| format!("run {}", config.join_leave_bin.display()))?
    };
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("exited with status {status}"))
    }
}

async fn run_tui(
    app: &mut AppState,
    event_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
    stop_tx: watch::Sender<bool>,
    max_duration: Option<Duration>,
) -> Result<bool> {
    let mut terminal = TerminalGuard::enter()?;
    let tick_rate = Duration::from_millis(200);
    let mut duration_stop_requested = false;
    let mut exit_requested_after_finish = false;
    loop {
        drain_events(app, event_rx);
        terminal
            .terminal
            .draw(|frame| draw(frame, app))
            .context("draw tui")?;

        if !duration_stop_requested
            && let Some(limit) = max_duration
            && app.elapsed() >= limit
        {
            duration_stop_requested = true;
            let _ = stop_tx.send(true);
            app.push_event(format!(
                "duration limit reached ({}); stopping gracefully",
                humantime(limit)
            ));
        }

        if event::poll(tick_rate).context("poll terminal events")?
            && let CEvent::Key(key) = event::read().context("read terminal event")?
        {
            if app.finished {
                if matches!(key.code, KeyCode::Enter | KeyCode::Char('q') | KeyCode::Esc) {
                    exit_requested_after_finish = true;
                }
            } else if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc) {
                let _ = stop_tx.send(true);
                app.push_event("graceful stop requested");
            }
        }

        if app.finished && exit_requested_after_finish {
            break;
        }
    }
    Ok(app.worker_failures > 0 || app.failed_rounds > 0 || app.capacity_check_failed)
}

async fn run_plain(
    app: &mut AppState,
    event_rx: &mut mpsc::UnboundedReceiver<AppEvent>,
    stop_tx: watch::Sender<bool>,
    max_duration: Option<Duration>,
) -> Result<bool> {
    let mut last_print = Instant::now();
    let mut duration_stop_requested = false;
    loop {
        drain_events(app, event_rx);
        if !duration_stop_requested
            && let Some(limit) = max_duration
            && app.elapsed() >= limit
        {
            duration_stop_requested = true;
            let _ = stop_tx.send(true);
            app.push_event(format!(
                "duration limit reached ({}); stopping gracefully",
                humantime(limit)
            ));
        }
        if last_print.elapsed() >= Duration::from_secs(1) {
            println!(
                "elapsed={} rounds={}/{} failed_rounds={} worker_failures={} capacity={} accept_ok={} refresh_conflicts={} p95={}",
                humantime(app.elapsed()),
                app.completed_rounds,
                app.total_rounds,
                app.failed_rounds,
                app.worker_failures,
                app.capacity_check_status,
                app.metrics.accept_epoch_ok,
                app.metrics.refresh_conflicts,
                app.metrics
                    .accept_p95_ms
                    .map(|value| format!("{value:.1}ms"))
                    .unwrap_or_else(|| "-".to_string())
            );
            last_print = Instant::now();
        }
        if app.finished {
            break;
        }
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if result.is_ok() {
                    let _ = stop_tx.send(true);
                    app.push_event("ctrl-c received; waiting for workers to settle");
                }
            }
            _ = sleep(Duration::from_millis(100)) => {}
        }
    }
    Ok(app.worker_failures > 0 || app.failed_rounds > 0 || app.capacity_check_failed)
}

fn drain_events(app: &mut AppState, event_rx: &mut mpsc::UnboundedReceiver<AppEvent>) {
    while let Ok(event) = event_rx.try_recv() {
        match event {
            AppEvent::WorkerRoundStarted {
                worker_id,
                round,
                room_id,
                mode,
                count,
            } => {
                if let Some(worker) = app.workers.get_mut(&worker_id) {
                    worker.current_round = round;
                    worker.status = "running".to_string();
                    worker.mode = mode.to_string();
                    worker.room_id = room_id.clone();
                    worker.count = count;
                    worker.last_error = None;
                }
                app.push_event(format!(
                    "worker {worker_id} round {round} started mode={mode} count={count} room={room_id}"
                ));
            }
            AppEvent::WorkerRoundCompleted {
                worker_id,
                round,
                elapsed,
            } => {
                app.completed_rounds = app.completed_rounds.saturating_add(1);
                if let Some(worker) = app.workers.get_mut(&worker_id) {
                    worker.completed_rounds = worker.completed_rounds.saturating_add(1);
                    worker.status = "idle".to_string();
                }
                app.push_event(format!(
                    "worker {worker_id} round {round} ok in {}",
                    humantime(elapsed)
                ));
            }
            AppEvent::WorkerRoundFailed {
                worker_id,
                round,
                error,
            } => {
                app.failed_rounds = app.failed_rounds.saturating_add(1);
                if let Some(worker) = app.workers.get_mut(&worker_id) {
                    worker.failed_rounds = worker.failed_rounds.saturating_add(1);
                    worker.status = "failed".to_string();
                    worker.last_error = Some(error.clone());
                }
                app.push_event(format!("worker {worker_id} round {round} failed: {error}"));
            }
            AppEvent::WorkerFinished { worker_id, ok } => {
                if ok {
                    app.worker_passes = app.worker_passes.saturating_add(1);
                } else {
                    app.worker_failures = app.worker_failures.saturating_add(1);
                }
                if let Some(worker) = app.workers.get_mut(&worker_id) {
                    worker.status = if ok { "done" } else { "failed" }.to_string();
                }
            }
            AppEvent::ServerReady { alive, ready } => {
                app.server_alive = alive;
                app.server_ready = ready;
            }
            AppEvent::ServerRestarting => {
                app.restarts = app.restarts.saturating_add(1);
                app.push_event(format!("server restart #{} in progress", app.restarts));
            }
            AppEvent::ServerRestarted { pid } => {
                app.push_event(format!(
                    "server restart complete pid={}",
                    pid.map(|id| id.to_string())
                        .unwrap_or_else(|| "-".to_string())
                ));
            }
            AppEvent::MetricsUpdated(snapshot) => {
                app.metrics = snapshot;
            }
            AppEvent::Info(line) => app.push_event(line),
            AppEvent::CapacityCheckStarted => {
                app.capacity_check_status = "running".to_string();
                app.push_event("final capacity check running");
            }
            AppEvent::CapacityCheckFinished { ok, log_path } => {
                app.capacity_check_status = if ok { "passed" } else { "failed" }.to_string();
                app.capacity_check_failed = !ok;
                app.push_event(format!(
                    "final capacity check {} ({})",
                    if ok { "passed" } else { "failed" },
                    log_path.display()
                ));
            }
            AppEvent::RunComplete => {
                app.finished = true;
                app.push_event("all workers complete");
                app.push_event("finished: press Enter, q, or Esc to exit");
            }
        }
    }
}

fn write_summary(artifact_dir: &Path, app: &AppState) -> Result<()> {
    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_sub(app.elapsed().as_secs());
    let finished_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut summary = String::new();
    let _ = writeln!(&mut summary, "started_at={started_at}");
    let _ = writeln!(&mut summary, "finished_at={finished_at}");
    let _ = writeln!(&mut summary, "server_url={}", app.server_url);
    let _ = writeln!(&mut summary, "workers={}", app.workers.len());
    let _ = writeln!(&mut summary, "worker_passes={}", app.worker_passes);
    let _ = writeln!(&mut summary, "worker_failures={}", app.worker_failures);
    let _ = writeln!(&mut summary, "rounds_completed={}", app.completed_rounds);
    let _ = writeln!(&mut summary, "rounds_failed={}", app.failed_rounds);
    let _ = writeln!(&mut summary, "restarts={}", app.restarts);
    let _ = writeln!(
        &mut summary,
        "capacity_check_status={}",
        app.capacity_check_status
    );
    let _ = writeln!(
        &mut summary,
        "accept_epoch_ok={}",
        app.metrics.accept_epoch_ok
    );
    let _ = writeln!(
        &mut summary,
        "refresh_conflicts={}",
        app.metrics.refresh_conflicts
    );
    let _ = writeln!(&mut summary, "artifact_dir={}", artifact_dir.display());
    let _ = writeln!(&mut summary, "elapsed_seconds={}", app.elapsed().as_secs());
    fs::write(artifact_dir.join("summary.txt"), summary)
        .with_context(|| format!("write {}", artifact_dir.join("summary.txt").display()))
}

fn print_final_summary(app: &AppState) {
    println!(
        "cityg-stress finished: workers_passed={} workers_failed={} rounds={}/{} capacity={} accept_ok={} refresh_conflicts={} artifacts={}",
        app.worker_passes,
        app.worker_failures,
        app.completed_rounds,
        app.total_rounds,
        app.capacity_check_status,
        app.metrics.accept_epoch_ok,
        app.metrics.refresh_conflicts,
        app.artifact_dir.display()
    );
}

fn humantime(duration: Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    if secs > 0 {
        format!("{secs}.{millis:03}s")
    } else {
        format!("{millis}ms")
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
