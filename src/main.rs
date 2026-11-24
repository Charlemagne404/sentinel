mod api;
mod auth;
mod collector;
mod config;
mod intelligence;
mod model;
mod notifications;
mod processes;
mod storage;
mod storage_watch;
mod workloads;

use clap::{Parser, Subcommand};
use config::Config;
use std::{net::SocketAddr, path::PathBuf, process::ExitCode};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sentinel", version, about = "Local-first server intelligence")]
struct Cli {
    #[arg(long, global = true, env = "SENTINEL_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Status,
    Doctor,
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Version,
}

#[derive(Subcommand)]
enum ConfigCommand {
    Validate,
}
#[derive(Subcommand)]
enum DbCommand {
    Backup { destination: PathBuf },
    Integrity,
}
#[derive(Subcommand)]
enum AdminCommand {
    ResetPassword,
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sentinel=info,tower_http=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sentinel: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    if matches!(cli.command, Some(Command::Version)) {
        println!("sentinel {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let config = Config::load(cli.config.as_deref())?;
    match cli.command {
        Some(Command::Config {
            command: ConfigCommand::Validate,
        }) => {
            config.validate()?;
            println!("Configuration is valid: {}", config.path.display());
        }
        Some(Command::Doctor) => doctor(&config)?,
        Some(Command::Status) => {
            let db = storage::Store::open(&config.database_path())?;
            println!(
                "Sentinel {}\nDatabase: {}\nSamples: {}\nIncidents: {}\nListen: {}:{}",
                env!("CARGO_PKG_VERSION"),
                config.database_path().display(),
                db.count("host_samples")?,
                db.count("incidents")?,
                config.listen_address(),
                config.server.port
            );
        }
        Some(Command::Db {
            command: DbCommand::Integrity,
        }) => {
            let db = storage::Store::open(&config.database_path())?;
            let result = db.integrity_check()?;
            println!("{result}");
            if result != "ok" {
                anyhow::bail!("database integrity check failed");
            }
            if let Some(storage_result) = storage_watch::integrity_history(
                &config.server.database_dir.join("storage-history.sqlite"),
            )? {
                println!("Storage history: {storage_result}");
            }
        }
        Some(Command::Db {
            command: DbCommand::Backup { destination },
        }) => {
            let storage_source = config.server.database_dir.join("storage-history.sqlite");
            let storage_destination = storage_history_backup_path(&destination);
            anyhow::ensure!(
                !storage_source.is_file() || !storage_destination.exists(),
                "storage-history backup destination already exists: {}",
                storage_destination.display()
            );
            let db = storage::Store::open(&config.database_path())?;
            db.backup(&destination)?;
            println!("Main database backup written to {}", destination.display());
            if storage_source.is_file() {
                storage_watch::backup_history(&storage_source, &storage_destination)?;
                println!(
                    "Storage-history backup written to {}",
                    storage_destination.display()
                );
            }
        }
        Some(Command::Admin {
            command: AdminCommand::ResetPassword,
        }) => {
            let store = storage::Store::open(&config.database_path())?;
            let auth = auth::Auth::new(&config, store);
            let path = auth.reset_password()?;
            println!(
                "Administrator password reset. Create a new password in the setup page using the one-time token at {}",
                path.display()
            );
        }
        None => serve(config).await?,
        Some(Command::Version) => unreachable!(),
    }
    Ok(())
}

fn storage_history_backup_path(destination: &std::path::Path) -> PathBuf {
    let mut name = destination
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("sentinel-backup"))
        .to_os_string();
    name.push(".storage-history.sqlite");
    destination
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(name)
}

fn doctor(config: &Config) -> anyhow::Result<()> {
    config.validate()?;
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_kib = |key: &str| {
        meminfo
            .lines()
            .find(|line| line.starts_with(key))
            .and_then(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let available_kib = mem_kib("MemAvailable:");
    let swap_total_kib = mem_kib("SwapTotal:");
    let swap_free_kib = mem_kib("SwapFree:");
    let iface = if_addrs::get_if_addrs()?
        .into_iter()
        .any(|i| i.name == config.server.interface);
    let (disk_total, disk_available) = filesystem_space("/").unwrap_or_default();
    let listen = config.listen_address();
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .map(|raw| raw.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unavailable".into());
    let cpu_psi = pressure_avg10("/proc/pressure/cpu", "some");
    let memory_psi = pressure_avg10("/proc/pressure/memory", "some");
    let io_psi = pressure_avg10("/proc/pressure/io", "some");
    let hottest = collector::read_temperatures()
        .iter()
        .map(|reading| reading.celsius)
        .reduce(f64::max)
        .map(|value| format!("{value:.1}°C"))
        .unwrap_or_else(|| "unavailable".into());
    let port_free = std::net::TcpListener::bind((listen.as_str(), config.server.port)).is_ok();
    println!(
        "Configuration: valid\nProcfs: {}\nLoad average (1/5/15m): {load}\nCPU PSI some avg10: {}\nMemory PSI some avg10: {}\nI/O PSI some avg10: {}\nHottest hwmon sensor: {hottest}\nAvailable memory: {:.1} GiB\nSwap used: {:.1} / {:.1} GiB\nRoot filesystem free: {:.1} / {:.1} GiB\nInterface {}: {}\nListen address: {}:{}\nPort currently free: {port_free}\nDatabase: {}",
        PathBuf::from("/proc/stat").exists(),
        display_percent(cpu_psi),
        display_percent(memory_psi),
        display_percent(io_psi),
        available_kib as f64 / 1_048_576.0,
        swap_total_kib.saturating_sub(swap_free_kib) as f64 / 1_048_576.0,
        swap_total_kib as f64 / 1_048_576.0,
        disk_available as f64 / 1_073_741_824.0,
        disk_total as f64 / 1_073_741_824.0,
        config.server.interface,
        if iface {
            "present"
        } else {
            "missing (will bind loopback)"
        },
        listen,
        config.server.port,
        config.database_path().display()
    );
    info!("doctor checks complete");
    Ok(())
}

fn pressure_avg10(path: &str, group: &str) -> Option<f64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let row = raw.lines().find(|line| line.starts_with(group))?;
    row.split_whitespace()
        .find_map(|item| item.strip_prefix("avg10=")?.parse().ok())
}

fn display_percent(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.2}%"))
        .unwrap_or_else(|| "unavailable".into())
}

fn filesystem_space(path: &str) -> Option<(u64, u64)> {
    let path = std::ffi::CString::new(path).ok()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    let block = stat.f_frsize as u64;
    Some((
        (stat.f_blocks as u64).saturating_mul(block),
        (stat.f_bavail as u64).saturating_mul(block),
    ))
}

async fn serve(config: Config) -> anyhow::Result<()> {
    config.validate()?;
    std::fs::create_dir_all(&config.server.database_dir)?;
    let store = storage::Store::open(&config.database_path())?;
    let notifications = notifications::Dispatcher::start(store.clone());
    let state = api::AppState::new(config.clone(), store.clone(), notifications)?;
    let bind = config.listen_address();
    let listener = tokio::net::TcpListener::bind((bind.as_str(), config.server.port)).await?;
    let actual = listener.local_addr()?;
    info!(address = %actual, "Sentinel listening");
    if !state.auth.is_configured()? {
        let token = state.auth.ensure_bootstrap_token()?;
        if let Some(path) = state.auth.bootstrap_path() {
            info!(bootstrap_file = %path.display(), "administrator setup token created");
        }
        let _ = token;
    }
    let monitor = state.monitor.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let storage_task = tokio::spawn(state.storage_watch.clone().run(shutdown_rx));
    let shutdown = shutdown_signal();
    let service_result = tokio::select! {
        result = axum::serve(listener, api::router(state).into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(shutdown) => result.map_err(anyhow::Error::from),
        result = monitor.run() => result,
    };
    let _ = shutdown_tx.send(true);
    storage_task
        .await
        .map_err(|error| anyhow::anyhow!("storage task failed: {error}"))?;
    service_result?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).expect("register SIGTERM handler");
        tokio::select! {_ = tokio::signal::ctrl_c()=>{},_ = terminate.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    info!("shutdown requested");
}
