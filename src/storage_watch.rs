use crate::{
    config::{Config, StorageConfig},
    notifications::{Dispatcher, IncidentNotice},
    storage::unix_now,
};
use rusqlite::{Connection, OptionalExtension, backup::Backup, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{RwLock, watch};
use tracing::warn;

const GIB: u64 = 1024 * 1024 * 1024;
const MAX_HISTORY_POINTS: usize = 9_000;
const MAX_FILESYSTEMS: usize = 64;
const ESTIMATED_BYTES_PER_HISTORY_ROW: u64 = 512;

#[derive(Debug, Clone, Serialize, Default)]
pub struct StorageReport {
    pub sampled_at: i64,
    pub last_attempt_at: i64,
    pub consecutive_failures: u64,
    pub severity: String,
    pub policy: StorageConfig,
    pub history_persistent: bool,
    pub history_budget_bytes: u64,
    pub history_samples: u64,
    pub history_oldest_sample_at: Option<i64>,
    pub history_truncated_by_budget: bool,
    pub filesystems: Vec<FilesystemUsage>,
    pub mount_errors: Vec<StorageMountError>,
    pub missing_required_mounts: Vec<String>,
    pub error: Option<String>,
    pub history_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageMountError {
    pub mount_point: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilesystemUsage {
    pub mount_point: String,
    pub aliases: Vec<String>,
    pub source: String,
    pub filesystem: String,
    pub read_only: bool,
    pub required_writable: bool,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    /// Free blocks unavailable to an unprivileged process (often ext4 reserved blocks).
    /// This is not a measurement of ext4 metadata overhead or its configured reserve.
    pub unavailable_free_bytes: u64,
    pub used_percent: f64,
    pub inode_total: u64,
    pub inode_used: u64,
    pub inode_available: u64,
    pub inode_used_percent: f64,
    pub growth_bytes_per_hour: Option<f64>,
    pub hours_until_full: Option<f64>,
    pub severity: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageHistoryPoint {
    pub sampled_at: i64,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageHistory {
    pub mount_point: String,
    pub hours: u64,
    pub points: Vec<StorageHistoryPoint>,
}

#[derive(Clone)]
pub struct StorageWatch {
    config: Arc<RwLock<Config>>,
    history: Arc<Mutex<Connection>>,
    latest: Arc<RwLock<StorageReport>>,
    notifications: Dispatcher,
    history_persistent: bool,
    history_error: Option<String>,
    history_path: Option<PathBuf>,
}

impl StorageWatch {
    pub fn open(
        config: Arc<RwLock<Config>>,
        history_path: &Path,
        notifications: Dispatcher,
    ) -> anyhow::Result<Self> {
        let disk_connection = (|| -> anyhow::Result<Connection> {
            if let Some(parent) = history_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let connection = Connection::open(history_path)?;
            #[cfg(unix)]
            fs::set_permissions(history_path, fs::Permissions::from_mode(0o600))?;
            connection.busy_timeout(Duration::from_secs(2))?;
            initialize_history(&connection)?;
            Ok(connection)
        })();
        let (connection, history_persistent, history_error) = match disk_connection {
            Ok(connection) => (connection, true, None),
            Err(error) => {
                let connection = Connection::open_in_memory()?;
                connection.busy_timeout(Duration::from_secs(2))?;
                initialize_history(&connection)?;
                (
                    connection,
                    false,
                    Some(format!("persistent storage history unavailable: {error}")),
                )
            }
        };
        let mut initial_report = StorageReport::default();
        initial_report.severity = "unknown".into();
        initial_report.history_persistent = history_persistent;
        initial_report.history_error = history_error.clone();
        Ok(Self {
            config,
            history: Arc::new(Mutex::new(connection)),
            latest: Arc::new(RwLock::new(initial_report)),
            notifications,
            history_persistent,
            history_error,
            history_path: history_persistent.then(|| history_path.to_path_buf()),
        })
    }

    pub async fn current(&self) -> StorageReport {
        self.latest.read().await.clone()
    }

    pub fn history_database_size_bytes(&self) -> u64 {
        let Some(path) = self.history_path.as_deref() else {
            return 0;
        };
        let mut size = fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            size = size.saturating_add(
                fs::metadata(PathBuf::from(sidecar))
                    .map(|metadata| metadata.len())
                    .unwrap_or(0),
            );
        }
        size
    }

    pub fn history(&self, mount_point: &str, hours: u64) -> anyhow::Result<StorageHistory> {
        anyhow::ensure!(
            mount_point.starts_with('/') && mount_point.len() <= 1024,
            "invalid mount point"
        );
        let hours = hours.clamp(1, 24 * 30);
        let since = unix_now().saturating_sub((hours.saturating_mul(3600)) as i64);
        let conn = self
            .history
            .lock()
            .map_err(|_| anyhow::anyhow!("storage history lock poisoned"))?;
        let mut statement = conn.prepare(
            "SELECT sampled_at,total_bytes,used_bytes,available_bytes,severity
             FROM filesystem_samples WHERE mount_point=?1 AND sampled_at>=?2
             ORDER BY sampled_at DESC LIMIT ?3",
        )?;
        let mut points = statement
            .query_map(
                params![mount_point, since, MAX_HISTORY_POINTS as i64],
                |row| {
                    Ok(StorageHistoryPoint {
                        sampled_at: row.get(0)?,
                        total_bytes: row.get::<_, i64>(1)?.max(0) as u64,
                        used_bytes: row.get::<_, i64>(2)?.max(0) as u64,
                        available_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                        severity: row.get(4)?,
                    })
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        points.reverse();
        Ok(StorageHistory {
            mount_point: mount_point.to_string(),
            hours,
            points,
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                break;
            }
            if let Err(error) = self.sample().await {
                warn!(error=%error, "storage sample failed; the next scheduled sample will retry");
                let mut report = self.latest.write().await;
                report.last_attempt_at = unix_now();
                report.consecutive_failures = report.consecutive_failures.saturating_add(1);
                report.error = Some(error.to_string());
                if report.sampled_at == 0 {
                    report.severity = "unknown".into();
                }
            }
            let delay = self.config.read().await.storage.sample_seconds.max(300);
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
            }
        }
        let history = self.history.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || {
            let connection = history
                .lock()
                .map_err(|_| anyhow::anyhow!("storage history lock poisoned"))?;
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            anyhow::Ok(())
        })
        .await
        .unwrap_or_else(|error| Err(error.into()))
        {
            warn!(error=%error, "storage history checkpoint failed during shutdown");
        }
    }

    async fn sample(&self) -> anyhow::Result<()> {
        let config = self.config.read().await.clone();
        let storage_config = config.storage.clone();
        let (_, history_budget_mb) =
            crate::config::database_budget_partitions_mb(config.server.database_budget_mb);
        let history_budget_bytes = history_budget_mb.saturating_mul(1024 * 1024);
        let history = self.history.clone();
        let measured = tokio::task::spawn_blocking(move || {
            measure_and_store(&storage_config, &history, unix_now(), history_budget_bytes)
        })
        .await??;
        let mut report = measured.report.clone();
        report.history_persistent = self.history_persistent;
        report.history_error = self.history_error.clone();
        *self.latest.write().await = report;
        for notice in measured.notices {
            self.notifications.notify(&config, notice).await;
        }
        Ok(())
    }
}

fn initialize_history(connection: &Connection) -> anyhow::Result<()> {
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS filesystem_samples (
                sampled_at INTEGER NOT NULL,
                mount_key TEXT NOT NULL,
                mount_point TEXT NOT NULL,
                source TEXT NOT NULL,
                filesystem TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                used_bytes INTEGER NOT NULL,
                available_bytes INTEGER NOT NULL,
                inode_total INTEGER NOT NULL,
                inode_used INTEGER NOT NULL,
                severity TEXT NOT NULL,
                PRIMARY KEY (sampled_at, mount_key)
             );
             CREATE INDEX IF NOT EXISTS filesystem_samples_by_mount_time
                ON filesystem_samples(mount_key, sampled_at);
             CREATE TABLE IF NOT EXISTS filesystem_watch_state (
                watch_key TEXT PRIMARY KEY,
                state TEXT NOT NULL
             );",
    )?;
    Ok(())
}

pub fn backup_history(source_path: &Path, destination: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        source_path.is_file(),
        "storage history database does not exist"
    );
    anyhow::ensure!(
        !destination.exists(),
        "backup destination already exists: {}",
        destination.display()
    );
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut temporary = destination.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    drop(file);

    let result = (|| -> anyhow::Result<()> {
        let source = Connection::open(source_path)?;
        source.busy_timeout(Duration::from_secs(3))?;
        let mut target = Connection::open(&temporary)?;
        let backup = Backup::new(&source, &mut target)?;
        backup.run_to_completion(64, Duration::from_millis(20), None)?;
        drop(backup);
        drop(target);
        drop(source);
        fs::rename(&temporary, destination)?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn integrity_history(path: &Path) -> anyhow::Result<Option<String>> {
    if !path.is_file() {
        return Ok(None);
    }
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(3))?;
    let result: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    anyhow::ensure!(
        result == "ok",
        "storage-history integrity check failed: {result}"
    );
    Ok(Some(result))
}

struct Measured {
    report: StorageReport,
    notices: Vec<IncidentNotice>,
}

#[derive(Debug, Clone)]
struct MountEntry {
    point: String,
    source: String,
    filesystem: String,
    device_id: u64,
    aliases: Vec<String>,
    read_only: bool,
}

fn measure_and_store(
    config: &StorageConfig,
    history: &Arc<Mutex<Connection>>,
    sampled_at: i64,
    history_budget_bytes: u64,
) -> anyhow::Result<Measured> {
    let entries = mounted_filesystems(&config.required_writable_mounts)?;
    let mut connection = history
        .lock()
        .map_err(|_| anyhow::anyhow!("storage history lock poisoned"))?;
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let max_pages = (history_budget_bytes / page_size.max(1) as u64)
        .max(1)
        .min(i64::MAX as u64) as i64;
    connection.pragma_update(None, "max_page_count", max_pages)?;
    connection.pragma_update(None, "wal_autocheckpoint", 256_i64)?;
    connection.pragma_update(
        None,
        "journal_size_limit",
        (history_budget_bytes / 16).min(4 * 1024 * 1024) as i64,
    )?;
    let page_count: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let page_budget_pressure =
        (page_count.max(0) as u64).saturating_mul(10) >= (max_pages as u64).saturating_mul(8);
    let transaction = connection.transaction()?;
    let mut filesystems = Vec::with_capacity(entries.len());
    let mut mount_errors = Vec::new();
    let mut notices = Vec::new();

    for entry in entries {
        let mount_key = format!("{}|{}", entry.source, entry.point);
        let previous = transaction
            .query_row(
                "SELECT severity FROM filesystem_samples WHERE mount_key=?1 ORDER BY sampled_at DESC LIMIT 1",
                [&mount_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let required_writable = config.required_writable_mounts.contains(&entry.point);
        let mut usage = match filesystem_usage(&entry, required_writable, config) {
            Ok(usage) => usage,
            Err(error) => {
                mount_errors.push(StorageMountError {
                    mount_point: entry.point,
                    error: error.to_string(),
                });
                continue;
            }
        };
        if let Some((timestamp, used_bytes)) =
            growth_baseline(&transaction, &mount_key, sampled_at)?
        {
            if timestamp < sampled_at {
                let seconds = sampled_at.saturating_sub(timestamp) as f64;
                if seconds >= 3600.0 {
                    let growth = (usage.used_bytes as f64 - used_bytes as f64) * 3600.0 / seconds;
                    usage.growth_bytes_per_hour = Some(growth);
                    if growth > 0.0 {
                        usage.hours_until_full = Some(usage.available_bytes as f64 / growth);
                    }
                    let abnormal = config.abnormal_growth_gib_per_hour * GIB as f64;
                    if growth >= abnormal {
                        usage.reasons.push(format!(
                            "growth is {:.2} GiB/hour, above the configured {:.2} GiB/hour threshold",
                            growth / GIB as f64,
                            config.abnormal_growth_gib_per_hour
                        ));
                        usage.severity = max_severity(&usage.severity, "high").to_string();
                    }
                }
            }
        }

        if previous.as_deref() != Some(usage.severity.as_str()) {
            let digest = Sha256::digest(mount_key.as_bytes());
            let signature = format!("storage:{}:{}", hex::encode(&digest[..12]), usage.severity);
            if usage.severity == "ok" {
                if let Some(old) = previous.as_deref().filter(|level| *level != "ok") {
                    notices.push(IncidentNotice {
                        incident_id: None,
                        signature,
                        severity: notification_severity(old).into(),
                        title: format!("Storage pressure recovered on {}", usage.mount_point),
                        recovered: true,
                        escalated: false,
                    });
                }
            } else {
                notices.push(IncidentNotice {
                    incident_id: None,
                    signature,
                    severity: notification_severity(&usage.severity).into(),
                    title: format!(
                        "{} storage pressure on {}",
                        usage.severity, usage.mount_point
                    ),
                    recovered: false,
                    escalated: previous
                        .as_deref()
                        .is_some_and(|level| severity_rank(&usage.severity) > severity_rank(level)),
                });
            }
        }

        transaction.execute(
            "INSERT OR REPLACE INTO filesystem_samples
             (sampled_at,mount_key,mount_point,source,filesystem,total_bytes,used_bytes,available_bytes,inode_total,inode_used,severity)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                sampled_at,
                mount_key,
                usage.mount_point,
                usage.source,
                usage.filesystem,
                usage.total_bytes.min(i64::MAX as u64) as i64,
                usage.used_bytes.min(i64::MAX as u64) as i64,
                usage.available_bytes.min(i64::MAX as u64) as i64,
                usage.inode_total.min(i64::MAX as u64) as i64,
                usage.inode_used.min(i64::MAX as u64) as i64,
                usage.severity,
            ],
        )?;
        filesystems.push(usage);
    }

    let cutoff = sampled_at.saturating_sub((config.history_days.min(3650) * 86_400) as i64);
    transaction.execute(
        "DELETE FROM filesystem_samples WHERE sampled_at < ?1",
        [cutoff],
    )?;

    let mut maximum_rows = (history_budget_bytes / ESTIMATED_BYTES_PER_HISTORY_ROW).max(1);
    if page_budget_pressure {
        maximum_rows = maximum_rows.saturating_mul(3) / 4;
    }
    let (history_samples, history_oldest_sample_at, history_truncated_by_budget) =
        prune_history_to_row_budget(&transaction, maximum_rows)?;

    let mut missing_required_mounts = config.required_writable_mounts.clone();
    for usage in &filesystems {
        missing_required_mounts.retain(|required| {
            required != &usage.mount_point && !usage.aliases.iter().any(|alias| alias == required)
        });
    }
    for required in &config.required_writable_mounts {
        let current_state = if missing_required_mounts.contains(required) {
            "missing"
        } else {
            "present"
        };
        let watch_key = format!("mount-presence:{required}");
        let previous = transaction
            .query_row(
                "SELECT state FROM filesystem_watch_state WHERE watch_key=?1",
                [&watch_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if (current_state == "missing" && previous.as_deref() != Some("missing"))
            || (current_state == "present" && previous.as_deref() == Some("missing"))
        {
            let digest = Sha256::digest(watch_key.as_bytes());
            notices.push(IncidentNotice {
                incident_id: None,
                signature: format!("storage:{}", hex::encode(&digest[..12])),
                severity: if current_state == "missing" {
                    "critical"
                } else {
                    "warning"
                }
                .into(),
                title: if current_state == "missing" {
                    format!("Required storage mount is missing: {required}")
                } else {
                    format!("Required storage mount returned: {required}")
                },
                recovered: current_state == "present",
                escalated: current_state == "missing",
            });
        }
        transaction.execute(
            "INSERT INTO filesystem_watch_state(watch_key,state) VALUES(?1,?2)
             ON CONFLICT(watch_key) DO UPDATE SET state=excluded.state",
            params![watch_key, current_state],
        )?;
    }
    let mut severity = filesystems
        .iter()
        .map(|fs| fs.severity.as_str())
        .max_by_key(|level| severity_rank(level))
        .unwrap_or("ok")
        .to_string();
    if !missing_required_mounts.is_empty() {
        severity = max_severity(&severity, "critical").to_string();
    }
    if !mount_errors.is_empty() {
        severity = max_severity(&severity, "warning").to_string();
    }
    transaction.commit()?;
    Ok(Measured {
        report: StorageReport {
            sampled_at,
            last_attempt_at: sampled_at,
            consecutive_failures: 0,
            severity,
            policy: config.clone(),
            history_persistent: false,
            history_budget_bytes,
            history_samples,
            history_oldest_sample_at,
            history_truncated_by_budget,
            filesystems,
            mount_errors,
            missing_required_mounts,
            error: None,
            history_error: None,
        },
        notices,
    })
}

fn prune_history_to_row_budget(
    transaction: &rusqlite::Transaction<'_>,
    maximum_rows: u64,
) -> anyhow::Result<(u64, Option<i64>, bool)> {
    let maximum_rows = maximum_rows.min(i64::MAX as u64) as i64;
    let before: i64 =
        transaction.query_row("SELECT COUNT(*) FROM filesystem_samples", [], |row| {
            row.get(0)
        })?;
    let truncated = before > maximum_rows;
    if truncated {
        // Cut at a sample timestamp so all filesystems measured in one pass
        // remain together, even if that leaves a small number above the cap.
        let cutoff: i64 = transaction.query_row(
            "SELECT sampled_at FROM filesystem_samples ORDER BY sampled_at DESC LIMIT 1 OFFSET ?1",
            [maximum_rows],
            |row| row.get(0),
        )?;
        transaction.execute(
            "DELETE FROM filesystem_samples WHERE sampled_at < ?1",
            [cutoff],
        )?;
    }
    let (count, oldest): (i64, Option<i64>) = transaction.query_row(
        "SELECT COUNT(*), MIN(sampled_at) FROM filesystem_samples",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((count.max(0) as u64, oldest, truncated))
}

fn mounted_filesystems(required_mounts: &[String]) -> anyhow::Result<Vec<MountEntry>> {
    // Sentinel's systemd unit uses ProtectSystem=strict. PID 1's mount table
    // gives the host mount flags instead of Sentinel's intentionally read-only
    // service namespace, while statvfs still supplies the live capacity values.
    let raw = fs::read_to_string("/proc/1/mounts")?;
    let mut candidates = Vec::new();
    for line in raw.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            continue;
        }
        let source = unescape_mount_field(fields[0]);
        let point = unescape_mount_field(fields[1]);
        let filesystem = unescape_mount_field(fields[2]);
        if !measurable_filesystem(&source, &point, &filesystem) {
            continue;
        }
        let Ok(metadata) = fs::metadata(&point) else {
            continue;
        };
        candidates.push(MountEntry {
            point,
            source,
            filesystem,
            device_id: metadata.dev(),
            aliases: Vec::new(),
            read_only: fields[3].split(',').any(|option| option == "ro"),
        });
    }
    candidates.sort_by(|a, b| {
        (
            if a.point == "/" {
                0
            } else if required_mounts.contains(&a.point) {
                1
            } else {
                2
            },
            a.point != "/",
            a.point.matches('/').count(),
            a.point.as_str(),
        )
            .cmp(&(
                if b.point == "/" {
                    0
                } else if required_mounts.contains(&b.point) {
                    1
                } else {
                    2
                },
                b.point != "/",
                b.point.matches('/').count(),
                b.point.as_str(),
            ))
    });

    let mut by_device: HashMap<u64, usize> = HashMap::new();
    let mut unique: Vec<MountEntry> = Vec::new();
    for candidate in candidates {
        let required = required_mounts.contains(&candidate.point);
        if !required && let Some(index) = by_device.get(&candidate.device_id).copied() {
            unique[index].aliases.push(candidate.point);
            continue;
        }
        if !by_device.contains_key(&candidate.device_id) {
            by_device.insert(candidate.device_id, unique.len());
        }
        unique.push(candidate);
    }
    unique.truncate(MAX_FILESYSTEMS);
    Ok(unique)
}

fn measurable_filesystem(source: &str, mount_point: &str, filesystem: &str) -> bool {
    if mount_point == "/" {
        return true;
    }
    if source.starts_with("/dev/loop")
        || matches!(
            filesystem,
            "proc"
                | "sysfs"
                | "devpts"
                | "tmpfs"
                | "devtmpfs"
                | "cgroup"
                | "cgroup2"
                | "overlay"
                | "squashfs"
                | "securityfs"
                | "debugfs"
                | "tracefs"
                | "configfs"
                | "pstore"
                | "mqueue"
                | "hugetlbfs"
                | "fusectl"
                | "rpc_pipefs"
        )
    {
        return false;
    }
    source.starts_with("/dev/")
        || matches!(
            filesystem,
            "nfs" | "nfs4" | "cifs" | "fuseblk" | "ntfs3" | "zfs" | "virtiofs"
        )
}

fn unescape_mount_field(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn filesystem_usage(
    entry: &MountEntry,
    required_writable: bool,
    config: &StorageConfig,
) -> anyhow::Result<FilesystemUsage> {
    let path = CString::new(entry.point.as_bytes())?;
    let mut raw = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    let result = unsafe { libc::statvfs(path.as_ptr(), raw.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { raw.assume_init() };
    let block_size = if stat.f_frsize > 0 {
        stat.f_frsize
    } else {
        stat.f_bsize
    } as u64;
    let total_bytes = (stat.f_blocks as u64).saturating_mul(block_size);
    let free_bytes = (stat.f_bfree as u64).saturating_mul(block_size);
    let available_bytes = (stat.f_bavail as u64).saturating_mul(block_size);
    let used_bytes = total_bytes.saturating_sub(free_bytes);
    let inode_total = stat.f_files as u64;
    let inode_free = stat.f_ffree as u64;
    let inode_available = stat.f_favail as u64;
    let inode_used = inode_total.saturating_sub(inode_free);
    // Match df's Use% denominator: used blocks / (used + blocks available to
    // an unprivileged caller). Reserved ext4 blocks are reported separately.
    let used_percent = percentage(used_bytes, used_bytes.saturating_add(available_bytes));
    let inode_used_percent = percentage(inode_used, inode_total);
    let read_only = entry.read_only;
    let (severity, reasons) = classify(
        used_percent,
        total_bytes,
        available_bytes,
        inode_used_percent,
        read_only,
        required_writable,
        config,
    );
    Ok(FilesystemUsage {
        mount_point: entry.point.clone(),
        aliases: entry.aliases.clone(),
        source: entry.source.clone(),
        filesystem: entry.filesystem.clone(),
        read_only,
        required_writable,
        total_bytes,
        used_bytes,
        free_bytes,
        available_bytes,
        unavailable_free_bytes: free_bytes.saturating_sub(available_bytes),
        used_percent,
        inode_total,
        inode_used,
        inode_available,
        inode_used_percent,
        growth_bytes_per_hour: None,
        hours_until_full: None,
        severity,
        reasons,
    })
}

fn percentage(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (used as f64 * 100.0 / total as f64).clamp(0.0, 100.0)
    }
}

fn classify(
    used_percent: f64,
    total_bytes: u64,
    available_bytes: u64,
    inode_used_percent: f64,
    read_only: bool,
    required_writable: bool,
    config: &StorageConfig,
) -> (String, Vec<String>) {
    let mut level = "ok";
    let mut reasons = Vec::new();
    let available_gib = available_bytes as f64 / GIB as f64;
    // Absolute GiB thresholds are meaningful for large volumes. Applying a
    // 5 GiB critical floor to a small EFI or boot partition would flag a
    // healthy filesystem solely because its total capacity is smaller.
    let absolute_capacity_thresholds = total_bytes
        >= config
            .warning_available_gib
            .saturating_mul(2)
            .saturating_mul(GIB);
    if read_only && required_writable {
        level = "critical";
        reasons.push("required mount is read-only".into());
    }
    if used_percent >= config.critical_used_percent
        || (absolute_capacity_thresholds
            && available_bytes <= config.critical_available_gib.saturating_mul(GIB))
        || inode_used_percent >= config.critical_used_percent
    {
        level = max_severity(level, "critical");
        reasons.push(format!(
            "critical capacity: {:.1}% used, {:.1} GiB available, {:.1}% inodes used",
            used_percent, available_gib, inode_used_percent
        ));
    } else if used_percent >= config.high_used_percent
        || (absolute_capacity_thresholds
            && available_bytes <= config.high_available_gib.saturating_mul(GIB))
        || inode_used_percent >= config.high_used_percent
    {
        level = max_severity(level, "high");
        reasons.push(format!(
            "high capacity: {:.1}% used, {:.1} GiB available, {:.1}% inodes used",
            used_percent, available_gib, inode_used_percent
        ));
    } else if used_percent >= config.warning_used_percent
        || (absolute_capacity_thresholds
            && available_bytes <= config.warning_available_gib.saturating_mul(GIB))
        || inode_used_percent >= config.warning_used_percent
    {
        level = max_severity(level, "warning");
        reasons.push(format!(
            "capacity warning: {:.1}% used, {:.1} GiB available, {:.1}% inodes used",
            used_percent, available_gib, inode_used_percent
        ));
    }
    if read_only && !required_writable {
        reasons.push("filesystem is mounted read-only".into());
    }
    (level.to_string(), reasons)
}

fn max_severity<'a>(left: &'a str, right: &'a str) -> &'a str {
    if severity_rank(left) >= severity_rank(right) {
        left
    } else {
        right
    }
}

fn severity_rank(level: &str) -> u8 {
    match level {
        "critical" => 3,
        "high" => 2,
        "warning" => 1,
        _ => 0,
    }
}

fn notification_severity(level: &str) -> &'static str {
    if level == "critical" {
        "critical"
    } else {
        "warning"
    }
}

fn growth_baseline(
    connection: &Connection,
    mount_key: &str,
    now: i64,
) -> anyhow::Result<Option<(i64, u64)>> {
    let one_day = now.saturating_sub(86_400);
    let baseline = connection
        .query_row(
            "SELECT sampled_at,used_bytes FROM filesystem_samples
             WHERE mount_key=?1 AND sampled_at<=?2 ORDER BY sampled_at DESC LIMIT 1",
            params![mount_key, one_day],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?.max(0) as u64)),
        )
        .optional()?;
    if baseline.is_some() {
        return Ok(baseline);
    }
    let recent = connection
        .query_row(
            "SELECT sampled_at,used_bytes FROM filesystem_samples
             WHERE mount_key=?1 AND sampled_at<=?2 ORDER BY sampled_at DESC LIMIT 1",
            params![mount_key, now.saturating_sub(3600)],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?.max(0) as u64)),
        )
        .optional()?;
    Ok(recent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn persistent_history_file_is_owner_only_and_counted() {
        let directory = tempfile::tempdir().unwrap();
        let config = Arc::new(RwLock::new(Config::default()));
        let store = crate::storage::Store::open(&directory.path().join("main.sqlite")).unwrap();
        let dispatcher = Dispatcher::start(store);
        let history_path = directory.path().join("storage-history.sqlite");
        let watch = StorageWatch::open(config, &history_path, dispatcher).unwrap();

        assert!(watch.current().await.history_persistent);
        assert!(watch.history_database_size_bytes() > 0);
        assert_eq!(
            fs::metadata(&history_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn storage_history_backup_includes_committed_data_and_is_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("storage-history.sqlite");
        let destination = directory.path().join("backup.storage-history.sqlite");
        {
            let connection = Connection::open(&source_path).unwrap();
            initialize_history(&connection).unwrap();
            connection
                .execute(
                    "INSERT INTO filesystem_samples VALUES(1,'/dev/test|/','/','/dev/test','ext4',100,75,20,10,7,'warning')",
                    [],
                )
                .unwrap();
        }

        backup_history(&source_path, &destination).unwrap();
        let backup = Connection::open(&destination).unwrap();
        let integrity: String = backup
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        assert_eq!(
            backup
                .query_row("SELECT count(*) FROM filesystem_samples", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn mount_table_escapes_are_decoded() {
        assert_eq!(
            unescape_mount_field("/mnt/large\\040disk"),
            "/mnt/large disk"
        );
        assert_eq!(unescape_mount_field("/mnt/a\\134b"), "/mnt/a\\b");
    }

    #[test]
    fn history_budget_pruning_keeps_complete_sample_timestamps() {
        let mut connection = Connection::open_in_memory().unwrap();
        initialize_history(&connection).unwrap();
        for timestamp in 1..=10_i64 {
            for mount in ["/", "/data"] {
                connection
                    .execute(
                        "INSERT INTO filesystem_samples VALUES(?1,?2,?3,'/dev/test','ext4',100,75,20,10,7,'ok')",
                        params![timestamp, format!("{mount}-{timestamp}"), mount],
                    )
                    .unwrap();
            }
        }
        let transaction = connection.transaction().unwrap();
        let (count, oldest, truncated) = prune_history_to_row_budget(&transaction, 5).unwrap();
        transaction.commit().unwrap();
        assert!(truncated);
        assert_eq!(count, 6); // two mount readings sharing the cutoff sample
        assert_eq!(oldest, Some(8));
    }

    #[test]
    fn configured_capacity_thresholds_follow_warning_high_critical_order() {
        let config = StorageConfig::default();
        assert_eq!(
            classify(79.9, 100 * GIB, 30 * GIB, 50.0, false, true, &config).0,
            "ok"
        );
        assert_eq!(
            classify(80.0, 100 * GIB, 30 * GIB, 50.0, false, true, &config).0,
            "warning"
        );
        assert_eq!(
            classify(90.0, 100 * GIB, 30 * GIB, 50.0, false, true, &config).0,
            "high"
        );
        assert_eq!(
            classify(95.0, 100 * GIB, 30 * GIB, 50.0, false, true, &config).0,
            "critical"
        );
        assert_eq!(
            classify(20.0, 100 * GIB, 4 * GIB, 50.0, false, true, &config).0,
            "critical"
        );
        assert_eq!(
            classify(20.0, 200 * GIB, 100 * GIB, 95.0, false, true, &config).0,
            "critical"
        );
        assert_eq!(
            classify(20.0, 200 * GIB, 100 * GIB, 50.0, true, true, &config).0,
            "critical"
        );
        assert_eq!(
            classify(20.0, 200 * GIB, 100 * GIB, 50.0, true, false, &config).0,
            "ok"
        );
        let small_volume = 512 * 1024 * 1024;
        assert_eq!(
            classify(
                20.0,
                small_volume,
                300 * 1024 * 1024,
                50.0,
                false,
                true,
                &config
            )
            .0,
            "ok"
        );
        assert_eq!(
            classify(
                96.0,
                small_volume,
                20 * 1024 * 1024,
                50.0,
                false,
                true,
                &config
            )
            .0,
            "critical"
        );
    }

    #[test]
    fn utilization_percent_matches_df_and_keeps_reserved_free_separate() {
        let used = 463_027_564_544_u64;
        let available = 13_268_070_400_u64;
        let total = 501_864_161_280_u64;
        let df_style = percentage(used, used.saturating_add(available));
        let physical_total_style = percentage(used, total);
        assert!((97.2..97.3).contains(&df_style));
        assert!(physical_total_style < df_style);
    }

    #[test]
    fn mounts_on_the_same_filesystem_are_not_double_counted() {
        assert!(measurable_filesystem("/dev/nvme0n1p2", "/", "ext4"));
        assert!(measurable_filesystem(
            "/dev/sda4",
            "/mnt/continental-cloud",
            "ext4"
        ));
        assert!(!measurable_filesystem(
            "/dev/loop0",
            "/snap/example/1",
            "squashfs"
        ));
        assert!(!measurable_filesystem("tmpfs", "/run", "tmpfs"));
    }

    #[test]
    fn growth_baseline_prefers_a_day_old_sample_and_falls_back_to_an_hour() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE filesystem_samples (
                sampled_at INTEGER NOT NULL,mount_key TEXT NOT NULL,mount_point TEXT NOT NULL,
                source TEXT NOT NULL,filesystem TEXT NOT NULL,total_bytes INTEGER NOT NULL,
                used_bytes INTEGER NOT NULL,available_bytes INTEGER NOT NULL,
                inode_total INTEGER NOT NULL,inode_used INTEGER NOT NULL,severity TEXT NOT NULL,
                PRIMARY KEY(sampled_at,mount_key));",
        )
        .unwrap();
        let now = 2_000_000_i64;
        for (key, timestamp, used) in [
            ("day", now - 86_400, 100),
            ("day", now - 3_600, 150),
            ("hour", now - 7_200, 200),
        ] {
            conn.execute(
                "INSERT INTO filesystem_samples VALUES (?1,?2,'/','dev','ext4',1000,?3,100,100,20,'ok')",
                params![timestamp, key, used],
            )
            .unwrap();
        }
        assert_eq!(
            growth_baseline(&conn, "day", now).unwrap(),
            Some((now - 86_400, 100))
        );
        assert_eq!(
            growth_baseline(&conn, "hour", now).unwrap(),
            Some((now - 7_200, 200))
        );
    }
}
