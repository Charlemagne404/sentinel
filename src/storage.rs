use crate::model::{
    HostSnapshot, Incident, ProcessLifecycleEvent, ProcessSnapshot, ServiceRestartEvent,
    ServiceSnapshot,
};
use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, backup::Backup, params};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
};

#[derive(Clone)]
pub struct Store {
    path: Arc<PathBuf>,
    connection: Arc<Mutex<Connection>>,
    history_degraded: Arc<AtomicBool>,
    last_metric_bucket: Arc<AtomicI64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseObjectSize {
    pub name: String,
    pub kind: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseFileSizes {
    pub main_bytes: u64,
    pub wal_bytes: u64,
    pub shm_bytes: u64,
    pub journal_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DatabaseCleanupReport {
    pub size_bytes: u64,
    pub budget_bytes: u64,
    pub pressure_stage: String,
    pub pressure_rows_pruned: u64,
    pub over_budget: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RawRetention {
    pub host_samples_oldest_at: Option<i64>,
    pub process_samples_oldest_at: Option<i64>,
    pub metric_points_oldest_at: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Baseline {
    pub metric: String,
    pub version: u32,
    pub samples: usize,
    pub first_timestamp: i64,
    pub observed_hours: f64,
    pub median: Option<f64>,
    pub mad: Option<f64>,
    pub ewma: Option<f64>,
    pub p95: Option<f64>,
    pub confidence: f64,
    pub frozen: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SeasonalValues {
    pub metric: String,
    pub pattern: String,
    pub periods: usize,
    pub first_timestamp: i64,
    pub last_timestamp: i64,
    pub median: f64,
    pub mad: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct NotificationRecord {
    pub id: i64,
    pub incident_id: Option<i64>,
    pub timestamp: i64,
    pub provider: String,
    pub status: String,
    pub detail: Option<String>,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create database directory {}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        if !path.exists() {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(3))?;
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "wal_autocheckpoint", 1000)?;
        conn.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS host_samples(ts INTEGER PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS latest_snapshot(id INTEGER PRIMARY KEY CHECK(id=1), ts INTEGER NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS metric_points(ts INTEGER NOT NULL, name TEXT NOT NULL, value REAL NOT NULL, PRIMARY KEY(ts,name)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS metric_points_lookup ON metric_points(name,ts);
            CREATE TABLE IF NOT EXISTS minute_points(ts INTEGER NOT NULL, name TEXT NOT NULL, value REAL NOT NULL, min_value REAL, max_value REAL, PRIMARY KEY(ts,name)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS minute_points_lookup ON minute_points(name,ts);
            CREATE TABLE IF NOT EXISTS quarter_points(ts INTEGER NOT NULL, name TEXT NOT NULL, value REAL NOT NULL, min_value REAL, max_value REAL, PRIMARY KEY(ts,name)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS quarter_points_lookup ON quarter_points(name,ts);
            CREATE TABLE IF NOT EXISTS process_samples(ts INTEGER NOT NULL, proc_key TEXT NOT NULL, pid INTEGER NOT NULL, ppid INTEGER NOT NULL, uid INTEGER NOT NULL, name TEXT NOT NULL, executable TEXT, state TEXT NOT NULL, start_ticks INTEGER NOT NULL, runtime_seconds INTEGER NOT NULL, cpu_percent REAL NOT NULL, rss_bytes INTEGER NOT NULL, virtual_bytes INTEGER NOT NULL, process_group INTEGER NOT NULL, session INTEGER NOT NULL, cgroup TEXT, workload TEXT NOT NULL, parent_disappeared INTEGER NOT NULL, PRIMARY KEY(ts,proc_key)) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS process_samples_key ON process_samples(proc_key,ts);
            CREATE TABLE IF NOT EXISTS process_lifecycle_events(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, proc_key TEXT NOT NULL, pid INTEGER NOT NULL, ppid INTEGER NOT NULL, uid INTEGER NOT NULL, name TEXT NOT NULL, executable TEXT, workload TEXT NOT NULL, cpu_percent REAL NOT NULL, rss_bytes INTEGER NOT NULL, runtime_seconds INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS process_lifecycle_events_ts ON process_lifecycle_events(ts DESC,id DESC);
            CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, signature TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, recovered_at INTEGER, confidence REAL NOT NULL, evidence TEXT NOT NULL, explanation TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS incidents_status_last ON incidents(status,last_seen DESC);
            CREATE UNIQUE INDEX IF NOT EXISTS active_incident_signature ON incidents(signature) WHERE status='active';
            CREATE TABLE IF NOT EXISTS anomalies(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, metric TEXT NOT NULL, value REAL NOT NULL, score REAL NOT NULL, reason TEXT NOT NULL, incident_id INTEGER REFERENCES incidents(id));
            CREATE INDEX IF NOT EXISTS anomalies_ts ON anomalies(ts DESC);
            CREATE TABLE IF NOT EXISTS baselines(metric TEXT PRIMARY KEY, version INTEGER NOT NULL DEFAULT 1, samples INTEGER NOT NULL, first_ts INTEGER NOT NULL, median REAL, mad REAL, ewma REAL, p95 REAL, confidence REAL NOT NULL, frozen INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS baseline_state(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, reset_at INTEGER NOT NULL);
            INSERT OR IGNORE INTO baseline_state(id,version,reset_at) VALUES(1,1,unixepoch());
            CREATE TABLE IF NOT EXISTS excluded_points(metric TEXT NOT NULL, ts INTEGER NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(metric,ts)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS accounts(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS bootstrap_tokens(token_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS workload_labels(workload TEXT PRIMARY KEY, display_name TEXT NOT NULL, labels_json TEXT NOT NULL DEFAULT '[]', updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS service_restart_state(unit TEXT PRIMARY KEY, restart_count INTEGER NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS notification_history(id INTEGER PRIMARY KEY, incident_id INTEGER, signature TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL, provider TEXT NOT NULL, status TEXT NOT NULL, detail TEXT);
            INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,unixepoch());
            COMMIT;")?;
        let has_signature: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('notification_history') WHERE name='signature')",
            [],
            |row| row.get(0),
        )?;
        if !has_signature {
            conn.execute(
                "ALTER TABLE notification_history ADD COLUMN signature TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        let has_baseline_version: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('baselines') WHERE name='version')",
            [],
            |row| row.get(0),
        )?;
        if !has_baseline_version {
            conn.execute(
                "ALTER TABLE baselines ADD COLUMN version INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        for (table, column) in [
            ("minute_points", "min_value"),
            ("minute_points", "max_value"),
            ("quarter_points", "min_value"),
            ("quarter_points", "max_value"),
        ] {
            let exists: bool = conn.query_row(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name='{column}')"
                ),
                [],
                |row| row.get(0),
            )?;
            if !exists {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} REAL"))?;
            }
        }
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(2,unixepoch()),(3,unixepoch()),(4,unixepoch()),(5,unixepoch())",
            [],
        )?;
        Ok(Self {
            path: Arc::new(path.to_path_buf()),
            connection: Arc::new(Mutex::new(conn)),
            history_degraded: Arc::new(AtomicBool::new(false)),
            last_metric_bucket: Arc::new(AtomicI64::new(i64::MIN)),
        })
    }

    fn lock(&self) -> anyhow::Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))
    }
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn health_readable(&self) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let _: i64 = conn.query_row("SELECT 1", [], |row| row.get(0))?;
        Ok(())
    }

    pub fn insert_snapshot(&self, snapshot: &HostSnapshot) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let payload = serde_json::to_string(snapshot)?;
        tx.execute(
            "INSERT INTO latest_snapshot(id,ts,payload) VALUES(1,?1,?2)
             ON CONFLICT(id) DO UPDATE SET ts=excluded.ts,payload=excluded.payload
             WHERE excluded.ts>=latest_snapshot.ts",
            params![snapshot.timestamp, payload],
        )?;
        let snapshot_minute = snapshot.timestamp.div_euclid(60) * 60;
        tx.execute(
            "INSERT OR REPLACE INTO host_samples(ts,payload) VALUES(?1,?2)",
            params![snapshot_minute, serde_json::to_string(snapshot)?],
        )?;
        let degraded = self.history_degraded.load(Ordering::Relaxed);
        let metric_bucket = snapshot.timestamp.div_euclid(30);
        let store_metrics = !degraded
            || self
                .last_metric_bucket
                .swap(metric_bucket, Ordering::Relaxed)
                != metric_bucket;
        if store_metrics {
            let metrics = snapshot.metrics();
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO metric_points(ts,name,value) VALUES(?1,?2,?3)",
            )?;
            for (name, value) in metrics {
                if value.is_finite() {
                    stmt.execute(params![snapshot.timestamp, name, value])?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn insert_named_metrics(
        &self,
        timestamp: i64,
        metrics: &[(String, f64)],
    ) -> anyhow::Result<()> {
        if self.history_degraded.load(Ordering::Relaxed) && timestamp.rem_euclid(300) >= 60 {
            return Ok(());
        }
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let mut statement = tx.prepare_cached(
            "INSERT OR REPLACE INTO metric_points(ts,name,value) VALUES(?1,?2,?3)",
        )?;
        for (name, value) in metrics {
            if known_metric(name) && value.is_finite() {
                statement.execute(params![timestamp, name, value])?;
            }
        }
        drop(statement);
        tx.commit()?;
        Ok(())
    }

    pub fn record_process_lifecycle(&self, events: &[ProcessLifecycleEvent]) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let mut statement = tx.prepare_cached("INSERT INTO process_lifecycle_events(ts,kind,proc_key,pid,ppid,uid,name,executable,workload,cpu_percent,rss_bytes,runtime_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")?;
        for event in events.iter().take(100) {
            statement.execute(params![
                event.timestamp,
                event.kind,
                event.key,
                event.pid as i64,
                event.ppid as i64,
                event.uid as i64,
                event.name,
                event.executable,
                event.workload,
                event.cpu_percent,
                to_sql_i64(event.rss_bytes),
                to_sql_i64(event.runtime_seconds),
            ])?;
        }
        drop(statement);
        tx.commit()?;
        Ok(())
    }

    pub fn process_lifecycle(
        &self,
        since: i64,
        limit: usize,
    ) -> anyhow::Result<Vec<ProcessLifecycleEvent>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare("SELECT ts,kind,proc_key,pid,ppid,uid,name,executable,workload,cpu_percent,rss_bytes,runtime_seconds FROM process_lifecycle_events WHERE ts>=? ORDER BY ts DESC,id DESC LIMIT ?")?;
        let rows = statement.query_map(params![since, limit.clamp(1, 1000) as i64], |row| {
            Ok(ProcessLifecycleEvent {
                timestamp: row.get(0)?,
                kind: row.get(1)?,
                key: row.get(2)?,
                pid: row.get::<_, i64>(3)?.max(0) as u32,
                ppid: row.get::<_, i64>(4)?.max(0) as u32,
                uid: row.get::<_, i64>(5)?.max(0) as u32,
                name: row.get(6)?,
                executable: row.get(7)?,
                workload: row.get(8)?,
                cpu_percent: row.get(9)?,
                rss_bytes: row.get::<_, i64>(10)?.max(0) as u64,
                runtime_seconds: row.get::<_, i64>(11)?.max(0) as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn save_processes(&self, ts: i64, processes: &[ProcessSnapshot]) -> anyhow::Result<()> {
        let mut selected = Vec::with_capacity(50);
        let mut by_cpu = processes.iter().collect::<Vec<_>>();
        by_cpu.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent));
        selected.extend(by_cpu.into_iter().take(25));
        let mut by_memory = processes.iter().collect::<Vec<_>>();
        by_memory.sort_by_key(|p| std::cmp::Reverse(p.rss_bytes));
        selected.extend(by_memory.into_iter().take(25));
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let mut stmt = tx.prepare_cached("INSERT OR REPLACE INTO process_samples(ts,proc_key,pid,ppid,uid,name,executable,state,start_ticks,runtime_seconds,cpu_percent,rss_bytes,virtual_bytes,process_group,session,cgroup,workload,parent_disappeared) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")?;
        let mut seen = std::collections::HashSet::new();
        for p in selected {
            if !seen.insert(p.key.as_str()) {
                continue;
            }
            stmt.execute(params![
                ts,
                p.key,
                p.pid as i64,
                p.ppid as i64,
                p.uid as i64,
                p.name,
                p.executable,
                p.state,
                to_sql_i64(p.start_ticks),
                to_sql_i64(p.runtime_seconds),
                p.cpu_percent,
                to_sql_i64(p.rss_bytes),
                to_sql_i64(p.virtual_bytes),
                p.process_group,
                p.session,
                p.cgroup,
                p.workload,
                p.parent_disappeared as i32
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    pub fn observe_service_restarts(
        &self,
        services: &[ServiceSnapshot],
        now: i64,
    ) -> anyhow::Result<Vec<ServiceRestartEvent>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let mut events = Vec::new();
        for service in services.iter().take(500) {
            let previous: Option<i64> = tx
                .query_row(
                    "SELECT restart_count FROM service_restart_state WHERE unit=?1",
                    [service.name.as_str()],
                    |row| row.get(0),
                )
                .optional()?;
            let current = service.restart_count.min(i64::MAX as u64) as i64;
            if let Some(previous) = previous {
                if current > previous {
                    events.push(ServiceRestartEvent {
                        unit: service.name.clone(),
                        previous_count: previous.max(0) as u64,
                        current_count: current as u64,
                    });
                }
            }
            tx.execute(
                "INSERT INTO service_restart_state(unit,restart_count,updated_at) VALUES(?1,?2,?3) ON CONFLICT(unit) DO UPDATE SET restart_count=excluded.restart_count,updated_at=excluded.updated_at",
                params![service.name, current, now],
            )?;
        }
        tx.commit()?;
        Ok(events)
    }

    pub fn latest_snapshot(&self) -> anyhow::Result<Option<HostSnapshot>> {
        let conn = self.lock()?;
        let raw: Option<String> = conn
            .query_row("SELECT payload FROM latest_snapshot WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        let raw = match raw {
            Some(raw) => Some(raw),
            None => conn
                .query_row(
                    "SELECT payload FROM host_samples ORDER BY ts DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?,
        };
        raw.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }

    pub fn process_history(
        &self,
        key: &str,
        since: i64,
        limit: usize,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let conn = self.lock()?;
        let mut stmt=conn.prepare("SELECT ts,cpu_percent,rss_bytes,ppid,workload,parent_disappeared FROM process_samples WHERE proc_key=? AND ts>=? ORDER BY ts DESC LIMIT ?")?;
        let rows=stmt.query_map(params![key,since,limit.clamp(1,2000) as i64],|r| Ok(serde_json::json!({"timestamp":r.get::<_,i64>(0)?,"cpu_percent":r.get::<_,f64>(1)?,"rss_bytes":r.get::<_,i64>(2)? as u64,"ppid":r.get::<_,i64>(3)? as u32,"workload":r.get::<_,String>(4)?,"parent_disappeared":r.get::<_,i32>(5)?!=0})))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn chart(
        &self,
        metric: &str,
        since: i64,
        max_points: usize,
    ) -> anyhow::Result<Vec<[f64; 4]>> {
        let max_points = max_points.max(1);
        if !known_metric(metric) {
            anyhow::bail!("unknown metric");
        }
        let conn = self.lock()?;
        let count: i64 = conn.query_row(
            "SELECT count(*) FROM metric_points WHERE name=? AND ts>=?",
            params![metric, since],
            |r| r.get(0),
        )?;
        let now = unix_now();
        let table = if since < now - 30 * 86400 {
            "quarter_points"
        } else if since < now - 48 * 3600 || count as usize > max_points {
            "minute_points"
        } else {
            "metric_points"
        };
        let group_seconds =
            if table == "minute_points" && count as usize > max_points.saturating_mul(10) {
                900
            } else if table == "minute_points" {
                60
            } else {
                0
            };
        let sql = if group_seconds > 0 {
            format!(
                "SELECT CAST(ts/{group_seconds} AS INTEGER)*{group_seconds},avg(value),min(COALESCE(min_value,value)),max(COALESCE(max_value,value)) FROM {table} WHERE name=? AND ts>=? GROUP BY 1 ORDER BY 1"
            )
        } else if table == "metric_points" {
            format!("SELECT ts,value,value,value FROM {table} WHERE name=? AND ts>=? ORDER BY ts")
        } else {
            format!(
                "SELECT ts,value,COALESCE(min_value,value),COALESCE(max_value,value) FROM {table} WHERE name=? AND ts>=? ORDER BY ts"
            )
        };
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![metric, since], |r| {
            Ok([
                r.get::<_, i64>(0)? as f64,
                r.get::<_, f64>(1)?,
                r.get::<_, f64>(2)?,
                r.get::<_, f64>(3)?,
            ])
        })?;
        let mut values = rows.collect::<Result<Vec<_>, _>>()?;
        if values.len() > max_points {
            let stride = (values.len() + max_points - 1) / max_points;
            values = values
                .chunks(stride)
                .map(|chunk| {
                    let last = chunk.last().copied().unwrap_or([0.0; 4]);
                    [
                        last[0],
                        last[1],
                        chunk
                            .iter()
                            .map(|point| point[2])
                            .fold(f64::INFINITY, f64::min),
                        chunk
                            .iter()
                            .map(|point| point[3])
                            .fold(f64::NEG_INFINITY, f64::max),
                    ]
                })
                .collect();
        }
        Ok(values)
    }

    #[cfg(test)]
    pub fn baseline_values(
        &self,
        metric: &str,
        since: i64,
        limit: usize,
    ) -> anyhow::Result<Vec<f64>> {
        Ok(self
            .baseline_observations(metric, since, limit)?
            .into_iter()
            .map(|(_, value)| value)
            .collect())
    }

    #[cfg(test)]
    pub(crate) fn seed_minute_points_for_test(
        &self,
        points: &[(i64, &str, f64)],
    ) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        for (timestamp, metric, value) in points {
            tx.execute(
                "INSERT INTO minute_points(ts,name,value) VALUES(?,?,?)",
                params![timestamp, metric, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn baseline_observations(
        &self,
        metric: &str,
        since: i64,
        limit: usize,
    ) -> anyhow::Result<Vec<(i64, f64)>> {
        if !known_metric(metric) {
            anyhow::bail!("unknown metric");
        }
        let conn = self.lock()?;
        let mut stmt=conn.prepare("SELECT m.ts,m.value FROM minute_points m WHERE m.name=? AND m.ts>=? AND NOT EXISTS(SELECT 1 FROM excluded_points e WHERE e.metric=m.name AND e.ts=m.ts) ORDER BY m.ts DESC LIMIT ?")?;
        let values = stmt
            .query_map(params![metric, since, limit.clamp(1, 10000) as i64], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<Result<Vec<(i64, f64)>, _>>()?;
        Ok(values.into_iter().rev().collect())
    }

    /// Return a mature same-hour seasonal comparison. Hour-of-week models need
    /// four clean weekly repetitions; hour-of-day models need fourteen distinct
    /// daily windows. Incomplete patterns are deliberately not used for scoring.
    pub fn seasonal_values(
        &self,
        metric: &str,
        since: i64,
        now: i64,
    ) -> anyhow::Result<Option<SeasonalValues>> {
        if !known_metric(metric) {
            anyhow::bail!("unknown metric");
        }
        let conn = self.lock()?;
        let since = since.max(now - 30 * 86400);
        let current_hour = now.div_euclid(3600);
        let weekday_hour = current_hour.saturating_add(72).rem_euclid(168);
        let current_week_start = (now + 259200).div_euclid(604800) * 604800 - 259200;
        let mut weekly = conn.prepare(
            "SELECT min(m.ts),avg(m.value),max(m.ts),count(*) FROM minute_points m
             WHERE m.name=?1 AND m.ts>=?2 AND m.ts<?3
               AND ((m.ts/3600 + 72) % 168)=?4
               AND NOT EXISTS(SELECT 1 FROM excluded_points e WHERE e.metric=m.name AND e.ts=m.ts)
             GROUP BY CAST((m.ts + 259200)/604800 AS INTEGER) HAVING count(*)>=30 ORDER BY 1",
        )?;
        let weekly_rows = weekly
            .query_map(
                params![metric, since, current_week_start, weekday_hour],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        if weekly_rows.len() >= 4
            && weekly_rows
                .last()
                .unwrap()
                .2
                .saturating_sub(weekly_rows[0].0)
                >= 21 * 86400
        {
            let periods = weekly_rows.len();
            let values = weekly_rows.iter().map(|row| row.1).collect::<Vec<_>>();
            let (median, mad) = robust_summary(&values);
            return Ok(Some(SeasonalValues {
                metric: metric.into(),
                pattern: "hour_of_week_utc".into(),
                periods,
                first_timestamp: weekly_rows[0].0,
                last_timestamp: weekly_rows.last().unwrap().2,
                median,
                mad,
                confidence: (periods as f64 / 4.0).clamp(0.0, 1.0),
            }));
        }

        let current_day_start = now.div_euclid(86400) * 86400;
        let hour_of_day = current_hour.rem_euclid(24);
        let mut daily = conn.prepare(
            "SELECT min(m.ts),avg(m.value),max(m.ts),count(*) FROM minute_points m
             WHERE m.name=?1 AND m.ts>=?2 AND m.ts<?3
               AND (m.ts/3600 % 24)=?4
               AND NOT EXISTS(SELECT 1 FROM excluded_points e WHERE e.metric=m.name AND e.ts=m.ts)
             GROUP BY CAST(m.ts/86400 AS INTEGER) HAVING count(*)>=30 ORDER BY 1",
        )?;
        let daily_rows = daily
            .query_map(
                params![metric, since, current_day_start, hour_of_day],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        if daily_rows.len() >= 14
            && daily_rows.last().unwrap().2.saturating_sub(daily_rows[0].0) >= 13 * 86400
        {
            let periods = daily_rows.len();
            let values = daily_rows.iter().map(|row| row.1).collect::<Vec<_>>();
            let (median, mad) = robust_summary(&values);
            return Ok(Some(SeasonalValues {
                metric: metric.into(),
                pattern: "hour_of_day_utc".into(),
                periods,
                first_timestamp: daily_rows[0].0,
                last_timestamp: daily_rows.last().unwrap().2,
                median,
                mad,
                confidence: (periods as f64 / 28.0).clamp(0.0, 1.0),
            }));
        }
        Ok(None)
    }

    pub fn baseline_state(&self) -> anyhow::Result<(u32, i64)> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT version,reset_at FROM baseline_state WHERE id=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?.max(1) as u32, row.get(1)?)),
        )
        .map_err(Into::into)
    }

    pub fn reset_baselines(&self, now: i64) -> anyhow::Result<(u32, i64)> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM baselines", [])?;
        tx.execute(
            "UPDATE baseline_state SET version=version+1,reset_at=?1 WHERE id=1",
            [now],
        )?;
        let state = tx.query_row(
            "SELECT version,reset_at FROM baseline_state WHERE id=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?.max(1) as u32, row.get(1)?)),
        )?;
        tx.commit()?;
        Ok(state)
    }

    pub fn save_baseline(&self, b: &Baseline, first_ts: i64) -> anyhow::Result<()> {
        self.lock()?.execute("INSERT INTO baselines(metric,version,samples,first_ts,median,mad,ewma,p95,confidence,frozen,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(metric) DO UPDATE SET version=excluded.version,samples=excluded.samples,first_ts=excluded.first_ts,median=excluded.median,mad=excluded.mad,ewma=excluded.ewma,p95=excluded.p95,confidence=excluded.confidence,frozen=excluded.frozen,updated_at=excluded.updated_at",params![b.metric,b.version as i64,b.samples as i64,first_ts,b.median,b.mad,b.ewma,b.p95,b.confidence,b.frozen as i32,b.updated_at])?;
        Ok(())
    }

    pub fn baselines(&self) -> anyhow::Result<Vec<Baseline>> {
        let conn = self.lock()?;
        let mut stmt=conn.prepare("SELECT metric,version,samples,first_ts,median,mad,ewma,p95,confidence,frozen,updated_at FROM baselines ORDER BY metric")?;
        let now = unix_now();
        let rows = stmt.query_map([], |r| {
            let first: i64 = r.get(3)?;
            Ok(Baseline {
                metric: r.get(0)?,
                version: r.get::<_, i64>(1)?.max(1) as u32,
                samples: r.get::<_, i64>(2)? as usize,
                first_timestamp: first,
                observed_hours: ((now - first).max(0) as f64) / 3600.0,
                median: r.get(4)?,
                mad: r.get(5)?,
                ewma: r.get(6)?,
                p95: r.get(7)?,
                confidence: r.get(8)?,
                frozen: r.get::<_, i32>(9)? != 0,
                updated_at: r.get(10)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn append_anomaly(
        &self,
        ts: i64,
        metric: &str,
        value: f64,
        score: f64,
        reason: &str,
        incident_id: Option<i64>,
    ) -> anyhow::Result<()> {
        self.lock()?.execute(
            "INSERT INTO anomalies(ts,metric,value,score,reason,incident_id) VALUES(?,?,?,?,?,?)",
            params![ts, metric, value, score, reason, incident_id],
        )?;
        Ok(())
    }
    pub fn exclude_baseline_point(
        &self,
        metric: &str,
        ts: i64,
        reason: &str,
    ) -> anyhow::Result<()> {
        self.lock()?.execute(
            "INSERT OR IGNORE INTO excluded_points(metric,ts,reason) VALUES(?,?,?)",
            params![metric, ts, reason],
        )?;
        Ok(())
    }

    pub fn open_or_update_incident(
        &self,
        signature: &str,
        severity: &str,
        title: &str,
        confidence: f64,
        evidence: &serde_json::Value,
        explanation: &str,
        now: i64,
    ) -> anyhow::Result<(i64, bool, bool)> {
        let conn = self.lock()?;
        let encoded = serde_json::to_string(evidence)?;
        if let Some((id, previous_severity)) = conn
            .query_row(
                "SELECT id,severity FROM incidents WHERE signature=? AND status='active'",
                [signature],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
        {
            let escalated = Self::incident_severity_rank(severity)
                > Self::incident_severity_rank(&previous_severity);
            let effective_severity = if escalated {
                severity
            } else {
                &previous_severity
            };
            conn.execute("UPDATE incidents SET severity=?2,title=?3,last_seen=?4,confidence=max(confidence,?5),evidence=?6,explanation=?7 WHERE id=?1",params![id,effective_severity,title,now,confidence,encoded,explanation])?;
            Ok((id, false, escalated))
        } else {
            conn.execute("INSERT INTO incidents(signature,severity,title,status,first_seen,last_seen,confidence,evidence,explanation) VALUES(?,?,?,'active',?,?,?,?,?)",params![signature,severity,title,now,now,confidence,encoded,explanation])?;
            Ok((conn.last_insert_rowid(), true, false))
        }
    }

    fn incident_severity_rank(severity: &str) -> u8 {
        match severity {
            "critical" => 3,
            "warning" => 2,
            "informational" => 1,
            _ => 0,
        }
    }

    pub fn recover_incident(&self, signature: &str, now: i64) -> anyhow::Result<bool> {
        Ok(self.lock()?.execute("UPDATE incidents SET status='recovered',recovered_at=?2,last_seen=?2 WHERE signature=?1 AND status='active'",params![signature,now])? > 0)
    }

    pub fn incidents(&self, active_only: bool, limit: usize) -> anyhow::Result<Vec<Incident>> {
        let conn = self.lock()?;
        let sql = if active_only {
            "SELECT id,signature,severity,title,status,first_seen,last_seen,recovered_at,confidence,evidence,explanation FROM incidents WHERE status='active' ORDER BY last_seen DESC LIMIT ?"
        } else {
            "SELECT id,signature,severity,title,status,first_seen,last_seen,recovered_at,confidence,evidence,explanation FROM incidents ORDER BY last_seen DESC LIMIT ?"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([limit.clamp(1, 500) as i64], |r| {
            let raw: String = r.get(9)?;
            Ok(Incident {
                id: r.get(0)?,
                signature: r.get(1)?,
                severity: r.get(2)?,
                title: r.get(3)?,
                status: r.get(4)?,
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
                recovered_at: r.get(7)?,
                confidence: r.get(8)?,
                evidence: serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null),
                explanation: r.get(10)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn log_notification(
        &self,
        incident_id: Option<i64>,
        signature: &str,
        timestamp: i64,
        provider: &str,
        status: &str,
        detail: Option<&str>,
    ) -> anyhow::Result<()> {
        self.lock()?.execute(
            "INSERT INTO notification_history(incident_id,signature,ts,provider,status,detail) VALUES(?,?,?,?,?,?)",
            params![incident_id, signature, timestamp, provider, status, detail],
        )?;
        Ok(())
    }

    pub fn notifications(&self, limit: usize) -> anyhow::Result<Vec<NotificationRecord>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT id,incident_id,ts,provider,status,detail FROM notification_history ORDER BY ts DESC,id DESC LIMIT ?",
        )?;
        let rows = statement.query_map([limit.clamp(1, 250) as i64], |row| {
            Ok(NotificationRecord {
                id: row.get(0)?,
                incident_id: row.get(1)?,
                timestamp: row.get(2)?,
                provider: row.get(3)?,
                status: row.get(4)?,
                detail: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn last_notification_at(&self, signature: &str) -> anyhow::Result<Option<i64>> {
        self.lock()?
            .query_row(
                "SELECT max(ts) FROM notification_history WHERE signature=? AND status='sent'",
                [signature],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub fn anomalies(&self, since: i64, limit: usize) -> anyhow::Result<Vec<serde_json::Value>> {
        let conn = self.lock()?;
        let mut stmt=conn.prepare("SELECT ts,metric,value,score,reason,incident_id FROM anomalies WHERE ts>=? ORDER BY ts DESC LIMIT ?")?;
        let rows=stmt.query_map(params![since,limit.clamp(1,1000) as i64],|r|Ok(serde_json::json!({"timestamp":r.get::<_,i64>(0)?,"metric":r.get::<_,String>(1)?,"value":r.get::<_,f64>(2)?,"score":r.get::<_,f64>(3)?,"reason":r.get::<_,String>(4)?,"incident_id":r.get::<_,Option<i64>>(5)?})))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn aggregate_until(&self, now: i64) -> anyhow::Result<()> {
        let bucket = now.div_euclid(60) * 60;
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("INSERT OR REPLACE INTO minute_points(ts,name,value,min_value,max_value) SELECT CAST(ts/60 AS INTEGER)*60,name,avg(value),min(value),max(value) FROM metric_points WHERE ts>=? AND ts<? GROUP BY CAST(ts/60 AS INTEGER),name",params![bucket-60,bucket])?;
        if bucket.rem_euclid(900) == 0 {
            tx.execute("INSERT OR REPLACE INTO quarter_points(ts,name,value,min_value,max_value) SELECT CAST(ts/900 AS INTEGER)*900,name,avg(value),min(COALESCE(min_value,value)),max(COALESCE(max_value,value)) FROM minute_points WHERE name IN ('cpu','memory_used_percent','memory_available_percent','swap_used_percent','load_1m','cpu_pressure','memory_pressure','io_pressure','disk_used_percent','cpu_temperature_c') AND ts>=? AND ts<? GROUP BY CAST(ts/900 AS INTEGER),name",params![bucket-900,bucket])?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn cleanup(
        &self,
        now: i64,
        raw_hours: u64,
        budget_mb: u64,
    ) -> anyhow::Result<DatabaseCleanupReport> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        let process_history_hours = raw_hours.min(24);
        tx.execute(
            "DELETE FROM host_samples WHERE ts<?",
            [now - (raw_hours as i64 * 3600)],
        )?;
        tx.execute(
            "DELETE FROM metric_points WHERE ts<?",
            [now - (raw_hours as i64 * 3600)],
        )?;
        tx.execute(
            "DELETE FROM process_samples WHERE ts<?",
            [now - (process_history_hours as i64 * 3600)],
        )?;
        tx.execute(
            "DELETE FROM process_lifecycle_events WHERE ts<?",
            [now - 7 * 86400],
        )?;
        tx.execute(
            "DELETE FROM minute_points WHERE ts<? AND name NOT IN ('cpu','memory_used_percent','memory_available_percent','swap_used_percent','load_1m','cpu_pressure','memory_pressure','io_pressure','disk_used_percent','cpu_temperature_c')",
            [now - 7 * 86400],
        )?;
        tx.execute(
            "DELETE FROM minute_points WHERE name LIKE 'workload::%' AND ts<?",
            [now - 2 * 86400],
        )?;
        tx.execute(
            "DELETE FROM minute_points WHERE name IN ('cpu','memory_used_percent','memory_available_percent','swap_used_percent','load_1m','cpu_pressure','memory_pressure','io_pressure','disk_used_percent','cpu_temperature_c') AND ts<?",
            [now - 14 * 86400],
        )?;
        tx.execute("DELETE FROM quarter_points WHERE ts<?", [now - 180 * 86400])?;
        tx.execute(
            "DELETE FROM incidents WHERE status='recovered' AND recovered_at<?",
            [now - 365 * 86400],
        )?;
        tx.execute("DELETE FROM anomalies WHERE ts<?", [now - 30 * 86400])?;
        tx.execute("DELETE FROM excluded_points WHERE ts<?", [now - 30 * 86400])?;
        tx.execute(
            "DELETE FROM notification_history WHERE ts<?",
            [now - 365 * 86400],
        )?;
        tx.execute(
            "DELETE FROM baselines WHERE metric LIKE 'workload::%' AND updated_at<?",
            [now - 30 * 86400],
        )?;
        tx.execute("DELETE FROM sessions WHERE expires_at<?", [now])?;
        tx.commit()?;
        if let Err(error) = checkpoint_wal(&conn, "PASSIVE", false) {
            tracing::warn!(error=%error,"SQLite passive WAL checkpoint failed during retention");
        }
        let budget = budget_mb.saturating_mul(1024 * 1024);
        let mut bytes = self.database_size_bytes();
        let mut pressure_stage = "normal";
        let mut rows_pruned = 0_u64;

        // Start shedding lower-value detail before the hard budget is reached.
        // Incident rows and their evidence are never included in these deletes.
        if bytes.saturating_mul(100) > budget.saturating_mul(90) {
            pressure_stage = "process-history-12h";
            rows_pruned += delete_batch_before(
                &conn,
                "process_samples",
                "ts,proc_key",
                "ts<?1",
                "ts,proc_key",
                now - (process_history_hours.min(12) as i64 * 3600),
            )?;
            reclaim_pages(&conn, 512)?;
            bytes = self.database_size_bytes();
        }

        if bytes.saturating_mul(100) > budget.saturating_mul(95) {
            pressure_stage = "compact-history";
            rows_pruned += delete_batch_before(
                &conn,
                "process_samples",
                "ts,proc_key",
                "ts<?1",
                "ts,proc_key",
                now - (process_history_hours.min(6) as i64 * 3600),
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "minute_points",
                "ts,name",
                "name LIKE 'workload::%' AND ts<?1",
                "ts,name",
                now - 48 * 3600,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "minute_points",
                "ts,name",
                "ts<?1 AND name NOT IN ('cpu','memory_used_percent','memory_available_percent','swap_used_percent','load_1m','cpu_pressure','memory_pressure','io_pressure','disk_used_percent','cpu_temperature_c')",
                "ts,name",
                now - 5 * 86400,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "quarter_points",
                "ts,name",
                "ts<?1",
                "ts,name",
                now - 90 * 86400,
            )?;
            reclaim_pages(&conn, 1024)?;
            bytes = self.database_size_bytes();
        }

        if bytes > budget {
            pressure_stage = "recent-metrics-only";
            let raw_cutoff = now - (raw_hours.min(6) as i64 * 3600);
            rows_pruned += delete_batch_before(
                &conn,
                "process_samples",
                "ts,proc_key",
                "ts<?1",
                "ts,proc_key",
                raw_cutoff,
            )?;
            rows_pruned +=
                delete_batch_before(&conn, "host_samples", "ts", "ts<?1", "ts", raw_cutoff)?;
            rows_pruned += delete_batch_before(
                &conn,
                "metric_points",
                "ts,name",
                "ts<?1",
                "ts,name",
                raw_cutoff,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "process_lifecycle_events",
                "id",
                "ts<?1",
                "ts,id",
                now - 24 * 3600,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "minute_points",
                "ts,name",
                "ts<?1 AND name IN ('cpu','memory_used_percent','memory_available_percent','swap_used_percent','load_1m','cpu_pressure','memory_pressure','io_pressure','disk_used_percent','cpu_temperature_c')",
                "ts,name",
                now - 7 * 86400,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "minute_points",
                "ts,name",
                "ts<?1 AND name NOT IN ('cpu','memory_used_percent','memory_available_percent','swap_used_percent','load_1m','cpu_pressure','memory_pressure','io_pressure','disk_used_percent','cpu_temperature_c')",
                "ts,name",
                now - 48 * 3600,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "quarter_points",
                "ts,name",
                "ts<?1",
                "ts,name",
                now - 60 * 86400,
            )?;
            reclaim_pages(&conn, 2048)?;
            bytes = self.database_size_bytes();
        }

        if bytes > budget {
            pressure_stage = "minimum-history";
            let raw_cutoff = now - 3600;
            rows_pruned += delete_batch_before(
                &conn,
                "process_samples",
                "ts,proc_key",
                "ts<?1",
                "ts,proc_key",
                raw_cutoff,
            )?;
            rows_pruned +=
                delete_batch_before(&conn, "host_samples", "ts", "ts<?1", "ts", raw_cutoff)?;
            rows_pruned += delete_batch_before(
                &conn,
                "metric_points",
                "ts,name",
                "ts<?1",
                "ts,name",
                raw_cutoff,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "process_lifecycle_events",
                "id",
                "ts<?1",
                "ts,id",
                now - 6 * 3600,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "minute_points",
                "ts,name",
                "ts<?1",
                "ts,name",
                now - 24 * 3600,
            )?;
            rows_pruned += delete_batch_before(
                &conn,
                "quarter_points",
                "ts,name",
                "ts<?1",
                "ts,name",
                now - 30 * 86400,
            )?;
            rows_pruned +=
                delete_batch_before(&conn, "anomalies", "id", "ts<?1", "ts,id", now - 7 * 86400)?;
            reclaim_pages(&conn, 4096)?;
            bytes = self.database_size_bytes();
        }

        let over_budget = bytes > budget;
        let degraded = bytes.saturating_mul(100) > budget.saturating_mul(85);
        let should_recover = bytes.saturating_mul(100) < budget.saturating_mul(75);
        if degraded {
            self.history_degraded.store(true, Ordering::Relaxed);
        } else if should_recover {
            self.history_degraded.store(false, Ordering::Relaxed);
        }
        Ok(DatabaseCleanupReport {
            size_bytes: bytes,
            budget_bytes: budget,
            pressure_stage: pressure_stage.into(),
            pressure_rows_pruned: rows_pruned,
            over_budget,
        })
    }

    pub fn history_degraded(&self) -> bool {
        self.history_degraded.load(Ordering::Relaxed)
    }

    pub fn raw_retention(&self) -> anyhow::Result<RawRetention> {
        let conn = self.lock()?;
        let oldest = |sql: &str| -> anyhow::Result<Option<i64>> {
            conn.query_row(sql, [], |row| row.get(0))
                .map_err(Into::into)
        };
        Ok(RawRetention {
            host_samples_oldest_at: oldest("SELECT min(ts) FROM host_samples")?,
            process_samples_oldest_at: oldest("SELECT min(ts) FROM process_samples")?,
            metric_points_oldest_at: oldest("SELECT min(ts) FROM metric_points")?,
        })
    }

    pub fn integrity_check(&self) -> anyhow::Result<String> {
        Ok(self
            .lock()?
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?)
    }

    pub fn checkpoint(&self) -> anyhow::Result<()> {
        let connection = self.lock()?;
        checkpoint_wal(&connection, "TRUNCATE", true)
    }
    pub fn count(&self, table: &str) -> anyhow::Result<i64> {
        let sql = match table {
            "host_samples" => "SELECT count(*) FROM host_samples",
            "incidents" => "SELECT count(*) FROM incidents",
            "process_samples" => "SELECT count(*) FROM process_samples",
            "process_lifecycle_events" => "SELECT count(*) FROM process_lifecycle_events",
            _ => anyhow::bail!("unsupported table"),
        };
        Ok(self.lock()?.query_row(sql, [], |r| r.get(0))?)
    }
    pub fn database_size_bytes(&self) -> u64 {
        self.database_file_sizes().total_bytes
    }

    pub fn database_file_sizes(&self) -> DatabaseFileSizes {
        let size_for = |suffix: &str| {
            let mut sidecar = self.path().as_os_str().to_os_string();
            if !suffix.is_empty() {
                sidecar.push(suffix);
            }
            std::fs::metadata(PathBuf::from(sidecar))
                .map(|metadata| metadata.len())
                .unwrap_or(0)
        };
        let main_bytes = size_for("");
        let wal_bytes = size_for("-wal");
        let shm_bytes = size_for("-shm");
        let journal_bytes = size_for("-journal");
        DatabaseFileSizes {
            main_bytes,
            wal_bytes,
            shm_bytes,
            journal_bytes,
            total_bytes: main_bytes
                .saturating_add(wal_bytes)
                .saturating_add(shm_bytes)
                .saturating_add(journal_bytes),
        }
    }

    pub fn database_object_sizes(&self) -> anyhow::Result<Vec<DatabaseObjectSize>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare(
            "SELECT schema.name,schema.type,coalesce(sum(stat.pgsize),0)
             FROM sqlite_schema AS schema LEFT JOIN dbstat AS stat ON stat.name=schema.name
             WHERE schema.type IN ('table','index')
             GROUP BY schema.name,schema.type ORDER BY sum(stat.pgsize) DESC,schema.name",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(DatabaseObjectSize {
                name: row.get(0)?,
                kind: row.get(1)?,
                bytes: row.get::<_, i64>(2)?.max(0) as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn account_hash(&self, username: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT password_hash FROM accounts WHERE username=?",
                [username],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn has_account(&self) -> anyhow::Result<bool> {
        Ok(self
            .lock()?
            .query_row("SELECT EXISTS(SELECT 1 FROM accounts)", [], |r| {
                r.get::<_, i32>(0)
            })?
            != 0)
    }
    pub fn register_bootstrap_token(&self, token_hash: &str, now: i64) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM bootstrap_tokens WHERE created_at<?",
            [now - 1800],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO bootstrap_tokens(token_hash,created_at) VALUES(?,?)",
            params![token_hash, now],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn bootstrap_token_valid(&self, token_hash: &str, now: i64) -> anyhow::Result<bool> {
        Ok(self.lock()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM bootstrap_tokens WHERE token_hash=? AND created_at>=?)",
            params![token_hash, now - 1800],
            |r| r.get::<_, i32>(0),
        )? != 0)
    }
    pub fn create_admin_once(
        &self,
        token_hash: &str,
        password_hash: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let valid: i32 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM bootstrap_tokens WHERE token_hash=? AND created_at>=?)",
            params![token_hash, now - 1800],
            |r| r.get(0),
        )?;
        let has_user: i32 =
            tx.query_row("SELECT EXISTS(SELECT 1 FROM accounts)", [], |r| r.get(0))?;
        if valid == 0 || has_user != 0 {
            tx.rollback()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO accounts(username,password_hash,created_at) VALUES('admin',?,?)",
            params![password_hash, now],
        )?;
        tx.execute("DELETE FROM bootstrap_tokens", [])?;
        tx.commit()?;
        Ok(true)
    }
    pub fn create_session(
        &self,
        token_hash: &str,
        csrf: &str,
        created: i64,
        expires: i64,
    ) -> anyhow::Result<()> {
        self.lock()?.execute(
            "INSERT INTO sessions(token_hash,csrf,created_at,expires_at) VALUES(?,?,?,?)",
            params![token_hash, csrf, created, expires],
        )?;
        Ok(())
    }
    pub fn session(&self, token_hash: &str, now: i64) -> anyhow::Result<Option<(String, i64)>> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT csrf,expires_at FROM sessions WHERE token_hash=? AND expires_at>?",
                params![token_hash, now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }
    pub fn delete_session(&self, token_hash: &str) -> anyhow::Result<()> {
        self.lock()?
            .execute("DELETE FROM sessions WHERE token_hash=?", [token_hash])?;
        Ok(())
    }
    pub fn reset_admin_account(&self) -> anyhow::Result<()> {
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM sessions", [])?;
        tx.execute("DELETE FROM accounts", [])?;
        tx.execute("DELETE FROM bootstrap_tokens", [])?;
        tx.commit()?;
        Ok(())
    }
    pub fn save_workload_label(
        &self,
        workload: &str,
        display_name: &str,
        labels: Vec<String>,
    ) -> anyhow::Result<()> {
        let encoded = serde_json::to_string(
            &labels
                .into_iter()
                .filter(|s| s.len() <= 64)
                .take(20)
                .collect::<Vec<_>>(),
        )?;
        self.lock()?.execute("INSERT INTO workload_labels(workload,display_name,labels_json,updated_at) VALUES(?,?,?,?) ON CONFLICT(workload) DO UPDATE SET display_name=excluded.display_name,labels_json=excluded.labels_json,updated_at=excluded.updated_at",params![workload,display_name,encoded,unix_now()])?;
        Ok(())
    }
    pub fn workload_labels(&self) -> anyhow::Result<HashMap<String, (String, Vec<String>)>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT workload,display_name,labels_json FROM workload_labels")?;
        let rows = stmt.query_map([], |r| {
            let labels: String = r.get(2)?;
            Ok((
                r.get::<_, String>(0)?,
                (
                    r.get::<_, String>(1)?,
                    serde_json::from_str(&labels).unwrap_or_default(),
                ),
            ))
        })?;
        Ok(rows.collect::<Result<HashMap<_, _>, _>>()?)
    }
    pub fn backup(&self, destination: &Path) -> anyhow::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        if destination.exists() {
            anyhow::bail!(
                "backup destination already exists: {}",
                destination.display()
            );
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut temp = destination.as_os_str().to_os_string();
        temp.push(".tmp");
        let temp = PathBuf::from(temp);
        let temp_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        drop(temp_file);
        let source = self.lock()?;
        let mut target = Connection::open(&temp)?;
        let backup = Backup::new(&source, &mut target)?;
        backup.run_to_completion(64, std::time::Duration::from_millis(20), None)?;
        drop(backup);
        drop(target);
        drop(source);
        std::fs::rename(&temp, destination)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

const PRESSURE_PRUNE_BATCH: usize = 20_000;

/// Pressure pruning is deliberately split into deterministic oldest-first batches.
/// Table and predicate fragments are internal constants at every call site.
fn delete_batch_before(
    connection: &Connection,
    table: &str,
    key: &str,
    predicate: &str,
    order_by: &str,
    cutoff: i64,
) -> anyhow::Result<u64> {
    let delete_key = if key.contains(',') {
        format!("({key})")
    } else {
        key.to_string()
    };
    let sql = format!(
        "DELETE FROM {table} WHERE {delete_key} IN (SELECT {key} FROM {table} WHERE {predicate} ORDER BY {order_by} LIMIT ?2)"
    );
    Ok(connection.execute(&sql, params![cutoff, PRESSURE_PRUNE_BATCH as i64])? as u64)
}

fn checkpoint_wal(
    connection: &Connection,
    mode: &str,
    require_complete: bool,
) -> anyhow::Result<()> {
    let sql = format!("PRAGMA wal_checkpoint({mode})");
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
        connection.query_row(&sql, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    let incomplete = busy != 0
        || (log_frames >= 0 && checkpointed_frames >= 0 && checkpointed_frames < log_frames);
    if incomplete {
        if require_complete {
            anyhow::bail!(
                "SQLite WAL checkpoint incomplete: busy={busy}, log_frames={log_frames}, checkpointed_frames={checkpointed_frames}"
            );
        }
        tracing::warn!(
            busy,
            log_frames,
            checkpointed_frames,
            "SQLite WAL checkpoint did not process every frame"
        );
    }
    Ok(())
}

fn reclaim_pages(connection: &Connection, vacuum_pages: u64) -> anyhow::Result<()> {
    checkpoint_wal(connection, "TRUNCATE", false)?;
    connection.execute_batch(&format!(
        "PRAGMA incremental_vacuum({})",
        vacuum_pages.min(i64::MAX as u64)
    ))?;
    checkpoint_wal(connection, "TRUNCATE", false)?;
    Ok(())
}

fn to_sql_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

impl HostSnapshot {
    pub fn metrics(&self) -> Vec<(String, f64)> {
        let mut v = vec![
            ("cpu".into(), self.cpu_percent),
            ("cpu_user_percent".into(), self.cpu_user_percent),
            ("cpu_system_percent".into(), self.cpu_system_percent),
            ("cpu_iowait_percent".into(), self.cpu_iowait_percent),
            (
                "cpu_idle_percent".into(),
                (100.0 - self.cpu_percent).max(0.0),
            ),
            (
                "memory_used_percent".into(),
                if self.memory_total_bytes > 0 {
                    self.memory_used_bytes as f64 * 100.0 / self.memory_total_bytes as f64
                } else {
                    0.0
                },
            ),
            (
                "memory_available_percent".into(),
                if self.memory_total_bytes > 0 {
                    self.memory_available_bytes as f64 * 100.0 / self.memory_total_bytes as f64
                } else {
                    0.0
                },
            ),
            (
                "swap_used_percent".into(),
                if self.swap_total_bytes > 0 {
                    (self.swap_total_bytes.saturating_sub(self.swap_free_bytes)) as f64 * 100.0
                        / self.swap_total_bytes as f64
                } else {
                    0.0
                },
            ),
            ("swap_in_bytes_per_sec".into(), self.swap_in_bytes_per_sec),
            ("swap_out_bytes_per_sec".into(), self.swap_out_bytes_per_sec),
            ("load_1m".into(), self.load[0]),
            ("load_5m".into(), self.load[1]),
            ("load_15m".into(), self.load[2]),
            (
                "cpu_pressure".into(),
                self.psi_cpu_some_percent.unwrap_or(0.0),
            ),
            (
                "memory_pressure".into(),
                self.psi_memory_some_percent.unwrap_or(0.0),
            ),
            (
                "memory_full_pressure".into(),
                self.psi_memory_full_percent.unwrap_or(0.0),
            ),
            (
                "io_pressure".into(),
                self.psi_io_some_percent.unwrap_or(0.0),
            ),
            (
                "disk_used_percent".into(),
                if self.disk_total_bytes > 0 {
                    (self
                        .disk_total_bytes
                        .saturating_sub(self.disk_available_bytes)) as f64
                        * 100.0
                        / self.disk_total_bytes as f64
                } else {
                    0.0
                },
            ),
            (
                "disk_read_bytes_per_sec".into(),
                self.disk_read_bytes_per_sec,
            ),
            (
                "disk_write_bytes_per_sec".into(),
                self.disk_write_bytes_per_sec,
            ),
            ("disk_read_iops".into(), self.disk_read_iops),
            ("disk_write_iops".into(), self.disk_write_iops),
            (
                "network_rx_bytes_per_sec".into(),
                self.network_rx_bytes_per_sec,
            ),
            (
                "network_tx_bytes_per_sec".into(),
                self.network_tx_bytes_per_sec,
            ),
        ];
        for (index, value) in self.per_core.iter().copied().enumerate() {
            v.push((format!("cpu_core_{index}"), value));
        }
        if let Some(t) = self.cpu_temperature_c {
            v.push(("cpu_temperature_c".into(), t));
        }
        if let Some(g) = &self.gpu {
            if let Some(x) = g.utilization_percent {
                v.push(("gpu_utilization_percent".into(), x));
            }
            if let (Some(used), Some(total)) = (g.memory_used_bytes, g.memory_total_bytes) {
                if total > 0 {
                    v.push((
                        "gpu_memory_used_percent".into(),
                        used as f64 * 100.0 / total as f64,
                    ));
                }
            }
            if let Some(x) = g.temperature_c {
                v.push(("gpu_temperature_c".into(), x));
            }
            if let Some(x) = g.power_watts {
                v.push(("gpu_power_watts".into(), x));
            }
        }
        v
    }
}
fn robust_summary(values: &[f64]) -> (f64, f64) {
    fn median(values: &[f64]) -> f64 {
        let mut sorted = values.to_vec();
        sorted.sort_by(f64::total_cmp);
        let middle = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[middle - 1] + sorted[middle]) / 2.0
        } else {
            sorted[middle]
        }
    }
    let center = median(values);
    let deviations = values
        .iter()
        .map(|value| (value - center).abs())
        .collect::<Vec<_>>();
    (center, median(&deviations))
}

fn known_metric(name: &str) -> bool {
    matches!(
        name,
        "cpu"
            | "cpu_user_percent"
            | "cpu_system_percent"
            | "cpu_iowait_percent"
            | "cpu_idle_percent"
            | "memory_used_percent"
            | "memory_available_percent"
            | "swap_used_percent"
            | "swap_in_bytes_per_sec"
            | "swap_out_bytes_per_sec"
            | "load_1m"
            | "load_5m"
            | "load_15m"
            | "cpu_pressure"
            | "memory_pressure"
            | "memory_full_pressure"
            | "io_pressure"
            | "disk_used_percent"
            | "disk_read_bytes_per_sec"
            | "disk_write_bytes_per_sec"
            | "disk_read_iops"
            | "disk_write_iops"
            | "network_rx_bytes_per_sec"
            | "network_tx_bytes_per_sec"
            | "cpu_temperature_c"
            | "gpu_utilization_percent"
            | "gpu_memory_used_percent"
            | "gpu_temperature_c"
            | "gpu_power_watts"
    ) || name
        .strip_prefix("cpu_core_")
        .is_some_and(|index| index.parse::<usize>().is_ok_and(|n| n < 256))
        || known_workload_metric(name)
}

fn known_workload_metric(name: &str) -> bool {
    let Some(encoded) = name.strip_prefix("workload::") else {
        return false;
    };
    let Some((key, suffix)) = encoded.rsplit_once("::") else {
        return false;
    };
    if !matches!(suffix, "cpu_percent" | "rss_bytes" | "process_count") || key.len() > 320 {
        return false;
    }
    let Some((label, hash)) = key.rsplit_once('~') else {
        return false;
    };
    if label.is_empty() || hash.len() != 16 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let bytes = label.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit() =>
            {
                i += 3;
            }
            b if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') => i += 1,
            _ => return false,
        }
    }
    true
}
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn migrations_create_database_and_integrity_passes() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("test.sqlite")).unwrap();
        assert_eq!(s.integrity_check().unwrap(), "ok");
        assert_eq!(s.count("host_samples").unwrap(), 0);
        assert_eq!(s.baseline_state().unwrap().0, 1);
    }
    #[test]
    fn migration_adds_notification_signature_and_baseline_version_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE notification_history(id INTEGER PRIMARY KEY, incident_id INTEGER, ts INTEGER NOT NULL, provider TEXT NOT NULL, status TEXT NOT NULL, detail TEXT);
                 INSERT INTO notification_history(id,ts,provider,status) VALUES(1,100,'ntfy','sent');
                 CREATE TABLE baselines(metric TEXT PRIMARY KEY, samples INTEGER NOT NULL, first_ts INTEGER NOT NULL, median REAL, mad REAL, ewma REAL, p95 REAL, confidence REAL NOT NULL, frozen INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL);
                 INSERT INTO baselines(metric,samples,first_ts,confidence,updated_at) VALUES('cpu',10,60,0.5,100);",
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let baseline = store.baselines().unwrap().pop().unwrap();
        assert_eq!(baseline.metric, "cpu");
        assert_eq!(baseline.version, 1);
        let conn = store.lock().unwrap();
        let signature_column: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('notification_history') WHERE name='signature')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(signature_column);
        let signature: String = conn
            .query_row(
                "SELECT signature FROM notification_history WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(signature, "");
    }

    #[test]
    fn migration_adds_rollup_extrema_without_losing_legacy_samples() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-rollups.sqlite");
        let now = unix_now();
        let old_sample = now - 40 * 86400;
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE minute_points(ts INTEGER NOT NULL,name TEXT NOT NULL,value REAL NOT NULL,PRIMARY KEY(ts,name)) WITHOUT ROWID;
                 CREATE INDEX minute_points_lookup ON minute_points(name,ts);
                 CREATE TABLE quarter_points(ts INTEGER NOT NULL,name TEXT NOT NULL,value REAL NOT NULL,PRIMARY KEY(ts,name)) WITHOUT ROWID;
                 CREATE INDEX quarter_points_lookup ON quarter_points(name,ts);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO minute_points(ts,name,value) VALUES(?,'cpu',42.0)",
                [old_sample],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO quarter_points(ts,name,value) VALUES(?,'cpu',37.0)",
                [old_sample],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let chart = store.chart("cpu", old_sample, 20).unwrap();
        assert_eq!(chart, vec![[old_sample as f64, 37.0, 37.0, 37.0]]);
        {
            let conn = store.lock().unwrap();
            let row: (f64, Option<f64>, Option<f64>) = conn
                .query_row(
                    "SELECT value,min_value,max_value FROM minute_points WHERE ts=? AND name='cpu'",
                    [old_sample],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(row, (42.0, None, None));
        }
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.integrity_check().unwrap(), "ok");
        reopened.checkpoint().unwrap();
    }
    #[test]
    fn baseline_reset_versions_model_without_deleting_history() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("test.sqlite")).unwrap();
        {
            let conn = s.lock().unwrap();
            conn.execute(
                "INSERT INTO minute_points(ts,name,value) VALUES(60,'cpu',12.0)",
                [],
            )
            .unwrap();
            conn.execute("INSERT INTO anomalies(ts,metric,value,score,reason) VALUES(60,'cpu',12.0,5.0,'test')", []).unwrap();
            conn.execute("INSERT INTO baselines(metric,version,samples,first_ts,confidence,updated_at) VALUES('cpu',1,1,60,0.1,60)", []).unwrap();
        }
        let (version, reset_at) = s.reset_baselines(120).unwrap();
        assert_eq!((version, reset_at), (2, 120));
        assert!(s.baselines().unwrap().is_empty());
        assert_eq!(s.anomalies(0, 10).unwrap().len(), 1);
        let history_points: i64 = s
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM minute_points", [], |r| r.get(0))
            .unwrap();
        assert_eq!(history_points, 1);
    }
    #[test]
    fn cleanup_expires_old_notification_history() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("test.sqlite")).unwrap();
        let now = 400 * 86400_i64;
        s.log_notification(None, "old", now - 366 * 86400, "ntfy", "sent", None)
            .unwrap();
        s.log_notification(None, "new", now - 10, "ntfy", "sent", None)
            .unwrap();
        s.cleanup(now, 48, 500).unwrap();
        let notifications = s.notifications(10).unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].timestamp, now - 10);
    }
    #[test]
    fn online_backup_is_restorable_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let source = Store::open(&dir.path().join("source.sqlite")).unwrap();
        let mut snapshot = HostSnapshot::default();
        snapshot.timestamp = unix_now();
        snapshot.cpu_percent = 17.0;
        source.insert_snapshot(&snapshot).unwrap();
        let backup_path = dir.path().join("backup.sqlite");
        source.backup(&backup_path).unwrap();
        assert!(source.backup(&backup_path).is_err());

        let restored = Store::open(&backup_path).unwrap();
        assert_eq!(restored.integrity_check().unwrap(), "ok");
        assert_eq!(
            restored.latest_snapshot().unwrap().unwrap().cpu_percent,
            17.0
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(backup_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
    #[test]
    fn snapshot_metrics_are_stored_and_charted() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("test.sqlite")).unwrap();
        let mut h = HostSnapshot::default();
        h.timestamp = unix_now();
        h.memory_total_bytes = 100;
        h.memory_used_bytes = 30;
        h.memory_available_bytes = 70;
        h.cpu_percent = 12.5;
        h.disk_read_iops = 12.0;
        s.insert_snapshot(&h).unwrap();
        assert_eq!(s.latest_snapshot().unwrap().unwrap().cpu_percent, 12.5);
        assert_eq!(
            s.chart("cpu", h.timestamp - 1, 100).unwrap(),
            vec![[h.timestamp as f64, 12.5, 12.5, 12.5]]
        );
        assert_eq!(
            s.chart("disk_read_iops", h.timestamp - 1, 100).unwrap(),
            vec![[h.timestamp as f64, 12.0, 12.0, 12.0]]
        );
    }

    #[test]
    fn database_size_accounting_includes_sidecars_and_dbstat_objects() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("sizes.sqlite")).unwrap();
        let files = store.database_file_sizes();
        assert_eq!(
            files.total_bytes,
            files.main_bytes + files.wal_bytes + files.shm_bytes + files.journal_bytes
        );
        let objects = store.database_object_sizes().unwrap();
        assert!(objects.iter().any(|object| object.name == "host_samples"));
        assert!(
            objects
                .iter()
                .any(|object| object.name == "metric_points_lookup")
        );
        assert!(objects.iter().all(|object| object.bytes > 0));
    }

    #[test]
    fn accelerated_raw_and_process_retention_keep_their_documented_windows() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("accelerated-retention.sqlite")).unwrap();
        let now = 1_900_000_000_i64;
        let stale_raw = now - 49 * 3600;
        let recent_raw = now - 47 * 3600;
        let stale_process = now - 25 * 3600;
        let recent_process = now - 23 * 3600;
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO host_samples(ts,payload) VALUES(?, 'old'),(?, 'recent')",
                params![stale_raw, recent_raw],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO metric_points(ts,name,value) VALUES(?, 'cpu', 1.0),(?, 'cpu', 2.0)",
                params![stale_raw, recent_raw],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO process_samples(ts,proc_key,pid,ppid,uid,name,executable,state,start_ticks,runtime_seconds,cpu_percent,rss_bytes,virtual_bytes,process_group,session,cgroup,workload,parent_disappeared) VALUES(?, 'old',1,1,1,'worker',NULL,'S',1,1,0.0,0,0,1,1,NULL,'worker',1),(?, 'recent',2,1,1,'worker',NULL,'S',2,1,0.0,0,0,1,1,NULL,'worker',1)",
                params![stale_process, recent_process],
            )
            .unwrap();
        }
        let report = store.cleanup(now, 48, 500).unwrap();
        assert_eq!(report.pressure_stage, "normal");
        let conn = store.lock().unwrap();
        for table in ["host_samples", "metric_points"] {
            let oldest: i64 = conn
                .query_row(&format!("SELECT min(ts) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            let newest: i64 = conn
                .query_row(&format!("SELECT max(ts) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(
                oldest, recent_raw,
                "{table} retained a stale raw observation"
            );
            assert_eq!(newest, recent_raw, "{table} lost the in-window observation");
        }
        let process_times: Vec<i64> = conn
            .prepare("SELECT ts FROM process_samples ORDER BY ts")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(process_times, vec![recent_process]);
    }

    #[test]
    fn pressure_stage_is_deterministic_and_prunes_process_detail_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("pressure-stage.sqlite")).unwrap();
        let now = 1_900_000_000_i64;
        let budget_bytes = 1024 * 1024;
        let host_payload = "h".repeat(700);
        let mut host_id = 0_i64;
        while store.database_size_bytes() < budget_bytes * 78 / 100 {
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO host_samples(ts,payload) VALUES(?,?)",
                    params![now - 3600 + host_id, host_payload],
                )
                .unwrap();
            host_id += 1;
        }
        let process_payload = "p".repeat(160);
        let mut process_id = 0_i64;
        while store.database_size_bytes() < budget_bytes * 92 / 100 {
            store
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO process_samples(ts,proc_key,pid,ppid,uid,name,executable,state,start_ticks,runtime_seconds,cpu_percent,rss_bytes,virtual_bytes,process_group,session,cgroup,workload,parent_disappeared) VALUES(?, ?,1,1,1,?,NULL,'S',1,1,0.0,0,0,1,1,NULL,'worker',0)",
                    params![now - 18 * 3600, format!("synthetic-{process_id}"), process_payload],
                )
                .unwrap();
            process_id += 1;
        }
        let before = store.database_size_bytes();
        assert!(before > budget_bytes * 90 / 100 && before <= budget_bytes * 95 / 100);
        assert!(process_id > 0);

        let report = store.cleanup(now, 48, 1).unwrap();
        assert_eq!(report.pressure_stage, "process-history-12h");
        assert!(!report.over_budget);
        assert!(report.pressure_rows_pruned > 0);
        assert!(report.pressure_rows_pruned <= PRESSURE_PRUNE_BATCH as u64);
        assert_eq!(store.count("process_samples").unwrap(), 0);
        assert!(store.count("host_samples").unwrap() > 0);
        assert!(!store.history_degraded());
    }

    #[test]
    fn pressure_delete_batches_are_oldest_first_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("bounded-prune.sqlite")).unwrap();
        {
            let conn = store.lock().unwrap();
            let tx = conn.unchecked_transaction().unwrap();
            for index in 0..=PRESSURE_PRUNE_BATCH {
                tx.execute(
                    "INSERT INTO metric_points(ts,name,value) VALUES(1,?,1.0)",
                    [format!("metric-{index:05}")],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let conn = store.lock().unwrap();
        let pruned =
            delete_batch_before(&conn, "metric_points", "ts,name", "ts<?1", "ts,name", 2).unwrap();
        assert_eq!(pruned, PRESSURE_PRUNE_BATCH as u64);
        let remaining: (i64, String) = conn
            .query_row("SELECT ts,name FROM metric_points", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(
            remaining,
            (1, format!("metric-{:05}", PRESSURE_PRUNE_BATCH))
        );
    }

    #[test]
    fn minute_and_quarter_rollups_preserve_observed_minimum_and_peak() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("rollup-extrema.sqlite")).unwrap();
        let now = unix_now();
        let quarter_end = now.div_euclid(900) * 900;
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO minute_points(ts,name,value,min_value,max_value) VALUES(?, 'cpu', 50.0, 45.0, 55.0)",
                [quarter_end - 120],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO metric_points(ts,name,value) VALUES(?, 'cpu',10.0),(?, 'cpu',90.0),(?, 'cpu',20.0)",
                params![quarter_end - 55, quarter_end - 35, quarter_end - 5],
            )
            .unwrap();
        }
        store.aggregate_until(quarter_end).unwrap();
        let conn = store.lock().unwrap();
        let minute: (f64, f64, f64) = conn
            .query_row(
                "SELECT value,min_value,max_value FROM minute_points WHERE ts=? AND name='cpu'",
                [quarter_end - 60],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(minute, (40.0, 10.0, 90.0));
        let quarter: (f64, f64, f64) = conn
            .query_row(
                "SELECT value,min_value,max_value FROM quarter_points WHERE ts=? AND name='cpu'",
                [quarter_end - 900],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(quarter, (45.0, 10.0, 90.0));
    }

    #[test]
    fn process_history_sampling_is_bounded_even_with_many_parent_loss_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("process-cap.sqlite")).unwrap();
        let processes = (0..150_u32)
            .map(|pid| ProcessSnapshot {
                key: format!("boot:{pid}:1"),
                pid,
                ppid: 1,
                uid: 1000,
                name: format!("worker-{pid}"),
                executable: None,
                state: "S".into(),
                start_ticks: 1,
                runtime_seconds: 60,
                cpu_percent: pid as f64,
                rss_bytes: pid as u64 * 1024,
                virtual_bytes: 0,
                process_group: 1,
                session: 1,
                cgroup: None,
                workload: "worker.service".into(),
                parent_disappeared: true,
            })
            .collect::<Vec<_>>();
        store.save_processes(unix_now(), &processes).unwrap();
        let count = store.count("process_samples").unwrap();
        assert!(count <= 50);
        assert!(count > 0);
    }

    #[test]
    fn synthetic_budget_pressure_sheds_old_detail_and_keeps_incident_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("budget-pressure.sqlite")).unwrap();
        let now = 1_900_000_000_i64;
        let payload = "x".repeat(2048);
        {
            let conn = store.lock().unwrap();
            let tx = conn.unchecked_transaction().unwrap();
            for index in 0..1500_i64 {
                tx.execute(
                    "INSERT INTO host_samples(ts,payload) VALUES(?,?)",
                    params![now - 7 * 3600 + index, payload],
                )
                .unwrap();
            }
            tx.execute(
                "INSERT INTO host_samples(ts,payload) VALUES(?, 'recent')",
                [now - 5 * 60],
            )
            .unwrap();
            for index in 1..=600_i64 {
                tx.execute(
                    "INSERT INTO host_samples(ts,payload) VALUES(?,?)",
                    params![now - 5 * 60 + index, payload],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        store
            .open_or_update_incident(
                "synthetic-active",
                "critical",
                "Synthetic active incident",
                0.99,
                &serde_json::json!({"preserve": "evidence"}),
                "test evidence",
                now - 10,
            )
            .unwrap();

        let report = store.cleanup(now, 48, 1).unwrap();
        assert_eq!(report.pressure_stage, "minimum-history");
        assert!(report.over_budget);
        assert!(report.pressure_rows_pruned <= PRESSURE_PRUNE_BATCH as u64 * 20);
        assert!(store.history_degraded());
        assert_eq!(
            store.incidents(true, 10).unwrap()[0].signature,
            "synthetic-active"
        );
        assert_eq!(
            store.incidents(true, 10).unwrap()[0].evidence["preserve"],
            "evidence"
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM host_samples WHERE ts=?",
                    [now - 5 * 60],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert!(report.size_bytes >= store.database_file_sizes().total_bytes);
    }

    #[test]
    fn named_workload_metrics_are_aggregated_and_baseline_readable() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("workload.sqlite")).unwrap();
        let metric = "workload::echo%20archives.service~0123456789abcdef::cpu_percent";
        let population_metric = "workload::echo%20archives.service~0123456789abcdef::process_count";
        let minute = unix_now().div_euclid(60) * 60;
        store
            .insert_named_metrics(
                minute - 30,
                &[(metric.into(), 12.5), (population_metric.into(), 4.0)],
            )
            .unwrap();
        store.aggregate_until(minute).unwrap();
        assert_eq!(
            store.baseline_values(metric, minute - 60, 100).unwrap(),
            vec![12.5]
        );
        assert_eq!(store.chart(metric, minute - 60, 100).unwrap()[0][1], 12.5);
        assert_eq!(
            store
                .baseline_values(population_metric, minute - 60, 100)
                .unwrap(),
            vec![4.0]
        );
        assert_eq!(
            store.chart(population_metric, minute - 60, 100).unwrap()[0][1],
            4.0
        );
        assert!(
            store
                .chart(
                    "workload::bad%Q0~0123456789abcdef::cpu_percent",
                    minute - 60,
                    100
                )
                .is_err()
        );
    }

    #[test]
    fn weekly_seasonal_model_waits_for_four_clean_repetitions() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("seasonal.sqlite")).unwrap();
        let metric = "cpu";
        let now = 1_800_000_000_i64;
        let current_week_start = (now + 259_200).div_euclid(604_800) * 604_800 - 259_200;
        let hour_of_week = (now.div_euclid(3600) + 72).rem_euclid(168);
        let insert_week = |store: &Store, week: i64| {
            let conn = store.lock().unwrap();
            let tx = conn.unchecked_transaction().unwrap();
            let hour_start = current_week_start - week * 604_800 + hour_of_week * 3600;
            for minute in 0..60_i64 {
                tx.execute(
                    "INSERT INTO minute_points(ts,name,value) VALUES(?,?,?)",
                    params![hour_start + minute * 60, metric, 10.0 + week as f64],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        };

        for week in 1..=3 {
            insert_week(&store, week);
        }
        assert!(
            store
                .seasonal_values(metric, now - 30 * 86400, now)
                .unwrap()
                .is_none()
        );
        insert_week(&store, 4);
        let model = store
            .seasonal_values(metric, now - 30 * 86400, now)
            .unwrap()
            .unwrap();
        assert_eq!(model.pattern, "hour_of_week_utc");
        assert_eq!(model.periods, 4);
        assert_eq!(model.median, 12.5);
        assert_eq!(model.mad, 1.0);
        assert_eq!(model.confidence, 1.0);
    }

    #[test]
    fn process_lifecycle_events_are_persisted_and_returned_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("lifecycle.sqlite")).unwrap();
        let make_event = |timestamp, kind: &str, pid| ProcessLifecycleEvent {
            timestamp,
            kind: kind.into(),
            key: format!("boot:{pid}:10"),
            pid,
            ppid: 1,
            uid: 1000,
            name: "worker".into(),
            executable: Some("/usr/bin/worker".into()),
            workload: "worker.service".into(),
            cpu_percent: 2.5,
            rss_bytes: 4096,
            runtime_seconds: 60,
        };
        store
            .record_process_lifecycle(&[
                make_event(100, "started", 10),
                make_event(110, "exited", 10),
            ])
            .unwrap();
        let rows = store.process_lifecycle(0, 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].timestamp, 110);
        assert_eq!(rows[0].kind, "exited");
        assert_eq!(rows[1].kind, "started");
        assert_eq!(store.count("process_lifecycle_events").unwrap(), 2);
    }

    #[test]
    fn service_restart_observer_detects_only_increasing_counters() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("test.sqlite")).unwrap();
        let service = |restart_count| ServiceSnapshot {
            name: "worker.service".into(),
            restart_count,
            ..ServiceSnapshot::default()
        };
        assert!(
            store
                .observe_service_restarts(&[service(2)], 100)
                .unwrap()
                .is_empty()
        );
        let events = store.observe_service_restarts(&[service(5)], 160).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].unit, "worker.service");
        assert_eq!(events[0].previous_count, 2);
        assert_eq!(events[0].current_count, 5);
        assert!(
            store
                .observe_service_restarts(&[service(5)], 220)
                .unwrap()
                .is_empty()
        );
        // A systemd manager reset re-baselines the counter without inventing an event.
        assert!(
            store
                .observe_service_restarts(&[service(1)], 280)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.observe_service_restarts(&[service(2)], 340).unwrap()[0].previous_count,
            1
        );
    }

    #[test]
    fn incidents_deduplicate_and_recover() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("test.sqlite")).unwrap();
        let (id, created, initially_escalated) = s
            .open_or_update_incident(
                "x",
                "warning",
                "Test",
                0.8,
                &serde_json::json!({"fact":1}),
                "why",
                100,
            )
            .unwrap();
        let (same, created_again, escalated) = s
            .open_or_update_incident(
                "x",
                "critical",
                "Test",
                0.9,
                &serde_json::json!({"fact":2}),
                "why",
                120,
            )
            .unwrap();
        assert_eq!(id, same);
        assert!(created);
        assert!(!created_again);
        assert!(!initially_escalated);
        assert!(escalated);
        let (_, _, downgraded) = s
            .open_or_update_incident(
                "x",
                "warning",
                "Test",
                0.85,
                &serde_json::json!({"fact":3}),
                "why",
                140,
            )
            .unwrap();
        assert!(!downgraded);
        assert_eq!(s.incidents(true, 10).unwrap().len(), 1);
        assert_eq!(s.incidents(true, 10).unwrap()[0].severity, "critical");
        assert!(s.recover_incident("x", 200).unwrap());
        assert_eq!(s.incidents(true, 10).unwrap().len(), 0);
    }
}
