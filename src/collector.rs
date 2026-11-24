use crate::{
    config::Config,
    model::{
        GpuProcessUsage, GpuSnapshot, HostSnapshot, NetworkSnapshot, ProcessSnapshot,
        ServiceRestartEvent, ServiceSnapshot, TemperatureReading,
    },
    notifications::Dispatcher,
    processes::ProcessCollector,
    storage::{SeasonalValues, Store, unix_now},
};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, watch};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct LiveState {
    pub latest: Arc<RwLock<Option<HostSnapshot>>>,
    pub processes: Arc<RwLock<Vec<ProcessSnapshot>>>,
    pub services: Arc<RwLock<Vec<ServiceSnapshot>>>,
    pub operational: Arc<RwLock<OperationalStatus>>,
    pub seasonal_models: Arc<RwLock<Vec<SeasonalValues>>>,
    revision: watch::Sender<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct OperationalStatus {
    pub last_host_sample_at: Option<i64>,
    pub last_process_scan_at: Option<i64>,
    pub last_hardware_scan_at: Option<i64>,
    pub last_service_scan_at: Option<i64>,
    pub service_inventory_available: bool,
    pub service_inventory_complete: bool,
    pub user_service_scope_available: bool,
    pub system_service_scope_available: bool,
    pub last_database_write_at: Option<i64>,
    pub last_database_write_ok: bool,
    pub database_write_latency_ms: f64,
    pub host_sample_duration_ms: f64,
    pub missed_host_samples: u64,
    pub process_collector_failures: u64,
    pub database_write_failures: u64,
}
impl LiveState {
    pub fn new() -> Self {
        let (revision, _) = watch::channel(0);
        Self {
            latest: Arc::new(RwLock::new(None)),
            processes: Arc::new(RwLock::new(Vec::new())),
            services: Arc::new(RwLock::new(Vec::new())),
            operational: Arc::new(RwLock::new(OperationalStatus::default())),
            seasonal_models: Arc::new(RwLock::new(Vec::new())),
            revision,
        }
    }
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision.subscribe()
    }
    pub fn changed(&self) {
        self.revision.send_modify(|n| *n = n.wrapping_add(1));
    }
}

#[derive(Clone)]
pub struct Monitor {
    config: Arc<RwLock<Config>>,
    store: Store,
    notifications: Dispatcher,
    live: LiveState,
    processes: Arc<Mutex<ProcessCollector>>,
}
impl Monitor {
    pub fn new(config: Config, store: Store, notifications: Dispatcher) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            store,
            notifications,
            live: LiveState::new(),
            processes: Arc::new(Mutex::new(ProcessCollector::new())),
        }
    }
    pub fn live(&self) -> LiveState {
        self.live.clone()
    }
    pub fn config(&self) -> Arc<RwLock<Config>> {
        self.config.clone()
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let initial = self.config.read().await.clone();
        let mut counters = Counters::default();
        let mut latest_temps = Vec::new();
        let mut latest_gpu = None;
        let mut latest_gpu_processes = Vec::<GpuProcessUsage>::new();
        let mut gpu_process_attribution_available = false;
        let mut gpu_process_attribution_sampled_at = None;
        let mut last_gpu_process_scan = Instant::now() - Duration::from_secs(60);
        let mut last_host = Instant::now() - Duration::from_secs(initial.collection.host_seconds);
        let mut last_process =
            Instant::now() - Duration::from_secs(initial.collection.process_seconds);
        let mut last_hardware =
            Instant::now() - Duration::from_secs(initial.collection.hardware_seconds);
        let mut last_service =
            Instant::now() - Duration::from_secs(initial.collection.service_seconds);
        let mut last_history = Instant::now() - Duration::from_secs(30);
        let mut last_cleanup = Instant::now();
        let mut last_cleanup_defer = Instant::now();
        let mut last_intel_bucket = 0_i64;
        let mut evaluator = crate::intelligence::Evaluator::default();
        let mut last_oom_kill_count = self
            .store
            .latest_snapshot()
            .ok()
            .flatten()
            .map(|snapshot| snapshot.oom_kill_count)
            .or_else(|| Some(read_vmstat().2));
        let mut pending_oom_kills = 0_u64;
        let mut pending_service_restarts = Vec::<ServiceRestartEvent>::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let config = self.config.read().await.clone();
            let now = Instant::now();
            let epoch = unix_now();
            let overloaded = self
                .live
                .latest
                .read()
                .await
                .as_ref()
                .is_some_and(host_is_overloaded);
            let mut did_update = false;
            let process_interval = if overloaded {
                config.collection.process_seconds.saturating_mul(3).min(300)
            } else {
                config.collection.process_seconds
            };
            if now.duration_since(last_process).as_secs() >= process_interval {
                last_process = now;
                let collector = self.processes.clone();
                let result = tokio::task::spawn_blocking(move || {
                    collector
                        .lock()
                        .map(|mut c| c.collect_with_lifecycle())
                        .map_err(|_| "process collector lock poisoned".to_string())
                        .and_then(|result| result.map_err(|error| error.to_string()))
                })
                .await;
                match result {
                    Ok(Ok((collected, lifecycle))) => {
                        self.live.operational.write().await.last_process_scan_at = Some(epoch);
                        if !lifecycle.is_empty()
                            && let Err(e) = self.store.record_process_lifecycle(&lifecycle)
                        {
                            warn!(error=%e,"failed to persist process lifecycle events");
                            self.live.operational.write().await.database_write_failures += 1;
                        }
                        if now.duration_since(last_history).as_secs() >= 30 {
                            if let Err(e) = self.store.save_processes(epoch, &collected) {
                                warn!(error=%e,"failed to persist process sample");
                                self.live.operational.write().await.database_write_failures += 1;
                            }
                            last_history = now;
                        }
                        *self.live.processes.write().await = collected;
                        did_update = true;
                    }
                    Ok(Err(error)) => {
                        warn!(
                            error,
                            "process collector failed; retaining the last inventory"
                        );
                        self.live
                            .operational
                            .write()
                            .await
                            .process_collector_failures += 1;
                    }
                    Err(error) => {
                        warn!(error=%error,"process collector task failed; retaining the last inventory");
                        self.live
                            .operational
                            .write()
                            .await
                            .process_collector_failures += 1;
                    }
                }
            }
            if now.duration_since(last_hardware).as_secs() >= config.collection.hardware_seconds {
                last_hardware = now;
                latest_temps = read_temperatures();
                latest_gpu = read_gpu().await;
                self.live.operational.write().await.last_hardware_scan_at = Some(epoch);
            }
            if now.duration_since(last_gpu_process_scan).as_secs() >= 60 {
                last_gpu_process_scan = now;
                if latest_gpu.is_some() {
                    match read_gpu_compute_apps().await {
                        Some(processes) => {
                            latest_gpu_processes = processes;
                            gpu_process_attribution_available = true;
                            gpu_process_attribution_sampled_at = Some(epoch);
                        }
                        None => {
                            latest_gpu_processes.clear();
                            gpu_process_attribution_available = false;
                            gpu_process_attribution_sampled_at = Some(epoch);
                        }
                    }
                } else {
                    latest_gpu_processes.clear();
                    gpu_process_attribution_available = false;
                    gpu_process_attribution_sampled_at = None;
                }
            }
            if now.duration_since(last_service).as_secs() >= config.collection.service_seconds {
                last_service = now;
                let inventory = collect_services().await;
                let inventory_available = inventory.available();
                let inventory_complete = inventory.complete();
                let services = inventory.services;
                {
                    let mut health = self.live.operational.write().await;
                    health.last_service_scan_at = Some(epoch);
                    health.user_service_scope_available = inventory.user_scope_available;
                    health.system_service_scope_available = inventory.system_scope_available;
                    health.service_inventory_available = inventory_available;
                    health.service_inventory_complete = inventory_complete;
                }
                match self.store.observe_service_restarts(&services, epoch) {
                    Ok(events) => {
                        for event in events {
                            if let Some(existing) = pending_service_restarts
                                .iter_mut()
                                .find(|pending| pending.unit == event.unit)
                            {
                                existing.current_count = event.current_count;
                            } else if pending_service_restarts.len() < 100 {
                                pending_service_restarts.push(event);
                            } else {
                                warn!("service restart event queue reached its 100-unit cap");
                            }
                        }
                    }
                    Err(e) => warn!(error=%e,"failed to observe service restart counters"),
                }
                if inventory_available {
                    *self.live.services.write().await = services;
                }
                did_update = true;
            }
            if now.duration_since(last_host).as_secs() >= config.collection.host_seconds {
                let elapsed = now.duration_since(last_host).as_secs_f64().max(0.1);
                last_host = now;
                let processes = self.live.processes.read().await.clone();
                let sample_started = Instant::now();
                let mut gpu = latest_gpu.clone();
                if let Some(gpu) = gpu.as_mut() {
                    gpu.process_attribution_available = gpu_process_attribution_available;
                    gpu.process_attribution_sampled_at = gpu_process_attribution_sampled_at;
                    gpu.processes.clone_from(&latest_gpu_processes);
                }
                let mut snapshot =
                    collect_host(&mut counters, elapsed, &latest_temps, gpu, &processes);
                snapshot.timestamp = epoch;
                if let Some(previous) = last_oom_kill_count {
                    pending_oom_kills = pending_oom_kills
                        .saturating_add(snapshot.oom_kill_count.saturating_sub(previous));
                }
                last_oom_kill_count = Some(snapshot.oom_kill_count);
                let write_started = Instant::now();
                let write_ok = match self.store.insert_snapshot(&snapshot) {
                    Ok(()) => true,
                    Err(e) => {
                        warn!(error=%e,"failed to write host sample");
                        false
                    }
                };
                {
                    let mut health = self.live.operational.write().await;
                    health.last_host_sample_at = Some(epoch);
                    health.last_database_write_at = Some(epoch);
                    health.last_database_write_ok = write_ok;
                    health.database_write_latency_ms =
                        write_started.elapsed().as_secs_f64() * 1000.0;
                    health.host_sample_duration_ms =
                        sample_started.elapsed().as_secs_f64() * 1000.0;
                    if !write_ok {
                        health.database_write_failures += 1;
                    }
                    let interval = config.collection.host_seconds.max(1);
                    if elapsed > (interval.saturating_mul(2)) as f64 {
                        health.missed_host_samples = health.missed_host_samples.saturating_add(
                            (elapsed / interval as f64).floor().max(1.0) as u64 - 1,
                        );
                    }
                }
                *self.live.latest.write().await = Some(snapshot.clone());
                if did_update || epoch % 5 == 0 {
                    self.live.changed();
                }
                let bucket = epoch.div_euclid(60);
                if bucket != last_intel_bucket {
                    last_intel_bucket = bucket;
                    if let Err(e) = self.store.aggregate_until(epoch) {
                        warn!(error=%e,"metric aggregation failed");
                    }
                    let workload_metrics = crate::workloads::baseline_metrics(&processes);
                    if let Err(e) = self.store.insert_named_metrics(epoch, &workload_metrics) {
                        warn!(error=%e,"failed to persist workload metrics");
                    }
                    match evaluator.evaluate(
                        &self.store,
                        &config,
                        &snapshot,
                        &processes,
                        &workload_metrics,
                        pending_oom_kills,
                        &pending_service_restarts,
                        epoch,
                    ) {
                        Ok(notices) => {
                            *self.live.seasonal_models.write().await =
                                evaluator.seasonal_models(epoch);
                            for notice in notices {
                                self.notifications.notify(&config, notice).await;
                            }
                            pending_oom_kills = 0;
                            pending_service_restarts.clear();
                        }
                        Err(e) => warn!(error=%e,"intelligence evaluation failed"),
                    }
                    self.live.changed();
                }
            }
            if now.duration_since(last_cleanup).as_secs() >= 3600 {
                if overloaded {
                    if now.duration_since(last_cleanup_defer).as_secs() >= 300 {
                        last_cleanup_defer = now;
                        debug!("database maintenance deferred while host pressure is high");
                    }
                } else {
                    last_cleanup = now;
                    let (main_database_budget_mb, _) = crate::config::database_budget_partitions_mb(
                        config.server.database_budget_mb,
                    );
                    match self.store.cleanup(
                        epoch,
                        config.collection.retention_hours,
                        main_database_budget_mb,
                    ) {
                        Ok(size) => debug!(database_bytes = size, "retention complete"),
                        Err(e) => warn!(error=%e,"retention maintenance failed"),
                    }
                }
            }
            if did_update {
                self.live.changed();
            }
        }
    }
}

fn host_is_overloaded(host: &HostSnapshot) -> bool {
    let available = if host.memory_total_bytes > 0 {
        host.memory_available_bytes as f64 / host.memory_total_bytes as f64
    } else {
        1.0
    };
    available < 0.10
        || host.psi_cpu_some_percent.is_some_and(|value| value > 50.0)
        || host
            .psi_memory_some_percent
            .is_some_and(|value| value > 20.0)
        || host
            .cpu_temperature_c
            .zip(host.cpu_temperature_limit_c)
            .is_some_and(|(temperature, limit)| limit > 0.0 && temperature >= limit * 0.95)
}

#[derive(Default)]
struct Counters {
    cpu: Option<(CpuTimes, Instant)>,
    core_cpu: HashMap<String, (CpuTimes, Instant)>,
    vm: Option<(u64, u64, Instant)>,
    net: HashMap<String, (u64, u64, Instant)>,
    disk: Option<(u64, u64, u64, u64, Instant)>,
}
#[derive(Clone, Copy, Default)]
struct CpuTimes {
    total: u64,
    idle: u64,
    user: u64,
    system: u64,
    iowait: u64,
}

fn collect_host(
    c: &mut Counters,
    elapsed: f64,
    temps: &[TemperatureReading],
    gpu: Option<GpuSnapshot>,
    processes: &[ProcessSnapshot],
) -> HostSnapshot {
    let timestamp = unix_now();
    let cpu = read_cpu();
    let mut usage = (0.0, 0.0, 0.0, 0.0, Vec::new());
    let _ = elapsed;
    if let Some((_, current)) = cpu.first() {
        if let Some((old, _when)) = c.cpu {
            let dt = current.total.saturating_sub(old.total) as f64;
            let pct = |a: u64, b: u64| {
                if dt > 0.0 {
                    a.saturating_sub(b) as f64 / dt * 100.0
                } else {
                    0.0
                }
            };
            usage.0 = pct(
                current.total.saturating_sub(current.idle),
                old.total.saturating_sub(old.idle),
            );
            usage.1 = pct(current.user, old.user);
            usage.2 = pct(current.system, old.system);
            usage.3 = pct(current.iowait, old.iowait);
        }
        c.cpu = Some((*current, Instant::now()));
    }
    for (name, current) in cpu.iter().skip(1) {
        if let Some((old, _)) = c.core_cpu.get(name) {
            let dt = current.total.saturating_sub(old.total) as f64;
            let busy = current
                .total
                .saturating_sub(current.idle)
                .saturating_sub(old.total.saturating_sub(old.idle));
            usage.4.push(if dt > 0.0 {
                busy as f64 / dt * 100.0
            } else {
                0.0
            });
        } else {
            usage.4.push(0.0)
        }
        c.core_cpu.insert(name.clone(), (*current, Instant::now()));
    }
    let mem = read_meminfo();
    let vm = read_vmstat();
    let mut swap_in = 0.0;
    let mut swap_out = 0.0;
    if let Some((old_in, old_out, when)) = c.vm {
        let dt = when.elapsed().as_secs_f64().max(0.1);
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as f64;
        swap_in = vm.0.saturating_sub(old_in) as f64 * page / dt;
        swap_out = vm.1.saturating_sub(old_out) as f64 * page / dt;
    }
    c.vm = Some((vm.0, vm.1, Instant::now()));
    let net = read_network();
    let mut interfaces = Vec::new();
    let mut rx_rate = 0.0;
    let mut tx_rate = 0.0;
    for (name, values) in net {
        let state = fs::read_to_string(format!("/sys/class/net/{name}/operstate"))
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_string();
        let mut iface_rx = 0.0;
        let mut iface_tx = 0.0;
        if let Some((old_rx, old_tx, when)) = c.net.get(&name) {
            let dt = when.elapsed().as_secs_f64().max(0.1);
            iface_rx = values.0.saturating_sub(*old_rx) as f64 / dt;
            iface_tx = values.1.saturating_sub(*old_tx) as f64 / dt;
            if !name.starts_with("lo")
                && !name.starts_with("br-")
                && !name.starts_with("veth")
                && !name.starts_with("docker")
                && name != "tailscale0"
            {
                rx_rate += iface_rx;
                tx_rate += iface_tx;
            }
        }
        c.net
            .insert(name.clone(), (values.0, values.1, Instant::now()));
        interfaces.push(NetworkSnapshot {
            name,
            state,
            rx_bytes: values.0,
            tx_bytes: values.1,
            rx_bytes_per_sec: iface_rx,
            tx_bytes_per_sec: iface_tx,
            rx_packets: values.2,
            tx_packets: values.3,
            rx_errors: values.4,
            tx_errors: values.6,
            rx_dropped: values.5,
            tx_dropped: values.7,
        });
    }
    let disk = read_diskstats();
    let mut read_rate = 0.0;
    let mut write_rate = 0.0;
    let mut read_iops = 0.0;
    let mut write_iops = 0.0;
    if let Some((old_r, old_w, old_read_ops, old_write_ops, when)) = c.disk {
        let dt = when.elapsed().as_secs_f64().max(0.1);
        read_rate = disk.0.saturating_sub(old_r) as f64 / dt;
        write_rate = disk.1.saturating_sub(old_w) as f64 / dt;
        read_iops = disk.2.saturating_sub(old_read_ops) as f64 / dt;
        write_iops = disk.3.saturating_sub(old_write_ops) as f64 / dt;
    }
    c.disk = Some((disk.0, disk.1, disk.2, disk.3, Instant::now()));
    let (disk_total, disk_free) = read_disk_capacity();
    let load = read_load();
    let uptime = read_uptime();
    let cpu_temp = temps
        .iter()
        .filter(|t| t.device.to_lowercase().contains("coretemp"))
        .map(|t| t.celsius)
        .reduce(f64::max);
    let cpu_limit = temps
        .iter()
        .filter(|t| t.device.to_lowercase().contains("coretemp"))
        .filter_map(|t| t.limit_celsius)
        .reduce(f64::min);
    let active_workloads = processes
        .iter()
        .map(|p| p.workload.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    HostSnapshot {
        timestamp,
        hostname: fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "localhost".into())
            .trim()
            .to_string(),
        uptime_seconds: uptime,
        cpu_percent: usage.0.clamp(0.0, 100.0),
        cpu_user_percent: usage.1,
        cpu_system_percent: usage.2,
        cpu_iowait_percent: usage.3,
        per_core: usage.4,
        cpu_frequency_mhz: read_frequency(),
        load,
        memory_total_bytes: mem.total,
        memory_available_bytes: mem.available,
        memory_used_bytes: mem.total.saturating_sub(mem.available),
        memory_cached_bytes: mem.cached,
        memory_buffers_bytes: mem.buffers,
        swap_total_bytes: mem.swap_total,
        swap_free_bytes: mem.swap_free,
        swap_in_bytes_per_sec: swap_in,
        swap_out_bytes_per_sec: swap_out,
        oom_kill_count: vm.2,
        psi_cpu_some_percent: read_psi("cpu", "some"),
        psi_memory_some_percent: read_psi("memory", "some"),
        psi_memory_full_percent: read_psi("memory", "full"),
        psi_io_some_percent: read_psi("io", "some"),
        cpu_temperature_c: cpu_temp,
        cpu_temperature_limit_c: cpu_limit,
        temperatures: temps.to_vec(),
        thermal_throttle_count: read_throttle_count(),
        disk_total_bytes: disk_total,
        disk_available_bytes: disk_free,
        disk_read_bytes_per_sec: read_rate,
        disk_write_bytes_per_sec: write_rate,
        disk_read_iops: read_iops,
        disk_write_iops: write_iops,
        network_rx_bytes_per_sec: rx_rate,
        network_tx_bytes_per_sec: tx_rate,
        network_interfaces: interfaces,
        gpu,
        process_count: processes.len(),
        active_workloads,
        collection_degraded: degraded_capabilities(),
    }
}

fn degraded_capabilities() -> Vec<String> {
    let mut d = Vec::new();
    if !Path::new("/proc/pressure/cpu").exists() {
        d.push("CPU PSI unavailable".into());
    }
    if !Path::new("/sys/class/hwmon").exists() {
        d.push("hardware sensors unavailable".into());
    }
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        d.push("cgroup v2 unavailable".into());
    }
    d
}
fn read_cpu() -> Vec<(String, CpuTimes)> {
    let Ok(raw) = fs::read_to_string("/proc/stat") else {
        return Vec::new();
    };
    parse_cpu(&raw)
}
fn parse_cpu(raw: &str) -> Vec<(String, CpuTimes)> {
    raw.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let name = f.next()?;
            if !name.starts_with("cpu") {
                return None;
            }
            let v = f.filter_map(|x| x.parse::<u64>().ok()).collect::<Vec<_>>();
            if v.len() < 4 {
                return None;
            }
            let user = v[0] + v.get(1).copied().unwrap_or(0);
            let system = v.get(2).copied().unwrap_or(0)
                + v.get(5).copied().unwrap_or(0)
                + v.get(6).copied().unwrap_or(0);
            let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
            let io = v.get(4).copied().unwrap_or(0);
            Some((
                name.to_string(),
                CpuTimes {
                    total: v.iter().sum(),
                    idle,
                    user,
                    system,
                    iowait: io,
                },
            ))
        })
        .collect()
}
#[derive(Default)]
struct Memory {
    total: u64,
    available: u64,
    cached: u64,
    buffers: u64,
    swap_total: u64,
    swap_free: u64,
}
fn read_meminfo() -> Memory {
    let raw = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    parse_meminfo(&raw)
}
fn parse_meminfo(raw: &str) -> Memory {
    let mut m = Memory::default();
    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let val = v
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_mul(1024);
        match k {
            "MemTotal" => m.total = val,
            "MemAvailable" => m.available = val,
            "Cached" => m.cached = val,
            "Buffers" => m.buffers = val,
            "SwapTotal" => m.swap_total = val,
            "SwapFree" => m.swap_free = val,
            _ => {}
        }
    }
    m
}
fn read_vmstat() -> (u64, u64, u64) {
    let raw = fs::read_to_string("/proc/vmstat").unwrap_or_default();
    parse_vmstat(&raw)
}
fn parse_vmstat(raw: &str) -> (u64, u64, u64) {
    let mut a = 0;
    let mut b = 0;
    let mut oom_kill = 0;
    for l in raw.lines() {
        let mut p = l.split_whitespace();
        match p.next() {
            Some("pswpin") => a = p.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            Some("pswpout") => b = p.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            Some("oom_kill") => oom_kill = p.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    (a, b, oom_kill)
}
fn read_load() -> [f64; 3] {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| {
            let mut i = s.split_whitespace().take(3).filter_map(|x| x.parse().ok());
            Some([i.next()?, i.next()?, i.next()?])
        })
        .unwrap_or([0.0; 3])
}
fn read_uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0) as u64
}
fn read_psi(kind: &str, group: &str) -> Option<f64> {
    let raw = fs::read_to_string(format!("/proc/pressure/{kind}")).ok()?;
    parse_psi_text(&raw, group)
}
fn parse_psi_text(raw: &str, group: &str) -> Option<f64> {
    let row = raw.lines().find(|l| l.starts_with(group))?;
    row.split_whitespace()
        .find_map(|x| x.strip_prefix("avg10=")?.parse().ok())
}
type NetworkCounters = HashMap<String, (u64, u64, u64, u64, u64, u64, u64, u64)>;

fn read_network() -> NetworkCounters {
    let Ok(raw) = fs::read_to_string("/proc/net/dev") else {
        return HashMap::new();
    };
    parse_network(&raw)
}
fn parse_network(raw: &str) -> NetworkCounters {
    raw.lines()
        .skip(2)
        .filter_map(|l| {
            let (name, v) = l.trim().split_once(':')?;
            let f = v
                .split_whitespace()
                .filter_map(|x| x.parse::<u64>().ok())
                .collect::<Vec<_>>();
            if f.len() < 16 {
                return None;
            }
            Some((
                name.trim().to_string(),
                (f[0], f[8], f[1], f[9], f[2], f[3], f[10], f[11]),
            ))
        })
        .collect()
}
fn read_diskstats() -> (u64, u64, u64, u64) {
    let Ok(raw) = fs::read_to_string("/proc/diskstats") else {
        return (0, 0, 0, 0);
    };
    let mut result = (0_u64, 0_u64, 0_u64, 0_u64);
    for (name, read_bytes, write_bytes, reads, writes) in parse_diskstats(&raw) {
        if name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("zram")
            || name.starts_with("dm-")
            || name.starts_with("md")
            || !Path::new(&format!("/sys/block/{name}")).exists()
        {
            continue;
        }
        result.0 = result.0.saturating_add(read_bytes);
        result.1 = result.1.saturating_add(write_bytes);
        result.2 = result.2.saturating_add(reads);
        result.3 = result.3.saturating_add(writes);
    }
    result
}
fn parse_diskstats(raw: &str) -> Vec<(String, u64, u64, u64, u64)> {
    let mut out = Vec::new();
    for l in raw.lines() {
        let f = l.split_whitespace().collect::<Vec<_>>();
        if f.len() < 14 {
            continue;
        }
        out.push((
            f[2].to_string(),
            f[5].parse::<u64>().unwrap_or(0).saturating_mul(512),
            f[9].parse::<u64>().unwrap_or(0).saturating_mul(512),
            f[3].parse::<u64>().unwrap_or(0),
            f[7].parse::<u64>().unwrap_or(0),
        ));
    }
    out
}
fn read_disk_capacity() -> (u64, u64) {
    use std::ffi::CString;
    let path = CString::new("/").unwrap();
    let mut s = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut s) } == 0 {
        let unit = s.f_frsize as u64;
        (s.f_blocks as u64 * unit, s.f_bavail as u64 * unit)
    } else {
        (0, 0)
    }
}
fn read_frequency() -> Option<f64> {
    fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")
        .ok()?
        .trim()
        .parse::<f64>()
        .ok()
        .map(|v| v / 1000.0)
}
fn read_throttle_count() -> u64 {
    fs::read_dir("/sys/devices/system/cpu")
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("cpu"))
        .filter_map(|e| {
            fs::read_to_string(e.path().join("thermal_throttle/core_throttle_count"))
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()
        })
        .sum()
}

pub fn read_temperatures() -> Vec<TemperatureReading> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/hwmon") else {
        return out;
    };
    for entry in entries.flatten() {
        let base = entry.path();
        let device = fs::read_to_string(base.join("name"))
            .unwrap_or_else(|_| "sensor".into())
            .trim()
            .to_string();
        let Ok(files) = fs::read_dir(&base) else {
            continue;
        };
        for file in files.flatten() {
            let fname = file.file_name().to_string_lossy().to_string();
            if !fname.starts_with("temp") || !fname.ends_with("_input") {
                continue;
            }
            let idx = fname.trim_start_matches("temp").trim_end_matches("_input");
            let Ok(raw) = fs::read_to_string(file.path()) else {
                continue;
            };
            let Ok(milli) = raw.trim().parse::<f64>() else {
                continue;
            };
            let label = fs::read_to_string(base.join(format!("temp{idx}_label")))
                .unwrap_or_else(|_| format!("sensor {idx}"))
                .trim()
                .to_string();
            let limit = ["crit", "max"]
                .iter()
                .find_map(|k| {
                    fs::read_to_string(base.join(format!("temp{idx}_{k}")))
                        .ok()?
                        .trim()
                        .parse::<f64>()
                        .ok()
                })
                .map(|v| v / 1000.0);
            out.push(TemperatureReading {
                device: device.clone(),
                sensor: label,
                celsius: milli / 1000.0,
                limit_celsius: limit,
            });
        }
    }
    out
}

async fn read_gpu() -> Option<GpuSnapshot> {
    let command = tokio::process::Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ])
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(3), command)
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()?
        .to_string();
    let f = line.split(',').map(str::trim).collect::<Vec<_>>();
    if f.len() < 6 {
        return None;
    }
    let parse = |s: &str| {
        if s == "[N/A]" || s == "N/A" {
            None
        } else {
            s.parse::<f64>().ok()
        }
    };
    Some(GpuSnapshot {
        name: Some(f[0].to_string()),
        utilization_percent: parse(f[1]),
        memory_used_bytes: parse(f[2]).map(|v| (v * 1024.0 * 1024.0) as u64),
        memory_total_bytes: parse(f[3]).map(|v| (v * 1024.0 * 1024.0) as u64),
        temperature_c: parse(f[4]),
        power_watts: parse(f[5]),
        process_attribution_available: false,
        process_attribution_sampled_at: None,
        processes: Vec::new(),
    })
}

async fn read_gpu_compute_apps() -> Option<Vec<GpuProcessUsage>> {
    let command = tokio::process::Command::new("nvidia-smi")
        .args([
            "--query-compute-apps=pid,process_name,used_memory",
            "--format=csv,noheader,nounits",
        ])
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(3), command)
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(parse_gpu_compute_apps(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_gpu_compute_apps(output: &str) -> Vec<GpuProcessUsage> {
    output
        .lines()
        .take(64)
        .filter_map(|line| {
            let (identity, memory_mib) = line.rsplit_once(',')?;
            let (pid, process_name) = identity.split_once(',')?;
            let pid = pid.trim().parse::<u32>().ok()?;
            let process_name = process_name.trim().to_string();
            let memory_mib = memory_mib.trim().parse::<f64>().ok()?;
            (pid > 0 && !process_name.is_empty() && memory_mib.is_finite() && memory_mib >= 0.0)
                .then_some(GpuProcessUsage {
                    pid,
                    process_name,
                    memory_used_bytes: (memory_mib * 1024.0 * 1024.0) as u64,
                })
        })
        .collect()
}

struct ServiceInventory {
    services: Vec<ServiceSnapshot>,
    user_scope_available: bool,
    system_scope_available: bool,
}

impl ServiceInventory {
    fn available(&self) -> bool {
        self.user_scope_available || self.system_scope_available
    }

    fn complete(&self) -> bool {
        self.user_scope_available && self.system_scope_available
    }
}

fn combine_service_scopes(
    user: Option<Vec<ServiceSnapshot>>,
    system: Option<Vec<ServiceSnapshot>>,
) -> ServiceInventory {
    let user_scope_available = user.is_some();
    let system_scope_available = system.is_some();
    let mut services = user.unwrap_or_default();
    services.extend(system.unwrap_or_default());
    services.sort_by(|a, b| a.name.cmp(&b.name));
    services.dedup_by(|a, b| a.name == b.name);
    services.truncate(500);
    ServiceInventory {
        services,
        user_scope_available,
        system_scope_available,
    }
}

async fn collect_services() -> ServiceInventory {
    let (user, system) = tokio::join!(collect_service_scope(true), collect_service_scope(false));
    // `all` is the user-scope result; a successful empty result is distinct
    // from a missing manager or a failed/timed-out systemctl invocation.
    combine_service_scopes(user, system)
}

async fn collect_service_scope(user: bool) -> Option<Vec<ServiceSnapshot>> {
    let mut command = tokio::process::Command::new("systemctl");
    if user {
        command.arg("--user");
    } else {
        command.arg("--no-ask-password");
    }
    command
        .args([
            "show",
            "--type=service",
            "--property=Id,NRestarts,LoadState,ActiveState,SubState,Description",
            "--no-pager",
        ])
        .kill_on_drop(true);
    let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(3), command.output()).await
    else {
        return None;
    };
    if !output.status.success() {
        return None;
    }
    Some(parse_service_show(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_service_show(raw: &str) -> Vec<ServiceSnapshot> {
    fn finish(properties: &mut HashMap<String, String>, services: &mut Vec<ServiceSnapshot>) {
        let Some(name) = properties.remove("Id") else {
            properties.clear();
            return;
        };
        if name.ends_with(".service") {
            services.push(ServiceSnapshot {
                name,
                load: properties.remove("LoadState").unwrap_or_default(),
                active: properties.remove("ActiveState").unwrap_or_default(),
                sub: properties.remove("SubState").unwrap_or_default(),
                description: properties.remove("Description").unwrap_or_default(),
                restart_count: properties
                    .remove("NRestarts")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0),
            });
        }
        properties.clear();
    }

    let mut services = Vec::new();
    let mut properties = HashMap::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            finish(&mut properties, &mut services);
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key == "Id" && properties.contains_key("Id") {
            finish(&mut properties, &mut services);
        }
        if matches!(
            key,
            "Id" | "NRestarts" | "LoadState" | "ActiveState" | "SubState" | "Description"
        ) {
            properties.insert(key.to_string(), value.to_string());
        }
    }
    finish(&mut properties, &mut services);
    services
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_compute_app_parser_bounds_and_converts_process_memory() {
        let processes = parse_gpu_compute_apps(
            "101, /usr/bin/python3, 256\nnot-a-pid, worker, 20\n202, app, N/A\n303, renderer, 0\n",
        );
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].pid, 101);
        assert_eq!(processes[0].process_name, "/usr/bin/python3");
        assert_eq!(processes[0].memory_used_bytes, 256 * 1024 * 1024);
        assert_eq!(processes[1].pid, 303);
        assert_eq!(processes[1].memory_used_bytes, 0);
    }

    #[test]
    fn psi_parser_reads_avg10() {
        let raw = "some avg10=1.25 avg60=0.70 avg300=0.20 total=42\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0";
        assert_eq!(parse_psi_text(raw, "some"), Some(1.25));
    }
    #[test]
    fn psi_missing_is_none() {
        assert_eq!(parse_psi_text("full avg10=0.0", "some"), None);
    }

    #[test]
    fn cpu_parser_reads_total_and_per_core_counters() {
        let parsed = parse_cpu("cpu  10 2 3 40 5 6 7 8 0 0\ncpu0 5 1 2 20 2 3 4 5 0 0\nintr 123");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "cpu");
        assert_eq!(parsed[0].1.total, 81);
        assert_eq!(parsed[0].1.idle, 45);
        assert_eq!(parsed[1].0, "cpu0");
    }

    #[test]
    fn systemd_show_parser_reads_restart_counts() {
        let parsed = parse_service_show(
            "Id=worker.service\nNRestarts=3\nLoadState=loaded\nActiveState=active\nSubState=running\nDescription=Worker=primary\n\nId=not-a-service.target\nNRestarts=0\nLoadState=loaded\nActiveState=active\nSubState=active\nDescription=Target\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "worker.service");
        assert_eq!(parsed[0].restart_count, 3);
        assert_eq!(parsed[0].description, "Worker=primary");
    }

    #[test]
    fn service_inventory_distinguishes_empty_accessible_scopes_from_unavailable_scopes() {
        let empty_but_accessible = combine_service_scopes(Some(Vec::new()), Some(Vec::new()));
        assert!(empty_but_accessible.available());
        assert!(empty_but_accessible.complete());
        assert!(empty_but_accessible.services.is_empty());

        let partially_accessible = combine_service_scopes(Some(Vec::new()), None);
        assert!(partially_accessible.available());
        assert!(!partially_accessible.complete());
        assert!(partially_accessible.user_scope_available);
        assert!(!partially_accessible.system_scope_available);

        let unavailable = combine_service_scopes(None, None);
        assert!(!unavailable.available());
        assert!(!unavailable.complete());
    }

    #[test]
    fn memory_parser_converts_kib_and_swap_counters_are_separate() {
        let mem = parse_meminfo(
            "MemTotal: 1024 kB\nMemAvailable: 768 kB\nCached: 128 kB\nBuffers: 16 kB\nSwapTotal: 512 kB\nSwapFree: 256 kB\n",
        );
        assert_eq!(mem.total, 1_048_576);
        assert_eq!(mem.available, 786_432);
        assert_eq!(mem.swap_total - mem.swap_free, 262_144);
        assert_eq!(
            parse_vmstat("pswpin 12\npswpout 34\npgfault 99\noom_kill 7\n"),
            (12, 34, 7)
        );
    }

    #[test]
    fn network_parser_preserves_counters_by_interface() {
        let parsed = parse_network(
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 100 2 3 4 5 6 7 8 200 9 10 11 12 13 14 15\n",
        );
        assert_eq!(parsed.get("eth0"), Some(&(100, 200, 2, 9, 3, 4, 10, 11)));
    }

    #[test]
    fn adaptive_pressure_guard_uses_observed_memory_and_psi() {
        let mut host = HostSnapshot {
            memory_total_bytes: 1000,
            memory_available_bytes: 200,
            ..HostSnapshot::default()
        };
        assert!(!host_is_overloaded(&host));
        host.memory_available_bytes = 90;
        assert!(host_is_overloaded(&host));
        host.memory_available_bytes = 200;
        host.psi_cpu_some_percent = Some(51.0);
        assert!(host_is_overloaded(&host));
    }

    #[test]
    fn diskstats_parser_extracts_throughput_and_operation_counters() {
        let rows = parse_diskstats("8 0 sda 10 2 30 40 50 6 70 80 0 90 100 110\n");
        assert_eq!(rows, vec![("sda".into(), 30 * 512, 70 * 512, 10, 50)]);
    }
}
