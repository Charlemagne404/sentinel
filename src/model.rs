use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostSnapshot {
    pub timestamp: i64,
    pub hostname: String,
    pub uptime_seconds: u64,
    pub cpu_percent: f64,
    pub cpu_user_percent: f64,
    pub cpu_system_percent: f64,
    pub cpu_iowait_percent: f64,
    pub per_core: Vec<f64>,
    pub cpu_frequency_mhz: Option<f64>,
    pub load: [f64; 3],
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_cached_bytes: u64,
    pub memory_buffers_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub swap_in_bytes_per_sec: f64,
    pub swap_out_bytes_per_sec: f64,
    pub oom_kill_count: u64,
    pub psi_cpu_some_percent: Option<f64>,
    pub psi_memory_some_percent: Option<f64>,
    pub psi_memory_full_percent: Option<f64>,
    pub psi_io_some_percent: Option<f64>,
    pub cpu_temperature_c: Option<f64>,
    pub cpu_temperature_limit_c: Option<f64>,
    pub temperatures: Vec<TemperatureReading>,
    pub thermal_throttle_count: u64,
    pub disk_total_bytes: u64,
    pub disk_available_bytes: u64,
    pub disk_read_bytes_per_sec: f64,
    pub disk_write_bytes_per_sec: f64,
    pub disk_read_iops: f64,
    pub disk_write_iops: f64,
    pub network_rx_bytes_per_sec: f64,
    pub network_tx_bytes_per_sec: f64,
    pub network_interfaces: Vec<NetworkSnapshot>,
    pub gpu: Option<GpuSnapshot>,
    pub process_count: usize,
    pub active_workloads: usize,
    pub collection_degraded: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSnapshot {
    pub name: Option<String>,
    pub utilization_percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub temperature_c: Option<f64>,
    pub power_watts: Option<f64>,
    pub process_attribution_available: bool,
    pub process_attribution_sampled_at: Option<i64>,
    pub processes: Vec<GpuProcessUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuProcessUsage {
    pub pid: u32,
    pub process_name: String,
    pub memory_used_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkSnapshot {
    pub name: String,
    pub state: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemperatureReading {
    pub device: String,
    pub sensor: String,
    pub celsius: f64,
    pub limit_celsius: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub key: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub name: String,
    pub executable: Option<String>,
    pub state: String,
    pub start_ticks: u64,
    pub runtime_seconds: u64,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub virtual_bytes: u64,
    pub process_group: i32,
    pub session: i32,
    pub cgroup: Option<String>,
    pub workload: String,
    pub parent_disappeared: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLifecycleEvent {
    pub timestamp: i64,
    pub kind: String,
    pub key: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub name: String,
    pub executable: Option<String>,
    pub workload: String,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub runtime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceSnapshot {
    pub name: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
    pub restart_count: u64,
}

impl Default for ServiceSnapshot {
    fn default() -> Self {
        Self {
            name: String::new(),
            load: String::new(),
            active: String::new(),
            sub: String::new(),
            description: String::new(),
            restart_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRestartEvent {
    pub unit: String,
    pub previous_count: u64,
    pub current_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: i64,
    pub signature: String,
    pub severity: String,
    pub title: String,
    pub status: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub recovered_at: Option<i64>,
    pub confidence: f64,
    pub evidence: serde_json::Value,
    pub explanation: String,
}
