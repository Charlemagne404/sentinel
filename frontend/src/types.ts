export type Health = "healthy" | "warning" | "critical";

export interface GpuSnapshot {
  name?: string | null;
  utilization_percent?: number | null;
  memory_used_bytes?: number | null;
  memory_total_bytes?: number | null;
  temperature_c?: number | null;
  power_watts?: number | null;
}
export interface NetworkSnapshot {
  name: string; state: string; rx_bytes: number; tx_bytes: number;
  rx_bytes_per_sec: number; tx_bytes_per_sec: number;
  rx_packets: number; tx_packets: number; rx_errors: number; tx_errors: number;
  rx_dropped: number; tx_dropped: number;
}
export interface TemperatureReading {
  device: string; sensor: string; celsius: number; limit_celsius?: number | null;
}
export interface HostSnapshot {
  timestamp: number; hostname: string; uptime_seconds: number;
  cpu_percent: number; cpu_user_percent: number; cpu_system_percent: number;
  cpu_iowait_percent: number; per_core: number[]; cpu_frequency_mhz?: number | null;
  load: [number, number, number];
  memory_total_bytes: number; memory_available_bytes: number; memory_used_bytes: number;
  memory_cached_bytes: number; memory_buffers_bytes: number;
  swap_total_bytes: number; swap_free_bytes: number;
  swap_in_bytes_per_sec: number; swap_out_bytes_per_sec: number;
  psi_cpu_some_percent?: number | null; psi_memory_some_percent?: number | null;
  psi_memory_full_percent?: number | null; psi_io_some_percent?: number | null;
  cpu_temperature_c?: number | null; cpu_temperature_limit_c?: number | null;
  temperatures: TemperatureReading[]; thermal_throttle_count: number;
  disk_total_bytes: number; disk_available_bytes: number;
  disk_read_bytes_per_sec: number; disk_write_bytes_per_sec: number;
  disk_read_iops: number; disk_write_iops: number;
  network_rx_bytes_per_sec: number; network_tx_bytes_per_sec: number;
  network_interfaces: NetworkSnapshot[]; gpu?: GpuSnapshot | null;
  process_count: number; active_workloads: number; collection_degraded: string[];
}
export interface ProcessSnapshot {
  key: string; pid: number; ppid: number; uid: number; name: string;
  executable?: string | null; state: string; start_ticks: number;
  runtime_seconds: number; cpu_percent: number; rss_bytes: number;
  virtual_bytes: number; process_group: number; session: number;
  cgroup?: string | null; workload: string; parent_disappeared: boolean;
}
export interface Workload {
  name: string; display_name: string; labels: string[]; process_count: number;
  cpu_percent: number; memory_bytes: number; parent_lost_count: number;
}
export interface Incident {
  id: number; signature: string; severity: "informational" | "warning" | "critical";
  title: string; status: "active" | "recovered"; first_seen: number;
  last_seen: number; recovered_at?: number | null; confidence: number;
  evidence: unknown; explanation: string;
}
export interface Baseline {
  metric: string; version: number; samples: number; first_timestamp: number; observed_hours: number;
  median?: number | null; mad?: number | null; ewma?: number | null;
  p95?: number | null; confidence: number; frozen: boolean; updated_at: number;
}
export interface ServiceSnapshot {
  name: string; load: string; active: string; sub: string; description: string;
}
export interface Overview {
  health: Health; host?: HostSnapshot | null; top_processes: ProcessSnapshot[];
  workloads: Workload[]; active_incidents: Incident[];
  service_summary: { total: number; failed: number }; database_bytes: number; updated_at: number;
}
export interface Series { name: string; minutes: number; unit: string; points: [number, number][] }
export interface PublicConfig {
  host_seconds: number; process_seconds: number; hardware_seconds: number; service_seconds: number;
  retention_hours: number; database_budget_mb: number;
  thresholds: {
    memory_available_warning_percent: number; memory_available_critical_percent: number;
    disk_used_warning_percent: number; cpu_pressure_warning_percent: number;
    memory_pressure_warning_percent: number;
  };
  notification_enabled: boolean; notification_provider: string;
  ai_enabled: boolean; ai_provider: string; interface: string; port: number; config_path: string;
  notification_configured: boolean; ai_configured: boolean;
}
