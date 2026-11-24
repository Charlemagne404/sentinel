export type Health = "healthy" | "warning" | "critical";

export interface GpuSnapshot {
  name?: string | null;
  utilization_percent?: number | null;
  memory_used_bytes?: number | null;
  memory_total_bytes?: number | null;
  temperature_c?: number | null;
  power_watts?: number | null;
  process_attribution_available?: boolean;
  process_attribution_sampled_at?: number | null;
  processes?: { pid: number; memory_used_bytes: number }[];
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
  oom_kill_count: number;
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
  gpu_memory_bytes?: number | null;
}
export interface ProcessLifecycleEvent {
  timestamp: number; kind: "started" | "exited" | "parent_lost"; key: string;
  pid: number; ppid: number; uid: number; name: string; executable?: string | null;
  workload: string; cpu_percent: number; rss_bytes: number; runtime_seconds: number;
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
export interface AiInvestigation {
  summary: string;
  confirmed_facts: string[];
  statistical_abnormalities: string[];
  inferences: string[];
  speculation: string[];
  diagnostic_steps: string[];
  confidence: number;
}
export interface Baseline {
  metric: string; version: number; samples: number; first_timestamp: number; observed_hours: number;
  median?: number | null; mad?: number | null; ewma?: number | null;
  p95?: number | null; confidence: number; frozen: boolean; updated_at: number;
}
export interface SeasonalBaseline {
  metric: string; pattern: "hour_of_day_utc" | "hour_of_week_utc";
  periods: number; first_timestamp: number; last_timestamp: number;
  median: number; mad: number; confidence: number;
}
export interface ServiceSnapshot {
  name: string; load: string; active: string; sub: string; description: string; restart_count: number;
}
export interface Overview {
  health: Health; host?: HostSnapshot | null; top_processes: ProcessSnapshot[];
  workloads: Workload[]; active_incidents: Incident[];
  data_fresh?: boolean; sample_age_seconds?: number | null; database_write_ok?: boolean;
  storage_summary?: {
    severity: string; sampled_at: number; sample_fresh: boolean; history_persistent: boolean;
    filesystems: { mount_point: string; used_percent: number; available_bytes: number; severity: string }[];
  };
  service_summary: { total: number; failed: number; available?: boolean }; database_bytes: number; updated_at: number;
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

export interface StoragePolicy {
  sample_seconds: number;
  history_days: number;
  warning_used_percent: number;
  high_used_percent: number;
  critical_used_percent: number;
  warning_available_gib: number;
  high_available_gib: number;
  critical_available_gib: number;
  abnormal_growth_gib_per_hour: number;
  required_writable_mounts: string[];
}
export interface FilesystemUsage {
  mount_point: string;
  aliases: string[];
  source: string;
  filesystem: string;
  read_only: boolean;
  required_writable: boolean;
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
  available_bytes: number;
  unavailable_free_bytes: number;
  used_percent: number;
  inode_total: number;
  inode_used: number;
  inode_available: number;
  inode_used_percent: number;
  growth_bytes_per_hour: number | null;
  hours_until_full: number | null;
  severity: string;
  reasons: string[];
}
export interface StorageReport {
  sampled_at: number;
  last_attempt_at: number;
  consecutive_failures: number;
  severity: string;
  policy: StoragePolicy;
  history_persistent: boolean;
  history_budget_bytes: number;
  history_samples: number;
  history_oldest_sample_at: number | null;
  history_truncated_by_budget: boolean;
  filesystems: FilesystemUsage[];
  mount_errors: { mount_point: string; error: string }[];
  missing_required_mounts: string[];
  error: string | null;
  history_error: string | null;
}
export interface StorageHistory {
  mount_point: string;
  hours: number;
  points: { sampled_at: number; total_bytes: number; used_bytes: number; available_bytes: number; severity: string }[];
}
