import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type { HostSnapshot, Overview, ProcessSnapshot } from "./types";

const process: ProcessSnapshot = {
  key: "boot-1:842:1234", pid: 842, ppid: 1, uid: 1000, name: "sentinel-worker",
  executable: "/usr/local/bin/sentinel-worker", state: "S", start_ticks: 1234,
  runtime_seconds: 3600, cpu_percent: 12.5, rss_bytes: 12 * 1024 * 1024,
  virtual_bytes: 80 * 1024 * 1024, process_group: 842, session: 1,
  cgroup: null, workload: "sentinel-worker", parent_disappeared: false,
};
const host: HostSnapshot = {
  timestamp: Math.floor(Date.now() / 1000), hostname: "node-01", uptime_seconds: 86_400,
  cpu_percent: 12.5, cpu_user_percent: 8, cpu_system_percent: 4, cpu_iowait_percent: 0,
  per_core: [12, 13, 14, 11, 12, 13], cpu_frequency_mhz: 3200, load: [0.5, 0.4, 0.3],
  memory_total_bytes: 16 * 1024 ** 3, memory_available_bytes: 8 * 1024 ** 3,
  memory_used_bytes: 8 * 1024 ** 3, memory_cached_bytes: 2 * 1024 ** 3, memory_buffers_bytes: 0,
  swap_total_bytes: 4 * 1024 ** 3, swap_free_bytes: 4 * 1024 ** 3,
  swap_in_bytes_per_sec: 0, swap_out_bytes_per_sec: 0, oom_kill_count: 0,
  psi_cpu_some_percent: 0.1, psi_memory_some_percent: 0, psi_memory_full_percent: 0,
  psi_io_some_percent: 0, cpu_temperature_c: 42, cpu_temperature_limit_c: 100,
  temperatures: [], thermal_throttle_count: 0, disk_total_bytes: 500 * 1024 ** 3,
  disk_available_bytes: 250 * 1024 ** 3, disk_read_bytes_per_sec: 0, disk_write_bytes_per_sec: 0,
  disk_read_iops: 0, disk_write_iops: 0,
  network_rx_bytes_per_sec: 0, network_tx_bytes_per_sec: 0, network_interfaces: [], gpu: null,
  process_count: 1, active_workloads: 1, collection_degraded: [],
};
const overview: Overview = {
  health: "healthy", host, top_processes: [process],
  workloads: [{ name: "sentinel-worker", display_name: "sentinel-worker", labels: [], process_count: 1, cpu_percent: 12.5, memory_bytes: process.rss_bytes, parent_lost_count: 0 }],
  active_incidents: [], data_fresh: true, database_write_ok: true,
  service_summary: { total: 2, failed: 0, available: true }, database_bytes: 4096, updated_at: host.timestamp,
};

const apiMocks = vi.hoisted(() => ({
  overview: vi.fn(), series: vi.fn(), processes: vi.fn(), process: vi.fn(), processLifecycle: vi.fn(), workloads: vi.fn(),
  incidents: vi.fn(), incident: vi.fn(), intelligence: vi.fn(), resetIntelligence: vi.fn(), services: vi.fn(), config: vi.fn(),
  notificationHistory: vi.fn(), authStatus: vi.fn(),
}));
vi.mock("./api", () => ({
  api: apiMocks,
  restoreSession: vi.fn(async () => true),
  signOut: vi.fn(async () => {}),
  signIn: vi.fn(async () => {}),
  finishSetup: vi.fn(async () => {}),
  connectLive: vi.fn(() => ({ close: vi.fn() })),
  ApiError: class ApiError extends Error { constructor(message: string, readonly status: number) { super(message); } },
}));

describe("Sentinel application", () => {
  beforeEach(() => {
    localStorage.clear();
    apiMocks.overview.mockResolvedValue(overview);
    apiMocks.series.mockResolvedValue({ name: "cpu", minutes: 360, unit: "%", points: [] });
    apiMocks.processes.mockResolvedValue({ total: 1, filtered: 1, gpu_attribution: { available: false, sampled_at: null, scope: "NVIDIA compute applications only" }, processes: [process] });
    apiMocks.process.mockResolvedValue({ current: process, history: [] });
    apiMocks.processLifecycle.mockResolvedValue({ minutes: 1440, events: [] });
    apiMocks.workloads.mockResolvedValue({ workloads: overview.workloads });
    apiMocks.incidents.mockResolvedValue({ incidents: [] });
    apiMocks.incident.mockResolvedValue(null);
    apiMocks.intelligence.mockResolvedValue({ baselines: [], seasonal_models: [], baseline_version: 1, baseline_reset_at: Math.floor(Date.now() / 1000), anomalies: [], learning: { maturity: "Confidence grows with clean observations." } });
    apiMocks.resetIntelligence.mockResolvedValue({ baselines: [], baseline_version: 2, baseline_reset_at: Math.floor(Date.now() / 1000) });
    apiMocks.services.mockResolvedValue({ services: [], available: false, complete: false, user_scope_available: false, system_scope_available: false, sampled_at: null, source: "systemctl" });
    apiMocks.config.mockResolvedValue({
      host_seconds: 5, process_seconds: 10, hardware_seconds: 15, service_seconds: 60,
      retention_hours: 48, database_budget_mb: 500,
      thresholds: { memory_available_warning_percent: 8, memory_available_critical_percent: 3, disk_used_warning_percent: 95, cpu_pressure_warning_percent: 20, memory_pressure_warning_percent: 10 },
      notification_enabled: false, notification_provider: "ntfy", notification_configured: false,
      ai_enabled: false, ai_provider: "ollama", ai_configured: false, interface: "tailscale0", port: 8765, config_path: "/home/test/.config/sentinel/config.toml",
    });
    apiMocks.notificationHistory.mockResolvedValue({ notifications: [], delivery_health: { worker_available: true, queue_depth: 0, dropped_jobs: 0, failed_deliveries: 0, consecutive_failures: 0, last_failure_at: null, last_failure_detail: null } });
  });

  it("renders a live overview with real host state and navigates to performance", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(await screen.findByText("node-01")).toBeInTheDocument();
    expect(screen.getByText("No active incidents")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Performance" }));
    expect(await screen.findByRole("heading", { name: "Performance" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Total CPU utilization" })).toBeInTheDocument();
  });

  it("shows safe notification delivery failures in Settings", async () => {
    apiMocks.config.mockResolvedValueOnce({
      host_seconds: 5, process_seconds: 10, hardware_seconds: 15, service_seconds: 60,
      retention_hours: 48, database_budget_mb: 500,
      thresholds: { memory_available_warning_percent: 8, memory_available_critical_percent: 3, disk_used_warning_percent: 95, cpu_pressure_warning_percent: 20, memory_pressure_warning_percent: 10 },
      notification_enabled: true, notification_provider: "ntfy", notification_configured: true,
      ai_enabled: false, ai_provider: "ollama", ai_configured: false, interface: "tailscale0", port: 8765, config_path: "/home/test/.config/sentinel/config.toml",
    });
    apiMocks.notificationHistory.mockResolvedValueOnce({
      notifications: [{ id: 1, incident_id: 2, timestamp: host.timestamp, provider: "ntfy", status: "failed", detail: "provider returned HTTP 401" }],
      delivery_health: { worker_available: true, queue_depth: 0, dropped_jobs: 0, failed_deliveries: 1, consecutive_failures: 1, last_failure_at: host.timestamp, last_failure_detail: "Notification delivery failed: provider returned HTTP 401." },
    });
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(await screen.findByText(/1 consecutive delivery failures/)).toBeInTheDocument();
    expect(screen.getByText(/Notification delivery failed: provider returned HTTP 401/)).toBeInTheDocument();
  });

  it("opens a selected process inspector with observed identity and parent information", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: "Processes" }));
    await screen.findByRole("heading", { name: "Processes" });
    const row = await screen.findByRole("row", { name: /sentinel-worker/ });
    fireEvent.click(row);
    expect(await screen.findByText("PROCESS INSPECTOR / PID 842")).toBeInTheDocument();
    expect(screen.getAllByText("/usr/local/bin/sentinel-worker")).toHaveLength(2);
  });

  it("shows fresh NVIDIA compute-process VRAM in the process explorer", async () => {
    const sampledAt = Math.floor(Date.now() / 1000);
    apiMocks.processes.mockResolvedValue({
      total: 1,
      filtered: 1,
      gpu_attribution: { available: true, sampled_at: sampledAt, scope: "NVIDIA compute applications only" },
      processes: [{ ...process, gpu_memory_bytes: 3 * 1024 ** 3 }],
    });
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: "Processes" }));
    expect(await screen.findByText(/NVIDIA compute-process memory sampled/)).toBeInTheDocument();
    expect(await screen.findByRole("columnheader", { name: "GPU VRAM" })).toBeInTheDocument();
    const row = await screen.findByRole("row", { name: /sentinel-worker/ });
    expect(row).toHaveTextContent("3.00 GiB");
    fireEvent.click(row);
    expect(await screen.findByText("PROCESS INSPECTOR / PID 842")).toBeInTheDocument();
    expect(screen.getAllByText("3.00 GiB")).toHaveLength(2);
  });

  it("shows observed process lifecycle events alongside the live inventory", async () => {
    apiMocks.processLifecycle.mockResolvedValue({ minutes: 1440, events: [{
      timestamp: Math.floor(Date.now() / 1000), kind: "started", key: "boot-1:842:1234",
      pid: 842, ppid: 1, uid: 1000, name: "sentinel-worker", executable: "/usr/local/bin/sentinel-worker",
      workload: "sentinel-worker", cpu_percent: 12.5, rss_bytes: 12 * 1024 * 1024, runtime_seconds: 1,
    }] });
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: "Processes" }));
    expect(await screen.findByRole("heading", { name: "Process lifecycle" })).toBeInTheDocument();
    expect(await screen.findByText(/started · sentinel-worker/)).toBeInTheDocument();
  });

  it("switches to the light theme and persists only the display preference", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: "Switch to light theme" }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("light"));
    expect(localStorage.getItem("sentinel-theme")).toBe("light");
  });

  it("shows a clear empty state when services are not visible", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: "Services" }));
    expect(await screen.findByText("Service inventory unavailable")).toBeInTheDocument();
  });

  it("labels a partial systemd inventory instead of implying it is complete", async () => {
    apiMocks.services.mockResolvedValue({ services: [], available: true, complete: false, user_scope_available: true, system_scope_available: false, sampled_at: Math.floor(Date.now() / 1000), source: "systemctl read-only inventory" });
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: "Services" }));
    expect(await screen.findByText("Partial inventory")).toBeInTheDocument();
    expect(screen.getByText(/system systemd scope is unavailable/)).toBeInTheDocument();
  });

  it("communicates stale samples and an inaccessible service inventory as degraded", async () => {
    apiMocks.overview.mockResolvedValue({
      ...overview,
      health: "warning",
      data_fresh: false,
      sample_age_seconds: 90,
      database_write_ok: false,
      service_summary: { total: 0, failed: 0, available: false },
    });
    render(<App />);
    expect(await screen.findByText("Host data is stale")).toBeInTheDocument();
    expect(screen.getByText("Unable to inspect")).toBeInTheDocument();
    expect(screen.queryByText("No failed units")).not.toBeInTheDocument();
    expect(screen.getByText(/90s ago/)).toBeInTheDocument();
  });

  it("resets a baseline only after an explicit confirmation", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: "Intelligence" }));
    fireEvent.click(await screen.findByRole("button", { name: "Reset baseline" }));
    await waitFor(() => expect(apiMocks.resetIntelligence).toHaveBeenCalledTimes(1));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(/MODEL VERSION 2/)).toBeInTheDocument();
    confirm.mockRestore();
  });
});
