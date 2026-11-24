import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { StoragePage } from "./StoragePage";
import type { StorageHistory, StorageReport } from "./types";

const apiMocks = vi.hoisted(() => ({ storage: vi.fn(), storageHistory: vi.fn() }));

vi.mock("./api", () => ({ api: apiMocks }));
vi.mock("./Chart", () => ({
  Chart: ({ points }: { points: [number, number][] }) => <div data-testid="storage-chart">{points.length} plotted samples</div>,
}));

const report: StorageReport = {
  sampled_at: Math.floor(Date.now() / 1000),
  last_attempt_at: Math.floor(Date.now() / 1000),
  consecutive_failures: 0,
  severity: "critical",
  policy: {
    sample_seconds: 900,
    history_days: 365,
    warning_used_percent: 80,
    high_used_percent: 90,
    critical_used_percent: 95,
    warning_available_gib: 20,
    high_available_gib: 10,
    critical_available_gib: 5,
    abnormal_growth_gib_per_hour: 1,
    required_writable_mounts: ["/", "/mnt/continental-cloud"],
  },
  history_persistent: true,
  history_budget_bytes: 75 * 1024 ** 2,
  history_samples: 12,
  history_oldest_sample_at: Math.floor(Date.now() / 1000) - 3600,
  history_truncated_by_budget: false,
  mount_errors: [],
  filesystems: [{
    mount_point: "/",
    aliases: [],
    source: "/dev/nvme0n1p2",
    filesystem: "ext4",
    read_only: false,
    required_writable: true,
    total_bytes: 500 * 1024 ** 3,
    used_bytes: 490 * 1024 ** 3,
    free_bytes: 10 * 1024 ** 3,
    available_bytes: 9 * 1024 ** 3,
    unavailable_free_bytes: 1024 ** 3,
    used_percent: 98,
    inode_total: 100_000,
    inode_used: 96_000,
    inode_available: 4_000,
    inode_used_percent: 96,
    growth_bytes_per_hour: null,
    hours_until_full: null,
    severity: "critical",
    reasons: ["capacity is critical"],
  }],
  missing_required_mounts: [],
  error: null,
  history_error: null,
};

const history: StorageHistory = {
  mount_point: "/",
  hours: 168,
  points: [{
    sampled_at: Math.floor(Date.now() / 1000) - 60,
    total_bytes: 500 * 1024 ** 3,
    used_bytes: 490 * 1024 ** 3,
    available_bytes: 9 * 1024 ** 3,
    severity: "critical",
  }],
};

describe("storage investigation page", () => {
  beforeEach(() => {
    apiMocks.storage.mockResolvedValue(report);
    apiMocks.storageHistory.mockResolvedValue(history);
  });

  it("shows measured filesystem capacity, severity, and retained history", async () => {
    render(<StoragePage />);

    expect(await screen.findByRole("heading", { name: "Mounted storage" })).toBeInTheDocument();
    expect(screen.getByText("98.0%", { exact: false })).toBeInTheDocument();
    expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(0);
    expect(await screen.findByTestId("storage-chart")).toHaveTextContent("1 plotted samples");
    expect(screen.getByText(/12 RETAINED/)).toBeInTheDocument();
    expect(screen.getByText(/DB BUDGET/)).toBeInTheDocument();
    expect(apiMocks.storageHistory).toHaveBeenCalledWith("/", 168);
    expect(screen.getByText("4,000 available")).toBeInTheDocument();
  });

  it("explains when filesystem readings work but durable history does not", async () => {
    apiMocks.storage.mockResolvedValue({
      ...report,
      history_persistent: false,
      history_error: "history database unavailable",
    });

    render(<StoragePage />);

    expect(await screen.findByText(/Live capacity readings are available, but historical storage could not be saved/)).toBeInTheDocument();
  });
});
