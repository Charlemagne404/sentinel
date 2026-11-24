import { describe, expect, it } from "vitest";
import { flattenProcessTree } from "./process-tree";
import type { ProcessSnapshot } from "./types";

const proc = (pid: number, ppid: number, cpu: number): ProcessSnapshot => ({
  key: `boot:${pid}:1`, pid, ppid, uid: 1000, name: `p${pid}`, state: "S", start_ticks: 1,
  runtime_seconds: 60, cpu_percent: cpu, rss_bytes: 1, virtual_bytes: 2, process_group: pid,
  session: 1, workload: "test", parent_disappeared: false,
});

describe("flattenProcessTree", () => {
  it("places children directly after their parents and orders sibling branches by CPU", () => {
    const rows = flattenProcessTree([proc(30, 10, 1), proc(10, 1, 2), proc(40, 10, 5), proc(1, 0, 0)]);
    expect(rows.map(({ process, depth }) => [process.pid, depth])).toEqual([[1, 0], [10, 1], [40, 2], [30, 2]]);
  });

  it("handles missing parents and circular ancestry without dropping processes", () => {
    const rows = flattenProcessTree([proc(7, 8, 1), proc(8, 7, 2), proc(9, 100, 0)]);
    expect(rows).toHaveLength(3);
    expect(new Set(rows.map(({ process }) => process.pid)).size).toBe(3);
  });
});
