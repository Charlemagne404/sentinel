import type { ProcessSnapshot } from "./types";

export interface TreeRow { process: ProcessSnapshot; depth: number }

export function flattenProcessTree(processes: ProcessSnapshot[]): TreeRow[] {
  const byPid = new Map(processes.map((process) => [process.pid, process]));
  const children = new Map<number, ProcessSnapshot[]>();
  const roots: ProcessSnapshot[] = [];
  for (const process of processes) {
    if (process.ppid !== process.pid && byPid.has(process.ppid)) {
      const list = children.get(process.ppid) ?? [];
      list.push(process);
      children.set(process.ppid, list);
    } else {
      roots.push(process);
    }
  }
  const order = (a: ProcessSnapshot, b: ProcessSnapshot) => b.cpu_percent - a.cpu_percent || a.pid - b.pid;
  roots.sort(order);
  for (const group of children.values()) group.sort(order);
  const result: TreeRow[] = [];
  const seen = new Set<string>();
  const visit = (process: ProcessSnapshot, depth: number) => {
    if (seen.has(process.key)) return;
    seen.add(process.key);
    result.push({ process, depth });
    for (const child of children.get(process.pid) ?? []) visit(child, depth + 1);
  };
  for (const root of roots) visit(root, 0);
  for (const process of processes.slice().sort(order)) visit(process, 0);
  return result;
}
