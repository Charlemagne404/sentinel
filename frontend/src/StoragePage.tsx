import { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { Chart } from "./Chart";
import { ago, bytes } from "./format";
import type { FilesystemUsage, StorageHistory, StorageReport } from "./types";
import "./storage.css";

function severityClass(value: string) {
  return value === "ok" ? "ok" : value === "unknown" ? "unknown" : value;
}

function Growth({ filesystem }: { filesystem: FilesystemUsage }) {
  if (filesystem.growth_bytes_per_hour == null) return <>Building a 1-hour baseline</>;
  const direction = filesystem.growth_bytes_per_hour >= 0 ? "+" : "−";
  const amount = bytes(Math.abs(filesystem.growth_bytes_per_hour));
  const estimate = filesystem.hours_until_full;
  return <>{direction}{amount}/h{estimate != null && <small> · {estimate < 48 ? `${estimate.toFixed(1)} hours` : `${(estimate / 24).toFixed(1)} days`} to full at this rate</small>}</>;
}

function UsageMeter({ filesystem }: { filesystem: FilesystemUsage }) {
  return <div className={`storage-meter ${severityClass(filesystem.severity)}`} role="img" aria-label={`${filesystem.used_percent.toFixed(1)} percent used`}>
    <i style={{ width: `${Math.min(100, filesystem.used_percent)}%` }} />
  </div>;
}

export function StoragePage() {
  const [report, setReport] = useState<StorageReport | null>(null);
  const [history, setHistory] = useState<StorageHistory | null>(null);
  const [mountPoint, setMountPoint] = useState("/");
  const [hours, setHours] = useState(24 * 7);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    const refresh = async () => {
      try {
        const next = await api.storage();
        if (live) { setReport(next); setError(""); }
      } catch (cause) {
        if (live) setError(cause instanceof Error ? cause.message : "Storage readings are unavailable.");
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 60_000);
    return () => { live = false; window.clearInterval(timer); };
  }, []);

  const filesystems = report?.filesystems ?? [];
  useEffect(() => {
    if (!filesystems.length) return;
    if (!filesystems.some((filesystem) => filesystem.mount_point === mountPoint)) {
      setMountPoint(filesystems[0].mount_point);
    }
  }, [filesystems, mountPoint]);

  useEffect(() => {
    let live = true;
    if (!mountPoint) return () => { live = false; };
    void api.storageHistory(mountPoint, hours)
      .then((next) => { if (live) setHistory(next); })
      .catch(() => { if (live) setHistory(null); });
    return () => { live = false; };
  }, [mountPoint, hours, report?.sampled_at]);

  const selected = filesystems.find((filesystem) => filesystem.mount_point === mountPoint);
  const points = useMemo(() => history?.points.map((point) => [point.sampled_at, point.used_bytes / (1024 ** 3)] as [number, number]) ?? [], [history]);
  const root = filesystems.find((filesystem) => filesystem.mount_point === "/");
  const summaryFilesystems = [root, ...filesystems.filter((filesystem) => filesystem.mount_point !== "/")]
    .filter((item): item is FilesystemUsage => Boolean(item))
    .slice(0, 3);

  return <>
    <div className="page-heading">
      <div><div className="eyebrow">09 / SENTINEL</div><h1>Storage</h1><p>Filesystem capacity, inode pressure, mount health, and measured growth. Readings use statvfs; no directory walk runs in the monitor loop.</p></div>
      {report && <span className={`storage-severity ${severityClass(report.severity)}`}><i />{report.severity.toUpperCase()}</span>}
    </div>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {report?.error && <div className="inline-error" role="status">Latest storage sample failed at {report.last_attempt_at ? ago(report.last_attempt_at) : "an unknown time"}: {report.error}. Showing the last successful sample.</div>}
    {report?.history_error && <div className="inline-error" role="status">Live capacity readings are available, but historical storage could not be saved: {report.history_error}</div>}
      {report?.mount_errors.map((mount) => <div className="inline-error" role="status" key={mount.mount_point}>Could not measure {mount.mount_point}: {mount.error}</div>)}
    {!report && <section className="instrument-panel"><div className="loading-line"><span className="spinner" />Reading mounted filesystems…</div></section>}
    {report && <>
      {report.missing_required_mounts.length > 0 && <section className="storage-alert critical" role="alert"><strong>Required mount missing or unreadable</strong><span>{report.missing_required_mounts.join(", ")}</span><small>Check the disk and mount state before relying on data stored there.</small></section>}
      <div className="storage-summary-grid">
        {summaryFilesystems.map((filesystem, index) => <section className="instrument-panel storage-summary" key={filesystem.mount_point}>
          <div className="storage-summary-head"><div><span className="eyebrow">{index === 0 && filesystem.mount_point === "/" ? "PRIMARY FILESYSTEM" : "FILESYSTEM"}</span><h2>{filesystem.mount_point}</h2></div><span className={`storage-severity ${severityClass(filesystem.severity)}`}><i />{filesystem.severity.toUpperCase()}</span></div>
          <UsageMeter filesystem={filesystem} />
          <div className="storage-summary-values"><strong>{filesystem.used_percent.toFixed(1)}<small>% used</small></strong><span>{bytes(filesystem.available_bytes)} available of {bytes(filesystem.total_bytes)}</span></div>
          <div className="storage-summary-meta"><span>{filesystem.source} · {filesystem.filesystem}</span><span>{filesystem.read_only ? "HOST MOUNT READ ONLY" : "HOST MOUNT READ / WRITE"}</span></div>
        </section>)}
      </div>
      <section className="instrument-panel storage-history-panel">
        <div className="section-head"><div><span className="eyebrow">CAPACITY HISTORY</span><h2>Used space over time</h2><p>Trend estimates use recorded samples, not file-size scans.</p></div>
          <div className="storage-controls"><label>Filesystem<select value={mountPoint} onChange={(event) => setMountPoint(event.target.value)}>{filesystems.map((filesystem) => <option key={filesystem.mount_point} value={filesystem.mount_point}>{filesystem.mount_point} · {filesystem.source}</option>)}</select></label><label>Range<select value={hours} onChange={(event) => setHours(Number(event.target.value))}><option value={24}>24 hours</option><option value={168}>7 days</option><option value={720}>30 days</option></select></label></div>
        </div>
        {points.length ? <Chart points={points} label="Used space" unit=" GiB" color="#a4e4b5" height={220} /> : <div className="chart-empty tall">Storage history is accumulating. The first growth estimate needs at least one hour of samples.</div>}
        <div className="chart-axis-foot"><span>{history?.points.length ?? 0} PLOTTED · {report.history_samples.toLocaleString()} RETAINED</span><span>
          {report.history_oldest_sample_at && report.sampled_at
            ? `OBSERVED ${(Math.max(0, report.sampled_at - report.history_oldest_sample_at) / 86400).toFixed(1)} DAYS`
            : `REQUESTED ${report.policy.history_days} DAYS`}
          {` · DB BUDGET ${bytes(report.history_budget_bytes)}`}
          {report.history_truncated_by_budget ? " · OLDEST DATA PRUNED AT BUDGET" : ""}
        </span></div>
      </section>
      <section className="instrument-panel storage-table-panel">
        <div className="section-head"><div><span className="eyebrow">FILESYSTEM INVENTORY</span><h2>Mounted storage</h2><p>Aliased mount paths on one filesystem are counted once.</p></div><small>Sampled {report.sampled_at ? ago(report.sampled_at) : "not yet"} · every {report.policy.sample_seconds}s</small></div>
        {filesystems.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>MOUNT / DEVICE</th><th>USED</th><th>AVAILABLE</th><th>INODES</th><th>GROWTH / ESTIMATE</th><th>STATE</th></tr></thead><tbody>{filesystems.map((filesystem) => <tr key={filesystem.mount_point}>
          <td><strong>{filesystem.mount_point}</strong><small className="storage-subline">{filesystem.source} · {filesystem.filesystem}{filesystem.aliases.length ? ` · aliases: ${filesystem.aliases.join(", ")}` : ""}</small></td>
          <td><div className="storage-table-usage"><span>{bytes(filesystem.used_bytes)} / {bytes(filesystem.total_bytes)}</span><strong>{filesystem.used_percent.toFixed(1)}%</strong></div><UsageMeter filesystem={filesystem} /></td>
          <td>{bytes(filesystem.available_bytes)}<small className="storage-subline">{bytes(filesystem.unavailable_free_bytes)} free blocks unavailable to this user</small></td>
          <td>{filesystem.inode_used_percent.toFixed(1)}%<small className="storage-subline">{filesystem.inode_available.toLocaleString()} available</small></td>
          <td><Growth filesystem={filesystem} /></td>
          <td><span className={`storage-severity ${severityClass(filesystem.severity)}`}><i />{filesystem.severity.toUpperCase()}</span>{filesystem.reasons.map((reason) => <small className="storage-subline" key={reason}>{reason}</small>)}</td>
        </tr>)}</tbody></table></div> : <div className="chart-empty">No supported physical or network filesystems were found.</div>}
      </section>
      {selected && <section className="instrument-panel storage-policy-panel">
        <div><span className="eyebrow">ACTIVE POLICY</span><h2>Action thresholds</h2><p>Alerts change severity once per transition and use Sentinel's configured notification cooldown.</p></div>
        <div className="storage-policy-values"><span>Warning <b>{report.policy.warning_used_percent}% used or ≤ {report.policy.warning_available_gib} GiB available</b></span><span>High <b>{report.policy.high_used_percent}% used or ≤ {report.policy.high_available_gib} GiB available</b></span><span>Critical <b>{report.policy.critical_used_percent}% used or ≤ {report.policy.critical_available_gib} GiB available</b></span><span>Required writable <b>{report.policy.required_writable_mounts.join(", ")}</b></span></div>
      </section>}
      {report.consecutive_failures > 0 && <p className="storage-maintenance-state">Storage maintenance: {report.consecutive_failures} consecutive sample failure(s); last success {report.sampled_at ? ago(report.sampled_at) : "none"}.</p>}
    </>}
  </>;
}
