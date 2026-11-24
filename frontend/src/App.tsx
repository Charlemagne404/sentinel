import { useCallback, useEffect, useMemo, useState } from "react";
import { api, connectLive, finishSetup, restoreSession, signIn, signOut } from "./api";
import { Chart } from "./Chart";
import { StoragePage } from "./StoragePage";
import { ago, bytes, clockTime, duration, percent, rate } from "./format";
import { flattenProcessTree } from "./process-tree";
import type { AiInvestigation, Baseline, HostSnapshot, Incident, Overview, ProcessLifecycleEvent, ProcessSnapshot, PublicConfig, SeasonalBaseline, ServiceSnapshot, Workload } from "./types";

type View = "overview" | "performance" | "processes" | "workloads" | "incidents" | "intelligence" | "services" | "settings" | "storage";
type Theme = "dark" | "light";
const NAV: { id: View; label: string; index: string; glyph: string }[] = [
  { id: "overview", label: "Overview", index: "01", glyph: "◫" },
  { id: "performance", label: "Performance", index: "02", glyph: "⌁" },
  { id: "processes", label: "Processes", index: "03", glyph: "▤" },
  { id: "workloads", label: "Workloads", index: "04", glyph: "◉" },
  { id: "incidents", label: "Incidents", index: "05", glyph: "!" },
  { id: "intelligence", label: "Intelligence", index: "06", glyph: "⌘" },
  { id: "services", label: "Services", index: "07", glyph: "▥" },
  { id: "settings", label: "Settings", index: "08", glyph: "⚙" },
  { id: "storage", label: "Storage", index: "09", glyph: "▰" },
];

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong. Try again.";
}
function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => localStorage.getItem("sentinel-theme") === "light" ? "light" : "dark");
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("sentinel-theme", theme);
  }, [theme]);
  return [theme, () => setTheme((current) => current === "dark" ? "light" : "dark")];
}

export default function App() {
  const [theme, toggleTheme] = useTheme();
  const [checking, setChecking] = useState(true);
  const [authReady, setAuthReady] = useState(false);
  const [setupRequired, setSetupRequired] = useState(false);
  const [bootstrapFile, setBootstrapFile] = useState("");
  const [pageError, setPageError] = useState("");
  const [authed, setAuthed] = useState(false);
  const [view, setView] = useState<View>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [liveTick, setLiveTick] = useState(0);
  const [connection, setConnection] = useState<"online" | "stale" | "offline">("offline");

  const refreshOverview = useCallback(async () => {
    const next = await api.overview();
    setOverview(next);
    setConnection("online");
    setLiveTick((n) => n + 1);
  }, []);

  const checkAuth = useCallback(async () => {
    setChecking(true);
    setPageError("");
    try {
      if (await restoreSession()) {
        setAuthed(true);
        setAuthReady(true);
      } else {
        const status = await api.authStatus();
        setSetupRequired(status.setup_required);
        setBootstrapFile(status.bootstrap_file ?? "");
        setAuthed(false);
        setAuthReady(true);
      }
    } catch (error) {
      setPageError(errorText(error));
      setAuthReady(false);
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => { void checkAuth(); }, [checkAuth]);

  useEffect(() => {
    if (!authed) return;
    let closed = false;
    let timer: number | undefined;
    const refresh = () => {
      if (timer) window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        void refreshOverview().catch(() => { setConnection("stale"); });
      }, 180);
    };
    void refreshOverview().catch((error) => { setConnection("offline"); setPageError(errorText(error)); });
    const source = connectLive(refresh, () => setConnection((current) => current === "online" ? "stale" : current));
    const poll = window.setInterval(() => {
      if (!closed) void refreshOverview().catch(() => setConnection("stale"));
    }, 15_000);
    return () => {
      closed = true;
      if (timer) window.clearTimeout(timer);
      window.clearInterval(poll);
      source.close();
    };
  }, [authed, refreshOverview]);

  const onAuthenticated = () => {
    setPageError("");
    setAuthed(true);
    setOverview(null);
  };
  const logout = async () => {
    try { await signOut(); } catch { /* clear the local session either way */ }
    setAuthed(false);
    setOverview(null);
  };
  const navigate = (next: View) => { setView(next); setPageError(""); };

  if (checking) return <FullState title="Connecting to Sentinel" detail="Checking this private instance…" />;
  if (!authReady) return <FullState title="Sentinel is unavailable" detail={pageError || "The local service did not respond."} action="Retry connection" onAction={() => void checkAuth()} />;
  if (!authed) return <AuthScreen setup={setupRequired} bootstrapFile={bootstrapFile} error={pageError} onError={setPageError} onDone={onAuthenticated} />;

  const title = NAV.find((item) => item.id === view)?.label ?? "Overview";
  return (
    <div className="app-shell" data-testid="app-shell">
      <aside className="rail">
        <button className="brand" aria-label="Sentinel overview" onClick={() => navigate("overview")}>
          <span className="brand-mark"><i /><i /><i /></span><span className="brand-name">SENTINEL</span>
        </button>
        <div className="rail-caption">SERVER / 01</div>
        <nav className="primary-nav" aria-label="Primary navigation">
          {NAV.map((item) => <button key={item.id} className={`nav-item ${view === item.id ? "active" : ""}`} onClick={() => navigate(item.id)} aria-label={item.label} aria-current={view === item.id ? "page" : undefined}>
            <span className="nav-glyph" aria-hidden="true">{item.glyph}</span><span className="nav-label">{item.label}</span><span className="nav-index">{item.index}</span>
          </button>)}
        </nav>
        <div className="rail-bottom">
          <span className={`connection-dot ${connection}`} />
          <span>{connection === "online" ? "Live connection" : connection === "stale" ? "Reconnecting" : "Waiting for data"}</span>
          <span className="rail-version">v{overview?.host?.hostname ? "0.1" : "—"}</span>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="breadcrumb"><span>HOST</span><b>/</b><strong>{title.toUpperCase()}</strong></div>
          <div className="topbar-actions">
            <span className="host-chip"><span className="connection-dot online" />{overview?.host?.hostname ?? "Sentinel node"}</span>
            <button className="icon-button theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>{theme === "dark" ? "☼" : "◐"}</button>
            <button className="text-button" onClick={() => void logout()}>Sign out <span aria-hidden="true">↗</span></button>
          </div>
        </header>
        {pageError && <div className="toast-error" role="alert"><span>{pageError}</span><button onClick={() => setPageError("")} aria-label="Dismiss error">×</button></div>}
        <div className="page-body">
          {view === "overview" && <OverviewPage overview={overview} tick={liveTick} onNavigate={navigate} />}
          {view === "performance" && <PerformancePage host={overview?.host ?? null} tick={liveTick} />}
          {view === "processes" && <ProcessesPage tick={liveTick} />}
          {view === "workloads" && <WorkloadsPage tick={liveTick} />}
          {view === "incidents" && <IncidentsPage tick={liveTick} onError={setPageError} />}
          {view === "intelligence" && <IntelligencePage tick={liveTick} />}
          {view === "services" && <ServicesPage tick={liveTick} />}
          {view === "settings" && <SettingsPage tick={liveTick} theme={theme} onToggleTheme={toggleTheme} onError={setPageError} />}
          {view === "storage" && <StoragePage />}
        </div>
        <footer className="statusbar"><span><i className={`connection-dot ${connection}`} />{connection === "online" ? "COLLECTING" : connection === "stale" ? "LAST KNOWN STATE" : "OFFLINE"}</span><span>UPDATED {overview?.updated_at ? clockTime(overview.updated_at) : "—"}</span><span>LOCAL SERVER INTELLIGENCE</span></footer>
      </main>
    </div>
  );
}

function FullState({ title, detail, action, onAction }: { title: string; detail: string; action?: string; onAction?: () => void }) {
  return <main className="auth-stage"><div className="auth-panel"><div className="brand-mark large"><i /><i /><i /></div><div className="eyebrow">SENTINEL / PRIVATE NODE</div><h1>{title}</h1><p>{detail}</p>{action && <button className="button primary" onClick={onAction}>{action}</button>}</div></main>;
}

function AuthScreen({ setup, bootstrapFile, error, onError, onDone }: { setup: boolean; bootstrapFile: string; error: string; onError: (value: string) => void; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onError(""); setBusy(true);
    const form = new FormData(event.currentTarget);
    try {
      const password = String(form.get("password") ?? "");
      if (setup) {
        if (password !== String(form.get("confirm") ?? "")) throw new Error("The passwords do not match.");
        await finishSetup(String(form.get("token") ?? "").trim(), password);
      } else {
        await signIn("admin", password);
      }
      onDone();
    } catch (e) { onError(errorText(e)); }
    finally { setBusy(false); }
  };
  return <main className="auth-stage">
    <div className="auth-aside"><div className="brand-mark large"><i /><i /><i /></div><div className="eyebrow">LOCAL SERVER INTELLIGENCE</div><h1>Know the shape<br />of your server.</h1><p>Quietly learn its normal behaviour. Make the unusual clear.</p><div className="auth-signal"><span>CPU</span><i /><i /><i /><i /><i /><i /><i /><span>LIVE</span></div></div>
    <section className="auth-panel">
      <div className="auth-panel-head"><span className="eyebrow">SENTINEL / 01</span><span className="private-label"><i /> PRIVATE ACCESS</span></div>
      <h2>{setup ? "Set up your node" : "Welcome back"}</h2>
      <p className="auth-subtitle">{setup ? "Create the administrator account for this Sentinel instance." : "Sign in to inspect the host and its history."}</p>
      <form onSubmit={(event) => void submit(event)} className="auth-form">
        {setup && <label>One-time setup token<input name="token" type="password" autoComplete="one-time-code" required /></label>}
        <label>Administrator password<input name="password" type="password" autoComplete={setup ? "new-password" : "current-password"} minLength={setup ? 14 : undefined} required autoFocus={!setup} /></label>
        {setup && <><p className="field-hint">Use at least 14 characters with a mix of letters, numbers and symbols.</p><label>Confirm password<input name="confirm" type="password" autoComplete="new-password" minLength={14} required /></label></>}
        {error && <div className="form-error" role="alert">{error}</div>}
        {setup && bootstrapFile && <div className="setup-note"><span className="note-mark">i</span><div><strong>Read the one-time token on the server</strong><code>{bootstrapFile}</code><small>The token is written to this private file and expires after 30 minutes. It is never shown in this page.</small></div></div>}
        <button className="button primary full" type="submit" disabled={busy}>{busy ? "Working…" : setup ? "Create administrator" : "Sign in"}<span aria-hidden="true">↗</span></button>
      </form>
      <div className="auth-foot"><span>AUTHENTICATED SESSION</span><span>HTTP ONLY · SAME ORIGIN</span></div>
    </section>
  </main>;
}

function PageHeading({ index, title, detail, actions }: { index: string; title: string; detail: string; actions?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{index} / SENTINEL</div><h1>{title}</h1><p>{detail}</p></div>{actions && <div className="heading-actions">{actions}</div>}</div>;
}
function Severity({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  return <span className={`severity ${normalized}`}>{value}</span>;
}
function StateLine({ label, value, tone = "" }: { label: string; value: React.ReactNode; tone?: string }) {
  return <div className="state-line"><span>{label}</span><strong className={tone}>{value}</strong></div>;
}
function Empty({ title, detail }: { title: string; detail: string }) { return <div className="empty-state"><span className="empty-mark">∅</span><strong>{title}</strong><p>{detail}</p></div>; }
function LoadingLine({ label = "Loading current observations…" }: { label?: string }) { return <div className="loading-line"><span className="spinner" />{label}</div>; }

function OverviewPage({ overview, tick, onNavigate }: { overview: Overview | null; tick: number; onNavigate: (view: View) => void }) {
  if (!overview?.host) return <><PageHeading index="01" title="Overview" detail="The host will appear after its first collector sample." /><section className="instrument-panel"><LoadingLine label="Waiting for the first system sample…" /></section></>;
  const host = overview.host;
  const freeMem = host.memory_total_bytes ? host.memory_available_bytes / host.memory_total_bytes * 100 : null;
  const swapUsed = host.swap_total_bytes ? (host.swap_total_bytes - host.swap_free_bytes) / host.swap_total_bytes * 100 : 0;
  const rootStorage = overview.storage_summary?.filesystems.find((filesystem) => filesystem.mount_point === "/");
  return <>
    <PageHeading index="01" title="Overview" detail={`${host.hostname} · online for ${duration(host.uptime_seconds)} · sampled ${ago(host.timestamp)}`} actions={<span className={`health-stamp ${overview.health}`}><i />{overview.health.toUpperCase()}</span>} />
    {host.collection_degraded.length > 0 && <div className="degraded-banner"><strong>Partial collection</strong><span>{host.collection_degraded.join(" · ")}</span></div>}
    {overview.data_fresh === false && <div className="degraded-banner" role="status"><strong>Host data is stale</strong><span>Last successful sample {overview.sample_age_seconds == null ? "is unknown" : `${overview.sample_age_seconds}s ago`}. The dashboard is responding, but live monitoring is degraded.</span></div>}
    {overview.database_write_ok === false && overview.data_fresh !== false && <div className="degraded-banner" role="status"><strong>Storage write is failing</strong><span>New observations may not be reaching history.</span></div>}
    <section className="resource-strip" aria-label="Current resource state">
      <ResourceReadout label="CPU" value={percent(host.cpu_percent)} meta={`${host.per_core.length} cores · load ${host.load.map((x) => x.toFixed(2)).join(" / ")}`} tone={host.cpu_percent > 85 ? "warning" : ""} />
      <ResourceReadout label="MEMORY AVAILABLE" value={percent(freeMem, 1)} meta={`${bytes(host.memory_available_bytes)} of ${bytes(host.memory_total_bytes)} free · ${host.oom_kill_count} OOM kills since boot`} tone={freeMem != null && freeMem < 8 ? "warning" : ""} />
      <ResourceReadout label="SWAP USED" value={percent(swapUsed)} meta={host.swap_total_bytes ? `${bytes(host.swap_total_bytes - host.swap_free_bytes)} of ${bytes(host.swap_total_bytes)}` : "No swap configured"} tone={swapUsed > 85 ? "warning" : ""} />
      <ResourceReadout label="CPU TEMPERATURE" value={host.cpu_temperature_c == null ? "—" : `${host.cpu_temperature_c.toFixed(1)}°`} meta={host.cpu_temperature_limit_c ? `hardware limit ${host.cpu_temperature_limit_c.toFixed(0)}°C` : "No sensor limit reported"} />
    </section>
    <div className="overview-grid">
      <section className="instrument-panel overview-trends">
        <div className="section-head"><div><span className="eyebrow">LIVE / LAST 6 HOURS</span><h2>Resource trajectory</h2></div><button className="quiet-link" onClick={() => onNavigate("performance")}>Open performance <span>↗</span></button></div>
        <div className="overview-charts"><MiniSeries metric="cpu" label="CPU UTILIZATION" unit="%" tick={tick} color="var(--mint)" /><MiniSeries metric="memory_used_percent" label="MEMORY USED" unit="%" tick={tick} color="var(--amber)" /><MiniSeries metric="cpu_pressure" label="CPU PRESSURE" unit="%" tick={tick} color="var(--rose)" /></div>
      </section>
      <section className="instrument-panel active-incidents">
        <div className="section-head"><div><span className="eyebrow">ATTENTION / {overview.active_incidents.length.toString().padStart(2, "0")}</span><h2>Active incidents</h2></div><button className="quiet-link" onClick={() => onNavigate("incidents")}>Timeline <span>↗</span></button></div>
        {overview.active_incidents.length === 0 ? <Empty title="No active incidents" detail="The current observation window has no open findings." /> : <div className="incident-list compact">{overview.active_incidents.slice(0, 5).map((incident) => <IncidentRow key={incident.id} item={incident} onClick={() => onNavigate("incidents")} />)}</div>}
      </section>
      <section className="instrument-panel process-panel">
        <div className="section-head"><div><span className="eyebrow">PROCESS TABLE / TOP CPU</span><h2>Resource leaders</h2></div><button className="quiet-link" onClick={() => onNavigate("processes")}>Process explorer <span>↗</span></button></div>
        <ProcessTable processes={overview.top_processes.slice(0, 6)} compact />
      </section>
      <section className="instrument-panel workload-panel">
        <div className="section-head"><div><span className="eyebrow">APPLICATION GROUPS</span><h2>Top workloads</h2></div><button className="quiet-link" onClick={() => onNavigate("workloads")}>Explore <span>↗</span></button></div>
        {overview.workloads.length === 0 ? <Empty title="No workload groups yet" detail="Process attribution will appear after collection." /> : <div className="workload-list">{overview.workloads.slice(0, 5).map((w) => <div className="workload-row" key={w.name}><span className="workload-symbol">◉</span><div className="workload-main"><strong>{w.display_name}</strong><small>{w.process_count} processes{w.parent_lost_count ? ` · ${w.parent_lost_count} parent exits` : ""}</small></div><span className="mono">{w.cpu_percent.toFixed(1)}%</span><span className="mono muted">{bytes(w.memory_bytes)}</span></div>)}</div>}
      </section>
      <section className="instrument-panel service-summary">
        <div className="section-head"><div><span className="eyebrow">SYSTEMD / READ ONLY</span><h2>Service state</h2></div><button className="quiet-link" onClick={() => onNavigate("services")}>View services <span>↗</span></button></div>
        <div className="service-count"><strong>{overview.service_summary.available === false ? "—" : overview.service_summary.total}</strong><span>{overview.service_summary.available === false ? "inventory unavailable" : "visible units"}</span><em className={overview.service_summary.available === false || overview.service_summary.failed ? "warning" : "good"}>{overview.service_summary.available === false ? "Unable to inspect" : overview.service_summary.failed ? `${overview.service_summary.failed} failed` : "No failed units"}</em></div>
        {rootStorage && <div className="storage-line"><span>Root filesystem</span><strong className={rootStorage.severity === "ok" ? "good" : rootStorage.severity === "warning" ? "warning" : "critical-text"}>{rootStorage.used_percent.toFixed(1)}% used · {bytes(rootStorage.available_bytes)} free</strong></div>}
        <div className="storage-line"><span>Database footprint</span><strong>{bytes(overview.database_bytes)}</strong></div>
      </section>
    </div>
  </>;
}
function ResourceReadout({ label, value, meta, tone }: { label: string; value: string; meta: string; tone?: string }) {
  return <div className={`resource-readout ${tone ?? ""}`}><span className="eyebrow">{label}</span><strong>{value}</strong><small>{meta}</small></div>;
}
function IncidentRow({ item, onClick }: { item: Incident; onClick: () => void }) {
  return <button className="incident-row" onClick={onClick}><Severity value={item.severity} /><span className="incident-row-main"><strong>{item.title}</strong><small>{item.explanation}</small></span><span className="incident-age">{ago(item.last_seen)}</span><span className="row-arrow">↗</span></button>;
}

function useSeries(metric: string, minutes: number, tick: number) {
  const [data, setData] = useState<{ points: [number, number][]; unit: string } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    void api.series(metric, minutes).then((result) => { if (live) { setData(result); setError(""); } }).catch((e) => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, [metric, minutes, tick]);
  return { data, error };
}
function MiniSeries({ metric, label, unit, tick, color }: { metric: string; label: string; unit: string; tick: number; color: string }) {
  const { data, error } = useSeries(metric, 360, tick);
  return <div className="mini-series"><div className="mini-series-head"><span>{label}</span><strong>{data?.points.length ? `${data.points.at(-1)?.[1].toFixed(1)}${unit}` : "—"}</strong></div>{error ? <div className="chart-empty">Series unavailable</div> : data?.points.length ? <Chart points={data.points} color={color} height={95} label={label} unit={unit} /> : <div className="chart-empty">Collecting history</div>}</div>;
}

const RANGE: { label: string; minutes: number }[] = [{ label: "1H", minutes: 60 }, { label: "6H", minutes: 360 }, { label: "24H", minutes: 1440 }, { label: "7D", minutes: 10_080 }];
const SERIES: { metric: string; label: string; unit: string; color: string }[] = [
  { metric: "cpu", label: "Total CPU utilization", unit: "%", color: "var(--mint)" },
  { metric: "cpu_user_percent", label: "CPU user time", unit: "%", color: "var(--mint)" },
  { metric: "cpu_system_percent", label: "CPU system time", unit: "%", color: "var(--amber)" },
  { metric: "cpu_iowait_percent", label: "CPU I/O wait", unit: "%", color: "var(--rose)" },
  { metric: "cpu_idle_percent", label: "CPU idle time", unit: "%", color: "var(--blue)" },
  { metric: "memory_used_percent", label: "Memory used", unit: "%", color: "var(--amber)" },
  { metric: "memory_available_percent", label: "Memory available", unit: "%", color: "var(--mint)" },
  { metric: "swap_used_percent", label: "Swap occupied", unit: "%", color: "var(--rose)" },
  { metric: "swap_in_bytes_per_sec", label: "Swap read activity", unit: "MiB/s", color: "var(--amber)" },
  { metric: "swap_out_bytes_per_sec", label: "Swap write activity", unit: "MiB/s", color: "var(--rose)" },
  { metric: "load_1m", label: "Load average · 1m", unit: "load", color: "var(--mint)" },
  { metric: "load_5m", label: "Load average · 5m", unit: "load", color: "var(--mint)" },
  { metric: "load_15m", label: "Load average · 15m", unit: "load", color: "var(--mint)" },
  { metric: "cpu_pressure", label: "CPU pressure · PSI some", unit: "%", color: "var(--rose)" },
  { metric: "memory_pressure", label: "Memory pressure · PSI some", unit: "%", color: "var(--amber)" },
  { metric: "memory_full_pressure", label: "Memory pressure · PSI full", unit: "%", color: "var(--rose)" },
  { metric: "io_pressure", label: "I/O pressure · PSI some", unit: "%", color: "var(--amber)" },
  { metric: "cpu_temperature_c", label: "CPU temperature", unit: "°C", color: "var(--amber)" },
  { metric: "gpu_utilization_percent", label: "GPU utilization", unit: "%", color: "var(--mint)" },
  { metric: "gpu_memory_used_percent", label: "GPU memory used", unit: "%", color: "var(--amber)" },
  { metric: "gpu_temperature_c", label: "GPU temperature", unit: "°C", color: "var(--rose)" },
  { metric: "gpu_power_watts", label: "GPU power", unit: "W", color: "var(--amber)" },
  { metric: "disk_used_percent", label: "Root filesystem used", unit: "%", color: "var(--amber)" },
  { metric: "disk_read_bytes_per_sec", label: "Disk read throughput", unit: "MiB/s", color: "var(--mint)" },
  { metric: "disk_write_bytes_per_sec", label: "Disk write throughput", unit: "MiB/s", color: "var(--amber)" },
  { metric: "disk_read_iops", label: "Disk read operations", unit: "IOPS", color: "var(--mint)" },
  { metric: "disk_write_iops", label: "Disk write operations", unit: "IOPS", color: "var(--amber)" },
  { metric: "network_rx_bytes_per_sec", label: "Network receive", unit: "MiB/s", color: "var(--mint)" },
  { metric: "network_tx_bytes_per_sec", label: "Network transmit", unit: "MiB/s", color: "var(--amber)" },
];
function PerformancePage({ host, tick }: { host: HostSnapshot | null; tick: number }) {
  const [range, setRange] = useState(1);
  const minutes = RANGE[range].minutes;
  const series = [...SERIES, ...(host?.per_core.map((_, index) => ({ metric: `cpu_core_${index}`, label: `CPU core ${index}`, unit: "%", color: "var(--mint)" })) ?? [])];
  return <>
    <PageHeading index="02" title="Performance" detail="Time-series from the local collector. Missing sensors stay blank; values are never synthesized." actions={<div className="segmented">{RANGE.map((r, i) => <button className={i === range ? "selected" : ""} key={r.label} onClick={() => setRange(i)}>{r.label}</button>)}</div>} />
    {host && <div className="inline-summary"><span>NOW</span><b>CPU {percent(host.cpu_percent)}</b><b>MEM {percent(host.memory_total_bytes ? host.memory_used_bytes / host.memory_total_bytes * 100 : null)}</b><b>SWAP {rate(host.swap_in_bytes_per_sec + host.swap_out_bytes_per_sec)}</b><b>GPU {host.gpu?.utilization_percent == null ? "—" : percent(host.gpu.utilization_percent)}</b></div>}
    <div className="performance-grid">{series.map((item) => <MetricPanel key={item.metric} {...item} minutes={minutes} tick={tick} />)}</div>
    {host && <PerformanceDetails host={host} />}
    <div className="page-footnote">Raw samples are retained for 48 hours. Older ranges use minute and quarter-hour aggregates.</div>
  </>;
}
function PerformanceDetails({ host }: { host: HostSnapshot }) {
  return <div className="performance-details-grid">
    <section className="instrument-panel"><div className="section-head"><div><span className="eyebrow">HARDWARE / CURRENT</span><h2>Temperature sensors</h2></div></div>
      <div className="hardware-summary"><span>CPU frequency<strong>{host.cpu_frequency_mhz == null ? "—" : `${host.cpu_frequency_mhz.toFixed(0)} MHz`}</strong></span><span>CPU iowait<strong>{percent(host.cpu_iowait_percent)}</strong></span><span>Thermal throttle count<strong>{host.thermal_throttle_count.toLocaleString()}</strong></span></div>
      {host.temperatures.length ? <div className="sensor-list">{host.temperatures.map((reading) => <div className="sensor-row" key={`${reading.device}-${reading.sensor}`}><span><strong>{reading.sensor}</strong><small>{reading.device}</small></span><b>{reading.celsius.toFixed(1)}°C</b><small>{reading.limit_celsius == null ? "no reported limit" : `limit ${reading.limit_celsius.toFixed(1)}°C`}</small></div>)}</div> : <Empty title="No hardware sensors found" detail="hwmon readings are not available to the current user or host." />}
    </section>
    <section className="instrument-panel"><div className="section-head"><div><span className="eyebrow">INTERFACES / {host.network_interfaces.length}</span><h2>Network activity</h2></div></div>
      {host.network_interfaces.length ? <div className="table-scroll"><table className="data-table interface-table"><thead><tr><th>Interface</th><th>State</th><th>RX / TX rate</th><th>Packets</th><th>Errors / drops</th></tr></thead><tbody>{host.network_interfaces.map((iface) => <tr key={iface.name}><td className="mono">{iface.name}</td><td>{iface.state}</td><td>{rate(iface.rx_bytes_per_sec)} / {rate(iface.tx_bytes_per_sec)}</td><td>{iface.rx_packets.toLocaleString()} / {iface.tx_packets.toLocaleString()}</td><td>{(iface.rx_errors + iface.tx_errors).toLocaleString()} / {(iface.rx_dropped + iface.tx_dropped).toLocaleString()}</td></tr>)}</tbody></table></div> : <Empty title="No interfaces found" detail="The kernel network counters are unavailable." />}
    </section>
    <section className="instrument-panel gpu-panel"><div className="section-head"><div><span className="eyebrow">GPU / OPTIONAL</span><h2>{host.gpu?.name ?? "NVIDIA telemetry"}</h2></div></div>
      {host.gpu ? <div className="detail-facts"><StateLine label="Utilization" value={percent(host.gpu.utilization_percent)} /><StateLine label="VRAM" value={host.gpu.memory_used_bytes == null || host.gpu.memory_total_bytes == null ? "—" : `${bytes(host.gpu.memory_used_bytes)} / ${bytes(host.gpu.memory_total_bytes)}`} /><StateLine label="Temperature" value={host.gpu.temperature_c == null ? "—" : `${host.gpu.temperature_c.toFixed(1)}°C`} /><StateLine label="Power" value={host.gpu.power_watts == null ? "—" : `${host.gpu.power_watts.toFixed(1)} W`} /></div> : <Empty title="GPU telemetry unavailable" detail="NVIDIA metrics require an accessible nvidia-smi binary and device." />}
    </section>
  </div>;
}
function MetricPanel({ metric, label, unit, color, minutes, tick }: { metric: string; label: string; unit: string; color: string; minutes: number; tick: number }) {
  const { data, error } = useSeries(metric, minutes, tick);
  const present = Boolean(data?.points.length);
  const current = present ? data!.points.at(-1)![1] : null;
  const displayUnit = unit;
  const points = useMemo(() => data?.points.map(([ts, value]) => [ts, unit === "MiB/s" ? value / (1024 * 1024) : value] as [number, number]) ?? [], [data, unit]);
  return <section className="instrument-panel metric-panel"><div className="metric-panel-head"><div><span className="eyebrow">{metric.replaceAll("_", " ").toUpperCase()}</span><h2>{label}</h2></div><strong className="metric-current">{current == null ? "—" : `${unit === "MiB/s" ? (current / 1024 / 1024).toFixed(2) : current.toFixed(1)}${displayUnit}`}</strong></div>
    {error ? <div className="chart-empty">Could not read this series.</div> : present ? <Chart points={points} label={label} unit={displayUnit === "MiB/s" ? " MiB/s" : displayUnit === "load" ? "" : displayUnit} color={color} height={178} /> : <div className="chart-empty tall">No samples in this time range{metric.includes("gpu") || metric.includes("temperature") ? "; sensor may be unavailable" : " yet"}.</div>}
    <div className="chart-axis-foot"><span>{minutes >= 1440 ? `${minutes / 1440}D RANGE` : `${minutes} MIN RANGE`}</span><span>{points.length ? `${points.length} SAMPLES` : "NO DATA"}</span></div>
  </section>;
}

function ProcessesPage({ tick }: { tick: number }) {
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState("cpu");
  const [treeMode, setTreeMode] = useState(false);
  const [processes, setProcesses] = useState<ProcessSnapshot[]>([]);
  const [total, setTotal] = useState(0);
  const [lifecycle, setLifecycle] = useState<ProcessLifecycleEvent[]>([]);
  const [gpuAttribution, setGpuAttribution] = useState<{ available: boolean; sampled_at: number | null; scope: string } | null>(null);
  const [selected, setSelected] = useState<ProcessSnapshot | null>(null);
  const [detail, setDetail] = useState<{ current: ProcessSnapshot | null; history: Record<string, number | string | boolean>[] } | null>(null);
  const [error, setError] = useState("");
  const selectedProcess = selected ? processes.find((process) => process.key === selected.key) ?? selected : null;
  useEffect(() => {
    let live = true;
    void api.processes(search, treeMode ? "tree" : sort).then((result) => { if (live) { setProcesses(result.processes); setTotal(result.total); setGpuAttribution(result.gpu_attribution); setError(""); } }).catch((e) => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, [search, sort, treeMode, tick]);
  useEffect(() => {
    let live = true;
    void api.processLifecycle().then((result) => { if (live) setLifecycle(result.events); }).catch((e) => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, [tick]);
  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    let live = true;
    void api.process(selected.key).then((result) => { if (live) setDetail(result); }).catch((e) => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, [selected, tick]);
  return <>
    <PageHeading index="03" title="Processes" detail={`${total.toLocaleString()} observed · identity combines boot session, PID and process start ticks`} />
    {gpuAttribution && gpuAttribution.sampled_at && <p className="secondary-line">{gpuAttribution.available ? `NVIDIA compute-process memory sampled ${ago(gpuAttribution.sampled_at)}.` : `NVIDIA compute-process attribution was unavailable at ${ago(gpuAttribution.sampled_at)}.`} Graphics-process memory may not be visible.</p>}
    {error && <InlineError text={error} />}
    <section className="instrument-panel process-explorer">
      <div className="table-toolbar"><label className="search-box"><span>⌕</span><input aria-label="Search processes" placeholder="Search name, executable, workload or PID" value={search} onChange={(e) => setSearch(e.target.value)} /></label><label className="select-control">SORT <select value={sort} disabled={treeMode} onChange={(e) => setSort(e.target.value)}><option value="cpu">CPU</option><option value="memory">Memory</option><option value="runtime">Runtime</option></select></label><button className={`filter-button tree-toggle ${treeMode ? "on" : ""}`} aria-pressed={treeMode} onClick={() => setTreeMode((value) => !value)}>Process tree</button><span className="table-count">{processes.length} SHOWN</span></div>
      <ProcessTable processes={processes} onSelect={setSelected} selectedKey={selected?.key} treeMode={treeMode} />
    </section>
    <section className="instrument-panel detail-panel">
      <div className="section-head"><div><span className="eyebrow">OBSERVED CHANGES / LAST 24 HOURS</span><h2>Process lifecycle</h2></div><small className="table-count">POLLING DETECTION</small></div>
      {lifecycle.length ? <div className="anomaly-list">{lifecycle.map((event, index) => <div className="anomaly-row" key={`${event.timestamp}-${event.key}-${event.kind}-${index}`}><span className="anomaly-time">{ago(event.timestamp)}</span><strong>{event.kind.replaceAll("_", " ")} · {event.name}</strong><span className="mono">PID {event.pid}</span><small>{event.workload} · {event.executable ?? `UID ${event.uid}`} · {event.cpu_percent.toFixed(1)}% CPU · {bytes(event.rss_bytes)} RSS</small></div>)}</div> : <Empty title="No lifecycle changes observed yet" detail="Sentinel records starts and exits between successful process polls. Processes shorter than the polling interval can be missed." />}
    </section>
    {selectedProcess && <section className="instrument-panel detail-panel">
      <div className="section-head"><div><span className="eyebrow">PROCESS INSPECTOR / PID {selectedProcess.pid}</span><h2>{selectedProcess.name}</h2></div><button className="icon-button" onClick={() => setSelected(null)} aria-label="Close process details">×</button></div>
      {detail?.current ? <><div className="detail-facts"><StateLine label="Executable" value={detail.current.executable ?? "Not exposed"} /><StateLine label="Workload" value={detail.current.workload} /><StateLine label="Parent PID" value={detail.current.ppid} /><StateLine label="Runtime" value={duration(detail.current.runtime_seconds)} /><StateLine label="Memory RSS" value={bytes(detail.current.rss_bytes)} />{selectedProcess.gpu_memory_bytes != null && <StateLine label="GPU memory" value={bytes(selectedProcess.gpu_memory_bytes)} />}<StateLine label="Parent identity" value={detail.current.parent_disappeared ? "Previously observed parent exited" : "Present or not established"} tone={detail.current.parent_disappeared ? "warning" : ""} /></div><div className="inspector-chart"><span className="eyebrow">CPU HISTORY / LAST 48 HOURS</span>{detail.history.length ? <Chart points={detail.history.map((p) => [Number(p.timestamp), Number(p.cpu_percent)] as [number, number])} label="Process CPU" unit="%" color="var(--mint)" height={170} /> : <div className="chart-empty">No persisted history for this process yet.</div>}</div></> : <LoadingLine label="Loading process history…" />}
    </section>}
  </>;
}
function ProcessTable({ processes, compact = false, onSelect, selectedKey, treeMode = false }: { processes: ProcessSnapshot[]; compact?: boolean; onSelect?: (process: ProcessSnapshot) => void; selectedKey?: string; treeMode?: boolean }) {
  if (!processes.length) return <Empty title="No matching processes" detail="Try a shorter search or wait for the next collector sample." />;
  const rows = treeMode ? flattenProcessTree(processes) : processes.map((process) => ({ process, depth: 0 }));
  const hasGpuMemory = rows.some(({ process }) => process.gpu_memory_bytes != null && process.gpu_memory_bytes > 0);
  return <div className="table-wrap"><table className={`data-table process-table ${compact ? "compact-table" : ""}`}><thead><tr><th>PROCESS</th><th>PID / PARENT</th><th>WORKLOAD</th><th>CPU</th><th>MEMORY</th>{hasGpuMemory && <th>GPU VRAM</th>}<th>RUNTIME</th></tr></thead><tbody>{rows.map(({ process: p, depth }) => <tr key={p.key} className={`${onSelect ? "selectable" : ""} ${selectedKey === p.key ? "selected-row" : ""}`} onClick={() => onSelect?.(p)} onKeyDown={(e) => { if (onSelect && (e.key === "Enter" || e.key === " ")) onSelect(p); }} tabIndex={onSelect ? 0 : undefined}>
    <td><div className="process-tree-name" style={{ paddingLeft: `${depth * 13}px` }}>{treeMode && depth > 0 && <span aria-hidden="true">↳</span>}<strong className="process-name">{p.name}</strong></div><small className="secondary-line">{p.executable ?? `UID ${p.uid}`} {p.parent_disappeared && <em className="warning-label">PARENT EXITED</em>}</small></td><td className="mono">{p.pid}<small className="secondary-line">parent {p.ppid}</small></td><td><span className="tag">{p.workload}</span></td><td className="mono">{p.cpu_percent.toFixed(1)}%</td><td className="mono">{bytes(p.rss_bytes)}</td>{hasGpuMemory && <td className="mono">{p.gpu_memory_bytes ? bytes(p.gpu_memory_bytes) : "—"}</td>}<td className="mono">{duration(p.runtime_seconds)}</td>
  </tr>)}</tbody></table></div>;
}

function WorkloadsPage({ tick }: { tick: number }) {
  const [workloads, setWorkloads] = useState<Workload[]>([]);
  const [labels, setLabels] = useState<Record<string, { display: string; tags: string }>>({});
  const [saving, setSaving] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    void api.workloads().then(({ workloads: next }) => { if (live) { setWorkloads(next); setLabels((old) => Object.fromEntries(next.map((w) => [w.name, old[w.name] ?? { display: w.display_name, tags: w.labels.join(", ") }]))); } }).catch((e) => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, [tick]);
  const save = async (w: Workload) => {
    const form = labels[w.name] ?? { display: w.name, tags: "" };
    setSaving(w.name); setError("");
    try { await api.labelWorkload(w.name, form.display, form.tags.split(",").map((x) => x.trim()).filter(Boolean)); setWorkloads((items) => items.map((x) => x.name === w.name ? { ...x, display_name: form.display.trim() || w.name, labels: form.tags.split(",").map((x) => x.trim()).filter(Boolean) } : x)); }
    catch (e) { setError(errorText(e)); }
    finally { setSaving(""); }
  };
  return <>
    <PageHeading index="04" title="Workloads" detail="Processes grouped by executable and service context. Labels are local annotations; Sentinel does not control workloads." />
    {error && <InlineError text={error} />}
    {!workloads.length ? <section className="instrument-panel"><Empty title="No workload groups yet" detail="Groups appear after the process collector completes its first observation." /></section> : <div className="workload-explorer">{workloads.map((w, i) => <section className="instrument-panel workload-detail" key={w.name}><div className="workload-index">{String(i + 1).padStart(2, "0")}</div><div className="workload-content"><div className="workload-top"><div><span className="eyebrow">{w.name}</span><h2>{w.display_name}</h2></div><span className="workload-active">{w.process_count} PROCESS{w.process_count === 1 ? "" : "ES"}</span></div><div className="workload-metrics"><div><span>CPU</span><strong>{w.cpu_percent.toFixed(1)}<small>%</small></strong></div><div><span>MEMORY RSS</span><strong>{bytes(w.memory_bytes)}</strong></div><div><span>PARENT EXITS</span><strong className={w.parent_lost_count ? "warning" : ""}>{w.parent_lost_count}</strong></div></div><div className="workload-label-form"><label>DISPLAY NAME<input value={labels[w.name]?.display ?? w.display_name} onChange={(e) => setLabels((old) => ({ ...old, [w.name]: { display: e.target.value, tags: old[w.name]?.tags ?? w.labels.join(", ") } }))} /></label><label>LOCAL TAGS<input placeholder="e.g. production, database" value={labels[w.name]?.tags ?? w.labels.join(", ")} onChange={(e) => setLabels((old) => ({ ...old, [w.name]: { display: old[w.name]?.display ?? w.display_name, tags: e.target.value } }))} /></label><button className="button secondary" disabled={saving === w.name} onClick={() => void save(w)}>{saving === w.name ? "Saving…" : "Save labels"}</button></div></div></section>)}</div>}
  </>;
}

function IncidentsPage({ tick, onError }: { tick: number; onError: (value: string) => void }) {
  const [items, setItems] = useState<Incident[]>([]);
  const [activeOnly, setActiveOnly] = useState(false);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [detail, setDetail] = useState<Incident | null>(null);
  const [investigation, setInvestigation] = useState<AiInvestigation | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    void api.incidents(activeOnly).then(({ incidents }) => { if (live) setItems(incidents); }).catch((e) => onError(errorText(e)));
    return () => { live = false; };
  }, [activeOnly, tick, onError]);
  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    let live = true;
    void api.incident(selected.id).then((item) => { if (live) setDetail(item); }).catch((e) => onError(errorText(e)));
    return () => { live = false; };
  }, [selected, tick, onError]);
  const investigate = async () => {
    if (!selected) return;
    setBusy(true); setInvestigation(null); onError("");
    try { const result = await api.investigate(selected.id); setInvestigation(result.analysis); }
    catch (e) { onError(errorText(e)); }
    finally { setBusy(false); }
  };
  return <>
    <PageHeading index="05" title="Incidents" detail="Correlated findings with measured evidence, confidence and recovery state." actions={<button className={`filter-button ${activeOnly ? "on" : ""}`} onClick={() => setActiveOnly((x) => !x)}><i /> Active only</button>} />
    <div className={`incident-workspace ${selected ? "has-selection" : ""}`}>
      <section className="instrument-panel incident-timeline"><div className="section-head"><div><span className="eyebrow">TIMELINE / {items.length.toString().padStart(2, "0")}</span><h2>{activeOnly ? "Open findings" : "Recent findings"}</h2></div></div>
        {items.length ? <div className="incident-list">{items.map((item) => <button className={`timeline-item ${selected?.id === item.id ? "selected" : ""}`} key={item.id} onClick={() => { setSelected(item); setInvestigation(null); }}><span className={`timeline-marker ${item.severity}`} /><span className="timeline-date">{ago(item.first_seen)}</span><strong>{item.title}</strong><small>{item.explanation}</small><span className="timeline-meta"><Severity value={item.severity} /><span>{item.status}</span><span>{Math.round(item.confidence * 100)}% confidence</span></span></button>)}</div> : <Empty title="No incidents in this view" detail={activeOnly ? "There are no open incidents." : "The observation window has not produced a finding."} />}
      </section>
      {selected && <aside className="instrument-panel incident-detail"><div className="detail-topline"><span className="eyebrow">INCIDENT / #{selected.id}</span><button className="icon-button" aria-label="Close incident detail" onClick={() => setSelected(null)}>×</button></div>{detail ? <>
        <Severity value={detail.severity} /><h2>{detail.title}</h2><p className="incident-explanation">{detail.explanation}</p><div className="detail-facts"><StateLine label="Status" value={detail.status} /><StateLine label="First observed" value={new Date(detail.first_seen * 1000).toLocaleString()} /><StateLine label="Last observed" value={new Date(detail.last_seen * 1000).toLocaleString()} /><StateLine label="Confidence" value={`${Math.round(detail.confidence * 100)}%`} /></div>
        <div className="evidence-block"><span className="eyebrow">SUPPORTING EVIDENCE</span><pre>{JSON.stringify(detail.evidence, null, 2)}</pre></div>
        <div className="evidence-block"><span className="eyebrow">INTERPRETATION</span><p>Observed measurements and statistical findings are shown separately from inferred causes. Review the evidence before acting.</p></div>
        <button className="button secondary full" onClick={() => void investigate()} disabled={busy}>{busy ? "Checking host pressure…" : "Request local AI investigation"}</button><small className="field-hint">Runs only when a local endpoint is configured, AI is enabled and the host has sufficient headroom.</small>
        {investigation && <div className="ai-result"><div className="ai-result-head"><span className="eyebrow">LOCAL MODEL INTERPRETATION</span><span>{Math.round(investigation.confidence * 100)}% model-reported confidence</span></div><p>{investigation.summary}</p>
          <AiSection title="Model-classified facts" items={investigation.confirmed_facts} />
          <AiSection title="Statistical abnormalities" items={investigation.statistical_abnormalities} />
          <AiSection title="Inferences" items={investigation.inferences} />
          <AiSection title="Speculation" items={investigation.speculation} />
          <AiSection title="Read-only diagnostic suggestions" items={investigation.diagnostic_steps} />
          <small>AI-generated categories and confidence are not independently calibrated. Compare them with Sentinel's measured evidence above.</small>
        </div>}
      </> : <LoadingLine label="Loading incident evidence…" />}</aside>}
    </div>
  </>;
}

function AiSection({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return <section className="ai-result-section"><strong>{title}</strong><ul>{items.map((item, index) => <li key={`${title}-${index}`}>{item}</li>)}</ul></section>;
}

function IntelligencePage({ tick }: { tick: number }) {
  const [baselines, setBaselines] = useState<Baseline[]>([]);
  const [seasonalModels, setSeasonalModels] = useState<SeasonalBaseline[]>([]);
  const [anomalies, setAnomalies] = useState<Record<string, unknown>[]>([]);
  const [learning, setLearning] = useState("");
  const [error, setError] = useState("");
  const [baselineVersion, setBaselineVersion] = useState(1);
  const [baselineResetAt, setBaselineResetAt] = useState(0);
  const [resetting, setResetting] = useState(false);
  useEffect(() => {
    let live = true;
    void api.intelligence().then((result) => { if (live) { setBaselines(result.baselines); setSeasonalModels(result.seasonal_models ?? []); setAnomalies(result.anomalies); setLearning(String(result.learning.maturity ?? "")); setBaselineVersion(result.baseline_version); setBaselineResetAt(result.baseline_reset_at); } }).catch((e) => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, [tick]);
  const resetBaseline = async () => {
    if (!window.confirm("Reset the learned baselines? Existing metric and incident history will be kept; Sentinel will begin a new calibration window.")) return;
    setResetting(true);
    setError("");
    try {
      const result = await api.resetIntelligence();
      setBaselines(result.baselines);
      setBaselineVersion(result.baseline_version);
      setBaselineResetAt(result.baseline_reset_at);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setResetting(false);
    }
  };
  return <>
    <PageHeading index="06" title="Intelligence" detail="Statistical learning is deliberately cautious. Safety thresholds work immediately; behavioural baselines need clean history." />
    {error && <InlineError text={error} />}
    <section className="intelligence-callout"><span className="callout-symbol">⌘</span><div><span className="eyebrow">CALIBRATION POLICY</span><strong>{learning || "Confidence grows with clean observations."}</strong><p>Rolling models need at least 48 clean hours. Time-of-day models need 14 clean daily windows; weekday and hour models need four clean weekly repetitions. Incident and candidate intervals are excluded.</p></div><div className="calibration-minimum"><strong>48h</strong><small>ROLLING MINIMUM</small></div></section>
    <section className="instrument-panel seasonal-panel"><div className="section-head"><div><span className="eyebrow">TIME AWARE / {seasonalModels.length.toString().padStart(2, "0")} MATURE MODELS</span><h2>Observed periodic patterns</h2></div></div>{seasonalModels.length ? <div className="seasonal-model-list">{seasonalModels.map((model) => <div className="seasonal-model-row" key={`${model.metric}-${model.pattern}`}><strong>{baselineLabel(model.metric)}</strong><span>{model.pattern === "hour_of_week_utc" ? "Weekday × hour · UTC" : "Time of day · UTC"}</span><span>{model.periods} clean periods</span><span>MED <b>{model.median.toFixed(2)}</b> · MAD <b>{model.mad.toFixed(2)}</b></span><span className="seasonal-confidence">{Math.round(model.confidence * 100)}% evidence</span></div>)}</div> : <p className="seasonal-empty">No seasonal pattern has met its minimum evidence window yet. Sentinel will compare a metric to matching UTC hours only after enough clean daily or weekly periods are present.</p>}</section>
    <div className="intelligence-grid"><section className="instrument-panel baseline-panel"><div className="section-head"><div><span className="eyebrow">MODEL VERSION {baselineVersion} / {baselines.length} METRICS</span><h2>Metric baselines</h2><small className="model-reset-date">Calibration began {baselineResetAt ? ago(baselineResetAt) : "with Sentinel"}</small></div><button className="button secondary" type="button" onClick={() => void resetBaseline()} disabled={resetting}>{resetting ? "Resetting…" : "Reset baseline"}</button></div>{baselines.length ? <div className="baseline-list">{baselines.map((b) => <div className="baseline-row" key={b.metric}><div className="baseline-name"><strong>{baselineLabel(b.metric)}</strong><small>{b.samples.toLocaleString()} clean minute samples · {b.observed_hours.toFixed(1)} observed hours</small></div><div className="baseline-progress"><div><i style={{ width: `${Math.min(100, b.confidence * 100)}%` }} /></div><span>{Math.round(b.confidence * 100)}%</span></div><div className="baseline-stats"><span>MEDIAN <b>{b.median == null ? "—" : b.median.toFixed(2)}</b></span><span>MAD <b>{b.mad == null ? "—" : b.mad.toFixed(2)}</b></span><span>P95 <b>{b.p95 == null ? "—" : b.p95.toFixed(2)}</b></span><em className={b.frozen ? "warning-label" : ""}>{b.frozen ? "FROZEN" : "LEARNING"}</em></div></div>)}</div> : <Empty title="Baselines are forming" detail="Sentinel uses immediate safety thresholds while collecting enough clean observations for robust statistics." />}</section>
    <section className="instrument-panel anomaly-panel"><div className="section-head"><div><span className="eyebrow">LAST 7 DAYS / {anomalies.length}</span><h2>Recent anomalies</h2></div></div>{anomalies.length ? <div className="anomaly-list">{anomalies.map((a, i) => <div className="anomaly-row" key={`${String(a.timestamp)}-${i}`}><span className="anomaly-time">{typeof a.timestamp === "number" ? ago(a.timestamp) : "—"}</span><strong>{String(a.metric ?? "finding").replaceAll("_", " ")}</strong><span className="mono">{typeof a.value === "number" ? a.value.toFixed(2) : "—"}</span><small>{String(a.reason ?? "")}</small></div>)}</div> : <Empty title="No anomaly events yet" detail="Unusual values only appear after the relevant baseline matures or a safety rule triggers." />}</section></div>
  </>;
}

function baselineLabel(metric: string): string {
  const match = /^workload::(.+)~[0-9a-f]{16}::(cpu_percent|rss_bytes|process_count)$/.exec(metric);
  if (!match) return metric.replaceAll("_", " ");
  let workload = match[1];
  try { workload = decodeURIComponent(workload); } catch { /* Keep the stored label readable if malformed. */ }
  const label = match[2] === "cpu_percent" ? "CPU" : match[2] === "rss_bytes" ? "RSS" : "process count";
  return `${workload} · ${label}`;
}

function ServicesPage({ tick }: { tick: number }) {
  const [services, setServices] = useState<ServiceSnapshot[]>([]);
  const [available, setAvailable] = useState(false);
  const [complete, setComplete] = useState(false);
  const [userScopeAvailable, setUserScopeAvailable] = useState(false);
  const [systemScopeAvailable, setSystemScopeAvailable] = useState(false);
  const [source, setSource] = useState("");
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    void api.services().then((result) => {
      if (!live) return;
      setServices(result.services);
      setAvailable(result.available);
      setComplete(result.complete);
      setUserScopeAvailable(result.user_scope_available);
      setSystemScopeAvailable(result.system_scope_available);
      setSource(result.source);
    }).catch((e) => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, [tick]);
  const filtered = services.filter((s) => `${s.name} ${s.description} ${s.active}`.toLowerCase().includes(filter.toLowerCase()));
  const unavailableScopes = [
    !userScopeAvailable && "user",
    !systemScopeAvailable && "system",
  ].filter(Boolean).join(" and ");
  return <>
    <PageHeading index="07" title="Services" detail="Read-only systemd inventory. Sentinel never starts, stops or changes another service." actions={<span className="read-only-label"><i /> READ ONLY</span>} />
    {error && <InlineError text={error} />}
    {!available ? <section className="instrument-panel"><Empty title="Service inventory unavailable" detail="Neither systemd scope could be read. The service manager may be unavailable or permissions may limit visibility." /></section> : <>
      {!complete && <div className="degraded-banner" role="status"><strong>Partial inventory</strong><span>The {unavailableScopes} systemd scope is unavailable; this list may omit units.</span></div>}
      <section className="instrument-panel service-explorer"><div className="table-toolbar"><label className="search-box"><span>⌕</span><input aria-label="Filter services" placeholder="Filter units" value={filter} onChange={(e) => setFilter(e.target.value)} /></label><span className="table-count">{filtered.length} UNITS · {source}</span></div><div className="table-wrap">{filtered.length ? <table className="data-table"><thead><tr><th>UNIT</th><th>DESCRIPTION</th><th>LOAD</th><th>ACTIVE</th><th>SUB STATE</th><th>RESTARTS</th></tr></thead><tbody>{filtered.map((s) => <tr key={s.name}><td><strong className="service-name">{s.name}</strong></td><td className="secondary-text">{s.description || "—"}</td><td><span className="tag">{s.load}</span></td><td><span className={`service-state ${s.active === "active" ? "good" : s.active === "failed" ? "bad" : ""}`}><i />{s.active}</span></td><td className="mono">{s.sub}</td><td className="mono">{s.restart_count}</td></tr>)}</tbody></table> : <Empty title="No visible service units" detail="The accessible systemd scopes responded successfully but returned no service units." />}</div></section>
    </>}
  </>;
}

function SettingsPage({ tick, theme, onToggleTheme, onError }: { tick: number; theme: Theme; onToggleTheme: () => void; onError: (value: string) => void }) {
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [notifyResult, setNotifyResult] = useState("");
  const [notifyBusy, setNotifyBusy] = useState(false);
  const [notificationHistory, setNotificationHistory] = useState<{ id: number; incident_id: number | null; timestamp: number; provider: string; status: string; detail: string | null }[]>([]);
  useEffect(() => { let live = true; void api.config().then((c) => { if (live) setConfig(c); }).catch((e) => onError(errorText(e))); return () => { live = false; }; }, [tick, onError]);
  useEffect(() => { let live = true; void api.notificationHistory().then(({ notifications }) => { if (live) setNotificationHistory(notifications); }).catch(() => {}); return () => { live = false; }; }, [tick]);
  const update = (field: keyof PublicConfig, value: number | boolean) => { setDirty(true); setConfig((c) => c ? { ...c, [field]: value } : c); };
  const updateThreshold = (field: keyof PublicConfig["thresholds"], value: number) => { setDirty(true); setConfig((c) => c ? { ...c, thresholds: { ...c.thresholds, [field]: value } } : c); };
  const save = async () => {
    if (!config) return;
    setSaving(true); setSaved(false); onError("");
    try { const result = await api.saveConfig({ host_seconds: config.host_seconds, process_seconds: config.process_seconds, hardware_seconds: config.hardware_seconds, service_seconds: config.service_seconds, retention_hours: config.retention_hours, thresholds: config.thresholds, notification_enabled: config.notification_enabled, ai_enabled: config.ai_enabled }); setConfig(result); setDirty(false); setSaved(true); window.setTimeout(() => setSaved(false), 2500); }
    catch (e) { onError(errorText(e)); }
    finally { setSaving(false); }
  };
  const testNotification = async () => {
    setNotifyBusy(true); setNotifyResult(""); onError("");
    try { const result = await api.testNotification(); setNotifyResult(result.detail); const { notifications } = await api.notificationHistory(); setNotificationHistory(notifications); }
    catch (e) { onError(errorText(e)); }
    finally { setNotifyBusy(false); }
  };
  if (!config) return <><PageHeading index="08" title="Settings" detail="Private configuration stored on this machine." /><section className="instrument-panel"><LoadingLine label="Reading configuration…" /></section></>;
  return <>
    <PageHeading index="08" title="Settings" detail="Controls are stored in the private TOML configuration file. Secrets are never returned to this interface." actions={<button className="button primary" onClick={() => void save()} disabled={saving}>{saving ? "Saving…" : saved ? "Saved ✓" : "Save changes"}</button>} />
    <div className="settings-grid">
      <section className="instrument-panel settings-section"><div className="settings-title"><span className="eyebrow">01 / COLLECTION</span><h2>Sampling & retention</h2></div><div className="settings-fields"><NumberField label="Host sample interval" unit="seconds" min={1} max={60} value={config.host_seconds} onChange={(v) => update("host_seconds", v)} /><NumberField label="Process scan interval" unit="seconds" min={5} max={300} value={config.process_seconds} onChange={(v) => update("process_seconds", v)} /><NumberField label="Hardware scan interval" unit="seconds" min={5} max={300} value={config.hardware_seconds} onChange={(v) => update("hardware_seconds", v)} /><NumberField label="Service inventory interval" unit="seconds" min={10} max={600} value={config.service_seconds} onChange={(v) => update("service_seconds", v)} /><NumberField label="Raw sample retention" unit="hours" min={6} max={168} value={config.retention_hours} onChange={(v) => update("retention_hours", v)} /></div></section>
      <section className="instrument-panel settings-section"><div className="settings-title"><span className="eyebrow">02 / SAFETY RULES</span><h2>Alert thresholds</h2></div><div className="settings-fields"><NumberField label="Memory available · warning" unit="%" min={0} max={100} value={config.thresholds.memory_available_warning_percent} step={0.5} onChange={(v) => updateThreshold("memory_available_warning_percent", v)} /><NumberField label="Memory available · critical" unit="%" min={0} max={100} value={config.thresholds.memory_available_critical_percent} step={0.5} onChange={(v) => updateThreshold("memory_available_critical_percent", v)} /><NumberField label="Root disk used · warning" unit="%" min={0} max={100} value={config.thresholds.disk_used_warning_percent} step={0.5} onChange={(v) => updateThreshold("disk_used_warning_percent", v)} /><NumberField label="CPU pressure · warning" unit="%" min={0} max={100} value={config.thresholds.cpu_pressure_warning_percent} step={0.5} onChange={(v) => updateThreshold("cpu_pressure_warning_percent", v)} /><NumberField label="Memory pressure · warning" unit="%" min={0} max={100} value={config.thresholds.memory_pressure_warning_percent} step={0.5} onChange={(v) => updateThreshold("memory_pressure_warning_percent", v)} /></div></section>
      <section className="instrument-panel settings-section"><div className="settings-title"><span className="eyebrow">03 / NOTIFICATIONS</span><h2>Attention routing</h2><p>Configured provider: <strong>{config.notification_provider}</strong>. {config.notification_configured ? "Endpoint is configured." : "Provider endpoint is not configured."} Credentials are never returned to this page.</p></div><ToggleRow label="Enable notifications" detail="Requires a provider endpoint in the private TOML file." checked={config.notification_enabled} disabled={!config.notification_configured} onChange={(v) => update("notification_enabled", v)} /><div className="settings-note">Supported providers: ntfy and Discord webhook. Minimum severity and cooldown are configurable in <code>{config.config_path}</code>.</div><button className="button secondary" onClick={() => void testNotification()} disabled={!config.notification_enabled || !config.notification_configured || dirty || notifyBusy}>{notifyBusy ? "Sending test…" : dirty ? "Save before sending test" : "Send test notification"}</button>{notifyResult && <p className="success-inline">{notifyResult}</p>}<div className="notification-history"><span className="eyebrow">RECENT DELIVERY HISTORY</span>{notificationHistory.length ? notificationHistory.slice(0, 5).map((row) => <div className="notification-row" key={row.id}><span>{ago(row.timestamp)}</span><strong className={row.status === "sent" ? "good" : row.status === "failed" ? "bad" : ""}>{row.status}</strong><small>{row.detail ?? row.provider}</small></div>) : <p className="settings-note">No notification attempts recorded.</p>}</div></section>
      <section className="instrument-panel settings-section"><div className="settings-title"><span className="eyebrow">04 / LOCAL AI</span><h2>Incident investigation</h2><p>AI is an on-demand interpretation layer. It does not participate in baseline detection.</p></div><ToggleRow label="Enable local AI investigations" detail="Requires a loopback Ollama or OpenAI-compatible endpoint." checked={config.ai_enabled} disabled={!config.ai_configured} onChange={(v) => update("ai_enabled", v)} /><div className="settings-note">Provider: {config.ai_provider}. {config.ai_configured ? "Loopback endpoint is configured." : "No local inference endpoint is configured."} Set endpoint, model and timeout in <code>{config.config_path}</code>. Requests are blocked when host pressure is high.</div></section>
      <section className="instrument-panel settings-section"><div className="settings-title"><span className="eyebrow">05 / APPEARANCE</span><h2>Interface</h2></div><div className="appearance-row"><div><strong>{theme === "dark" ? "Dark instrument" : "Light instrument"}</strong><small>Preference is stored in this browser only.</small></div><button className="button secondary" onClick={onToggleTheme}>Switch to {theme === "dark" ? "light" : "dark"}</button></div></section>
      <section className="instrument-panel settings-section"><div className="settings-title"><span className="eyebrow">06 / NODE</span><h2>Instance details</h2></div><div className="settings-facts"><StateLine label="Private interface" value={config.interface} /><StateLine label="Dashboard port" value={config.port} /><StateLine label="Configuration" value={config.config_path} /><StateLine label="Database limit" value={`${config.database_budget_mb} MiB`} /><StateLine label="Admin password reset" value="sentinel admin reset-password" /></div></section>
    </div>
  </>;
}
function NumberField({ label, unit, min, max, step = 1, value, onChange }: { label: string; unit: string; min: number; max: number; step?: number; value: number; onChange: (v: number) => void }) {
  return <label className="number-field"><span>{label}</span><span className="number-input"><input type="number" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} /><em>{unit}</em></span></label>;
}
function ToggleRow({ label, detail, checked, disabled = false, onChange }: { label: string; detail: string; checked: boolean; disabled?: boolean; onChange: (value: boolean) => void }) {
  return <label className={`toggle-row ${disabled ? "disabled" : ""}`}><span><strong>{label}</strong><small>{detail}</small></span><input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} /><i className="toggle-visual" /></label>;
}
function InlineError({ text }: { text: string }) { return <div className="inline-error" role="alert">{text}</div>; }
