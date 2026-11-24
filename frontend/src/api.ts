import type {
  Baseline, HostSnapshot, Incident, Overview, ProcessSnapshot, PublicConfig,
  Series, ServiceSnapshot, Workload,
} from "./types";

let csrfToken: string | null = null;
export function setCsrfToken(value: string | null) { csrfToken = value; }

export class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); this.name = "ApiError"; }
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) headers.set("X-CSRF-Token", csrfToken);
  const response = await fetch(path, { ...init, method, headers, credentials: "same-origin" });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try { message = (await response.json() as { error?: string }).error ?? message; } catch { /* plain error response */ }
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function signIn(username: string, password: string): Promise<void> {
  const result = await request<{ csrf_token: string }>("/api/v1/auth/login", {
    method: "POST", body: JSON.stringify({ username, password }),
  });
  setCsrfToken(result.csrf_token);
}
export async function finishSetup(token: string, password: string): Promise<void> {
  const result = await request<{ csrf_token: string }>("/api/v1/auth/setup", {
    method: "POST", body: JSON.stringify({ token, password }),
  });
  setCsrfToken(result.csrf_token);
}
export async function restoreSession(): Promise<boolean> {
  try {
    const result = await request<{ csrf_token: string }>("/api/v1/auth/me");
    setCsrfToken(result.csrf_token);
    return true;
  } catch (error) {
    setCsrfToken(null);
    if (error instanceof ApiError && error.status === 401) return false;
    throw error;
  }
}
export async function signOut(): Promise<void> {
  try { await request("/api/v1/auth/logout", { method: "POST", body: "{}" }); }
  finally { setCsrfToken(null); }
}

export const api = {
  overview: () => request<Overview>("/api/v1/overview"),
  series: (metric: string, minutes: number) =>
    request<Series>(`/api/v1/metrics/${encodeURIComponent(metric)}?minutes=${minutes}`),
  processes: (q = "", sort = "cpu") =>
    request<{ total: number; filtered: number; processes: ProcessSnapshot[] }>(
      `/api/v1/processes?q=${encodeURIComponent(q)}&sort=${encodeURIComponent(sort)}&limit=1000`,
    ),
  process: (key: string) => request<{ current: ProcessSnapshot | null; history: Record<string, number | string | boolean>[] }>(
    `/api/v1/processes/${encodeURIComponent(key)}`,
  ),
  workloads: () => request<{ workloads: Workload[] }>("/api/v1/workloads"),
  labelWorkload: (name: string, display_name: string, labels: string[]) =>
    request<{ saved: boolean }>(`/api/v1/workloads/${encodeURIComponent(name)}/label`, {
      method: "PUT", body: JSON.stringify({ display_name, labels }),
    }),
  incidents: (active = false) => request<{ incidents: Incident[] }>(
    `/api/v1/incidents?active=${active}&limit=250`,
  ),
  incident: (id: number) => request<Incident>(`/api/v1/incidents/${id}`),
  investigate: (id: number) =>
    request<{ incident_id: number; provider: string; interpretation: string; measured_facts: unknown; ai_generated: boolean }>(
      `/api/v1/incidents/${id}/investigate`, { method: "POST", body: "{}" },
    ),
  intelligence: () => request<{ baselines: Baseline[]; baseline_version: number; baseline_reset_at: number; anomalies: Record<string, unknown>[]; learning: Record<string, unknown> }>(
    "/api/v1/intelligence",
  ),
  resetIntelligence: () => request<{ baselines: Baseline[]; baseline_version: number; baseline_reset_at: number }>(
    "/api/v1/intelligence", { method: "DELETE" },
  ),
  anomalies: () => request<{ anomalies: Record<string, unknown>[] }>("/api/v1/anomalies?hours=168&limit=500"),
  services: () => request<{ services: ServiceSnapshot[]; available: boolean; source: string }>("/api/v1/services"),
  config: () => request<PublicConfig>("/api/v1/config"),
  saveConfig: (patch: Partial<Pick<PublicConfig, "host_seconds" | "process_seconds" | "hardware_seconds" | "service_seconds" | "retention_hours" | "thresholds" | "notification_enabled" | "ai_enabled">>) =>
    request<PublicConfig>("/api/v1/config", { method: "PUT", body: JSON.stringify(patch) }),
  testNotification: () => request<{ ok: boolean; detail: string }>("/api/v1/notifications/test", { method: "POST", body: "{}" }),
  notificationHistory: () => request<{ notifications: { id: number; incident_id: number | null; timestamp: number; provider: string; status: string; detail: string | null }[] }>("/api/v1/notifications"),
  authStatus: () => request<{ configured: boolean; setup_required: boolean; bootstrap_file?: string }>("/api/v1/auth/status"),
  health: () => request<{ status: string; version: string; timestamp: number; collector_started: boolean }>("/api/v1/health"),
};

export function connectLive(onUpdate: () => void, onError?: () => void): EventSource {
  const source = new EventSource("/api/v1/events", { withCredentials: true });
  source.addEventListener("update", (event) => {
    try {
      const data = JSON.parse((event as MessageEvent<string>).data) as { snapshot: HostSnapshot | null };
      if (data.snapshot) onUpdate();
    } catch { /* a malformed event does not break later updates */ }
  });
  source.onerror = () => onError?.();
  return source;
}
