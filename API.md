# HTTP API

The OpenAPI 3.1 description is docs/openapi.yaml. Routes are same-origin JSON at /api/v1. /health, /auth/status, /auth/setup, and /auth/login are public. Other routes require the sentinel_session HttpOnly cookie. Mutations require the session X-CSRF-Token and an exact same-origin Origin; protected requests also validate Host.

| Method | Route | Purpose |
|---|---|---|
| GET | /health | Coarse process/API, sample freshness and database status; returns 503 when monitoring is degraded, while the body distinguishes a running process/API from stale data or failed storage. |
| GET | /auth/status | Setup availability. |
| POST | /auth/setup | One-time administrator setup. |
| POST | /auth/login and /auth/logout | Create/revoke session. |
| GET | /auth/me | Session validity and CSRF token. |
| GET | /health/details | Protected collector freshness, write health, both database sizes including sidecars and their allocated budget shares, combined-budget status, runtime counters and Sentinel RSS/thread count. |
| GET | /storage | Current read-only filesystem capacity, inode, mount, growth, and history-persistence state. |
| GET | /storage/history?mount_point=/&hours=168 | Retained capacity history for a filesystem; range is clamped to 1–720 hours and 9,000 points. `/storage` reports sample count, oldest retained timestamp, history budget and budget-driven pruning. |
| GET | /overview | Live host (including the kernel OOM counter), top processes/workloads, active incidents, service summary, and storage health summary. |
| GET | /events | Authenticated SSE updates. |
| GET | /metrics/{name}?minutes=360 | Bounded history, up to one year and 1,600 points. |
| GET | /processes?q=&sort=&limit= | Search/sort current inventory, maximum 1,000. When available, includes a once-per-minute NVIDIA compute-app PID/name/VRAM sample and matches GPU memory into process rows only when PID and name agree. |
| GET | /process-lifecycle?minutes=1440&limit=250 | Recent sampled starts, exits and parent-loss transitions, bounded to seven days. |
| GET | /processes/{key} | Current process and sampled history. |
| GET | /workloads | Current cgroup/workload grouping. |
| PUT | /workloads/{workload}/label | Save display name and labels. |
| GET | /incidents?active=&limit= | Incident list, maximum 500. |
| GET | /incidents/{id} | Incident detail. |
| POST | /incidents/{id}/investigate | On-demand local AI if configured and pressure permits; returns bounded structured categories and separate measured evidence. |
| GET | /anomalies?hours=&limit= | Recent anomaly records, up to 720 hours/1,000 rows. |
| GET/DELETE | /intelligence | Rolling and matured seasonal model status, evidence counts, anomalies; DELETE resets baselines and preserves history. |
| GET | /services | Read-only system/user service inventory, including per-scope accessibility, partial-inventory status and systemd NRestarts counters. |
| GET/PUT | /config | Public status / editable collection, thresholds and enable toggles. |
| GET | /notifications | Recent delivery history. |
| POST | /notifications/test | Send configured test notification. |

Errors use { "error": "..." }. Common status codes: 400 invalid request/host, 401 unauthenticated, 403 origin/CSRF rejected, 404 missing record, 409 setup already complete, 429 login throttled, 503 degraded health, unavailable data, or pressure-guarded AI.
