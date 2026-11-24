# HTTP API

The OpenAPI 3.1 description is docs/openapi.yaml. Routes are same-origin JSON at /api/v1. /health, /auth/status, /auth/setup, and /auth/login are public. Other routes require the sentinel_session HttpOnly cookie. Mutations require the session X-CSRF-Token and an exact same-origin Origin; protected requests also validate Host.

| Method | Route | Purpose |
|---|---|---|
| GET | /health | Version, timestamp, collector state. |
| GET | /auth/status | Setup availability. |
| POST | /auth/setup | One-time administrator setup. |
| POST | /auth/login and /auth/logout | Create/revoke session. |
| GET | /auth/me | Session validity and CSRF token. |
| GET | /overview | Live host (including the kernel OOM counter), top processes/workloads, active incidents and service summary. |
| GET | /events | Authenticated SSE updates. |
| GET | /metrics/{name}?minutes=360 | Bounded history, up to one year and 1,600 points. |
| GET | /processes?q=&sort=&limit= | Search/sort current inventory, maximum 1,000. |
| GET | /process-lifecycle?minutes=1440&limit=250 | Recent sampled starts, exits and parent-loss transitions, bounded to seven days. |
| GET | /processes/{key} | Current process and sampled history. |
| GET | /workloads | Current cgroup/workload grouping. |
| PUT | /workloads/{workload}/label | Save display name and labels. |
| GET | /incidents?active=&limit= | Incident list, maximum 500. |
| GET | /incidents/{id} | Incident detail. |
| POST | /incidents/{id}/investigate | On-demand local AI if configured and pressure permits. |
| GET | /anomalies?hours=&limit= | Recent anomaly records, up to 720 hours/1,000 rows. |
| GET/DELETE | /intelligence | Model status; DELETE resets baselines and preserves history. |
| GET | /services | Read-only system/user service inventory, including systemd NRestarts counters. |
| GET/PUT | /config | Public status / editable collection, thresholds and enable toggles. |
| GET | /notifications | Recent delivery history. |
| POST | /notifications/test | Send configured test notification. |

Errors use { "error": "..." }. Common status codes: 400 invalid request/host, 401 unauthenticated, 403 origin/CSRF rejected, 404 missing record, 409 setup already complete, 429 login throttled, 503 unavailable/pressure guarded.
