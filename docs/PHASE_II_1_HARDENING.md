# Sentinel Phase II.1 — production hardening report

Date: 2026-11-24

## State and safety

The hardening changes remain a local candidate until this finalization commit; they were not installed or activated. The config is mode `0600` and selects `interface = "tailscale0"`, port `8765`, a 500 MiB database budget, 48-hour raw host/metric retention, and 10-second process scans. Notifications are disabled, with no endpoint or secret configured. No notification was sent.

### Demonstrated deployment access barrier

The shell execution context does not have host service/network control. `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` are present, and both `/run/user/1000/bus` and `/run/user/1000/systemd/private` exist with the expected user ownership. Connecting to either Unix socket returns `EPERM`; `systemctl --user` and `loginctl` both return `Failed to connect to bus: Operation not permitted`. The process reports `NoNewPrivs: 1`, `Seccomp: 2`, and one seccomp filter. `ip`/`ss` cannot open netlink, and creating an IPv4 socket returns `EPERM`. This demonstrates an execution-sandbox restriction, not an absent session bus or a demonstrated Sentinel unit failure.

At 17:29 UTC, the browser was able to request `http://100.64.0.2:8765/api/v1/health` at the configured private address. It returned `status: ok`, with the API responding, fresh data, a readable database, a successful database write check, a running process, and version `0.1.0`. This confirms the private endpoint was responding at that time; OS-level listener inspection and proof that no other interface is bound remain unavailable. The earlier `127.0.0.1` result was not used as a service-health test. An authenticated dashboard/API check could not be completed: the browser security policy blocked the local-file credential handoff protocol and explicitly disallowed workarounds. No credential was entered after that block. No attempt was made to bypass seccomp, fabricate bus context, use sudo, or change system configuration.

Although the browser confirms the health endpoint is live, the user systemd manager cannot be controlled from this execution context and active cgroup enforcement cannot be refreshed. The previous host audit found CPU, memory, and PID controllers available; `IOWeight=20` is configured but not enforced because the user cgroup has no I/O controller. No application backup, migration, install, restart, or production write was attempted. Production rollback remains the current installation. The prior read-only audit observed production database samples advancing at about 5.50 seconds per host sample. This finalization environment could not sample host CPU/RSS, collector errors, missed samples, cgroup usage, restarts, temperatures, PSI, or longer-term storage growth. Source review and synthetic tests verify bounded process/workload history and notification queues but do not replace those live measurements.

## Production database inventory

Both production SQLite databases passed read-only `PRAGMA integrity_check`: `ok`. The primary database reported `auto_vacuum=INCREMENTAL`, 18,424 pages, and no free-list pages at the sampled read. The filesystem-history database retained 51 samples.

At the sampled read, the primary database files were:

| File | Bytes |
| --- | ---: |
| `sentinel.sqlite3` | 76,754,944 |
| WAL | 5,512,592 |
| SHM | 32,768 |
| Journal | 0 |
| **Primary total** | **82,300,304 (78.49 MiB)** |

The independent filesystem-history database used 193,336 bytes across its main file and sidecars. Combined SQLite footprint was **82,493,640 bytes (78.67 MiB)**.

`dbstat` page allocation for every primary table and index at that read:

| Kind | Object | Bytes |
| --- | --- | ---: |
| table | host_samples | 21,164,032 |
| table | process_samples | 16,936,960 |
| table | metric_points | 11,513,856 |
| index | metric_points_lookup | 9,420,800 |
| table | minute_points | 5,357,568 |
| index | process_samples_key | 4,902,912 |
| index | minute_points_lookup | 4,857,856 |
| table | process_lifecycle_events | 770,048 |
| table | quarter_points | 651,264 |
| index | quarter_points_lookup | 581,632 |
| index | process_lifecycle_events_ts | 139,264 |
| table | excluded_points | 118,784 |
| table | baselines | 110,592 |
| index | sqlite_autoindex_baselines_1 | 73,728 |
| table | anomalies | 57,344 |
| index | anomalies_ts | 12,288 |
| table | service_restart_state | 16,384 |
| index | sqlite_autoindex_service_restart_state_1 | 16,384 |
| table | accounts | 4,096 |
| index | active_incident_signature | 4,096 |
| index | incidents_status_last | 4,096 |
| table | baseline_state | 4,096 |
| table | bootstrap_tokens | 4,096 |
| table | incidents | 4,096 |
| table | notification_history | 4,096 |
| table | schema_migrations | 4,096 |
| table | sessions | 4,096 |
| table | workload_labels | 4,096 |
| index | sqlite_autoindex_accounts_1 | 4,096 |
| index | sqlite_autoindex_bootstrap_tokens_1 | 4,096 |
| index | sqlite_autoindex_sessions_1 | 4,096 |
| index | sqlite_autoindex_workload_labels_1 | 4,096 |

At the same snapshot there were 4,830 host rows, 216,400 raw metric points, 68,698 process-history rows across 838 timestamps, 62,119 minute rows, 6,763 quarter-hour rows, and 4,895 lifecycle events. Process history averaged **81.98 rows every 31.74 seconds**, with 100 rows at its largest timestamp. The process table plus its lookup index occupied 21,839,872 bytes. Raw metric points plus their lookup index occupied 20,934,656 bytes; the metric index alone used 9,420,800 bytes. Host payloads occupied 21,164,032 bytes while being saved about every 5.5 seconds. These measurements show material write amplification from process snapshots, repeated host JSON, and secondary indexes.

The snapshot covered about 7.38 hours. It predates activation of the new bounded writers. The existing code measured by the database still had up to 100 process rows per sample and high-resolution host payloads; the new limits have not yet been measured in production.

### Finalization read-only recheck — 2026-11-24 17:26 UTC

Both databases again passed read-only `PRAGMA integrity_check`. The primary DB had 25,259 pages and no free pages. Main/WAL/SHM/journal sizes were 103,383,040 / 5,726,832 / 32,768 / 0 bytes, totaling **109,142,640 bytes (104.09 MiB)**. Filesystem-history sidecars totaled **304,576 bytes (0.29 MiB)**, for **104.38 MiB combined**. The newest host and metric sample timestamps were four seconds behind the read and there were 6,365 host rows and 289,664 metric points, so the database writer was recently active. The `latest_snapshot` table was absent, confirming this was still the previous schema; the candidate was not installed or migrated.

The largest current primary objects were `host_samples` (28,278,784 bytes), `process_samples` (22,626,304), `metric_points` (15,638,528), `metric_points_lookup` (12,750,848), `minute_points` (7,540,736), `minute_points_lookup` (6,811,648), `process_samples_key` (6,496,256), and `process_lifecycle_events` (925,696). The installed binary timestamp was 13:48 CET and its SHA-256 was `9fc2dcd3e9108bacbe692fe4511e336162806ef46c21228bc7fd4bfa92bb4575`; the uninstalled release candidate SHA-256 was `b97f438f15765dd5f912008ac93b637dfecf25b5f4d88866af553495fc59dc08`. The unit file still contains the configured CPU, memory, task, and filesystem protections, but active cgroup enforcement could not be refreshed because the user manager is sandbox-inaccessible.

## Growth and 48-hour projection

The supplied production interval grew by 5.12 MiB in 25m46s, or approximately **11.92 MiB/hour (286 MiB/day)**. If that rate continued unchanged from 58.7 MiB, the combined 500 MiB limit would be reached in roughly **37 hours**. Since the budget assigns 425 MiB to the primary database, its headroom could be exhausted sooner if most growth remains there. Under that observed rate, 48 hours of raw history does not fit.

The bounded writer and revised retention policy materially reduce the expected steady state:

- Host payload history becomes one row per minute rather than one per host poll.
- Persisted process detail becomes at most 50 rows once per minute and is retained for at most 24 hours; it falls to once per five minutes in degradation mode.
- Workload series are bounded to at most 72 metrics per minute. Their minute history is retained for two days.
- Core minute metrics remain for 14 days, other minute metrics for seven days, and ten core quarter-hour metrics for 180 days. Rollups keep average, minimum, and maximum.
- Under pressure, cleanup trims lower-value detail in stages while leaving active incident evidence intact.

Using the sampled database's per-row `dbstat` costs and measured producer rates, the earlier candidate estimate was about **401 MiB**, including populated min/max values and an allowance for the observed 5.3 MiB WAL. Capping process detail at 24 hours instead of 48 saves an estimated 21.8 MiB; reducing core quarter-hour retention from 365 to 180 days saves about 30.9 MiB. The updated estimate is therefore roughly **348 MiB**, leaving about **77 MiB** below the 425 MiB primary share. This includes 48-hour raw host/metric observations, 24-hour process detail, 14/7/2-day minute tiers, 180-day core quarter-hour data, seven-day lifecycle events, and 30-day anomaly/exclusion rows.

This remains a rate-and-row-size projection, not a 48-hour soak test. The reduced estimate improves modeled headroom but is not proven under longer WALs, high process churn, larger payloads, or anomaly bursts. The adaptive path can shorten retained detail when measured size approaches the budget; a duration run on the host is still required before treating this capacity estimate as validated.

## Changes in the candidate

- Limited workload baseline selection to the union of the eight busiest groups by CPU, RSS, and process count.
- Kept the latest host snapshot in a singleton row and wrote historical host payloads once per minute.
- Capped saved process history at the union of 25 CPU and 25 RSS processes and reduced its normal save interval to one minute.
- Added aggregate minimum/maximum values so minute and quarter-hour views preserve observed peaks.
- Added staged retention, checkpointing, incremental vacuum, pressure-mode sampling, and health reporting for per-file and per-object storage consumption. Pressure-stage deletes are oldest-first and capped at 20,000 rows per table/predicate action; the stage, pruned-row count, resulting size, and duration are logged.
- Made host pressure defer database cleanup only while the database remains below 85% of its assigned share. Cleanup duration, stage, and remaining overage are logged.
- Tightened CPU statistical incidents so utilization deviations require observed CPU PSI contention. Browser accumulation now requires measured population/RSS growth over a 10–20 minute window; stable large browser pools stay quiet.
- Added bounded notification health state, explicit provider status, retryability rules, owner-only setup guidance, and a graceful worker drain with a ten-second shutdown deadline. The setup remains disabled until the operator configures a destination.
- Added accessible chart range/peak summaries and visible notification failure state. No layout redesign was attempted without rendered evidence.

## Accelerated-time retention and detection checks

Rust fixtures use synthetic timestamps in temporary databases; they do not touch production history and do not sleep for the retention window.

- A 49-hour-old raw host/metric observation was pruned while a 47-hour-old one remained; process history pruned a 25-hour sample and retained a 23-hour sample.
- A synthetic database at 92% of budget entered the first pressure stage, removed old process detail first, and retained host payload history. A 20,001-row fixture verified oldest-first pruning capped at 20,000 rows per action.
- Severe synthetic budget pressure shed older detail, left recent samples and active incident evidence intact, reported that an irreducible fixture remained over its 1 MiB stress budget, and entered history degradation instead of failing the writer.
- Minute and quarter-hour rollups preserved average/minimum/maximum values.
- Process-history selection remained at or below 50 rows despite 150 parent-loss candidates.
- A stable browser pool produced no incident; four new browser processes and 1 GiB RSS growth over ten minutes produced evidence. A recurring high-CPU window without CPU PSI produced no incident.

## Verification

- `cargo check`: passed.
- `cargo build --release`: passed.
- Rust suite: 88 passed and three loopback-provider tests failed before application assertions because local TCP server binding returned `Operation not permitted` under seccomp. Those tests are `ai_investigation_sends_redacted_evidence_to_a_mock_local_provider`, `severity_escalation_bypasses_cooldown_and_is_identified_to_provider`, and `test_delivery_is_logged_without_exposing_endpoint`. The non-network suite passed 88/88 with those three filtered out. This is an environmental bind restriction; the provider HTTP behavior in those tests remains unverified here.
- Frontend: 19 tests passed; TypeScript and Vite production build passed.
- `cargo fmt --check` and `git diff --check`: passed.
- Production main and filesystem-history databases: read-only integrity checks passed.
- No production migration, cleanup, checkpoint, notification, or deployment was performed.

## Visual review still needed

The login page and coarse health endpoint rendered, but an authenticated Sentinel dashboard was unavailable in this sandbox. Review the authenticated application manually at 320, 560, 820, and 1120 px widths in both themes. Check overview severity and storage summaries; performance chart peaks and 7-day ranges; storage controls and table overflow; notification error and delivery history; keyboard focus order; and screen-reader chart summaries and table labels. Physical-device and assistive-technology verification remain open.

## Rollback and unresolved concerns

Nothing from this candidate was installed, so production rollback was not needed and the existing service/configuration/history remain the rollback baseline. This candidate is committed locally, but production activation remains explicitly blocked because the execution environment is denied access to the user service manager sockets. The private health endpoint is reachable, but that does not grant safe restart or cgroup verification access. The pre-existing untracked storage scripts, notes, and `systemd/` work were left untouched.

Before activation, the remaining gate is a supervised service-health and visual review with the actual installation path and previous executable available. Re-run the three loopback tests in a test environment that permits local binds. A production-duration observation is still required to validate the 348 MiB estimate under real workloads. The authenticated application review checklist above remains manual because the browser security policy blocked the credential handoff.
