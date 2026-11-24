# Architecture

Sentinel is one Rust executable with an embedded static React application. Tokio runs the collector/evaluator loop, a bounded notification worker, a low-frequency storage watcher, and the Axum HTTP server. There are no separate daemons or production Node process.

## Data path

    procfs / sysfs / cgroup v2 / systemctl / nvidia-smi
                         |
              timed collectors (5–60 seconds)
                         |
              live snapshot + SQLite WAL
                         |
              minute aggregation and evaluator
              |-- baseline and exclusion metadata
              |-- anomalies and correlated incidents
              +-- bounded notification queue
                         |
             authenticated REST and authenticated SSE
                         |
             static React + TypeScript + uPlot UI

## Runtime modules

- collector.rs: host metric reads, temperatures, disk/network counters, optional bounded nvidia-smi aggregate telemetry and once-per-minute NVIDIA compute-process attribution, and read-only system/user service listing.
- processes.rs: procfs inventory, boot/PID/start-tick identity, resource deltas, executable and unified cgroup identity, sampled starts/exits, and parent-loss transitions.
- workloads.rs: groups by deepest .service/.scope, then cgroup path, executable/session, or name/session fallback; emits bounded aggregate CPU/RSS/process-count baseline streams for the busiest workload groups.
- storage.rs: a serialized SQLite writer, WAL, schema migrations, raw and aggregated metrics, process history/lifecycle events, service restart counters, incidents, baselines, notification history, backup and integrity checks.
- storage_watch.rs: low-frequency `statvfs` readings from the host mount table, required-mount checks, capacity/inode thresholds, conservative growth estimates, bounded independent history database, and mount-level error isolation. It does not recursively walk filesystems.
- intelligence.rs: immediate host safety rules (including OOM counter increases), systemd restart findings, robust host/workload baselines, mature same-hour-of-day/week models, bounded CUSUM for sustained drift, incident exclusions, workload-level evidence grouping, and recovery after three missed minute evaluations.
- notifications.rs: a capacity-16 queue with non-blocking incident enqueue, bounded HTTP timeouts/retries and incident cooldown; queue overflow is counted in protected operational health.
- auth.rs and api.rs: one administrator account, Argon2 password hashing, hashed session tokens, CSRF/origin/Host checks, login rate limiting, REST, SSE, and static asset serving.

## Storage model

Host snapshots and metric points are sampled at the configured host interval. Metric samples are rolled into one-minute and fifteen-minute tables. Process details are sampled separately; storage selects top resource users plus processes with observed parent loss. Lifecycle transitions are persisted separately for up to seven days, subject to the database budget. The database uses SQLite's bundled runtime.

Default retention is 48 hours for raw host/process points, seven days for lifecycle transitions, 30 days for minute aggregates and anomalies, and 365 days for quarter-hour aggregates, notification history, and recovered incidents. The total database budget defaults to 500 MiB and is split 85%/15% between the main metrics database and filesystem history. The filesystem history has a SQLite page cap plus a row cap that prunes oldest complete sample timestamps. The main database cleanup trims older lifecycle events first, then process detail and raw metrics, and finally older aggregates. Detailed health reports all sidecars and marks the monitoring pipeline degraded if combined database size exceeds the configured total. Incident history is kept independently from raw measurements.

Filesystem capacity history is stored separately in `storage-history.sqlite`, sampled every 15 minutes by default and retained for 365 days unless its 15% budget share requires earlier pruning. It is included with its WAL/SHM/journal sidecars in operational size reporting and is backed up alongside the primary database by `sentinel db backup`.

## Network boundary

At startup, Sentinel resolves the configured private interface (default tailscale0) and binds to its address. If missing, it binds to loopback. It never binds to 0.0.0.0. Application authentication remains required. There is no TLS listener; remote use relies on encrypted Tailnet transport.

## Failure behavior

Unavailable procfs/sysfs capabilities are represented as missing/degraded readings. The dashboard does not synthesize measurements. Service and NVIDIA subprocesses have bounded timeouts. Process and storage collection use Tokio's blocking pool; failed process scans retain the last inventory, and a failed filesystem measurement does not discard successful measurements from other mounts. Storage-history initialization falls back to bounded in-memory state and reports the loss of persistence. Public `/api/v1/health` exposes coarse status; authenticated `/api/v1/health/details` reports collector freshness, database readability/write state, write latency, both database sizes including sidecars, budget status, missed samples, queue depth, and dropped notification count.
