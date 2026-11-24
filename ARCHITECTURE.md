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
- notifications.rs: a capacity-16 queue with non-blocking incident enqueue, bounded HTTP timeouts/retries and incident cooldown; queue overflow is counted in protected operational health. Graceful shutdown drains queued work for at most ten seconds, then reports the remaining queue depth and stops the worker.
- auth.rs and api.rs: one administrator account, Argon2 password hashing, hashed session tokens, CSRF/origin/Host checks, login rate limiting, REST, SSE, and static asset serving.

## Storage model

The current host snapshot is kept in a single-row table and updated at each host sample. Historical host payloads are stored once per minute; metric points retain the configured host interval (five seconds by default) until retention. Process inventory scans continue at the configured interval, while persisted process history is sampled once per minute and bounded to the union of the top 25 CPU and top 25 RSS processes. Under storage pressure, process history drops to five-minute samples. Parent-loss transitions remain in the separate lifecycle table, capped at 100 events per scan.

Workload metrics are limited to the union of the eight busiest workload groups by CPU, RSS, and process count. Minute rollups retain average, minimum, and maximum. Quarter-hour rollups retain only ten core host metrics and preserve the extrema observed by their minute buckets. Normal retention keeps raw host payloads and metric points for the configured 48 hours, detailed process snapshots for at most 24 hours, lifecycle transitions for seven days, non-core minute data for seven days (workload metrics for two), core minute data for 14 days, and the ten quarter-hour host metrics for 180 days. Anomalies remain for 30 days; notification history and recovered incidents remain for 365 days. Active incident evidence is not part of routine storage-pressure deletion.

The total database budget defaults to 500 MiB and is split 85%/15% between the main metrics database and filesystem history, including WAL/SHM/journal sidecars. Cleanup runs during the first monitor cycle and then every 15 minutes. When host pressure is high, cleanup can wait in five-minute checks while the main database remains below 85% of its share; storage pressure takes priority and triggers cleanup even then. Above 90% of the main-database share it shortens process history; above 95% it further prunes workload and other aggregates; over budget it cuts old raw and aggregate detail in stages. Pressure-stage deletes use deterministic oldest-first batches capped at 20,000 rows per table and predicate; the stage, pruned-row count, resulting size, duration, and any overage are logged. If remaining recent data and evidence still exceed the share, the monitor keeps running, reports the overage, and enters history-sampling degradation: host history is sampled at most every 30 seconds and workload history once per five-minute interval. It recovers from this mode below 75% of the share. Cleanup uses checkpointing and incremental vacuum, but the database may temporarily remain above budget while recent measurements or active evidence occupy pages. Detailed health reports per-file sizes, largest SQLite tables/indexes, effective raw-history age, and the degradation state.

Filesystem capacity history is stored separately in `storage-history.sqlite`, sampled every 15 minutes by default and retained for 365 days unless its 15% budget share requires earlier pruning. It is included with its WAL/SHM/journal sidecars in operational size reporting and is backed up alongside the primary database by `sentinel db backup`.

## Network boundary

At startup, Sentinel resolves the configured private interface (default tailscale0) and binds to its address. If missing, it binds to loopback. It never binds to 0.0.0.0. Application authentication remains required. There is no TLS listener; remote use relies on encrypted Tailnet transport.

## Failure behavior

Unavailable procfs/sysfs capabilities are represented as missing/degraded readings. The dashboard does not synthesize measurements. Service and NVIDIA subprocesses have bounded timeouts. Process and storage collection use Tokio's blocking pool; failed process scans retain the last inventory, and a failed filesystem measurement does not discard successful measurements from other mounts. Storage-history initialization falls back to bounded in-memory state and reports the loss of persistence. Public `/api/v1/health` exposes coarse status; authenticated `/api/v1/health/details` reports collector freshness, database readability/write state, write latency, both database sizes including sidecars, budget status, missed samples, queue depth, and dropped notification count.
