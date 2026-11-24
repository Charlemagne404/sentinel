# Architecture

Sentinel is one Rust executable with an embedded static React application. Tokio runs a collector/evaluator loop, a bounded notification worker, and the Axum HTTP server. There are no separate daemons or production Node process.

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

- collector.rs: host metric reads, temperatures, disk/network counters, optional bounded nvidia-smi, and read-only system/user service listing.
- processes.rs: procfs inventory, boot/PID/start-tick identity, resource deltas, executable and unified cgroup identity, sampled starts/exits, and parent-loss transitions.
- workloads.rs: groups by deepest .service/.scope, then cgroup path, executable/session, or name/session fallback; emits bounded aggregate CPU/RSS baseline streams for the busiest workload groups.
- storage.rs: a serialized SQLite writer, WAL, schema migrations, raw and aggregated metrics, process history/lifecycle events, service restart counters, incidents, baselines, notification history, backup and integrity checks.
- intelligence.rs: immediate host safety rules (including OOM counter increases), systemd restart findings, host/workload baseline statistics, candidate exclusion, incident grouping, and recovery after three missed minute evaluations.
- notifications.rs: a capacity-16 queue with bounded HTTP timeouts/retries and incident cooldown.
- auth.rs and api.rs: one administrator account, Argon2 password hashing, hashed session tokens, CSRF/origin/Host checks, login rate limiting, REST, SSE, and static asset serving.

## Storage model

Host snapshots and metric points are sampled at the configured host interval. Metric samples are rolled into one-minute and fifteen-minute tables. Process details are sampled separately; storage selects top resource users plus processes with observed parent loss. Lifecycle transitions are persisted separately for up to seven days, subject to the database budget. The database uses SQLite's bundled runtime.

Default retention is 48 hours for raw host/process points, seven days for lifecycle transitions, 30 days for minute aggregates and anomalies, and 365 days for quarter-hour aggregates, notification history, and recovered incidents. The database budget defaults to 500 MiB and accounts for SQLite WAL sidecars. If that budget is exceeded, cleanup trims older lifecycle events first, then process detail and raw metrics, and finally older aggregates. Incident history is kept independently from raw measurements.

## Network boundary

At startup, Sentinel resolves the configured private interface (default tailscale0) and binds to its address. If missing, it binds to loopback. It never binds to 0.0.0.0. Application authentication remains required. There is no TLS listener; remote use relies on encrypted Tailnet transport.

## Failure behavior

Unavailable procfs/sysfs capabilities are represented as missing/degraded readings. The dashboard does not synthesize measurements. Collector and service subprocesses have bounded timeouts. SQLite errors are logged and the daemon continues where possible. The health endpoint exposes whether a collector snapshot exists.
