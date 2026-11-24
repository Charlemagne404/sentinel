# Sentinel

Sentinel is a single-host, local-first Linux monitoring daemon with a private React dashboard. It samples host and process state, stores bounded history in SQLite, learns cautious host and workload baselines, correlates findings into incidents, and can send notifications or request an on-demand local AI explanation.

## Current status

The current Phase II build is installed and running as the unprivileged `sentinel.service` user unit. The listener is verified at `100.64.0.2:8765`; authenticated login, protected APIs, and live SSE work. During a 28m07s post-release observation, Sentinel averaged 0.85% of one CPU core, used 36.6 MiB RSS and 56.5 MiB current cgroup memory (72.2 MiB peak), and ran three tasks without a restart. The database and sidecars totaled 58.7 MiB at the end of the sample. The root filesystem remains under critical storage pressure at 96% used, with 18.15 GiB available; Sentinel did not remove unrelated data. These short samples do not establish long-term performance or storage trends; see [DEPLOYMENT.md](DEPLOYMENT.md) and [RESOURCE_BUDGET.md](RESOURCE_BUDGET.md) for measurement details and limits.

## Quick start

Requirements: stable Rust/Cargo, Node/npm, a systemd user session, Linux procfs, and (for private remote access) a Tailscale/Headscale interface. Production has no Node server.

    scripts/build.sh
    scripts/install.sh --no-start

Review ~/.config/sentinel/config.toml, confirm the private interface and port 8765, then start with systemctl --user enable --now sentinel.service. On first start the daemon creates ~/.config/sentinel/bootstrap-token; enter it on the setup page and choose a password. The token expires after 30 minutes and is removed after setup. If the interface is absent, Sentinel binds only to 127.0.0.1.

Sentinel serves HTTP. It does not terminate TLS. Remote access is intended only over the encrypted private Tailnet; do not expose the port publicly. See SECURITY.md and DEPLOYMENT.md.

## Capabilities

- CPU totals, user/system/idle/iowait breakdown, per-core use, load averages and frequency; memory, cache, swap occupancy and movement; PSI; filesystem capacity, inode pressure and growth history; disk throughput and IOPS; network interface counters; hwmon temperatures and thermal-throttle counters; optional NVIDIA utilization, per-compute-process VRAM, temperature and power metrics.
- Process identity is boot ID + PID + start ticks. Sentinel reads procfs without collecting environment variables or command lines, persists selected resource-heavy processes and sampled starts/exits/parent-loss events, and groups processes by systemd unit/cgroup or executable/session.
- Read-only system/user service inventory with restart counters, SQLite WAL history, migrations, aggregation, retention, integrity checks and online backup.
- Immediate safety thresholds including kernel OOM-counter increases, robust median/MAD scores, EWMA and percentile summaries, workload CPU/RSS/process-count baselines, mature time-of-day/week models, bounded sustained-change detection, anomaly exclusion, incident freeze and recovery.
- Authenticated versioned REST and SSE, nine dashboard areas, notification controls, and optional pressure-gated local AI investigation.

Defaults sample host every 5 seconds, processes every 10 seconds, hardware every 15 seconds, and service inventory every 60 seconds. Rolling baseline maturity requires at least 2,880 clean minute observations spanning 48 hours. Workload baselines cover the union of the 25 busiest groups by CPU, RSS, or process count. Time-of-day models require 14 clean daily windows; same-hour-of-week models require four clean weekly repetitions.

## Development

See DEVELOPMENT.md, ARCHITECTURE.md, API.md and docs/openapi.yaml. Run Rust tests with cargo test --locked -j1; frontend tests with npm test -- --reporter=dot from frontend; build with npm run build from frontend.

## Known limitations

- No built-in TLS; remote access relies on the encrypted Tailnet and the verified private-address binding. A reboot was not performed, so startup persistence is verified from user-manager configuration, not by reboot.
- NVIDIA process attribution covers compute applications reported by `nvidia-smi` and samples once per minute; graphics contexts and hidden processes may be absent. No SMART health reads or OOM victim attribution are available. This host denies `/dev/kmsg` reads and does not expose kernel journal messages to the service user, so OOM monitoring uses the host-wide kernel counter. Service restart detection compares systemd `NRestarts` counters. Polling can miss short-lived processes and lifecycle timestamps are detection times.
- Workload baseline coverage is bounded to the busiest 25 groups by each of CPU, RSS and process count; lower-activity groups may not receive their own model. Time-aware patterns use UTC hourly buckets and activate only after their published evidence thresholds.
- Lifecycle history is sampled and bounded to seven days. Parent-loss and browser accumulation rules remain conservative heuristics; processes shorter than the polling interval can be missed. Workload and host-pressure co-occurrence is evidence of timing, not proof of cause. Repeated short-lived child creation and process-group burst models are not implemented.
- Cgroup v2/systemd visibility depends on host layout and permissions. Sentinel remains unprivileged and does not execute remediation.
- Local AI supports Ollama and OpenAI-compatible chat completions on loopback only. It is disabled by default and never downloads models.

Sentinel is observational software. Investigate evidence before taking action.
