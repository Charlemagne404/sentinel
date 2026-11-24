# Sentinel

Sentinel is a single-host, local-first Linux monitoring daemon with a private React dashboard. It samples host and process state, stores bounded history in SQLite, learns cautious host and workload baselines, correlates findings into incidents, and can send notifications or request an on-demand local AI explanation.

## Current status

The release is installed and running as the unprivileged `sentinel.service` user unit. The listener is verified at `100.64.0.2:8765`; administrator setup is complete. On 2026-11-24, a four-minute low-impact observation measured about 0.84% of one CPU core average, 14.9 MiB RSS (32.9 MiB peak), and 0.49 MiB database growth. After the final build, a 6m28s run averaged about 0.87% of one core. The filesystem is 98% used but still has 12.66 GiB free; see [DEPLOYMENT.md](DEPLOYMENT.md) and [RESOURCE_BUDGET.md](RESOURCE_BUDGET.md) for storage details and limits.

## Quick start

Requirements: stable Rust/Cargo, Node/npm, a systemd user session, Linux procfs, and (for private remote access) a Tailscale/Headscale interface. Production has no Node server.

    scripts/build.sh
    scripts/install.sh --no-start

Review ~/.config/sentinel/config.toml, confirm the private interface and port 8765, then start with systemctl --user enable --now sentinel.service. On first start the daemon creates ~/.config/sentinel/bootstrap-token; enter it on the setup page and choose a password. The token expires after 30 minutes and is removed after setup. If the interface is absent, Sentinel binds only to 127.0.0.1.

Sentinel serves HTTP. It does not terminate TLS. Remote access is intended only over the encrypted private Tailnet; do not expose the port publicly. See SECURITY.md and DEPLOYMENT.md.

## Capabilities

- CPU totals, user/system/idle/iowait breakdown, per-core use, load averages and frequency; memory, cache, swap occupancy and movement; PSI; root filesystem capacity, disk throughput and IOPS; network interface counters; hwmon temperatures and thermal-throttle counters; optional NVIDIA utilization, VRAM, temperature and power metrics.
- Process identity is boot ID + PID + start ticks. Sentinel reads procfs without collecting environment variables or command lines, persists selected resource-heavy processes and sampled starts/exits/parent-loss events, and groups processes by systemd unit/cgroup or executable/session.
- Read-only system/user service inventory with restart counters, SQLite WAL history, migrations, aggregation, retention, integrity checks and online backup.
- Immediate safety thresholds including kernel OOM-counter increases, robust median/MAD scores, EWMA and percentile summaries, workload CPU/RSS baselines for the top groups, anomaly exclusion, incident freeze and recovery.
- Authenticated versioned REST and SSE, eight dashboard areas, notification controls, and optional pressure-gated local AI investigation.

Defaults sample host every 5 seconds, processes every 10 seconds, hardware every 15 seconds, and service inventory every 60 seconds. Baseline maturity requires at least 2,880 clean minute observations spanning 48 hours. Workload baselines cover up to 25 groups by CPU and 25 by RSS; weekly/day-of-week models are not implemented.

## Development

See DEVELOPMENT.md, ARCHITECTURE.md, API.md and docs/openapi.yaml. Run Rust tests with cargo test --locked -j1; frontend tests with npm test -- --reporter=dot from frontend; build with npm run build from frontend.

## Known limitations

- No built-in TLS; remote access relies on the encrypted Tailnet and the verified private-address binding. A reboot was not performed, so startup persistence is verified from user-manager configuration, not by reboot.
- No GPU process attribution, SMART health reads, or OOM victim attribution. OOM monitoring uses a host-wide counter; service restart detection compares systemd `NRestarts` counters. Polling can miss short-lived processes and lifecycle timestamps are detection times.
- Workload baseline coverage is bounded to the busiest 25 groups by each resource; lower-activity groups, weekly patterns and time-of-day models are not covered.
- Lifecycle history is sampled and bounded to seven days. Parent-loss and browser correlation are conservative heuristics; repeated child creation, process-group bursts and richer ancestry correlation are not yet modeled. Broader cross-metric cause correlation remains limited.
- Cgroup v2/systemd visibility depends on host layout and permissions. Sentinel remains unprivileged and does not execute remediation.
- Local AI supports Ollama and OpenAI-compatible chat completions on loopback only. It is disabled by default and never downloads models.

Sentinel is observational software. Investigate evidence before taking action.
