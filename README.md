# Sentinel

Sentinel is a single-host, local-first Linux monitoring daemon with a private React dashboard. It samples host and process state, stores bounded history in SQLite, learns cautious per-metric baselines, correlates findings into incidents, and can send notifications or request an on-demand local AI explanation.

## Current status

The daemon, API, dashboard, CLI, build/install utilities, and tests are implemented in this repository. A production release has not been installed or started on the target machine. Check host headroom before release builds or service startup; the initial inspection found a nearly full root filesystem and heavily used swap. No runtime CPU/RAM soak measurement exists yet.

## Quick start

Requirements: stable Rust/Cargo, Node/npm, a systemd user session, Linux procfs, and (for private remote access) a Tailscale/Headscale interface. Production has no Node server.

    scripts/build.sh
    scripts/install.sh --no-start

Review ~/.config/sentinel/config.toml, confirm the private interface and port 8765, then start with systemctl --user enable --now sentinel.service. On first start the daemon creates ~/.config/sentinel/bootstrap-token; enter it on the setup page and choose a password. The token expires after 30 minutes and is removed after setup. If the interface is absent, Sentinel binds only to 127.0.0.1.

Sentinel serves HTTP. It does not terminate TLS. Remote access is intended only over the encrypted private Tailnet; do not expose the port publicly. See SECURITY.md and DEPLOYMENT.md.

## Capabilities

- CPU totals, user/system/idle/iowait breakdown, per-core use, load averages and frequency; memory, cache, swap occupancy and movement; PSI; root filesystem capacity, disk throughput and IOPS; network interface counters; hwmon temperatures and thermal-throttle counters; optional NVIDIA utilization, VRAM, temperature and power metrics.
- Process identity is boot ID + PID + start ticks. Sentinel reads procfs without collecting environment variables or command lines, persists selected resource-heavy/parent-lost processes, and groups processes by systemd unit/cgroup or executable/session.
- Read-only system/user service inventory, SQLite WAL history, migrations, aggregation, retention, integrity checks and online backup.
- Immediate safety thresholds, robust median/MAD scores, EWMA and percentile summaries, anomaly exclusion, incident freeze and recovery.
- Authenticated versioned REST and SSE, eight dashboard areas, notification controls, and optional pressure-gated local AI investigation.

Defaults sample host every 5 seconds, processes every 10 seconds, hardware every 15 seconds, and service inventory every 60 seconds. Baseline maturity requires at least 2,880 clean minute observations spanning 48 hours. Weekly/day-of-week models are not implemented.

## Development

See DEVELOPMENT.md, ARCHITECTURE.md, API.md and docs/openapi.yaml. Run Rust tests with cargo test --locked -j1; frontend tests with npm test -- --reporter=dot from frontend; build with npm run build from frontend.

## Known limitations

- No built-in TLS. The target service is deliberately uninstalled until host resources are rechecked.
- No GPU process attribution, SMART health reads, OOM journal integration, service restart counters, or short-lived process capture. Polling can miss short-lived processes.
- Baselines are machine-wide per metric; workload-specific statistical models and weekly patterns are not implemented.
- Cgroup v2/systemd visibility depends on host layout and permissions. Sentinel remains unprivileged and does not execute remediation.
- Local AI supports Ollama and OpenAI-compatible chat completions on loopback only. It is disabled by default and never downloads models.

Sentinel is observational software. Investigate evidence before taking action.
