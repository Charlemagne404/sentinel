# Troubleshooting

## Service will not start

    sentinel doctor
    sentinel config validate
    systemctl --user status sentinel.service
    journalctl --user -u sentinel.service -n 100 --no-pager

Check that frontend/dist/index.html existed during install, config paths are readable/writable, and the port is unused. The installer refuses to overwrite another listener. Check root disk and swap headroom before rebuilding.

## Dashboard is not reachable

Confirm the service is active and inspect its bound address with ss -ltnp. If tailscale0 is absent, Sentinel binds only to 127.0.0.1, so remote access will not work. Restore the private interface outside Sentinel, restart, then verify the actual bind. Never change the bind to 0.0.0.0. HTTP is expected; remote use is only over the encrypted private Tailnet.

## Setup token rejected

The bootstrap token expires after 30 minutes and can be used once. Read it locally from the configured path. If expired or missing, use sentinel admin reset-password and read the new token file. Do not paste it into logs or chat.

## Empty sensors or services

Sentinel runs as the user and does not escalate privileges. Review collection_degraded in the overview and the Services page availability note. PSI, hwmon, cgroup v2, systemd visibility and NVIDIA tooling depend on host support/permissions. Missing data is not replaced with synthetic values.

## No anomaly findings

Safety rules are immediate. Statistical rules wait for 48 hours and 2,880 clean minute points, require a robust score of 4.5 for three evaluations, and freeze training during incidents. Visit Intelligence for samples/confidence. Baseline reset starts a new calibration version and keeps metric and incident history.

## Notifications fail

Check provider and endpoint/token in the owner-only config, validate with sentinel config validate, enable notifications, and use the settings test action. History stores status/detail without endpoint or token. External network availability is needed only for the selected provider.

## AI investigation unavailable

AI is off by default and requires a loopback Ollama/OpenAI-compatible endpoint and model. It refuses to run without a current sample or if available memory is below 15%, memory PSI exceeds 10%, CPU PSI exceeds 30%, or reported CPU temperature exceeds 90% of its hardware limit. Sentinel never downloads or starts a model.

## Database maintenance

Run sentinel db integrity and make an online backup before manual repair. Keep backups outside the live data directory and protect them as sensitive host history. Avoid opening a live database with tools that may write while Sentinel is running.
