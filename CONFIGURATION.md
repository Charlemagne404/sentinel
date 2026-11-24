# Configuration

The installer creates ~/.config/sentinel/config.toml with restrictive permissions and preserves it on updates. SENTINEL_CONFIG or --config FILE selects another path. Missing fields use defaults. Run sentinel config validate after editing.

    [server]
    interface = "tailscale0"
    port = 8765
    database_dir = "/home/USER/.local/share/sentinel"
    asset_dir = "/home/USER/.local/share/sentinel/web"
    bootstrap_file = "/home/USER/.config/sentinel/bootstrap-token"
    session_hours = 12
    database_budget_mb = 500

    [collection]
    host_seconds = 5
    process_seconds = 10
    hardware_seconds = 15
    service_seconds = 60
    retention_hours = 48

    [thresholds]
    memory_available_warning_percent = 8.0
    memory_available_critical_percent = 3.0
    disk_used_warning_percent = 95.0
    cpu_pressure_warning_percent = 20.0
    memory_pressure_warning_percent = 10.0

    [storage]
    sample_seconds = 900
    history_days = 365
    warning_used_percent = 80.0
    high_used_percent = 90.0
    critical_used_percent = 95.0
    warning_available_gib = 20
    high_available_gib = 10
    critical_available_gib = 5
    abnormal_growth_gib_per_hour = 1.0
    required_writable_mounts = ["/", "/mnt/continental-cloud"]

    [notifications]
    enabled = false
    provider = "ntfy"
    minimum_severity = "warning"
    cooldown_minutes = 30
    # After choosing a destination, add its exact URL and (for ntfy) token if required:
    # endpoint = "<your private ntfy topic URL or Discord webhook URL>"
    # secret = "<your ntfy access token>"

    [ai]
    enabled = false
    provider = "ollama"
    endpoint = "http://127.0.0.1:11434/api/generate"
    model = ""
    timeout_seconds = 60

Valid ranges: host 1–60s, process/hardware 5–300s, services 10–600s, retention 6–168h, total SQLite budget 50–2048 MiB, storage samples 300–86400s, storage history 30–730 days, session 1–168h (clamped), notification cooldown at most 1440 minutes, and AI timeout 5–180s. The total database budget reserves 15% for filesystem history and 85% for the main metrics database; storage history trims oldest complete sample timestamps when its budget is reached. Under normal operation, `retention_hours` controls raw host payloads and metric observations; detailed process snapshots are capped at 24 hours to reduce churn. Core quarter-hour summaries are kept for 180 days. Storage pressure shortens retention in deterministic oldest-first batches while preserving active incident evidence. Absolute free-space thresholds apply to filesystems at least twice as large as the configured warning-free-space threshold; smaller filesystems use percentage and inode thresholds, avoiding false critical alerts on small boot partitions. Up to 32 required writable mount paths may be configured. Notification destinations must be HTTPS except loopback HTTP ntfy. Discord URLs are restricted to Discord webhook hosts and path. AI endpoints must be loopback HTTP(S); credentials in URL userinfo and URL fragments are rejected.

The authenticated settings page changes host sampling, retention, thresholds and enable/disable toggles for configured notification/AI integrations. Storage sampling and required mount paths are currently configured in this file. Provider endpoints, models, and secrets are also edited here. API responses report whether an endpoint is configured but never return endpoint URLs or secrets. Changes are atomically written with mode 0600 and take effect in the process.

## Secure notification setup

1. Create a private topic on the ntfy server you control or a Discord webhook in a server you administer. Keep the topic URL, webhook token, and any ntfy access token private; do not paste them into chat, tickets, or logs.
2. Edit the Sentinel TOML file shown by `sentinel config validate` and select `provider = "ntfy"` or `provider = "discord"`. Add the exact destination URL you obtained. For ntfy, add `secret` only when your server requires an access token; Discord uses the secret embedded in the webhook URL. Remote endpoints must use HTTPS. HTTP is accepted only for loopback ntfy.
3. Restrict the file and directory permissions, then validate it:

       chmod 700 ~/.config/sentinel
       chmod 600 ~/.config/sentinel/config.toml
       sentinel config validate

   If Sentinel uses a non-default `SENTINEL_CONFIG` path, apply the same owner-only permissions to that file and its parent directory.
4. Restart Sentinel after editing the TOML file so the running process loads the destination. In Settings, enable notifications and use **Send test notification** only after confirming the configured destination is yours. Check the returned delivery result and recent notification history.
5. If delivery fails, read the safe provider status in Settings and verify the URL/token locally. Disable notifications until the destination is corrected. Revoke a webhook or token at its provider if it was exposed.

Sentinel never sends a setup probe automatically. Test notifications are explicit, and the application rejects remote HTTP endpoints, credential-bearing URL userinfo, and non-Discord webhook hosts.

tailscale0 is the default private interface. Sentinel resolves its current address when binding and uses 127.0.0.1 if absent. Other interface names are rejected unless they begin with tailscale or are loopback.
