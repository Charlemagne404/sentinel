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

    [notifications]
    enabled = false
    provider = "ntfy"
    endpoint = "https://ntfy.example/topic"
    secret = ""
    minimum_severity = "warning"
    cooldown_minutes = 30

    [ai]
    enabled = false
    provider = "ollama"
    endpoint = "http://127.0.0.1:11434/api/generate"
    model = ""
    timeout_seconds = 60

Valid ranges: host 1–60s, process/hardware 5–300s, services 10–600s, retention 6–168h, database budget 50–2048 MiB, session 1–168h (clamped), notification cooldown at most 1440 minutes, and AI timeout 5–180s. Notification destinations must be HTTPS except loopback HTTP ntfy. Discord URLs are restricted to Discord webhook hosts and path. AI endpoints must be loopback HTTP(S); credentials in URL userinfo and URL fragments are rejected.

The authenticated settings page changes sampling, retention, thresholds and enable/disable toggles for configured notification/AI integrations. Provider endpoints, models, and secrets are edited in the config file. API responses report whether an endpoint is configured but never return secrets. Changes are atomically written with mode 0600 and take effect in the process.

tailscale0 is the default private interface. Sentinel resolves its current address when binding and uses 127.0.0.1 if absent. Other interface names are rejected unless they begin with tailscale or are loopback.
