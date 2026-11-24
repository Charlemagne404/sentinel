#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
NO_START=false
for arg in "$@"; do
  case "$arg" in
    --no-start) NO_START=true ;;
    --help|-h) echo "Usage: scripts/install.sh [--no-start]"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

BIN_DIR="${HOME:?HOME must be set}/.local/bin"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/sentinel"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sentinel"
ASSET_DIR="$DATA_DIR/web"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_FILE="$UNIT_DIR/sentinel.service"
BIN_FILE="$BIN_DIR/sentinel"
CONFIG_FILE="$CONFIG_DIR/config.toml"
BOOTSTRAP_FILE="$CONFIG_DIR/bootstrap-token"
PORT=8765
if [[ -f "$CONFIG_FILE" ]]; then
  CONFIGURED_PORT="$(awk '
    /^\[server\]$/ { in_server=1; next }
    /^\[/ { in_server=0 }
    in_server && /^port[[:space:]]*=/ { gsub(/[^0-9]/, "", $0); print; exit }
  ' "$CONFIG_FILE")"
  if [[ "$CONFIGURED_PORT" =~ ^[0-9]+$ ]] && (( CONFIGURED_PORT > 0 && CONFIGURED_PORT <= 65535 )); then
    PORT="$CONFIGURED_PORT"
  fi
fi

[[ -x "$ROOT_DIR/target/release/sentinel" ]] || { echo "Missing release binary. Run scripts/build.sh first." >&2; exit 1; }
[[ -f "$ROOT_DIR/frontend/dist/index.html" ]] || { echo "Missing frontend build. Run scripts/build.sh first." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemctl is required" >&2; exit 1; }

if ! systemctl --user is-active --quiet sentinel.service 2>/dev/null; then
  if command -v ss >/dev/null && ss -H -ltn "sport = :$PORT" | grep -q .; then
    echo "Port $PORT is already in use; refusing to install over another listener." >&2
    exit 1
  fi
fi

toml_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

install -d -m 0755 "$BIN_DIR"
install -d -m 0700 "$CONFIG_DIR" "$DATA_DIR"
install -d -m 0755 "$UNIT_DIR"
install -m 0755 "$ROOT_DIR/target/release/sentinel" "$BIN_FILE"

ASSET_NEXT="$DATA_DIR/.web.next"
ASSET_OLD="$DATA_DIR/.web.previous"
rm -rf -- "$ASSET_NEXT" "$ASSET_OLD"
install -d -m 0755 "$ASSET_NEXT"
cp -a "$ROOT_DIR/frontend/dist/." "$ASSET_NEXT/"
if [[ -e "$ASSET_DIR" ]]; then mv -- "$ASSET_DIR" "$ASSET_OLD"; fi
mv -- "$ASSET_NEXT" "$ASSET_DIR"
rm -rf -- "$ASSET_OLD"

if [[ ! -e "$CONFIG_FILE" ]]; then
  cat >"$CONFIG_FILE" <<EOF
[server]
interface = "tailscale0"
port = 8765
database_dir = $(toml_quote "$DATA_DIR")
asset_dir = $(toml_quote "$ASSET_DIR")
bootstrap_file = $(toml_quote "$BOOTSTRAP_FILE")
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
minimum_severity = "warning"
cooldown_minutes = 30

[ai]
enabled = false
provider = "ollama"
timeout_seconds = 60
EOF
  chmod 0600 "$CONFIG_FILE"
else
  echo "Preserving existing configuration: $CONFIG_FILE"
fi

cat >"$UNIT_FILE" <<EOF
[Unit]
Description=Sentinel local server intelligence
After=network.target

[Service]
Type=simple
ExecStart=$BIN_FILE --config $CONFIG_FILE
Restart=on-failure
RestartSec=5s
WorkingDirectory=$DATA_DIR
Environment=RUST_LOG=sentinel=info,tower_http=warn
UMask=0077
Nice=10
CPUWeight=20
CPUQuota=20%
MemoryHigh=128M
MemoryMax=192M
TasksMax=32
IOWeight=20
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$CONFIG_DIR $DATA_DIR
ProtectKernelTunables=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=default.target
EOF
chmod 0600 "$UNIT_FILE"

"$BIN_FILE" --config "$CONFIG_FILE" config validate
systemctl --user daemon-reload
if [[ "$NO_START" == true ]]; then
  echo "Installed files and user service unit. Service was not enabled or started (--no-start)."
  echo "Config: $CONFIG_FILE"
  exit 0
fi
if systemctl --user is-active --quiet sentinel.service; then
  systemctl --user restart sentinel.service
else
  systemctl --user enable --now sentinel.service
fi
systemctl --user --no-pager --full status sentinel.service
