#!/usr/bin/env bash
set -euo pipefail

PURGE_DATA=false
for arg in "$@"; do
  case "$arg" in
    --purge-data) PURGE_DATA=true ;;
    --help|-h) echo "Usage: scripts/uninstall.sh [--purge-data]"; echo "By default, configuration and historical data are preserved."; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

BIN_FILE="${HOME:?HOME must be set}/.local/bin/sentinel"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/sentinel"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/sentinel"
UNIT_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/sentinel.service"

if [[ "$PURGE_DATA" == true ]]; then
  printf 'This permanently deletes Sentinel configuration and all history under:\n  %s\n  %s\nType "delete Sentinel data" to continue: ' "$CONFIG_DIR" "$DATA_DIR" >&2
  read -r confirmation
  [[ "$confirmation" == "delete Sentinel data" ]] || { echo "Cancelled."; exit 1; }
fi

systemctl --user disable --now sentinel.service 2>/dev/null || true
rm -f -- "$UNIT_FILE" "$BIN_FILE"
rm -rf -- "$DATA_DIR/web" "$DATA_DIR/.web.next" "$DATA_DIR/.web.previous"
systemctl --user daemon-reload 2>/dev/null || true

if [[ "$PURGE_DATA" == true ]]; then
  rm -rf -- "$CONFIG_DIR" "$DATA_DIR"
  echo "Sentinel application, configuration and data removed."
else
  echo "Sentinel application files removed; configuration and historical data were preserved."
  echo "Configuration: $CONFIG_DIR"
  echo "Data: $DATA_DIR"
fi
