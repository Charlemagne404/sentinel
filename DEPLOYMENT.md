# Deployment and maintenance

Sentinel installs per user; no sudo is used. Before a release build or service start, run sentinel doctor or check disk, memory, swap, PSI and I/O manually. If the machine is under pressure, defer release build and service startup.

## Install

    scripts/build.sh
    scripts/install.sh --no-start
    sentinel doctor
    sentinel config validate

The installer stages ~/.local/bin/sentinel, web assets in ~/.local/share/sentinel/web, config under ~/.config/sentinel, and ~/.config/systemd/user/sentinel.service. Review config, then start:

    systemctl --user enable --now sentinel.service
    systemctl --user status sentinel.service
    sentinel status

No user lingering is enabled automatically. A user unit normally runs only while that user manager/session is active. For boot-time operation after logout, inspect existing lingering state and decide separately; Sentinel does not change it. The listener binds the resolved tailscale0 address on port 8765 by default. If the interface is unavailable, it binds loopback. Confirm with ss -ltnp before sharing the address.

On first start, Sentinel creates a one-time bootstrap token in ~/.config/sentinel/bootstrap-token (mode 0600). Read it locally and complete setup in the dashboard; it expires after 30 minutes and is invalidated/removed after setup. If lost, sentinel admin reset-password creates a new setup token and invalidates existing sessions.

## Update and rollback

Build the desired checkout, then run scripts/update.sh; it uses the install flow and preserves configuration and SQLite data. The installer replaces web assets and binary and restarts an active unit. Keep a SQLite backup before a database migration and retain the previous release binary/web assets yourself if application rollback is needed.

## Backup and health

    sentinel db integrity
    sentinel db backup "$HOME/sentinel-$(date +%F).sqlite3"
    sentinel doctor
    journalctl --user -u sentinel.service --since today

The backup command uses SQLite's online backup API. Store backups with owner-only permissions and outside the live data directory. Health is available at /api/v1/health; other API routes require login.

## Uninstall

scripts/uninstall.sh disables the user unit and removes the executable, unit, and installed web assets but keeps configuration/history. To delete config and data, pass --purge-data and type the exact confirmation phrase. This is destructive.

Sentinel currently serves HTTP only. Use it remotely only over Tailnet; the application has no certificate configuration or TLS termination.
