# Deployment and maintenance

Sentinel installs per user; no sudo is used. Before a release build or service start, run `sentinel doctor` or check disk, memory, swap, PSI and I/O manually. After the final 2026-11-24 release build, `/` had 13,586,886,656 bytes free (12.66 GiB) despite reporting 98% used, with 12% inode use. Available RAM was about 4.6 GiB. Current memory PSI was 0%; CPU PSI 0.57% and I/O PSI 0.77%. The release build and initial run completed within that headroom. The host's 4 GiB swap was occupied, but `vmstat` showed zero swap-in/out in its interval rows. No unrelated files, project data, backups, databases or caches were removed. The filesystem usage breakdown and measurement window are recorded in `RESOURCE_BUDGET.md`.

## Install

    scripts/build.sh
    scripts/install.sh --no-start
    sentinel doctor
    sentinel config validate

The installer stages ~/.local/bin/sentinel, web assets in ~/.local/share/sentinel/web, config under ~/.config/sentinel, and ~/.config/systemd/user/sentinel.service. Review config, then start:

    systemctl --user enable --now sentinel.service
    systemctl --user status sentinel.service
    sentinel status

No user lingering is enabled automatically. A user unit normally runs only while that user manager/session is active. This host already had `Linger=yes`; Sentinel did not change it. The service is enabled under `default.target`, so the existing lingering user manager starts it without an interactive login. A reboot was not performed, so boot-time startup was verified from user-manager configuration rather than by reboot. The listener binds the resolved `tailscale0` address on port 8765 by default. If the interface is unavailable, it binds loopback. Confirm with `ss -ltnp` before sharing the address. On this host the verified dashboard address is `http://100.64.0.2:8765/`; it is available only through the private Tailnet address and application authentication.

On first start, Sentinel creates a one-time bootstrap token in `~/.config/sentinel/bootstrap-token` (mode 0600). Read it locally and complete setup in the dashboard; it expires after 30 minutes and is invalidated/removed after setup. The current administrator is already configured and that bootstrap file has been removed. If access needs to be reset, `sentinel admin reset-password` creates a new setup token and invalidates existing sessions.

## Verified operation on this host

The installed user service is enabled and active. After the lifecycle fix was rebuilt and installed, it binds only `100.64.0.2:8765`, reports healthy, and has `NRestarts=0`. A fresh administrator login and session check returned 200; authenticated overview, service, lifecycle and intelligence API reads returned live host data, and an authenticated SSE `update` event with data arrived. A protected unauthenticated read returned 401. In a temporary authenticated browser session, the dashboard rendered live CPU/memory/swap/temperature values, the kernel OOM counter, the active storage warning, process/workload tables, and service summary. I closed the tab after verification. The service was stopped (MainPID 0, inactive, no listener) and started again with a new PID and one listener; the database passed `PRAGMA integrity_check` and `sentinel db integrity`.

A five-sample, four-minute low-impact window measured ~0.84% of one core average and ~0.49 MiB database growth. After the final installed build, a 6m28s runtime check including fresh login/API/SSE activity measured 3.36 seconds cumulative service CPU (~0.87% of one core), ~14.1 MiB RSS, ~27.7 MiB cgroup memory peak, and three tasks. See `RESOURCE_BUDGET.md` for host PSI, temperature, storage and configured-limit details. Workload baselines are still learning and not mature; baseline maturity requires at least 2,880 clean minute samples spanning 48 hours. Rust tests passed 44/44 after the lifecycle fix; the frontend suite had previously passed 12/12 and production build, with no later frontend source changes.

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
