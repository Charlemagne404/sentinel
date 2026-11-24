# Deployment and maintenance

Sentinel installs per user; no sudo is used. Before a release build or service start, run `sentinel doctor` or check disk, memory, swap, PSI and I/O manually. At the 2026-11-24 final deployment preflight, `/` had 19,501,027,328 bytes free (18.16 GiB) at 96% used, with 12% inode use. Available RAM was about 3.8 GiB; the host's 4 GiB swap was occupied. Memory PSI was low and one-second `vmstat` showed no swap-in/out in its interval row. The release build completed within this headroom. No unrelated files, project data, backups, databases or caches were removed. The filesystem usage breakdown and measurement windows are recorded in `RESOURCE_BUDGET.md`.

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

On first start, Sentinel creates a one-time bootstrap token in `~/.config/sentinel/bootstrap-token` (mode 0600). Read it locally and complete setup in the dashboard; it expires after 30 minutes and is invalidated/removed after setup. If access needs to be reset, `sentinel admin reset-password` deletes the previous account and sessions, then creates a new setup token.

On 2026-11-24, the previously exposed administrator credential was rotated through that supported reset flow. The replacement is stored in the owner-readable file `~/.config/sentinel/admin-credential` (mode 0600). Retrieve it locally from that path; do not copy it into logs, reports, or source control. The reset removed all prior account credentials and sessions before creating the new account.

## Verified operation on this host

The latest Phase II build was installed on 2026-11-24 at 13:48 CET. The user service is enabled and active, bound only to `100.64.0.2:8765`, has `NRestarts=0`, and reports fresh monitoring data, complete service inventory, and successful database writes. A fresh administrator login succeeded; protected overview, intelligence, storage, storage history, services, process inventory, lifecycle, historical metrics, notification history, and detailed-health reads returned 200; a protected unauthenticated read returned 401; authenticated SSE delivered an update; and the dashboard root returned HTML. SQLite integrity passed for the active main and storage-history databases and both pre-deployment online backups. Configuration was preserved, no schema migration was made, and the existing CPU/memory/task limits remain enforced. The detailed pipeline health is `ok`; the independent storage watch still flags the host root filesystem as critical.

From 12:48:19 to 13:16:26 UTC (28m07s), cumulative service CPU was 14.39 seconds, or 0.85% of one core. Process RSS was 36.6 MiB; cgroup memory was 56.5 MiB current and 72.2 MiB peak, with three tasks and no restart. The database and sidecars totaled 61,581,400 bytes (58.7 MiB). Over the 25m46s after the authenticated endpoint sweep, total SQLite size increased from 56,211,968 to 61,581,400 bytes (about 5.12 MiB). Two later low-activity windows added 0.90 MiB in 5m08 and 2.03 MiB in 10m40; these short windows do not establish a stable long-term rate. Root remained 96% used with 19,484,069,888 bytes free (18.15 GiB). No Sentinel warning-level journal entries appeared after activation. Rust tests passed 78/78, frontend tests 18/18, `cargo fmt --check` passed, the TypeScript/Vite production build and Rust release build passed. `npm audit --audit-level=moderate` reported zero vulnerabilities. `cargo-audit` and the Rust Clippy component are not installed, so an advisory-database scan and Clippy run were unavailable.

Visual browser verification remains incomplete because this session's browser controls are disabled. A supervised Chromium attempt exited before page load, and the Firefox/Snap driver rejected its browser binary; the separate Chrome binary had no matching installed driver. No dashboard screenshot or desktop/mobile interaction evidence was produced. I stopped the transient driver scope created by the test and left pre-existing browser processes untouched. Frontend behavior was checked with component/data tests and the production build. No physical iPhone or GPU stress testing was performed. NVIDIA compute-process attribution is available and currently reports compute applications only; graphics contexts may be omitted. Kernel OOM victim attribution is unavailable to this unprivileged service because `/dev/kmsg` reads are denied and kernel journal messages are inaccessible; host-wide OOM counters remain monitored. AI and live notification delivery are disabled/unconfigured, so neither was sent to an external provider. The new admin credential is stored locally at `~/.config/sentinel/admin-credential` with mode 0600; the previous account was removed by the supported reset flow. The old password was not independently re-entered for a rejection test because it was not retained.

## Update and rollback

Build the desired checkout, then run `scripts/update.sh`; it preserves configuration and SQLite data, replaces the executable/web assets, and restarts an active unit. Before this activation, the online SQLite backups for both databases, previous executable, web assets, and service unit were saved under `~/.local/share/sentinel/backups/sentinel-phase2-final-pre-deploy-20261124T124757Z/`.

To roll back this activation, stop the user service, restore that saved executable, web directory and service unit, reload the user manager, then start the service again. The backup directory contains the exact pre-update files. No schema change was made, so this rollback does not require replacing the live database. Run `sentinel db integrity` and verify the listener afterward.

```sh
BACKUP="$HOME/.local/share/sentinel/backups/sentinel-phase2-final-pre-deploy-20261124T124757Z"
systemctl --user stop sentinel.service
install -m 0755 "$BACKUP/sentinel" "$HOME/.local/bin/sentinel"
rm -rf "$HOME/.local/share/sentinel/web"
cp -a "$BACKUP/web" "$HOME/.local/share/sentinel/web"
install -m 0600 "$BACKUP/sentinel.service" "$HOME/.config/systemd/user/sentinel.service"
systemctl --user daemon-reload
systemctl --user start sentinel.service
```

No schema migration was made, so a rollback restores the executable, web assets, and unit while retaining the active databases. The snapshot also contains owner-only online copies of the main and storage-history databases for recovery if an integrity check later fails.

## Backup and health

    sentinel db integrity
    sentinel db backup "$HOME/sentinel-$(date +%F).sqlite3"
    sentinel doctor
    journalctl --user -u sentinel.service --since today

The backup command uses SQLite's online backup API. Store backups with owner-only permissions and outside the live data directory. Public coarse health is available at `/api/v1/health`; detailed health at `/api/v1/health/details` and other operational API routes require login.

## Uninstall

scripts/uninstall.sh disables the user unit and removes the executable, unit, and installed web assets but keeps configuration/history. To delete config and data, pass --purge-data and type the exact confirmation phrase. This is destructive.

Sentinel currently serves HTTP only. Use it remotely only over Tailnet; the application has no certificate configuration or TLS termination.
