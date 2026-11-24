# Resource budget

## Configured starting limits

The generated user systemd unit sets Nice=10, CPUWeight=20, CPUQuota=20%, MemoryHigh=128M, MemoryMax=192M, TasksMax=32, and IOWeight=20. It also uses NoNewPrivileges, PrivateTmp, ProtectSystem=strict, read-only home protection, kernel-tunables and control-group protection, with write paths limited to Sentinel config/data. ProtectKernelModules is omitted because this host's unprivileged user manager cannot enforce it (a transient unit probe exits with 218/CAPABILITIES). These are guardrails, not measurements of actual idle use.

## Collection work

Host metrics default to 5 seconds; process inventory 10 seconds; sensors/GPU 15 seconds; service listing 60 seconds. Process/service operations are bounded. nvidia-smi has a 3-second timeout and kill-on-drop; service listing has a 3-second timeout per scope. The notification queue holds at most 16 jobs, deliveries time out after 5 seconds and may retry three times. AI has a 5–180-second timeout, loopback-only destination and host-pressure gate.

When available memory falls below 10%, CPU PSI exceeds 50%, memory PSI exceeds 20%, or reported CPU temperature reaches 95% of its limit, detailed process polling slows to three times its configured interval (capped at 300 seconds), baseline training pauses, and hourly database cleanup is deferred. Host metric sampling continues. Only one AI investigation may run at once; AI uses stricter guards and is refused at its investigation endpoint when pressure is high.

## Storage

Defaults retain raw host/process observations for 48 hours, minute points and anomalies for 30 days, and quarter-hour points, notification history, and recovered incidents for 365 days. SQLite budget defaults to 500 MiB and includes WAL sidecars. Under budget pressure cleanup progressively trims process detail, raw metrics, and then older aggregates; incident history remains separate. Monitor database and free disk because file size can remain elevated until checkpoint/vacuum.

## Measurement status

No sustained CPU/RSS/database growth measurement has been completed for a running Sentinel service. Builds and tests are not substitutes. A service soak should happen only after checking current machine pressure and free disk; record RSS, CPU, database/WAL size, process count, shutdown, and restart without artificial stress.
