# Intelligence and incident model

Sentinel does not use an LLM for routine monitoring. Immediate rules run as soon as samples are available. Statistical findings wait for mature history and remain explainable.

## Baselines

The evaluator uses minute aggregates from the last seven days (or the current reset time, whichever is newer) and excludes points recorded as anomalies. It stores median, median absolute deviation (MAD), EWMA with alpha 0.2, p95, sample count, confidence, update time, version and frozen status.

For scoring, scale is max(1.4826 × MAD, 5% × absolute median, 0.01). Score is absolute distance from median divided by the scale. A baseline is mature only after at least 2,880 clean minute samples spanning 48 hours. A candidate score of 4.5 or more is excluded from training immediately; three consecutive candidate evaluations are needed for a statistical incident. Safety rules do not wait for maturity.

Training freezes for metrics affected by an active incident or current candidate. OOM events and adaptive high-pressure guards pause all model updates; service-restart and orphan-browser findings pause workload streams. An unrelated persistent warning (for example, a root-disk warning) does not stop other metrics from calibrating. Reset increments model version and reset timestamp, clears learned baseline rows, and preserves metric/anomaly/incident history. The UI requires confirmation.

Sentinel also maintains separate aggregate CPU and RSS histories for up to 25 workloads ranked by CPU and 25 ranked by memory. These streams use the same 48-hour maturity and exclusion rules as host metrics. Workloads outside those rankings do not receive statistical baselines. Day-of-week/time-of-day patterns remain unavailable.

## Immediate safety rules

- Available memory below configured warning/critical percentages.
- CPU PSI and memory PSI above configured warning thresholds.
- Root filesystem utilization above its configured threshold.
- CPU temperature at 90%/98% of a sensor-reported limit when available.
- Aggregate swap-in/out movement above 5 MiB/s. Swap occupancy alone is not an incident.
- Increases in the host-wide `/proc/vmstat` `oom_kill` counter create a critical incident. The counter does not identify the victim process. Sentinel compares against its latest stored sample (or seeds from the current counter when no history exists); an increase may have happened while Sentinel was stopped.
- Increases in systemd `NRestarts` between service inventory samples create a warning incident for that unit. The first observation seeds the current count; counter resets are treated as a new baseline.

Sensor-specific configurable fallback temperature limits are not implemented. A CPU sensor without a reported limit does not produce this thermal rule.

## Correlation and recovery

Resource safety triggers share one resource-pressure incident signature. Thermal and storage each have a shared signature; statistical findings use a metric-specific signature. A detected group updates in place. Incidents recover after three consecutive minute evaluations without that signature. Recovery state is persisted and can produce a recovery notification.

The process collector records sampled starts, exits, and first observed parent-loss transitions with stable boot/PID/start-tick identity. It seeds the first inventory, avoids treating unreadable `/proc` entries as exits, caps event ingestion at 100 per poll, and retains up to seven days (or less under database-budget pressure). Processes shorter than the 10-second polling interval can be missed; exit timestamps are detection times, not kernel event times. A conservative browser incident requires at least two long-lived orphaned browser processes, 20% total CPU, or 1 GiB RSS. The explanation notes that daemonization is another possible cause. Broader cross-metric correlation remains limited.

## Evidence language

Incident evidence distinguishes direct thresholds/statistical observations from the explanation and confidence estimate. The AI layer interprets bounded evidence on request but is not a detector and cannot execute commands.
