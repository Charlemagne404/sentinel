# Intelligence and incident model

Sentinel does not use an LLM for routine monitoring. Immediate rules run as soon as samples are available. Statistical findings wait for mature history and remain explainable.

## Baselines

The evaluator uses minute aggregates from the last seven days (or the current reset time, whichever is newer) and excludes points recorded as anomalies. It stores median, median absolute deviation (MAD), EWMA with alpha 0.2, p95, sample count, confidence, update time, version and frozen status.

For scoring, scale is max(1.4826 × MAD, 5% × absolute median, 0.01). Score is absolute distance from median divided by the scale. A baseline is mature only after at least 2,880 clean minute samples spanning 48 hours. A candidate score of 4.5 or more is excluded from training immediately; three consecutive candidate evaluations are needed for a statistical incident. Safety rules do not wait for maturity.

Training freezes while any incident is active or a direct safety trigger is present. Reset increments model version and reset timestamp, clears learned baseline rows, and preserves metric/anomaly/incident history. The UI requires confirmation. Day-of-week/time-of-day patterns and per-workload statistical baselines are not implemented; the API reports weekly patterns unavailable.

## Immediate safety rules

- Available memory below configured warning/critical percentages.
- CPU PSI and memory PSI above configured warning thresholds.
- Root filesystem utilization above its configured threshold.
- CPU temperature at 90%/98% of a sensor-reported limit when available.
- Aggregate swap-in/out movement above 5 MiB/s. Swap occupancy alone is not an incident.

Sensor-specific configurable fallback temperature limits are not implemented. A CPU sensor without a reported limit does not produce this thermal rule.

## Correlation and recovery

Resource safety triggers share one resource-pressure incident signature. Thermal and storage each have a shared signature; statistical findings use a metric-specific signature. A detected group updates in place. Incidents recover after three consecutive minute evaluations without that signature. Recovery state is persisted and can produce a recovery notification.

The process lifecycle detector tracks a process whose previously observed parent identity disappears, accounting for PID reuse. A conservative browser incident requires at least two long-lived orphaned browser processes, 20% total CPU, or 1 GiB RSS. The explanation notes that daemonization is another possible cause. Broader cross-metric correlation remains limited.

## Evidence language

Incident evidence distinguishes direct thresholds/statistical observations from the explanation and confidence estimate. The AI layer interprets bounded evidence on request but is not a detector and cannot execute commands.
