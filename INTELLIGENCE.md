# Intelligence and incident model

Sentinel does not use an LLM for routine monitoring. Immediate rules run as soon as samples are available. Statistical findings wait for mature history and remain explainable.

## Baselines

The evaluator uses minute aggregates from the last seven days (or the current reset time, whichever is newer) and excludes points recorded as anomalies. It stores median, median absolute deviation (MAD), EWMA with alpha 0.2, p95, sample count, confidence, update time, version and frozen status.

For scoring, scale is max(1.4826 × MAD, 5% × absolute median, 0.01). Score is absolute distance from median divided by the scale. A baseline is mature only after at least 2,880 clean minute samples spanning 48 hours. A candidate score of 4.5 or more is excluded from training immediately; three consecutive candidate evaluations are needed for a statistical incident. Safety rules do not wait for maturity.

Training freezes for metrics affected by an active incident or current candidate. OOM events and adaptive high-pressure guards pause all model updates; service-restart and orphan-browser findings pause workload streams. An unrelated persistent warning (for example, a root-disk warning) does not stop other metrics from calibrating. Reset increments model version and reset timestamp, clears learned baseline rows, and preserves metric/anomaly/incident history. The UI requires confirmation.

Sentinel also maintains aggregate CPU, RSS, and process-count histories for the union of the 25 busiest workloads by each measure. Workload keys use the observed systemd unit/cgroup where available, then executable plus session, with a name/session fallback. User labels change display only and do not change the history key. Workloads outside the bounded ranking do not receive statistical baselines.

The evaluator caches a time-aware comparison per metric and current UTC hour. A same-hour-of-day model requires at least 14 distinct clean daily windows, each with 30 or more minute observations and at least 13 days of span. A same-hour-of-week model requires four clean weekly repetitions, each with 30 or more observations and at least 21 days of span. Weekly models take precedence. Neither pattern is scored before its evidence threshold; model rows expose period count, median, MAD, and confidence. Resetting the baseline version discards cached seasonal models immediately.

For sustained changes, a bounded two-sided CUSUM examines up to 30 recent minutes for eligible memory, swap, disk-use, and workload-RSS metrics. Gaps longer than three minutes reset the accumulated signal. It is combined with the robust rolling and seasonal scores and still requires three consecutive candidate evaluations. This is intended to surface gradual change without making a single point an incident; it is not a forecast.

## Immediate safety rules

- Available memory below configured warning/critical percentages.
- CPU PSI and memory PSI above configured warning thresholds.
- Root filesystem utilization above its configured threshold.
- CPU temperature at 90%/98% of a sensor-reported limit when available.
- Aggregate swap-in/out movement above 5 MiB/s. Swap occupancy alone is not an incident.
- NVIDIA GPU memory at or above 99% of reported capacity is a warning; 99.8% is critical when the optional telemetry is available. When NVIDIA reports compute applications, Sentinel samples their PID, executable name, and VRAM use once per minute and adds those observations to the process explorer and GPU incident evidence. The join to procfs requires both PID and process name; graphics contexts and unreported processes may be absent.
- Increases in the host-wide `/proc/vmstat` `oom_kill` counter create a critical incident. The counter does not identify the victim process. Sentinel compares against its latest stored sample (or seeds from the current counter when no history exists); an increase may have happened while Sentinel was stopped.
- Increases in systemd `NRestarts` between service inventory samples create a warning incident for that unit. The first observation seeds the current count; counter resets are treated as a new baseline.

Sensor-specific configurable fallback temperature limits are not implemented. A CPU sensor without a reported limit does not produce this thermal rule.

## Correlation and recovery

Resource safety triggers share one resource-pressure incident signature. Thermal, storage and GPU memory use separate signatures. Statistical findings for the same workload key are grouped into one workload investigation; its evidence includes current related process identity, resource use, parent-loss observations, and co-observed host pressure signals. A large browser population with observed parent loss and simultaneous host pressure updates one browser investigation with both sets of evidence instead of opening a second generic resource warning. These combinations record temporal association, not causation, and the explanation retains alternatives such as unrelated workload pressure or expected daemonization. Other host statistical findings use metric-specific signatures. A detected group updates in place; active severity only escalates and remains at its highest level until recovery. Escalation notifications bypass the ordinary cooldown. Incidents recover after three consecutive minute evaluations without that signature. Recovery state is persisted and can produce a recovery notification.

The process collector records sampled starts, exits, and first observed parent-loss transitions with stable boot/PID/start-tick identity. It seeds the first inventory, avoids treating unreadable `/proc` entries as exits, caps event ingestion at 100 per poll, and retains up to seven days (or less under database-budget pressure). Processes shorter than the 10-second polling interval can be missed; exit timestamps are detection times, not kernel event times. Kernel OOM counters are host-wide. Victim identity could not be read here because opening `/dev/kmsg` is denied and the user's journal does not expose kernel messages; the incident preserves the counter evidence without inventing a victim. A conservative browser accumulation finding requires at least eight long-lived observed-parent-loss browser processes with 20% total CPU or 2 GiB RSS, or at least 40% total CPU or 4 GiB RSS regardless of count. A workload population anomaly suppresses the duplicate browser finding. The explanation notes that daemonization is another possible cause.

## Evidence language

Incident evidence distinguishes direct thresholds/statistical observations from the explanation and confidence estimate. The AI layer interprets bounded evidence on request but is not a detector and cannot execute commands.

## Synthetic regression coverage

The Rust suite exercises healthy high-CPU and mature compute workloads as no-alert cases; rising memory as a sustained-change case; and CPU pressure, low available memory, swap churn, disk capacity, thermal escalation, GPU memory exhaustion, browser parent loss/accumulation, OOM-counter increments, and service restart counters as expected findings. Separate pressure fixtures assert that unrelated signals remain separate and a browser accumulation finding can absorb co-observed host pressure. Tests assert expected signatures and severity, no false alert in the clean fixtures, no missed finding in the targeted cases, and memory-drift detection within 20 minutes. These are deterministic regression checks, not a calibrated production false-positive rate or a replay of another machine's incident.
