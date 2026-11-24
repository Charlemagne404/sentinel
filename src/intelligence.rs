use crate::{
    config::Config,
    model::{HostSnapshot, ProcessSnapshot, ServiceRestartEvent},
    notifications::IncidentNotice,
    storage::{Baseline, SeasonalValues, Store},
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

#[derive(Default)]
pub struct Evaluator {
    streaks: HashMap<String, u8>,
    misses: HashMap<String, u8>,
    baseline_version: Option<u32>,
    seasonal_cache: HashMap<String, (i64, i64, i64, Option<SeasonalValues>)>,
    browser_history: HashMap<String, VecDeque<BrowserSample>>,
}

#[derive(Clone)]
struct BrowserSample {
    timestamp: i64,
    identities: HashSet<String>,
    count: usize,
    rss_bytes: u64,
}

#[derive(Clone)]
struct BrowserGrowth {
    previous_count: usize,
    window_seconds: i64,
    new_processes: usize,
    rss_increase_bytes: u64,
}

#[derive(Debug, Clone)]
struct Trigger {
    metric: String,
    value: f64,
    score: f64,
    severity: String,
    reason: String,
    kind: String,
}

impl Evaluator {
    pub fn seasonal_models(&self, now: i64) -> Vec<SeasonalValues> {
        let hour_slot = now.div_euclid(3600);
        let mut models = self
            .seasonal_cache
            .values()
            .filter(|(checked_at, cached_slot, _, model)| {
                *cached_slot == hour_slot
                    && now.saturating_sub(*checked_at) <= 2 * 3600
                    && model.is_some()
            })
            .filter_map(|(_, _, _, model)| model.clone())
            .collect::<Vec<_>>();
        models.sort_by(|a, b| a.metric.cmp(&b.metric));
        models
    }

    fn seasonal_model(
        &mut self,
        store: &Store,
        metric: &str,
        since: i64,
        now: i64,
    ) -> anyhow::Result<Option<SeasonalValues>> {
        let hour_slot = now.div_euclid(3600);
        if let Some((checked_at, cached_slot, cached_since, model)) =
            self.seasonal_cache.get(metric)
            && *cached_slot == hour_slot
            && *cached_since == since
            && now.saturating_sub(*checked_at) < 3600
        {
            return Ok(model.clone());
        }
        let model = store.seasonal_values(metric, since, now)?;
        self.seasonal_cache
            .insert(metric.to_string(), (now, hour_slot, since, model.clone()));
        if self.seasonal_cache.len() > 320
            && let Some(oldest) = self
                .seasonal_cache
                .iter()
                .min_by_key(|(_, (checked_at, _, _, _))| *checked_at)
                .map(|(key, _)| key.clone())
        {
            self.seasonal_cache.remove(&oldest);
        }
        Ok(model)
    }

    fn observe_browser_population(
        &mut self,
        workload: &str,
        members: &[&ProcessSnapshot],
        now: i64,
    ) -> Option<BrowserGrowth> {
        let cutoff = now.saturating_sub(30 * 60);
        for history in self.browser_history.values_mut() {
            while history
                .front()
                .is_some_and(|sample| sample.timestamp < cutoff)
            {
                history.pop_front();
            }
        }
        self.browser_history
            .retain(|_, history| !history.is_empty());
        if !self.browser_history.contains_key(workload) && self.browser_history.len() >= 64 {
            let oldest = self
                .browser_history
                .iter()
                .min_by_key(|(_, history)| history.back().map(|sample| sample.timestamp))
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.browser_history.remove(&oldest);
            }
        }

        let sample = BrowserSample {
            timestamp: now,
            identities: members
                .iter()
                .take(200)
                .map(|process| process.key.clone())
                .collect(),
            count: members.len(),
            rss_bytes: members
                .iter()
                .map(|process| process.rss_bytes)
                .fold(0_u64, u64::saturating_add),
        };
        let history = self
            .browser_history
            .entry(workload.to_string())
            .or_default();
        if history
            .back()
            .is_some_and(|previous| previous.timestamp == now)
        {
            history.pop_back();
        }
        history.push_back(sample.clone());
        while history.len() > 31 {
            history.pop_front();
        }
        let previous = history.iter().rev().skip(1).find(|previous| {
            let age = now.saturating_sub(previous.timestamp);
            (10 * 60..=20 * 60).contains(&age)
        })?;
        let new_processes = sample.identities.difference(&previous.identities).count();
        Some(BrowserGrowth {
            previous_count: previous.count,
            window_seconds: now.saturating_sub(previous.timestamp),
            new_processes,
            rss_increase_bytes: sample.rss_bytes.saturating_sub(previous.rss_bytes),
        })
    }

    pub fn evaluate(
        &mut self,
        store: &Store,
        config: &Config,
        host: &HostSnapshot,
        processes: &[ProcessSnapshot],
        workload_metrics: &[(String, f64)],
        oom_kill_delta: u64,
        service_restarts: &[ServiceRestartEvent],
        now: i64,
    ) -> anyhow::Result<Vec<IncidentNotice>> {
        let mut notices = Vec::new();
        let mut triggers = Vec::<Trigger>::new();
        let mut metrics = host.metrics();
        metrics.extend_from_slice(workload_metrics);
        let (baseline_version, reset_at) = store.baseline_state()?;
        if self.baseline_version != Some(baseline_version) {
            self.seasonal_cache.clear();
            self.baseline_version = Some(baseline_version);
        }
        let current_baselines = store
            .baselines()?
            .into_iter()
            .filter(|b| b.version == baseline_version)
            .map(|b| (b.metric.clone(), b))
            .collect::<HashMap<_, _>>();

        let available_pct = if host.memory_total_bytes > 0 {
            host.memory_available_bytes as f64 * 100.0 / host.memory_total_bytes as f64
        } else {
            100.0
        };
        if available_pct <= config.thresholds.memory_available_critical_percent {
            triggers.push(trigger(
                "memory_available_percent",
                available_pct,
                10.0,
                "critical",
                "Available RAM is below the configured critical threshold.",
                "resource",
            ));
        } else if available_pct <= config.thresholds.memory_available_warning_percent {
            triggers.push(trigger(
                "memory_available_percent",
                available_pct,
                6.0,
                "warning",
                "Available RAM is below the configured warning threshold.",
                "resource",
            ));
        }
        if host.disk_total_bytes > 0 {
            let used = (host.disk_total_bytes - host.disk_available_bytes) as f64 * 100.0
                / host.disk_total_bytes as f64;
            if used >= config.thresholds.disk_used_warning_percent {
                triggers.push(trigger(
                    "disk_used_percent",
                    used,
                    5.0,
                    "warning",
                    "Root filesystem usage has crossed the configured threshold.",
                    "storage",
                ));
            }
        }
        if host
            .psi_cpu_some_percent
            .is_some_and(|v| v >= config.thresholds.cpu_pressure_warning_percent)
        {
            triggers.push(trigger(
                "cpu_pressure",
                host.psi_cpu_some_percent.unwrap_or(0.0),
                5.0,
                "warning",
                "CPU PSI reports runnable-task contention.",
                "resource",
            ));
        }
        if host
            .psi_memory_some_percent
            .is_some_and(|v| v >= config.thresholds.memory_pressure_warning_percent)
        {
            triggers.push(trigger(
                "memory_pressure",
                host.psi_memory_some_percent.unwrap_or(0.0),
                5.0,
                "warning",
                "Memory PSI reports processes stalled on memory pressure.",
                "resource",
            ));
        }
        if let (Some(temp), Some(limit)) = (host.cpu_temperature_c, host.cpu_temperature_limit_c) {
            if limit > 0.0 && temp >= limit * 0.98 {
                triggers.push(trigger(
                    "cpu_temperature_c",
                    temp,
                    9.0,
                    "critical",
                    "CPU temperature is at least 98% of the hardware-reported limit.",
                    "thermal",
                ));
            } else if limit > 0.0 && temp >= limit * 0.90 {
                triggers.push(trigger(
                    "cpu_temperature_c",
                    temp,
                    6.0,
                    "warning",
                    "CPU temperature is at least 90% of the hardware-reported limit.",
                    "thermal",
                ));
            }
        }
        let swap_rate = host.swap_in_bytes_per_sec + host.swap_out_bytes_per_sec;
        if swap_rate > 5.0 * 1024.0 * 1024.0 {
            triggers.push(trigger("swap_activity",swap_rate,5.0,"warning","Swap is actively moving more than 5 MiB/s; occupied swap alone is not treated as an incident.","resource"));
        }
        if let Some(gpu) = &host.gpu
            && let (Some(used), Some(total)) = (gpu.memory_used_bytes, gpu.memory_total_bytes)
            && total > 0
        {
            let used_percent = (used as f64 * 100.0 / total as f64).clamp(0.0, 100.0);
            if used_percent >= 99.8 {
                triggers.push(trigger(
                    "gpu_memory_used_percent",
                    used_percent,
                    9.0,
                    "critical",
                    "GPU memory use is at least 99.8% of reported capacity.",
                    "gpu",
                ));
            } else if used_percent >= 99.0 {
                triggers.push(trigger(
                    "gpu_memory_used_percent",
                    used_percent,
                    6.0,
                    "warning",
                    "GPU memory use is at least 99% of reported capacity.",
                    "gpu",
                ));
            }
        }

        let active_incidents = store.incidents(true, 500)?;
        let adaptive_hold = available_pct < 10.0
            || host.psi_cpu_some_percent.is_some_and(|value| value > 50.0)
            || host
                .psi_memory_some_percent
                .is_some_and(|value| value > 20.0)
            || host
                .cpu_temperature_c
                .zip(host.cpu_temperature_limit_c)
                .is_some_and(|(temperature, limit)| limit > 0.0 && temperature >= limit * 0.95);
        for (metric, value) in metrics {
            let since = (now - 7 * 86400).max(reset_at);
            let observations = store.baseline_observations(&metric, since, 10_080)?;
            let values = observations
                .iter()
                .map(|(_, value)| *value)
                .collect::<Vec<_>>();
            let old = current_baselines.get(&metric);
            let first = observations.first().map(|(ts, _)| *ts).unwrap_or(now);
            let med = median(&values);
            let deviations = med
                .map(|m| values.iter().map(|v| (v - m).abs()).collect::<Vec<_>>())
                .unwrap_or_default();
            let mad = median(&deviations);
            let p95 = percentile(&values, 0.95);
            let moving = ewma(&values);
            let mature = values.len() >= 2880 && now - first >= 48 * 3600;
            let score = med
                .zip(mad)
                .map(|(m, d)| robust_score(value, m, d))
                .unwrap_or(0.0);
            let seasonal = if mature {
                self.seasonal_model(store, &metric, reset_at, now)?
            } else {
                None
            };
            let seasonal_stats = seasonal.as_ref().map(|model| (model.median, model.mad));
            let seasonal_score =
                seasonal_stats.map(|(center, spread)| robust_score(value, center, spread));
            let cusum = if mature && cusum_eligible_metric(&metric) {
                seasonal_stats
                    .or(med.zip(mad))
                    .map(|(center, spread)| cusum_score(&observations, now, value, center, spread))
                    .unwrap_or(0.0)
            } else {
                0.0
            };
            let rolling_candidate =
                score >= 4.5 && seasonal_score.is_none_or(|seasonal_score| seasonal_score >= 3.5);
            let seasonal_candidate =
                seasonal_score.is_some_and(|seasonal_score| seasonal_score >= 4.5);
            let cpu_candidate_allowed = !is_cpu_utilization_metric(&metric)
                || host
                    .psi_cpu_some_percent
                    .is_some_and(|value| value >= config.thresholds.cpu_pressure_warning_percent);
            let is_candidate = mature
                && cpu_candidate_allowed
                && (rolling_candidate || seasonal_candidate || cusum >= 8.0);
            let streak = self.streaks.entry(metric.to_string()).or_default();
            *streak = next_candidate_streak(*streak, is_candidate);
            if mature && *streak >= 3 {
                let anomaly_score = if seasonal_candidate {
                    seasonal_score.unwrap_or(score)
                } else {
                    score
                };
                let reason = if seasonal_candidate {
                    if let Some(model) = &seasonal {
                        format!(
                            "Value differs by {anomaly_score:.1} robust deviations from the mature {} pattern ({} clean periods).",
                            model.pattern, model.periods
                        )
                    } else {
                        format!(
                            "Value is {anomaly_score:.1} robust deviations from its seasonal baseline."
                        )
                    }
                } else if cusum >= 8.0 && score < 4.5 {
                    format!(
                        "Sustained change detected by two-sided CUSUM (score {cusum:.1}); current point is {score:.1} robust deviations from the rolling baseline."
                    )
                } else {
                    format!(
                        "Value is {score:.1} robust deviations from the mature rolling baseline."
                    )
                };
                triggers.push(trigger(
                    &metric,
                    value,
                    anomaly_score,
                    "warning",
                    &reason,
                    "statistical",
                ));
            }
            let metric_frozen = adaptive_hold
                || oom_kill_delta > 0
                || is_candidate
                || triggers.iter().any(|t| t.metric == metric)
                || active_incidents
                    .iter()
                    .any(|incident| incident_affects_metric(incident, &metric))
                || (!service_restarts.is_empty() && metric.starts_with("workload::"));
            if metric_frozen {
                let reason = if is_candidate {
                    "statistical anomaly candidate"
                } else if adaptive_hold || oom_kill_delta > 0 {
                    "host pressure or OOM observation"
                } else if !service_restarts.is_empty() && metric.starts_with("workload::") {
                    "service restart observation"
                } else {
                    "active or newly observed incident"
                };
                store.exclude_baseline_point(&metric, now.div_euclid(60) * 60, reason)?;
            }
            if !metric_frozen {
                let baseline = Baseline {
                    metric: metric.clone(),
                    version: baseline_version,
                    samples: values.len(),
                    first_timestamp: first,
                    observed_hours: ((now - first).max(0) as f64) / 3600.0,
                    median: med,
                    mad,
                    ewma: moving,
                    p95,
                    confidence: (values.len() as f64 / 10_080.0).clamp(0.0, 1.0),
                    frozen: false,
                    updated_at: now,
                };
                store.save_baseline(&baseline, first)?;
            } else if let Some(old) = old {
                let mut frozen = old.clone();
                frozen.frozen = true;
                frozen.updated_at = now;
                store.save_baseline(&frozen, frozen.first_timestamp)?;
            }
        }

        let mut browser_workloads = BTreeMap::<String, Vec<&ProcessSnapshot>>::new();
        for process in processes
            .iter()
            .filter(|p| p.parent_disappeared && p.runtime_seconds > 60 && is_browser(&p.name))
        {
            browser_workloads
                .entry(process.workload.clone())
                .or_default()
                .push(process);
        }
        let mut browsers = Vec::<&ProcessSnapshot>::new();
        let mut browser_growth = Vec::<serde_json::Value>::new();
        let active_browser_incident = active_incidents
            .iter()
            .any(|incident| incident.signature == "orphan-browser");
        for (workload, members) in browser_workloads {
            let cpu = members
                .iter()
                .map(|process| process.cpu_percent)
                .sum::<f64>();
            let rss = members.iter().map(|process| process.rss_bytes).sum::<u64>();
            let Some(growth) = self.observe_browser_population(&workload, &members, now) else {
                continue;
            };
            let population_modeled = members.iter().any(|process| {
                let key = crate::workloads::workload_metric_key(&process.workload);
                triggers.iter().any(|finding| {
                    finding.kind == "statistical"
                        && finding.metric.ends_with("::process_count")
                        && workload_key_from_metric(&finding.metric) == Some(key.as_str())
                })
            });
            let growing = (growth.new_processes >= 4
                && growth.rss_increase_bytes >= 512 * 1024 * 1024)
                || growth.rss_increase_bytes >= 1024 * 1024 * 1024
                || growth.new_processes >= 8;
            if !population_modeled
                && browser_accumulation_suspicious(members.len(), cpu, rss)
                && (growing || active_browser_incident)
            {
                browsers.extend(members.iter().copied());
                browser_growth.push(serde_json::json!({
                    "workload": workload,
                    "previous_process_count": growth.previous_count,
                    "new_processes": growth.new_processes,
                    "window_seconds": growth.window_seconds,
                    "rss_increase_bytes": growth.rss_increase_bytes
                }));
            }
        }
        let browser_cpu = browsers.iter().map(|p| p.cpu_percent).sum::<f64>();
        let browser_rss = browsers.iter().map(|p| p.rss_bytes).sum::<u64>();
        let orphan_active = !browsers.is_empty();
        let resource = triggers
            .iter()
            .filter(|trigger| trigger.kind == "resource")
            .cloned()
            .collect::<Vec<_>>();
        let correlated_browser_pressure = orphan_active && !resource.is_empty();
        let mut observed = HashSet::<String>::new();
        if orphan_active {
            let workloads = browsers
                .iter()
                .map(|process| process.workload.as_str())
                .collect::<BTreeSet<_>>();
            let groups = browsers
                .iter()
                .map(|process| process.process_group)
                .collect::<BTreeSet<_>>();
            let sessions = browsers
                .iter()
                .map(|process| process.session)
                .collect::<BTreeSet<_>>();
            let mut evidence = serde_json::json!({
                "observed_processes": browsers.iter().take(30).map(|process| serde_json::json!({
                    "identity": process.key,
                    "pid": process.pid,
                    "name": process.name,
                    "parent_pid": process.ppid,
                    "runtime_seconds": process.runtime_seconds,
                    "cpu_percent": process.cpu_percent,
                    "rss_bytes": process.rss_bytes,
                    "workload": process.workload,
                    "cgroup": process.cgroup,
                    "process_group": process.process_group,
                    "session": process.session,
                    "parent_disappeared": process.parent_disappeared
                })).collect::<Vec<_>>(),
                "count": browsers.len(),
                "cpu_percent_total": browser_cpu,
                "rss_bytes_total": browser_rss,
                "workloads": workloads,
                "process_groups": groups,
                "sessions": sessions,
                "growth_windows": browser_growth,
                "direct_fact": "previous parent identity disappeared between process observations",
                "inference": "orphaned browser work is possible, but normal daemonization is also possible"
            });
            let severity = if resource
                .iter()
                .any(|trigger| trigger.severity == "critical")
            {
                "critical"
            } else {
                "warning"
            };
            let title = if correlated_browser_pressure {
                "Browser accumulation coincided with host resource pressure"
            } else {
                "Browser processes outlived their observed parent"
            };
            let explanation = if correlated_browser_pressure {
                evidence["co_observed_resource_signals"] =
                    trigger_evidence(&resource)["observations"].clone();
                "Sentinel observed a large population of browser processes whose previously observed parent identities disappeared, alongside host resource pressure in the same evaluation window. The timing supports investigating a possible association, but does not establish that these processes caused the host pressure. Other workloads may contribute, and browser daemonization is an alternative explanation. Review the listed workload, process groups, sessions, and measurements."
            } else {
                "Sentinel observed browser processes whose previously observed parent identities disappeared. That relationship can be consistent with abandoned automation, but daemonization is another explanation. Review the listed workload, process groups, and session before taking action."
            };
            let (id, created, escalated) = store.open_or_update_incident(
                "orphan-browser",
                severity,
                title,
                0.72,
                &evidence,
                explanation,
                now,
            )?;
            if let Some(notice) = incident_notice(
                id,
                "orphan-browser",
                title,
                severity,
                created,
                escalated,
                false,
            ) {
                notices.push(notice);
            }
            self.misses.insert("orphan-browser".into(), 0);
            store.append_anomaly(
                now,
                "orphan_browser_processes",
                browsers.len() as f64,
                4.0,
                "parent identity disappeared; workload review recommended",
                Some(id),
            )?;
            if correlated_browser_pressure {
                for trigger in &resource {
                    store.append_anomaly(
                        now,
                        &trigger.metric,
                        trigger.value,
                        trigger.score,
                        &trigger.reason,
                        Some(id),
                    )?;
                }
            }
            observed.insert("orphan-browser".into());
        }

        if oom_kill_delta > 0 {
            let signature = "oom-kill";
            let evidence = serde_json::json!({
                "events_since_last_evaluation": oom_kill_delta,
                "kernel_oom_kill_counter": host.oom_kill_count,
                "source": "/proc/vmstat oom_kill",
                "attribution": "The kernel counter is host-wide; it does not identify the killed process."
            });
            let explanation = format!(
                "The kernel OOM-kill counter increased by {oom_kill_delta} since Sentinel's previous observation. This is a direct host-wide counter; it does not identify which process was killed."
            );
            let (id, created, escalated) = store.open_or_update_incident(
                signature,
                "critical",
                "The kernel killed a process under memory pressure",
                0.98,
                &evidence,
                &explanation,
                now,
            )?;
            if let Some(notice) = incident_notice(
                id,
                signature,
                "The kernel killed a process under memory pressure",
                "critical",
                created,
                escalated,
                false,
            ) {
                notices.push(notice);
            }
            store.append_anomaly(
                now,
                "oom_kill_events",
                oom_kill_delta as f64,
                10.0,
                &format!("/proc/vmstat oom_kill increased by {oom_kill_delta}"),
                Some(id),
            )?;
            observed.insert(signature.into());
        }
        for event in service_restarts.iter().take(100) {
            let signature = format!("service-restart:{}", event.unit);
            let delta = event.current_count.saturating_sub(event.previous_count);
            let evidence = serde_json::json!({
                "unit": event.unit,
                "previous_restart_count": event.previous_count,
                "current_restart_count": event.current_count,
                "observed_increase": delta,
                "source": "systemd NRestarts"
            });
            let title = format!("Service restart observed: {}", event.unit);
            let explanation = format!(
                "systemd's NRestarts counter for {} increased from {} to {} between Sentinel service inventory samples. Sentinel observes this counter; it does not restart or modify the unit.",
                event.unit, event.previous_count, event.current_count
            );
            let (id, created, escalated) = store.open_or_update_incident(
                &signature,
                "warning",
                &title,
                0.95,
                &evidence,
                &explanation,
                now,
            )?;
            if let Some(notice) =
                incident_notice(id, &signature, &title, "warning", created, escalated, false)
            {
                notices.push(notice);
            }
            store.append_anomaly(
                now,
                "service_restart_events",
                delta as f64,
                5.0,
                &format!("{} NRestarts increased by {delta}", event.unit),
                Some(id),
            )?;
            observed.insert(signature);
        }
        let resource = triggers
            .iter()
            .filter(|t| t.kind == "resource")
            .cloned()
            .collect::<Vec<_>>();

        // Statistical signals from the same stable workload key are presented as
        // one investigation with the current process and host-pressure context.
        // This records temporal association only; it does not claim causation.
        let mut workload_findings = BTreeMap::<String, Vec<Trigger>>::new();
        for finding in triggers
            .iter()
            .filter(|finding| finding.kind == "statistical")
        {
            if let Some(key) = workload_key_from_metric(&finding.metric) {
                workload_findings
                    .entry(key.to_string())
                    .or_default()
                    .push(finding.clone());
            }
        }
        for (key, findings) in workload_findings {
            let related_processes = processes
                .iter()
                .filter(|process| crate::workloads::workload_metric_key(&process.workload) == key)
                .collect::<Vec<_>>();
            let parent_loss_count = related_processes
                .iter()
                .filter(|process| process.parent_disappeared)
                .count();
            let mut evidence = trigger_evidence(&findings);
            evidence["workload"] = serde_json::json!({
                "stable_key": key,
                "observed_name": related_processes.first().map(|process| process.workload.as_str()),
                "process_count": related_processes.len(),
                "parent_loss_count": parent_loss_count,
                "processes": related_processes.iter().take(30).map(|process| serde_json::json!({
                    "identity": process.key,
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "uid": process.uid,
                    "name": process.name,
                    "executable": process.executable,
                    "runtime_seconds": process.runtime_seconds,
                    "cpu_percent": process.cpu_percent,
                    "rss_bytes": process.rss_bytes,
                    "process_group": process.process_group,
                    "session": process.session,
                    "cgroup": process.cgroup,
                    "parent_disappeared": process.parent_disappeared
                })).collect::<Vec<_>>()
            });
            evidence["co_observed_host_signals"] =
                trigger_evidence(&resource)["observations"].clone();
            let signature = format!("workload-stat:{key}");
            let title = if findings
                .iter()
                .any(|finding| finding.metric.ends_with("::process_count"))
            {
                "Workload process population differs from its learned pattern"
            } else {
                "Workload resource use differs from its learned pattern"
            };
            let extra_context = if resource.is_empty() {
                String::new()
            } else {
                format!(
                    " At the same evaluation, host-level pressure signals were also observed ({}); their timing is recorded as context, not proof that this workload caused them.",
                    resource
                        .iter()
                        .map(|finding| finding.metric.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let explanation = format!(
                "{} The workload metrics share one stable workload key. Sentinel observed {} current processes, including {} with a previously observed parent identity loss. These measurements may be related, but they do not prove causation; expected workload scaling or daemonization are alternative explanations.{}",
                format_explanation(&findings),
                related_processes.len(),
                parent_loss_count,
                extra_context
            );
            let grouped_confidence = (confidence(&findings)
                + if findings.len() > 1 { 0.05 } else { 0.0 }
                + if parent_loss_count > 0 { 0.03 } else { 0.0 })
            .min(0.92);
            let (id, created, escalated) = store.open_or_update_incident(
                &signature,
                "warning",
                title,
                grouped_confidence,
                &evidence,
                &explanation,
                now,
            )?;
            if let Some(notice) =
                incident_notice(id, &signature, title, "warning", created, escalated, false)
            {
                notices.push(notice);
            }
            for finding in &findings {
                store.append_anomaly(
                    now,
                    &finding.metric,
                    finding.value,
                    finding.score,
                    &finding.reason,
                    Some(id),
                )?;
            }
            observed.insert(signature);
        }
        if !resource.is_empty() && !correlated_browser_pressure {
            let critical = resource.iter().any(|t| t.severity == "critical");
            let evidence = trigger_evidence(&resource);
            let (id, created, escalated) = store.open_or_update_incident(
                "resource-pressure",
                if critical { "critical" } else { "warning" },
                "Host resource pressure needs attention",
                confidence(&resource),
                &evidence,
                &format_explanation(&resource),
                now,
            )?;
            let severity = if critical { "critical" } else { "warning" };
            if let Some(notice) = incident_notice(
                id,
                "resource-pressure",
                "Host resource pressure needs attention",
                severity,
                created,
                escalated,
                false,
            ) {
                notices.push(notice);
            }
            for t in &resource {
                store.append_anomaly(now, &t.metric, t.value, t.score, &t.reason, Some(id))?;
            }
            observed.insert("resource-pressure".into());
        }
        for kind in ["thermal", "storage", "statistical", "gpu"] {
            let items = triggers
                .iter()
                .filter(|t| {
                    t.kind == kind && !(kind == "statistical" && t.metric.starts_with("workload::"))
                })
                .cloned()
                .collect::<Vec<_>>();
            for t in items {
                let signature = if kind == "statistical" {
                    format!("stat:{}", t.metric)
                } else {
                    kind.to_string()
                };
                let title = match kind {
                    "thermal" => {
                        "Hardware temperature is approaching its reported limit".to_string()
                    }
                    "storage" => "Root filesystem is running low on space".to_string(),
                    "gpu" => "GPU memory is nearly exhausted".to_string(),
                    _ => format!("Unusual {} behaviour", t.metric.replace('_', " ")),
                };
                let mut evidence = trigger_evidence(std::slice::from_ref(&t));
                if kind == "gpu"
                    && let Some(gpu) = host.gpu.as_ref()
                {
                    evidence["gpu_process_attribution"] = serde_json::json!({
                        "available": gpu.process_attribution_available,
                        "sampled_at": gpu.process_attribution_sampled_at,
                        "scope": "NVIDIA compute applications only; graphics processes may not be visible",
                        "processes": gpu.processes.iter().take(64).map(|app| {
                            let name = app.process_name.rsplit('/').next().unwrap_or(&app.process_name);
                            let observed = processes.iter().find(|process| {
                                process.pid == app.pid
                                    && (process.executable.as_deref() == Some(app.process_name.as_str())
                                        || process.name == name)
                            });
                            serde_json::json!({
                                "pid": app.pid,
                                "reported_process_name": app.process_name,
                                "gpu_memory_bytes": app.memory_used_bytes,
                                "process_identity": observed.map(|process| process.key.as_str()),
                                "workload": observed.map(|process| process.workload.as_str()),
                                "identity_match": observed.is_some()
                            })
                        }).collect::<Vec<_>>()
                    });
                }
                let (id, created, escalated) = store.open_or_update_incident(
                    &signature,
                    &t.severity,
                    &title,
                    confidence(std::slice::from_ref(&t)),
                    &evidence,
                    &format_explanation(std::slice::from_ref(&t)),
                    now,
                )?;
                if let Some(notice) = incident_notice(
                    id,
                    &signature,
                    &title,
                    &t.severity,
                    created,
                    escalated,
                    false,
                ) {
                    notices.push(notice);
                }
                store.append_anomaly(now, &t.metric, t.value, t.score, &t.reason, Some(id))?;
                observed.insert(signature);
            }
        }
        for incident in store.incidents(true, 500)? {
            if observed.contains(&incident.signature) {
                self.misses.insert(incident.signature, 0);
                continue;
            }
            let missed = self.misses.entry(incident.signature.clone()).or_default();
            *missed = missed.saturating_add(1);
            if *missed >= 3 {
                if store.recover_incident(&incident.signature, now)? {
                    if let Some(notice) = incident_notice(
                        incident.id,
                        &incident.signature,
                        &incident.title,
                        &incident.severity,
                        false,
                        false,
                        true,
                    ) {
                        notices.push(notice);
                    }
                }
                *missed = 0;
            }
        }
        Ok(notices)
    }
}

fn trigger(
    metric: &str,
    value: f64,
    score: f64,
    severity: &str,
    reason: &str,
    kind: &str,
) -> Trigger {
    Trigger {
        metric: metric.into(),
        value,
        score,
        severity: severity.into(),
        reason: reason.into(),
        kind: kind.into(),
    }
}
fn is_browser(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("chrom") || n.contains("firefox") || n.contains("browser")
}
fn browser_accumulation_suspicious(count: usize, cpu_percent: f64, rss_bytes: u64) -> bool {
    (count >= 8 && (cpu_percent >= 20.0 || rss_bytes >= 2 * 1024 * 1024 * 1024))
        || cpu_percent >= 40.0
        || rss_bytes >= 4 * 1024 * 1024 * 1024
}
fn workload_key_from_metric(metric: &str) -> Option<&str> {
    let metric = metric.strip_prefix("workload::")?;
    let (key, suffix) = metric.rsplit_once("::")?;
    matches!(suffix, "cpu_percent" | "rss_bytes" | "process_count").then_some(key)
}
fn incident_affects_metric(incident: &crate::model::Incident, metric: &str) -> bool {
    match incident.signature.as_str() {
        "resource-pressure" => {
            incident.evidence["observations"]
                .as_array()
                .is_some_and(|observations| {
                    observations
                        .iter()
                        .any(|observation| observation["metric"].as_str() == Some(metric))
                })
        }
        "thermal" => metric == "cpu_temperature_c",
        "storage" => metric == "disk_used_percent",
        "gpu" => metric.starts_with("gpu_"),
        "oom-kill" => true,
        "orphan-browser" => metric.starts_with("workload::"),
        signature if signature.starts_with("stat:") => {
            signature.strip_prefix("stat:") == Some(metric)
        }
        signature if signature.starts_with("service-restart:") => metric.starts_with("workload::"),
        _ => false,
    }
}
fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        Some((sorted[mid - 1] + sorted[mid]) / 2.0)
    } else {
        Some(sorted[mid])
    }
}
fn percentile(values: &[f64], p: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let idx = ((sorted.len() - 1) as f64 * p.clamp(0.0, 1.0)).ceil() as usize;
    sorted.get(idx).copied()
}
fn ewma(values: &[f64]) -> Option<f64> {
    let mut iter = values.iter();
    let mut prev = *iter.next()?;
    for v in iter {
        prev = 0.2 * *v + 0.8 * prev;
    }
    Some(prev)
}
fn robust_score(value: f64, median: f64, mad: f64) -> f64 {
    let scale = (mad * 1.4826).max(median.abs() * 0.05).max(0.01);
    (value - median).abs() / scale
}
fn cusum_eligible_metric(metric: &str) -> bool {
    matches!(
        metric,
        "memory_used_percent" | "swap_used_percent" | "disk_used_percent"
    ) || metric.ends_with("::rss_bytes")
}
fn is_cpu_utilization_metric(metric: &str) -> bool {
    matches!(
        metric,
        "cpu"
            | "cpu_user_percent"
            | "cpu_system_percent"
            | "cpu_iowait_percent"
            | "cpu_idle_percent"
    ) || metric.starts_with("cpu_core_")
        || (metric.starts_with("workload::") && metric.ends_with("::cpu_percent"))
}
fn cusum_score(observations: &[(i64, f64)], now: i64, current: f64, center: f64, mad: f64) -> f64 {
    let scale = (mad * 1.4826).max(center.abs() * 0.05).max(0.01);
    let mut values = observations
        .iter()
        .rev()
        .filter(|(ts, _)| *ts >= now - 30 * 60 && *ts <= now)
        .take(30)
        .map(|(ts, value)| (*ts, *value))
        .collect::<Vec<_>>();
    values.reverse();
    values.push((now, current));

    let (mut upward, mut downward, mut maximum, mut previous_ts) =
        (0.0_f64, 0.0_f64, 0.0_f64, None);
    for (ts, value) in values {
        if previous_ts.is_some_and(|previous| ts.saturating_sub(previous) > 180) {
            upward = 0.0;
            downward = 0.0;
            maximum = 0.0;
        }
        let residual = (value - center) / scale;
        upward = (upward + residual - 0.5).max(0.0);
        downward = (downward - residual - 0.5).max(0.0);
        maximum = maximum.max(upward).max(downward);
        previous_ts = Some(ts);
    }
    maximum
}
fn next_candidate_streak(previous: u8, candidate: bool) -> u8 {
    if candidate {
        previous.saturating_add(1)
    } else {
        0
    }
}
fn confidence(items: &[Trigger]) -> f64 {
    items
        .iter()
        .map(|t| {
            if t.kind == "statistical" {
                (t.score / 10.0).clamp(0.55, 0.95)
            } else {
                0.9
            }
        })
        .fold(0.0, f64::max)
}

fn incident_notice(
    incident_id: i64,
    signature: &str,
    title: &str,
    severity: &str,
    created: bool,
    escalated: bool,
    recovered: bool,
) -> Option<IncidentNotice> {
    if !created && !escalated && !recovered {
        return None;
    }
    Some(IncidentNotice {
        incident_id: Some(incident_id),
        signature: signature.to_string(),
        severity: severity.to_string(),
        title: if escalated {
            format!("Incident escalated: {title}")
        } else {
            title.to_string()
        },
        recovered,
        escalated,
    })
}

fn trigger_evidence(items: &[Trigger]) -> serde_json::Value {
    serde_json::json!({"observations":items.iter().map(|t|serde_json::json!({"metric":t.metric,"value":t.value,"score":t.score,"reason":t.reason,"classification":if t.kind=="statistical"{"statistical anomaly"}else{"direct safety threshold"}})).collect::<Vec<_>>()})
}
fn format_explanation(items: &[Trigger]) -> String {
    let facts = items
        .iter()
        .map(|t| format!("{} = {:.2} ({})", t.metric, t.value, t.reason))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "Direct observations: {facts}. The incident groups these signals for review; the measurements do not by themselves establish a root cause."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn median_and_percentile_handle_even_and_odd_samples() {
        assert_eq!(median(&[4.0, 1.0, 3.0]), Some(3.0));
        assert_eq!(median(&[4.0, 1.0]), Some(2.5));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 0.95), Some(4.0));
    }
    #[test]
    fn robust_score_uses_mad_with_a_scale_floor() {
        assert!(robust_score(20.0, 1.0, 0.0) > 10.0);
        assert_eq!(robust_score(1.0, 1.0, 0.0), 0.0);
    }
    #[test]
    fn ewma_smooths_recent_spikes() {
        assert!(ewma(&[10.0, 10.0, 100.0]).unwrap() < 100.0);
    }
    #[test]
    fn anomaly_candidate_streak_requires_consecutive_observations() {
        assert_eq!(next_candidate_streak(2, false), 0);
        assert_eq!(next_candidate_streak(2, true), 3);
    }

    #[test]
    fn cusum_detects_a_gradual_memory_drift_before_a_single_point_is_extreme() {
        let mut observations = Vec::new();
        let mut now = 1_000_000_i64;
        let mut detection_delay = None;
        for minute in 0..30 {
            let value = 100.0 + minute as f64;
            let score = cusum_score(&observations, now, value, 100.0, 0.0);
            if score >= 8.0 {
                detection_delay = Some(minute);
                break;
            }
            observations.push((now, value));
            now += 60;
        }
        assert!(detection_delay.is_some_and(|minutes| (5..=15).contains(&minutes)));
        assert!(cusum_eligible_metric("memory_used_percent"));
        assert!(!cusum_eligible_metric("cpu"));
    }

    #[test]
    fn cusum_restarts_after_missing_history_instead_of_bridging_the_gap() {
        let observations = vec![(1_000_000, 120.0), (1_000_060, 120.0), (1_000_120, 120.0)];
        let score = cusum_score(&observations, 1_001_000, 101.0, 100.0, 0.0);
        assert!(score < 8.0);
    }

    #[test]
    fn gradual_memory_growth_is_detected_without_alerting_on_steady_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gradual-memory-growth.sqlite");
        let store = Store::open(&path).unwrap();
        let now = crate::storage::unix_now().div_euclid(60) * 60;
        let start = now - 48 * 3600;
        store.reset_baselines(start).unwrap();
        let mut fixture = rusqlite::Connection::open(&path).unwrap();
        let transaction = fixture.transaction().unwrap();
        for index in 0..2880_i64 {
            transaction
                .execute(
                    "INSERT INTO minute_points(ts,name,value) VALUES(?1,'memory_used_percent',40.0)",
                    [start + index * 60],
                )
                .unwrap();
        }
        transaction.commit().unwrap();

        let mut evaluator = Evaluator::default();
        let total = 100 * 1024 * 1024 * 1024_u64;
        let mut first_detection = None;
        for step in 0..30_i64 {
            let used_percent = if step < 3 {
                40.0
            } else {
                40.0 + (step - 2) as f64
            };
            let used_bytes = total * used_percent as u64 / 100;
            let timestamp = now + step * 60;
            let host = HostSnapshot {
                timestamp,
                memory_total_bytes: total,
                memory_available_bytes: total - used_bytes,
                memory_used_bytes: used_bytes,
                ..HostSnapshot::default()
            };
            store
                .insert_named_metrics(timestamp, &host.metrics())
                .unwrap();
            store.aggregate_until(timestamp + 60).unwrap();
            let notices = evaluator
                .evaluate(
                    &store,
                    &Config::default(),
                    &host,
                    &[],
                    &[],
                    0,
                    &[],
                    timestamp,
                )
                .unwrap();
            if notices
                .iter()
                .any(|notice| notice.signature == "stat:memory_used_percent")
            {
                first_detection = Some(step);
                break;
            }
            if step == 2 {
                assert!(store.incidents(true, 10).unwrap().is_empty());
            }
        }
        let delay_minutes = first_detection.expect("the rising memory trend should be detected");
        assert!(
            delay_minutes <= 20,
            "detected after {delay_minutes} minutes"
        );
        assert_eq!(
            store.incidents(true, 10).unwrap()[0].signature,
            "stat:memory_used_percent"
        );
    }

    #[test]
    fn browser_orphan_rule_requires_accumulation_or_substantial_resource_use() {
        assert!(!browser_accumulation_suspicious(2, 0.0, 128 * 1024 * 1024));
        assert!(!browser_accumulation_suspicious(7, 5.0, 700 * 1024 * 1024));
        assert!(browser_accumulation_suspicious(8, 22.0, 500 * 1024 * 1024));
        assert!(browser_accumulation_suspicious(2, 45.0, 0));
    }

    #[test]
    fn healthy_high_cpu_with_low_pressure_does_not_create_an_incident() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("healthy-compute.sqlite")).unwrap();
        let mut evaluator = Evaluator::default();
        let host = HostSnapshot {
            cpu_percent: 92.0,
            memory_total_bytes: 100 * 1024 * 1024 * 1024,
            memory_available_bytes: 20 * 1024 * 1024 * 1024,
            disk_total_bytes: 100 * 1024 * 1024 * 1024,
            disk_available_bytes: 30 * 1024 * 1024 * 1024,
            psi_cpu_some_percent: Some(2.0),
            psi_memory_some_percent: Some(1.0),
            ..HostSnapshot::default()
        };
        let now = crate::storage::unix_now();

        assert!(
            evaluator
                .evaluate(&store, &Config::default(), &host, &[], &[], 0, &[], now)
                .unwrap()
                .is_empty()
        );
        assert!(store.incidents(true, 10).unwrap().is_empty());
    }

    #[test]
    fn legitimate_sustained_workload_is_compared_with_its_own_mature_baseline() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("steady-compute.sqlite")).unwrap();
        let workload_metric = "workload::computation.service~0123456789abcdef::cpu_percent";
        let now = crate::storage::unix_now().div_euclid(60) * 60;
        let first = now - 48 * 3600;
        store.reset_baselines(first - 60).unwrap();
        {
            let connection = rusqlite::Connection::open(store.path()).unwrap();
            let transaction = connection.unchecked_transaction().unwrap();
            let mut insert = transaction
                .prepare("INSERT INTO minute_points(ts,name,value) VALUES(?1,?2,?3)")
                .unwrap();
            for minute in 0..2880_i64 {
                insert
                    .execute(rusqlite::params![
                        first + minute * 60,
                        workload_metric,
                        72.0
                    ])
                    .unwrap();
            }
            drop(insert);
            transaction.commit().unwrap();
        }

        let mut evaluator = Evaluator::default();
        let findings = evaluator
            .evaluate(
                &store,
                &Config::default(),
                &HostSnapshot::default(),
                &[],
                &[(workload_metric.into(), 72.0)],
                0,
                &[],
                now,
            )
            .unwrap();

        assert!(findings.is_empty());
        assert!(store.incidents(true, 10).unwrap().is_empty());
        let learned = store
            .baselines()
            .unwrap()
            .into_iter()
            .find(|baseline| baseline.metric == workload_metric)
            .unwrap();
        assert_eq!(learned.samples, 2880);
        assert_eq!(learned.median, Some(72.0));
    }

    #[test]
    fn pressure_scenarios_are_detected_on_the_first_observation_with_direct_evidence() {
        let scenarios = [
            (
                "cpu-contention-with-low-utilization",
                HostSnapshot {
                    cpu_percent: 12.0,
                    psi_cpu_some_percent: Some(22.0),
                    ..HostSnapshot::default()
                },
                "warning",
            ),
            (
                "filesystem-near-capacity",
                HostSnapshot {
                    disk_total_bytes: 100 * 1024 * 1024 * 1024,
                    disk_available_bytes: 3 * 1024 * 1024 * 1024,
                    ..HostSnapshot::default()
                },
                "warning",
            ),
            (
                "active-swap-churn",
                HostSnapshot {
                    swap_in_bytes_per_sec: 4.0 * 1024.0 * 1024.0,
                    swap_out_bytes_per_sec: 2.0 * 1024.0 * 1024.0,
                    ..HostSnapshot::default()
                },
                "warning",
            ),
            (
                "thermal-escalation",
                HostSnapshot {
                    cpu_temperature_c: Some(95.0),
                    cpu_temperature_limit_c: Some(100.0),
                    ..HostSnapshot::default()
                },
                "warning",
            ),
            (
                "gpu-memory-exhaustion",
                HostSnapshot {
                    gpu: Some(crate::model::GpuSnapshot {
                        name: Some("synthetic GPU".into()),
                        utilization_percent: None,
                        memory_used_bytes: Some(99),
                        memory_total_bytes: Some(100),
                        temperature_c: None,
                        power_watts: None,
                        process_attribution_available: true,
                        process_attribution_sampled_at: Some(1),
                        processes: vec![],
                    }),
                    ..HostSnapshot::default()
                },
                "warning",
            ),
        ];

        for (name, host, expected_severity) in scenarios {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::open(&temp.path().join(format!("{name}.sqlite"))).unwrap();
            let now = crate::storage::unix_now();
            let findings = Evaluator::default()
                .evaluate(&store, &Config::default(), &host, &[], &[], 0, &[], now)
                .unwrap();

            assert_eq!(findings.len(), 1, "scenario {name}");
            let incident = store.incidents(true, 10).unwrap().remove(0);
            assert_eq!(incident.first_seen, now, "scenario {name}");
            assert_eq!(incident.severity, expected_severity, "scenario {name}");
            assert!(incident.explanation.contains("Direct observations:"));
        }
    }

    #[test]
    fn gpu_memory_incident_keeps_pid_and_process_name_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("gpu-process-evidence.sqlite")).unwrap();
        let host = HostSnapshot {
            gpu: Some(crate::model::GpuSnapshot {
                name: Some("synthetic GPU".into()),
                utilization_percent: Some(90.0),
                memory_used_bytes: Some(99),
                memory_total_bytes: Some(100),
                temperature_c: None,
                power_watts: None,
                process_attribution_available: true,
                process_attribution_sampled_at: Some(1000),
                processes: vec![crate::model::GpuProcessUsage {
                    pid: 123,
                    process_name: "/usr/bin/worker".into(),
                    memory_used_bytes: 99,
                }],
            }),
            ..HostSnapshot::default()
        };
        let process = ProcessSnapshot {
            key: "boot:123:456".into(),
            pid: 123,
            ppid: 1,
            uid: 1000,
            name: "worker".into(),
            executable: Some("/usr/bin/worker".into()),
            state: "R".into(),
            start_ticks: 456,
            runtime_seconds: 10,
            cpu_percent: 1.0,
            rss_bytes: 1024,
            virtual_bytes: 2048,
            process_group: 123,
            session: 123,
            cgroup: Some("/user.slice/worker.service".into()),
            workload: "worker.service".into(),
            parent_disappeared: false,
        };
        let now = 1000;
        Evaluator::default()
            .evaluate(
                &store,
                &Config::default(),
                &host,
                &[process],
                &[],
                0,
                &[],
                now,
            )
            .unwrap();
        let incident = store.incidents(true, 10).unwrap().remove(0);
        let attribution = &incident.evidence["gpu_process_attribution"];
        assert_eq!(attribution["available"], true);
        assert_eq!(attribution["processes"][0]["pid"], 123);
        assert_eq!(attribution["processes"][0]["identity_match"], true);
        assert_eq!(
            attribution["processes"][0]["process_identity"],
            "boot:123:456"
        );
        assert_eq!(attribution["processes"][0]["gpu_memory_bytes"], 99);
    }

    #[test]
    fn simultaneous_unrelated_pressure_remains_separately_investigable() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("unrelated-pressure.sqlite")).unwrap();
        let now = crate::storage::unix_now();
        let findings = Evaluator::default()
            .evaluate(
                &store,
                &Config::default(),
                &HostSnapshot {
                    memory_total_bytes: 100,
                    memory_available_bytes: 2,
                    disk_total_bytes: 100,
                    disk_available_bytes: 3,
                    cpu_temperature_c: Some(99.0),
                    cpu_temperature_limit_c: Some(100.0),
                    ..HostSnapshot::default()
                },
                &[],
                &[],
                0,
                &[],
                now,
            )
            .unwrap();
        assert_eq!(findings.len(), 3);
        let signatures = store
            .incidents(true, 10)
            .unwrap()
            .into_iter()
            .map(|incident| incident.signature)
            .collect::<HashSet<_>>();
        assert!(signatures.contains("resource-pressure"));
        assert!(signatures.contains("storage"));
        assert!(signatures.contains("thermal"));
    }

    #[test]
    fn browser_accumulation_requires_observed_parent_loss_and_preserves_uncertainty() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("browser-accumulation.sqlite")).unwrap();
        let processes = (0..8)
            .map(|index| ProcessSnapshot {
                key: format!("boot:{}:{}", index + 100, 1),
                pid: index + 100,
                ppid: 42,
                uid: 1000,
                name: "chromium".into(),
                executable: Some("/usr/lib/chromium/chromium".into()),
                state: "S".into(),
                start_ticks: 1,
                runtime_seconds: 300,
                cpu_percent: 3.0,
                rss_bytes: 256 * 1024 * 1024,
                virtual_bytes: 0,
                process_group: 42,
                session: 42,
                cgroup: Some("/user.slice/user-1000.slice/experiment.scope".into()),
                workload: "experiment.scope".into(),
                parent_disappeared: true,
            })
            .collect::<Vec<_>>();
        let now = crate::storage::unix_now();
        let mut evaluator = Evaluator::default();
        let initial_population = processes.iter().take(4).cloned().collect::<Vec<_>>();
        assert!(
            evaluator
                .evaluate(
                    &store,
                    &Config::default(),
                    &HostSnapshot::default(),
                    &initial_population,
                    &[],
                    0,
                    &[],
                    now - 600,
                )
                .unwrap()
                .is_empty()
        );

        let findings = evaluator
            .evaluate(
                &store,
                &Config::default(),
                &HostSnapshot::default(),
                &processes,
                &[],
                0,
                &[],
                now,
            )
            .unwrap();
        assert_eq!(findings.len(), 1);
        let incident = store.incidents(true, 10).unwrap().remove(0);
        assert_eq!(incident.signature, "orphan-browser");
        assert_eq!(incident.evidence["count"], 8);
        assert!(
            incident.evidence["inference"]
                .as_str()
                .unwrap()
                .contains("possible")
        );

        let no_parent_loss = processes
            .iter()
            .cloned()
            .map(|mut process| {
                process.parent_disappeared = false;
                process
            })
            .collect::<Vec<_>>();
        let no_parent_store = Store::open(&temp.path().join("browser-running.sqlite")).unwrap();
        assert!(
            Evaluator::default()
                .evaluate(
                    &no_parent_store,
                    &Config::default(),
                    &HostSnapshot::default(),
                    &no_parent_loss,
                    &[],
                    0,
                    &[],
                    now,
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn browser_accumulation_and_host_pressure_share_one_escalating_incident() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("browser-pressure-correlation.sqlite")).unwrap();
        let processes = (0..8)
            .map(|index| ProcessSnapshot {
                key: format!("boot:{}:{}", index + 200, 2),
                pid: index + 200,
                ppid: 42,
                uid: 1000,
                name: "chromium".into(),
                executable: Some("/usr/lib/chromium/chromium".into()),
                state: "S".into(),
                start_ticks: 2,
                runtime_seconds: 600,
                cpu_percent: 3.0,
                rss_bytes: 256 * 1024 * 1024,
                virtual_bytes: 0,
                process_group: 42,
                session: 42,
                cgroup: Some("/user.slice/user-1000.slice/experiment.scope".into()),
                workload: "experiment.scope".into(),
                parent_disappeared: true,
            })
            .collect::<Vec<_>>();
        let mut evaluator = Evaluator::default();
        let now = crate::storage::unix_now();
        let initial_population = processes.iter().take(4).cloned().collect::<Vec<_>>();
        assert!(
            evaluator
                .evaluate(
                    &store,
                    &Config::default(),
                    &HostSnapshot::default(),
                    &initial_population,
                    &[],
                    0,
                    &[],
                    now - 600,
                )
                .unwrap()
                .is_empty()
        );
        let warning = evaluator
            .evaluate(
                &store,
                &Config::default(),
                &HostSnapshot {
                    cpu_percent: 14.0,
                    psi_cpu_some_percent: Some(22.0),
                    ..HostSnapshot::default()
                },
                &processes,
                &[],
                0,
                &[],
                now,
            )
            .unwrap();
        assert_eq!(warning.len(), 1);
        assert!(!warning[0].escalated);
        let active = store.incidents(true, 10).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].signature, "orphan-browser");
        assert!(active[0].evidence["co_observed_resource_signals"].is_array());
        assert!(active[0].explanation.contains("does not establish"));

        let critical = evaluator
            .evaluate(
                &store,
                &Config::default(),
                &HostSnapshot {
                    memory_total_bytes: 100,
                    memory_available_bytes: 2,
                    ..HostSnapshot::default()
                },
                &processes,
                &[],
                0,
                &[],
                now + 60,
            )
            .unwrap();
        assert_eq!(critical.len(), 1);
        assert!(critical[0].escalated);
        assert!(critical[0].title.starts_with("Incident escalated:"));
        assert_eq!(store.incidents(true, 10).unwrap()[0].severity, "critical");

        let steady = evaluator
            .evaluate(
                &store,
                &Config::default(),
                &HostSnapshot {
                    cpu_percent: 14.0,
                    psi_cpu_some_percent: Some(22.0),
                    ..HostSnapshot::default()
                },
                &processes,
                &[],
                0,
                &[],
                now + 120,
            )
            .unwrap();
        assert!(steady.is_empty());
        assert_eq!(store.incidents(true, 10).unwrap()[0].severity, "critical");
    }

    #[test]
    fn stable_browser_pool_is_quiet_but_observed_growth_is_reported() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("browser-growth.sqlite")).unwrap();
        let make_population = |count: u32| {
            (0..count)
                .map(|index| ProcessSnapshot {
                    key: format!("boot:{}:50", index + 500),
                    pid: index + 500,
                    ppid: 1,
                    uid: 1000,
                    name: "chromium".into(),
                    executable: Some("/usr/lib/chromium/chromium".into()),
                    state: "S".into(),
                    start_ticks: 50,
                    runtime_seconds: 1800,
                    cpu_percent: 1.0,
                    rss_bytes: 256 * 1024 * 1024,
                    virtual_bytes: 0,
                    process_group: 1,
                    session: 1,
                    cgroup: Some("/user.slice/browser-pool.scope".into()),
                    workload: "browser-pool.scope".into(),
                    parent_disappeared: true,
                })
                .collect::<Vec<_>>()
        };
        let mut evaluator = Evaluator::default();
        let now = crate::storage::unix_now().div_euclid(60) * 60;
        let stable = make_population(8);
        for minute in 0..4 {
            let findings = evaluator
                .evaluate(
                    &store,
                    &Config::default(),
                    &HostSnapshot::default(),
                    &stable,
                    &[],
                    0,
                    &[],
                    now - 1200 + minute * 600,
                )
                .unwrap();
            assert!(findings.is_empty());
        }
        assert!(store.incidents(true, 10).unwrap().is_empty());

        let growing = make_population(12);
        let findings = evaluator
            .evaluate(
                &store,
                &Config::default(),
                &HostSnapshot::default(),
                &growing,
                &[],
                0,
                &[],
                now + 1200,
            )
            .unwrap();
        assert_eq!(findings.len(), 1);
        let incident = store.incidents(true, 10).unwrap().remove(0);
        assert_eq!(incident.signature, "orphan-browser");
        assert_eq!(incident.evidence["growth_windows"][0]["new_processes"], 4);
        assert_eq!(
            incident.evidence["growth_windows"][0]["window_seconds"],
            600
        );
        assert_eq!(
            incident.evidence["growth_windows"][0]["rss_increase_bytes"],
            1024_u64 * 1024 * 1024
        );
    }

    #[test]
    fn sustained_cpu_work_window_does_not_alert_without_cpu_pressure() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("sustained-cpu.sqlite")).unwrap();
        let now = crate::storage::unix_now().div_euclid(60) * 60;
        let history = (1..=2880_i64)
            .map(|minute| {
                let timestamp = now - (2881 - minute) * 60;
                let value = if minute.rem_euclid(60) < 10 {
                    88.0
                } else {
                    60.0
                };
                (timestamp, "cpu", value)
            })
            .collect::<Vec<_>>();
        store.seed_minute_points_for_test(&history).unwrap();
        let mut evaluator = Evaluator::default();
        for minute in 0..3 {
            let findings = evaluator
                .evaluate(
                    &store,
                    &Config::default(),
                    &HostSnapshot {
                        cpu_percent: 88.0,
                        psi_cpu_some_percent: Some(0.2),
                        ..HostSnapshot::default()
                    },
                    &[],
                    &[],
                    0,
                    &[],
                    now + minute * 60,
                )
                .unwrap();
            assert!(findings.is_empty());
        }
        assert!(store.incidents(true, 10).unwrap().is_empty());
    }

    #[test]
    fn workload_metric_keys_are_grouped_without_parsing_user_labels() {
        assert_eq!(
            workload_key_from_metric("workload::browser%20scope~0123456789abcdef::process_count"),
            Some("browser%20scope~0123456789abcdef")
        );
        assert_eq!(workload_key_from_metric("cpu"), None);
    }

    #[test]
    fn baseline_reset_clears_cached_seasonal_models() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("reset-seasonal.sqlite")).unwrap();
        let mut evaluator = Evaluator::default();
        let now = crate::storage::unix_now();
        evaluator.baseline_version = Some(1);
        evaluator.seasonal_cache.insert(
            "cpu".into(),
            (
                now,
                now.div_euclid(3600),
                now - 30 * 86400,
                Some(SeasonalValues {
                    metric: "cpu".into(),
                    pattern: "hour_of_week_utc".into(),
                    periods: 4,
                    first_timestamp: now - 28 * 86400,
                    last_timestamp: now - 7 * 86400,
                    median: 25.0,
                    mad: 2.0,
                    confidence: 1.0,
                }),
            ),
        );
        assert_eq!(evaluator.seasonal_models(now).len(), 1);
        store.reset_baselines(now + 1).unwrap();

        evaluator
            .evaluate(
                &store,
                &Config::default(),
                &HostSnapshot::default(),
                &[],
                &[],
                0,
                &[],
                now + 1,
            )
            .unwrap();

        assert!(evaluator.seasonal_models(now + 1).is_empty());
    }

    #[test]
    fn safety_observation_creates_and_recovers_resource_incident() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("test.sqlite")).unwrap();
        let config = Config::default();
        let mut evaluator = Evaluator::default();
        let mut host = HostSnapshot {
            memory_total_bytes: 1000,
            memory_available_bytes: 20,
            memory_used_bytes: 980,
            ..HostSnapshot::default()
        };
        let now = crate::storage::unix_now();
        let opened = evaluator
            .evaluate(&store, &config, &host, &[], &[], 0, &[], now)
            .unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(store.incidents(true, 10).unwrap()[0].severity, "critical");

        host.memory_available_bytes = 800;
        host.memory_used_bytes = 200;
        assert!(
            evaluator
                .evaluate(&store, &config, &host, &[], &[], 0, &[], now + 60)
                .unwrap()
                .is_empty()
        );
        assert!(
            evaluator
                .evaluate(&store, &config, &host, &[], &[], 0, &[], now + 120)
                .unwrap()
                .is_empty()
        );
        let recovered = evaluator
            .evaluate(&store, &config, &host, &[], &[], 0, &[], now + 180)
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].recovered);
        assert!(store.incidents(true, 10).unwrap().is_empty());
    }

    #[test]
    fn synthetic_oom_and_service_restart_evidence_opens_and_recovers_incidents() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("synthetic.sqlite")).unwrap();
        let config = Config::default();
        let mut evaluator = Evaluator::default();
        let host = HostSnapshot {
            oom_kill_count: 8,
            ..HostSnapshot::default()
        };
        let restart = ServiceRestartEvent {
            unit: "example-worker.service".into(),
            previous_count: 1,
            current_count: 3,
        };
        let now = crate::storage::unix_now();
        let opened = evaluator
            .evaluate(&store, &config, &host, &[], &[], 2, &[restart], now)
            .unwrap();
        assert_eq!(opened.len(), 2);
        let active = store.incidents(true, 10).unwrap();
        assert_eq!(active.len(), 2);
        assert!(
            active
                .iter()
                .any(|incident| incident.signature == "oom-kill")
        );
        assert!(
            active
                .iter()
                .any(|incident| incident.signature == "service-restart:example-worker.service")
        );
        assert_eq!(store.anomalies(now - 1, 10).unwrap().len(), 2);

        for offset in [60, 120] {
            assert!(
                evaluator
                    .evaluate(&store, &config, &host, &[], &[], 0, &[], now + offset)
                    .unwrap()
                    .is_empty()
            );
        }
        let recovered = evaluator
            .evaluate(&store, &config, &host, &[], &[], 0, &[], now + 180)
            .unwrap();
        assert_eq!(recovered.len(), 2);
        assert!(recovered.iter().all(|notice| notice.recovered));
        assert!(store.incidents(true, 10).unwrap().is_empty());
    }

    #[test]
    fn persistent_storage_warning_freezes_only_its_related_baseline() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("selective-freeze.sqlite")).unwrap();
        let config = Config::default();
        let mut evaluator = Evaluator::default();
        let now = crate::storage::unix_now();
        let mut host = HostSnapshot {
            disk_total_bytes: 1000,
            disk_available_bytes: 10,
            ..HostSnapshot::default()
        };
        evaluator
            .evaluate(&store, &config, &host, &[], &[], 0, &[], now)
            .unwrap();
        let metrics = store
            .baselines()
            .unwrap()
            .into_iter()
            .map(|baseline| baseline.metric)
            .collect::<HashSet<_>>();
        assert!(metrics.contains("cpu"));
        assert!(!metrics.contains("disk_used_percent"));

        host.disk_available_bytes = 900;
        evaluator
            .evaluate(&store, &config, &host, &[], &[], 0, &[], now + 60)
            .unwrap();
        let metrics = store
            .baselines()
            .unwrap()
            .into_iter()
            .map(|baseline| baseline.metric)
            .collect::<HashSet<_>>();
        assert!(metrics.contains("cpu"));
        assert!(!metrics.contains("disk_used_percent"));
    }
}
