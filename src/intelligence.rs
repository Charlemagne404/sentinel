use crate::{
    config::Config,
    model::{HostSnapshot, ProcessSnapshot, ServiceRestartEvent},
    notifications::IncidentNotice,
    storage::{Baseline, Store},
};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub struct Evaluator {
    streaks: HashMap<String, u8>,
    misses: HashMap<String, u8>,
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
            let values = store.baseline_values(&metric, since, 10_080)?;
            let old = current_baselines.get(&metric);
            let first = store
                .baseline_first_timestamp(&metric, since)?
                .unwrap_or(now);
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
            let is_candidate = mature && score >= 4.5;
            let streak = self.streaks.entry(metric.to_string()).or_default();
            *streak = next_candidate_streak(*streak, is_candidate);
            if is_candidate {
                store.exclude_baseline_point(
                    &metric,
                    now.div_euclid(60) * 60,
                    "statistical anomaly",
                )?;
            }
            if mature && *streak >= 3 {
                triggers.push(trigger(
                    &metric,
                    value,
                    score,
                    "warning",
                    &format!(
                        "Value is {score:.1} robust deviations from the mature rolling baseline."
                    ),
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

        let browsers = processes
            .iter()
            .filter(|p| p.parent_disappeared && p.runtime_seconds > 60 && is_browser(&p.name))
            .collect::<Vec<_>>();
        let browser_cpu = browsers.iter().map(|p| p.cpu_percent).sum::<f64>();
        let browser_rss = browsers.iter().map(|p| p.rss_bytes).sum::<u64>();
        let orphan_active =
            browsers.len() >= 2 || browser_cpu >= 20.0 || browser_rss >= 1024 * 1024 * 1024;
        if orphan_active {
            let evidence = serde_json::json!({"observed_processes":browsers.iter().take(30).map(|p|serde_json::json!({"pid":p.pid,"name":p.name,"parent_pid":p.ppid,"runtime_seconds":p.runtime_seconds,"cpu_percent":p.cpu_percent,"rss_bytes":p.rss_bytes,"workload":p.workload,"parent_disappeared":p.parent_disappeared})).collect::<Vec<_>>(),"count":browsers.len(),"cpu_percent_total":browser_cpu,"rss_bytes_total":browser_rss,"direct_fact":"previous parent identity disappeared between process observations","inference":"orphaned browser work is possible, but normal daemonization is also possible"});
            let (id, created)=store.open_or_update_incident("orphan-browser","warning","Browser processes outlived their observed parent",0.72,&evidence,"Sentinel observed browser processes whose previously observed parent identity disappeared. That relationship can be consistent with abandoned automation, but daemonization is another explanation. Review the listed user, workload, and session before taking action.",now)?;
            if created {
                notices.push(IncidentNotice {
                    incident_id: Some(id),
                    signature: "orphan-browser".into(),
                    severity: "warning".into(),
                    title: "Browser processes outlived their observed parent".into(),
                    recovered: false,
                });
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
        }

        let mut observed = HashSet::<String>::new();
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
            let (id, created) = store.open_or_update_incident(
                signature,
                "critical",
                "The kernel killed a process under memory pressure",
                0.98,
                &evidence,
                &explanation,
                now,
            )?;
            if created {
                notices.push(IncidentNotice {
                    incident_id: Some(id),
                    signature: signature.into(),
                    severity: "critical".into(),
                    title: "The kernel killed a process under memory pressure".into(),
                    recovered: false,
                });
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
            let (id, created) = store.open_or_update_incident(
                &signature,
                "warning",
                &title,
                0.95,
                &evidence,
                &explanation,
                now,
            )?;
            if created {
                notices.push(IncidentNotice {
                    incident_id: Some(id),
                    signature: signature.clone(),
                    severity: "warning".into(),
                    title,
                    recovered: false,
                });
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
        if !resource.is_empty() {
            let critical = resource.iter().any(|t| t.severity == "critical");
            let evidence = trigger_evidence(&resource);
            let (id, created) = store.open_or_update_incident(
                "resource-pressure",
                if critical { "critical" } else { "warning" },
                "Host resource pressure needs attention",
                confidence(&resource),
                &evidence,
                &format_explanation(&resource),
                now,
            )?;
            if created {
                notices.push(IncidentNotice {
                    incident_id: Some(id),
                    signature: "resource-pressure".into(),
                    severity: if critical { "critical" } else { "warning" }.into(),
                    title: "Host resource pressure needs attention".into(),
                    recovered: false,
                });
            }
            for t in &resource {
                store.append_anomaly(now, &t.metric, t.value, t.score, &t.reason, Some(id))?;
            }
            observed.insert("resource-pressure".into());
        }
        for kind in ["thermal", "storage", "statistical"] {
            let items = triggers
                .iter()
                .filter(|t| t.kind == kind)
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
                    _ => format!("Unusual {} behaviour", t.metric.replace('_', " ")),
                };
                let evidence = trigger_evidence(std::slice::from_ref(&t));
                let (id, created) = store.open_or_update_incident(
                    &signature,
                    &t.severity,
                    &title,
                    confidence(std::slice::from_ref(&t)),
                    &evidence,
                    &format_explanation(std::slice::from_ref(&t)),
                    now,
                )?;
                if created {
                    notices.push(IncidentNotice {
                        incident_id: Some(id),
                        signature: signature.clone(),
                        severity: t.severity.clone(),
                        title: title.clone(),
                        recovered: false,
                    });
                }
                store.append_anomaly(now, &t.metric, t.value, t.score, &t.reason, Some(id))?;
                observed.insert(signature);
            }
        }
        if orphan_active {
            observed.insert("orphan-browser".into());
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
                    notices.push(IncidentNotice {
                        incident_id: Some(incident.id),
                        signature: incident.signature.clone(),
                        severity: incident.severity.clone(),
                        title: incident.title.clone(),
                        recovered: true,
                    });
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
