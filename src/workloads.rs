use crate::model::ProcessSnapshot;
use std::collections::{BTreeMap, HashMap, HashSet};

pub fn group(processes: &[ProcessSnapshot]) -> BTreeMap<String, Vec<&ProcessSnapshot>> {
    let mut groups = BTreeMap::new();
    for process in processes {
        groups
            .entry(process.workload.clone())
            .or_insert_with(Vec::new)
            .push(process);
    }
    groups
}

/// Build bounded, stable metric names for the 25 busiest workload groups by CPU
/// and memory. Names contain a readable percent-encoded label plus a stable hash.
pub fn baseline_metrics(processes: &[ProcessSnapshot]) -> Vec<(String, f64)> {
    let aggregates = group(processes)
        .into_iter()
        .map(|(name, members)| {
            let cpu = members.iter().map(|p| p.cpu_percent).sum::<f64>();
            let rss = members.iter().map(|p| p.rss_bytes).sum::<u64>();
            (name, cpu, rss)
        })
        .collect::<Vec<_>>();
    let mut by_cpu = aggregates.clone();
    by_cpu.sort_by(|a, b| b.1.total_cmp(&a.1));
    let mut by_memory = aggregates.clone();
    by_memory.sort_by_key(|item| std::cmp::Reverse(item.2));
    let mut selected = HashSet::new();
    selected.extend(by_cpu.into_iter().take(25).map(|item| item.0));
    selected.extend(by_memory.into_iter().take(25).map(|item| item.0));

    let values = aggregates
        .into_iter()
        .map(|(name, cpu, rss)| (name, (cpu, rss)))
        .collect::<HashMap<_, _>>();
    let mut metrics = Vec::with_capacity(selected.len() * 2);
    for name in selected {
        let Some((cpu, rss)) = values.get(&name) else {
            continue;
        };
        let key = workload_metric_key(&name);
        metrics.push((format!("workload::{key}::cpu_percent"), *cpu));
        metrics.push((format!("workload::{key}::rss_bytes"), *rss as f64));
    }
    metrics.sort_by(|a, b| a.0.cmp(&b.0));
    metrics
}

fn workload_metric_key(name: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut encoded = String::new();
    for byte in name.bytes().take(96) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("{encoded}~{hash:016x}")
}

pub fn label_for(
    cgroup: Option<&str>,
    executable: Option<&str>,
    name: &str,
    session: i32,
) -> String {
    if let Some(path) = cgroup {
        if let Some(unit) = path
            .split('/')
            .rev()
            .find(|s| s.ends_with(".service") || s.ends_with(".scope"))
        {
            return unit.to_string();
        }
        let components = path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if let Some(app) = components
            .iter()
            .rev()
            .find(|s| **s != "user.slice" && !s.starts_with("user-") && !s.starts_with("session-"))
        {
            return (*app).to_string();
        }
    }
    if let Some(exe) = executable {
        if let Some(base) = std::path::Path::new(exe)
            .file_name()
            .and_then(|s| s.to_str())
        {
            return format!("{base} · session {session}");
        }
    }
    format!("{name} · session {session}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(workload: &str, cpu_percent: f64, rss_bytes: u64) -> ProcessSnapshot {
        ProcessSnapshot {
            key: format!("boot:1:{}", workload.len()),
            pid: 1,
            ppid: 0,
            uid: 1000,
            name: "worker".into(),
            executable: None,
            state: "S".into(),
            start_ticks: 1,
            runtime_seconds: 1,
            cpu_percent,
            rss_bytes,
            virtual_bytes: 0,
            process_group: 1,
            session: 1,
            cgroup: None,
            workload: workload.into(),
            parent_disappeared: false,
        }
    }

    #[test]
    fn groups_user_processes_by_the_deepest_systemd_scope() {
        let result = label_for(
            Some("/user.slice/user-1000.slice/user@1000.service/app.slice/app-browser.scope"),
            Some("/usr/bin/chromium"),
            "chromium",
            4,
        );
        assert_eq!(result, "app-browser.scope");
    }

    #[test]
    fn falls_back_to_executable_and_session() {
        assert_eq!(
            label_for(None, Some("/usr/bin/worker"), "worker", 3),
            "worker · session 3"
        );
    }

    #[test]
    fn workload_baseline_metrics_are_aggregated_and_bounded() {
        let processes = vec![
            process("echo archives.service", 2.0, 100),
            process("echo archives.service", 3.0, 150),
        ];
        let metrics = baseline_metrics(&processes);
        assert_eq!(metrics.len(), 2);
        assert!(
            metrics
                .iter()
                .any(|(name, value)| name.ends_with("::cpu_percent") && *value == 5.0)
        );
        assert!(
            metrics
                .iter()
                .any(|(name, value)| name.ends_with("::rss_bytes") && *value == 250.0)
        );
        assert!(metrics[0].0.contains("echo%20archives.service"));
    }
}
