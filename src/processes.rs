use crate::{
    model::{ProcessLifecycleEvent, ProcessSnapshot},
    storage::unix_now,
    workloads,
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    time::Instant,
};

#[derive(Debug, Clone)]
pub struct ProcStat {
    pub name: String,
    pub state: String,
    pub ppid: u32,
    pub process_group: i32,
    pub session: i32,
    pub user_ticks: u64,
    pub system_ticks: u64,
    pub start_ticks: u64,
    pub virtual_bytes: u64,
    pub resident_pages: u64,
}

pub fn parse_proc_stat(raw: &str) -> Option<ProcStat> {
    let end = raw.rfind(')')?;
    let name = raw.get(raw.find('(')? + 1..end)?.to_string();
    let fields = raw.get(end + 1..)?.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 22 {
        return None;
    }
    Some(ProcStat {
        name,
        state: fields[0].to_string(),
        ppid: fields[1].parse().ok()?,
        process_group: fields[2].parse().ok()?,
        session: fields[3].parse().ok()?,
        user_ticks: fields[11].parse().ok()?,
        system_ticks: fields[12].parse().ok()?,
        start_ticks: fields[19].parse().ok()?,
        virtual_bytes: fields[20].parse().ok()?,
        resident_pages: fields[21].parse().ok()?,
    })
}

#[derive(Default)]
pub struct ProcessCollector {
    boot_id: String,
    ticks_per_second: f64,
    page_size: u64,
    previous: HashMap<String, ProcessSnapshot>,
    previous_pids: HashMap<u32, String>,
    orphaned: HashSet<String>,
    cpu: HashMap<String, (u64, Instant)>,
    initialized: bool,
}

impl ProcessCollector {
    pub fn new() -> Self {
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap_or_else(|_| "unknown-boot".into())
            .trim()
            .to_string();
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
        Self {
            boot_id,
            ticks_per_second: ticks,
            page_size: page,
            ..Self::default()
        }
    }

    pub fn collect_with_lifecycle(&mut self) -> (Vec<ProcessSnapshot>, Vec<ProcessLifecycleEvent>) {
        let Ok(entries) = fs::read_dir("/proc") else {
            return (Vec::new(), Vec::new());
        };
        let entries = entries.flatten().collect::<Vec<_>>();
        let mut observed_pids = HashSet::new();
        let mut raw = Vec::<(ProcessSnapshot, u64)>::new();
        let now = Instant::now();
        let uptime = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .unwrap_or(0.0);
        for entry in entries {
            let pid = entry.file_name().to_string_lossy().parse::<u32>().ok();
            let Some(pid) = pid else { continue };
            observed_pids.insert(pid);
            let dir = entry.path();
            let Ok(stat_raw) = fs::read_to_string(dir.join("stat")) else {
                continue;
            };
            let Some(stat) = parse_proc_stat(&stat_raw) else {
                continue;
            };
            let key = process_key(&self.boot_id, pid, stat.start_ticks);
            let cpu_ticks = stat.user_ticks.saturating_add(stat.system_ticks);
            let cpu_percent = if let Some((prev, instant)) = self.cpu.get(&key) {
                let seconds = now.duration_since(*instant).as_secs_f64();
                if seconds > 0.01 {
                    cpu_ticks.saturating_sub(*prev) as f64 / self.ticks_per_second / seconds * 100.0
                } else {
                    0.0
                }
            } else {
                0.0
            };
            self.cpu.insert(key.clone(), (cpu_ticks, now));
            let (uid, rss_bytes, virtual_bytes) = parse_status(
                &dir.join("status"),
                stat.resident_pages,
                self.page_size,
                stat.virtual_bytes,
            );
            let executable = fs::read_link(dir.join("exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned());
            let cgroup = read_unified_cgroup(&dir.join("cgroup"));
            let name = stat.name.clone();
            let workload = workloads::label_for(
                cgroup.as_deref(),
                executable.as_deref(),
                &name,
                stat.session,
            );
            let runtime =
                (uptime - stat.start_ticks as f64 / self.ticks_per_second).max(0.0) as u64;
            raw.push((
                ProcessSnapshot {
                    key,
                    pid,
                    ppid: stat.ppid,
                    uid,
                    name,
                    executable,
                    state: stat.state,
                    start_ticks: stat.start_ticks,
                    runtime_seconds: runtime,
                    cpu_percent: cpu_percent.max(0.0),
                    rss_bytes,
                    virtual_bytes,
                    process_group: stat.process_group,
                    session: stat.session,
                    cgroup,
                    workload,
                    parent_disappeared: false,
                },
                cpu_ticks,
            ));
        }
        let current_pid_keys = raw
            .iter()
            .map(|(p, _)| (p.pid, p.key.clone()))
            .collect::<HashMap<_, _>>();
        let mut current_processes = raw.iter_mut().map(|(p, _)| p).collect::<Vec<_>>();
        mark_parent_losses(
            &mut current_processes,
            &self.previous,
            &self.previous_pids,
            &current_pid_keys,
            &observed_pids,
            &mut self.orphaned,
        );
        let current = raw
            .iter()
            .map(|(p, _)| (p.key.clone(), p.clone()))
            .collect::<HashMap<_, _>>();
        let lifecycle = lifecycle_changes(
            &self.previous,
            &current,
            &observed_pids,
            self.initialized,
            unix_now(),
        );
        self.previous = current;
        self.initialized = true;
        self.previous_pids = current_pid_keys;
        let alive = self
            .previous
            .keys()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        self.orphaned.retain(|key| alive.contains(key));
        self.cpu.retain(|key, _| alive.contains(key));
        let mut processes = raw.into_iter().map(|(p, _)| p).collect::<Vec<_>>();
        processes.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent));
        (processes, lifecycle)
    }
}

fn lifecycle_changes(
    previous: &HashMap<String, ProcessSnapshot>,
    current: &HashMap<String, ProcessSnapshot>,
    observed_pids: &HashSet<u32>,
    initialized: bool,
    timestamp: i64,
) -> Vec<ProcessLifecycleEvent> {
    if !initialized {
        return Vec::new();
    }
    let mut events = Vec::new();
    for process in current.values() {
        match previous.get(&process.key) {
            None => events.push(lifecycle_event("started", process, timestamp)),
            Some(old) if process.parent_disappeared && !old.parent_disappeared => {
                events.push(lifecycle_event("parent_lost", process, timestamp));
            }
            _ => {}
        }
    }
    for process in previous.values() {
        if current.contains_key(&process.key) {
            continue;
        }
        let pid_reused = current.values().any(|now| now.pid == process.pid);
        if pid_reused || !observed_pids.contains(&process.pid) {
            events.push(lifecycle_event("exited", process, timestamp));
        }
    }
    events.sort_by(|a, b| {
        b.cpu_percent
            .total_cmp(&a.cpu_percent)
            .then_with(|| b.rss_bytes.cmp(&a.rss_bytes))
    });
    events.truncate(100);
    events
}

fn lifecycle_event(kind: &str, process: &ProcessSnapshot, timestamp: i64) -> ProcessLifecycleEvent {
    ProcessLifecycleEvent {
        timestamp,
        kind: kind.into(),
        key: process.key.clone(),
        pid: process.pid,
        ppid: process.ppid,
        uid: process.uid,
        name: process.name.clone(),
        executable: process.executable.clone(),
        workload: process.workload.clone(),
        cpu_percent: process.cpu_percent,
        rss_bytes: process.rss_bytes,
        runtime_seconds: process.runtime_seconds,
    }
}

fn process_key(boot_id: &str, pid: u32, start_ticks: u64) -> String {
    format!("{boot_id}:{pid}:{start_ticks}")
}

fn mark_parent_losses(
    current: &mut [&mut ProcessSnapshot],
    previous: &HashMap<String, ProcessSnapshot>,
    previous_pids: &HashMap<u32, String>,
    current_pids: &HashMap<u32, String>,
    observed_pids: &HashSet<u32>,
    orphaned: &mut HashSet<String>,
) {
    for process in current {
        let was_orphaned = orphaned.contains(&process.key);
        let parent_gone = previous
            .get(&process.key)
            .and_then(|old| previous_pids.get(&old.ppid).map(|key| (old.ppid, key)))
            .is_some_and(|(pid, old_key)| {
                if pid <= 1 {
                    return false;
                }
                match current_pids.get(&pid) {
                    Some(current_key) => current_key != old_key,
                    None => !observed_pids.contains(&pid),
                }
            });
        if parent_gone {
            orphaned.insert(process.key.clone());
        }
        process.parent_disappeared = parent_gone || was_orphaned;
    }
}

fn parse_status(
    path: &std::path::Path,
    rss_pages: u64,
    page_size: u64,
    virtual_bytes: u64,
) -> (u32, u64, u64) {
    let mut uid = 0;
    let mut rss = rss_pages.saturating_mul(page_size);
    let mut virtual_mem = virtual_bytes;
    if let Ok(raw) = fs::read_to_string(path) {
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("Uid:") {
                uid = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("VmRSS:") {
                rss = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    .saturating_mul(1024);
            } else if let Some(v) = line.strip_prefix("VmSize:") {
                virtual_mem = v
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    .saturating_mul(1024);
            }
        }
    }
    (uid, rss, virtual_mem)
}
fn read_unified_cgroup(path: &std::path::Path) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    raw.lines().find_map(|line| {
        let (hier, rest) = line.split_once(':')?;
        let (controllers, group) = rest.split_once(':')?;
        if hier == "0" && controllers.is_empty() {
            Some(group.to_string())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(pid: u32, start_ticks: u64) -> ProcessSnapshot {
        ProcessSnapshot {
            key: process_key("boot", pid, start_ticks),
            pid,
            ppid: 1,
            uid: 1000,
            name: "worker".into(),
            executable: Some("/usr/bin/worker".into()),
            state: "S".into(),
            start_ticks,
            runtime_seconds: 60,
            cpu_percent: 1.0,
            rss_bytes: 4096,
            virtual_bytes: 8192,
            process_group: pid as i32,
            session: 1,
            cgroup: None,
            workload: "worker.service".into(),
            parent_disappeared: false,
        }
    }
    #[test]
    fn proc_stat_handles_spaces_and_parentheses_in_comm() {
        let mut fields = vec![
            "S", "1", "1", "1", "0", "0", "0", "0", "0", "0", "0", "42", "8", "0", "0", "20", "0",
            "1", "0", "100", "4096", "2",
        ];
        let row = format!("123 (browser worker (x)) {}", fields.join(" "));
        let p = parse_proc_stat(&row).unwrap();
        assert_eq!(p.name, "browser worker (x)");
        assert_eq!(p.ppid, 1);
        assert_eq!(p.user_ticks, 42);
        assert_eq!(p.start_ticks, 100);
        fields.clear();
    }
    #[test]
    fn malformed_proc_stat_is_ignored() {
        assert!(parse_proc_stat("not a proc stat").is_none());
    }

    #[test]
    fn process_identity_changes_when_a_pid_is_reused() {
        assert_ne!(process_key("boot", 42, 100), process_key("boot", 42, 200));
        assert_ne!(
            process_key("boot-a", 42, 100),
            process_key("boot-b", 42, 100)
        );
    }

    #[test]
    fn parent_loss_remains_visible_after_the_parent_is_already_gone() {
        let child = ProcessSnapshot {
            key: "boot:300:10".into(),
            pid: 300,
            ppid: 100,
            uid: 1000,
            name: "child".into(),
            executable: None,
            state: "S".into(),
            start_ticks: 10,
            runtime_seconds: 60,
            cpu_percent: 0.0,
            rss_bytes: 1024,
            virtual_bytes: 2048,
            process_group: 300,
            session: 300,
            cgroup: None,
            workload: "child".into(),
            parent_disappeared: false,
        };
        let previous = HashMap::from([(child.key.clone(), child.clone())]);
        let previous_pids = HashMap::from([(100, "boot:100:4".into()), (300, child.key.clone())]);
        let current_pids = HashMap::from([(300, child.key.clone())]);
        let mut orphaned = HashSet::new();
        let mut first = child.clone();
        mark_parent_losses(
            &mut [&mut first],
            &previous,
            &previous_pids,
            &current_pids,
            &HashSet::from([300]),
            &mut orphaned,
        );
        assert!(first.parent_disappeared);

        let now_previous = HashMap::from([(child.key.clone(), first.clone())]);
        let mut second = first;
        mark_parent_losses(
            &mut [&mut second],
            &now_previous,
            &current_pids,
            &current_pids,
            &HashSet::from([300]),
            &mut orphaned,
        );
        assert!(second.parent_disappeared);
    }

    #[test]
    fn parent_loss_waits_when_parent_pid_exists_but_stat_was_unreadable() {
        let mut child = snapshot(300, 10);
        child.ppid = 100;
        let previous = HashMap::from([(child.key.clone(), child.clone())]);
        let previous_pids = HashMap::from([(100, "boot:100:4".into()), (300, child.key.clone())]);
        let current_pids = HashMap::from([(300, child.key.clone())]);
        let observed_pids = HashSet::from([100, 300]);
        let mut orphaned = HashSet::new();
        mark_parent_losses(
            &mut [&mut child],
            &previous,
            &previous_pids,
            &current_pids,
            &observed_pids,
            &mut orphaned,
        );
        assert!(!child.parent_disappeared);
        assert!(orphaned.is_empty());
    }

    #[test]
    fn parent_pid_reuse_counts_as_the_original_parent_disappearing() {
        let mut child = snapshot(300, 10);
        child.ppid = 100;
        let previous = HashMap::from([(child.key.clone(), child.clone())]);
        let previous_pids = HashMap::from([(100, "boot:100:4".into()), (300, child.key.clone())]);
        let current_pids = HashMap::from([(100, "boot:100:9".into()), (300, child.key.clone())]);
        let observed_pids = HashSet::from([100, 300]);
        let mut orphaned = HashSet::new();
        mark_parent_losses(
            &mut [&mut child],
            &previous,
            &previous_pids,
            &current_pids,
            &observed_pids,
            &mut orphaned,
        );
        assert!(child.parent_disappeared);
    }

    #[test]
    fn lifecycle_diff_ignores_seed_inventory_and_records_start_exit_and_parent_loss() {
        let first = snapshot(10, 1);
        let first_map = HashMap::from([(first.key.clone(), first.clone())]);
        assert!(
            lifecycle_changes(
                &HashMap::new(),
                &first_map,
                &HashSet::from([10]),
                false,
                100,
            )
            .is_empty()
        );

        let child = snapshot(11, 2);
        let next = HashMap::from([
            (first.key.clone(), first.clone()),
            (child.key.clone(), child.clone()),
        ]);
        let started = lifecycle_changes(&first_map, &next, &HashSet::from([10, 11]), true, 110);
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].kind, "started");
        assert_eq!(started[0].pid, 11);

        let ended = lifecycle_changes(
            &next,
            &HashMap::from([(child.key.clone(), child.clone())]),
            &HashSet::from([11]),
            true,
            120,
        );
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].kind, "exited");
        assert_eq!(ended[0].pid, 10);

        let mut orphan = child.clone();
        orphan.parent_disappeared = true;
        let parent_lost = lifecycle_changes(
            &HashMap::from([(child.key.clone(), child)]),
            &HashMap::from([(orphan.key.clone(), orphan)]),
            &HashSet::from([11]),
            true,
            130,
        );
        assert_eq!(parent_lost.len(), 1);
        assert_eq!(parent_lost[0].kind, "parent_lost");
    }
}
