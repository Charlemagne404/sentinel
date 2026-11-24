use crate::model::ProcessSnapshot;
use std::collections::BTreeMap;

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
}
