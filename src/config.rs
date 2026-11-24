use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub collection: CollectionConfig,
    pub thresholds: ThresholdConfig,
    pub storage: StorageConfig,
    pub notifications: NotificationConfig,
    pub ai: AiConfig,
    #[serde(skip)]
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub interface: String,
    pub port: u16,
    pub database_dir: PathBuf,
    pub asset_dir: PathBuf,
    pub bootstrap_file: PathBuf,
    pub session_hours: u64,
    pub database_budget_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectionConfig {
    pub host_seconds: u64,
    pub process_seconds: u64,
    pub hardware_seconds: u64,
    pub service_seconds: u64,
    pub retention_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdConfig {
    pub memory_available_warning_percent: f64,
    pub memory_available_critical_percent: f64,
    pub disk_used_warning_percent: f64,
    pub cpu_pressure_warning_percent: f64,
    pub memory_pressure_warning_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Collect statvfs readings without recursively walking the filesystem.
    pub sample_seconds: u64,
    pub history_days: u64,
    pub warning_used_percent: f64,
    pub high_used_percent: f64,
    pub critical_used_percent: f64,
    pub warning_available_gib: u64,
    pub high_available_gib: u64,
    pub critical_available_gib: u64,
    pub abnormal_growth_gib_per_hour: f64,
    /// Mount points which must remain mounted and writable for their intended use.
    pub required_writable_mounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub provider: String,
    pub endpoint: Option<String>,
    pub secret: Option<String>,
    pub minimum_severity: String,
    pub cooldown_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub enabled: bool,
    pub provider: String,
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub timeout_seconds: u64,
}

/// Split the configured SQLite budget between high-resolution host history
/// and the independently sampled filesystem history. Keeping a fixed share
/// lets both databases enforce retention without an unbounded side database.
pub fn database_budget_partitions_mb(total_budget_mb: u64) -> (u64, u64) {
    let history_mb = (total_budget_mb.saturating_mul(15) / 100).max(1);
    (total_budget_mb.saturating_sub(history_mb), history_mb)
}

impl Default for Config {
    fn default() -> Self {
        let cfg = config_home();
        let data = data_home();
        Self {
            server: ServerConfig {
                interface: "tailscale0".into(),
                port: 8765,
                database_dir: data.join("sentinel"),
                asset_dir: PathBuf::from("frontend/dist"),
                bootstrap_file: cfg.join("sentinel/bootstrap-token"),
                session_hours: 12,
                database_budget_mb: 500,
            },
            collection: CollectionConfig {
                host_seconds: 5,
                process_seconds: 10,
                hardware_seconds: 15,
                service_seconds: 60,
                retention_hours: 48,
            },
            thresholds: ThresholdConfig {
                memory_available_warning_percent: 8.0,
                memory_available_critical_percent: 3.0,
                disk_used_warning_percent: 95.0,
                cpu_pressure_warning_percent: 20.0,
                memory_pressure_warning_percent: 10.0,
            },
            storage: StorageConfig::default(),
            notifications: NotificationConfig {
                enabled: false,
                provider: "ntfy".into(),
                endpoint: None,
                secret: None,
                minimum_severity: "warning".into(),
                cooldown_minutes: 30,
            },
            ai: AiConfig {
                enabled: false,
                provider: "ollama".into(),
                endpoint: None,
                model: None,
                timeout_seconds: 60,
            },
            path: config_home().join("sentinel/config.toml"),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Config::default().server
    }
}
impl Default for CollectionConfig {
    fn default() -> Self {
        Config::default().collection
    }
}
impl Default for ThresholdConfig {
    fn default() -> Self {
        Config::default().thresholds
    }
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            sample_seconds: 900,
            history_days: 365,
            warning_used_percent: 80.0,
            high_used_percent: 90.0,
            critical_used_percent: 95.0,
            warning_available_gib: 20,
            high_available_gib: 10,
            critical_available_gib: 5,
            abnormal_growth_gib_per_hour: 1.0,
            required_writable_mounts: vec!["/".into(), "/mnt/continental-cloud".into()],
        }
    }
}
impl Default for NotificationConfig {
    fn default() -> Self {
        Config::default().notifications
    }
}
impl Default for AiConfig {
    fn default() -> Self {
        Config::default().ai
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let chosen = path
            .map(Path::to_path_buf)
            .or_else(|| std::env::var_os("SENTINEL_CONFIG").map(PathBuf::from))
            .unwrap_or_else(|| Config::default().path);
        let mut cfg = if chosen.exists() {
            toml::from_str::<Config>(&fs::read_to_string(&chosen)?)?
        } else {
            Config::default()
        };
        cfg.path = chosen.clone();
        if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
            if !chosen.exists() {
                cfg.server.database_dir = PathBuf::from(dir).join("sentinel");
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.server.port != 0,
            "server.port must be a valid TCP port"
        );
        anyhow::ensure!(
            self.server.interface == "tailscale0"
                || self.server.interface == "lo"
                || self.server.interface.starts_with("tailscale"),
            "refusing to bind to non-private interface {}",
            self.server.interface
        );
        anyhow::ensure!(
            (1..=60).contains(&self.collection.host_seconds),
            "collection.host_seconds must be between 1 and 60"
        );
        anyhow::ensure!(
            (5..=300).contains(&self.collection.process_seconds),
            "collection.process_seconds must be between 5 and 300"
        );
        anyhow::ensure!(
            (5..=300).contains(&self.collection.hardware_seconds),
            "collection.hardware_seconds must be between 5 and 300"
        );
        anyhow::ensure!(
            (10..=600).contains(&self.collection.service_seconds),
            "collection.service_seconds must be between 10 and 600"
        );
        anyhow::ensure!(
            (6..=168).contains(&self.collection.retention_hours),
            "collection.retention_hours must be between 6 and 168"
        );
        anyhow::ensure!(
            self.server.database_budget_mb >= 50 && self.server.database_budget_mb <= 2048,
            "database_budget_mb must be between 50 and 2048"
        );
        anyhow::ensure!(
            (300..=86_400).contains(&self.storage.sample_seconds),
            "storage.sample_seconds must be between 300 and 86400"
        );
        anyhow::ensure!(
            (30..=730).contains(&self.storage.history_days),
            "storage.history_days must be between 30 and 730"
        );
        for (key, value) in [
            ("warning_used_percent", self.storage.warning_used_percent),
            ("high_used_percent", self.storage.high_used_percent),
            ("critical_used_percent", self.storage.critical_used_percent),
        ] {
            anyhow::ensure!(
                value.is_finite() && (0.0..=100.0).contains(&value),
                "storage.{key} must be between 0 and 100"
            );
        }
        anyhow::ensure!(
            self.storage.warning_used_percent < self.storage.high_used_percent
                && self.storage.high_used_percent < self.storage.critical_used_percent,
            "storage thresholds must increase from warning to critical"
        );
        anyhow::ensure!(
            self.storage.warning_available_gib > self.storage.high_available_gib
                && self.storage.high_available_gib > self.storage.critical_available_gib
                && self.storage.critical_available_gib > 0,
            "storage available-space thresholds must decrease from warning to critical"
        );
        anyhow::ensure!(
            self.storage.abnormal_growth_gib_per_hour.is_finite()
                && self.storage.abnormal_growth_gib_per_hour > 0.0
                && self.storage.abnormal_growth_gib_per_hour <= 1024.0,
            "storage.abnormal_growth_gib_per_hour must be between 0 and 1024"
        );
        anyhow::ensure!(
            !self.storage.required_writable_mounts.is_empty()
                && self.storage.required_writable_mounts.len() <= 32
                && self.storage.required_writable_mounts.iter().all(|mount| {
                    mount.starts_with('/')
                        && !mount.split('/').any(|component| component == "..")
                        && mount.len() <= 1024
                }),
            "storage.required_writable_mounts must contain 1 to 32 absolute paths without parent traversal"
        );
        for (key, value) in [
            (
                "memory_available_warning_percent",
                self.thresholds.memory_available_warning_percent,
            ),
            (
                "memory_available_critical_percent",
                self.thresholds.memory_available_critical_percent,
            ),
            (
                "disk_used_warning_percent",
                self.thresholds.disk_used_warning_percent,
            ),
            (
                "cpu_pressure_warning_percent",
                self.thresholds.cpu_pressure_warning_percent,
            ),
            (
                "memory_pressure_warning_percent",
                self.thresholds.memory_pressure_warning_percent,
            ),
        ] {
            anyhow::ensure!(
                value.is_finite() && (0.0..=100.0).contains(&value),
                "threshold {key} must be between 0 and 100"
            );
        }
        anyhow::ensure!(
            self.thresholds.memory_available_critical_percent
                <= self.thresholds.memory_available_warning_percent,
            "critical memory threshold must not exceed warning threshold"
        );
        anyhow::ensure!(
            ["ntfy", "discord"].contains(&self.notifications.provider.as_str()),
            "notifications.provider must be ntfy or discord"
        );
        anyhow::ensure!(
            ["info", "warning", "critical"].contains(&self.notifications.minimum_severity.as_str()),
            "notifications.minimum_severity must be info, warning or critical"
        );
        anyhow::ensure!(
            self.notifications.cooldown_minutes <= 1440,
            "notifications.cooldown_minutes must be at most 1440"
        );
        if self.notifications.enabled {
            let endpoint = self.notifications.endpoint.as_deref().unwrap_or_default();
            anyhow::ensure!(
                valid_notification_endpoint(&self.notifications.provider, endpoint),
                "notifications.endpoint must be a valid HTTPS provider URL (HTTP is allowed only for a loopback ntfy server)"
            );
        }
        anyhow::ensure!(
            ["ollama", "openai-compatible"].contains(&self.ai.provider.as_str()),
            "ai.provider must be ollama or openai-compatible"
        );
        anyhow::ensure!(
            (5..=180).contains(&self.ai.timeout_seconds),
            "ai.timeout_seconds must be between 5 and 180"
        );
        if self.ai.enabled {
            let endpoint = self.ai.endpoint.as_deref().unwrap_or_default();
            let parsed = url::Url::parse(endpoint).ok();
            anyhow::ensure!(
                parsed.as_ref().is_some_and(|u| {
                    (u.scheme() == "http" || u.scheme() == "https")
                        && u.username().is_empty()
                        && u.password().is_none()
                        && u.fragment().is_none()
                        && u.host_str().is_some_and(|host| {
                            host == "localhost"
                                || host
                                    .parse::<std::net::IpAddr>()
                                    .is_ok_and(|ip| ip.is_loopback())
                        })
                }),
                "ai.endpoint must use a loopback address"
            );
        }
        Ok(())
    }
    pub fn database_path(&self) -> PathBuf {
        self.server.database_dir.join("sentinel.sqlite3")
    }
    pub fn listen_address(&self) -> String {
        if let Ok(addrs) = if_addrs::get_if_addrs() {
            let selected = addrs
                .into_iter()
                .filter(|i| i.name == self.server.interface)
                .map(|i| i.ip())
                .find(|ip| ip.is_ipv4())
                .or_else(|| {
                    if_addrs::get_if_addrs()
                        .ok()?
                        .into_iter()
                        .find(|i| i.name == self.server.interface)
                        .map(|i| i.ip())
                });
            if let Some(address) = selected {
                return address.to_string();
            }
        }
        "127.0.0.1".into()
    }
}

fn valid_notification_endpoint(provider: &str, value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    match provider {
        "ntfy" => {
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && url.host_str().is_some_and(|host| {
                        host == "localhost"
                            || host
                                .parse::<std::net::IpAddr>()
                                .is_ok_and(|ip| ip.is_loopback())
                    }))
        }
        "discord" => {
            url.scheme() == "https"
                && matches!(url.host_str(), Some("discord.com" | "discordapp.com"))
                && url.path().starts_with("/api/webhooks/")
        }
        _ => false,
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    #[test]
    fn storage_policy_defaults_are_ordered_and_valid() {
        let config = Config::default();
        config.validate().unwrap();
        assert_eq!(config.storage.warning_used_percent, 80.0);
        assert_eq!(config.storage.high_used_percent, 90.0);
        assert_eq!(config.storage.critical_used_percent, 95.0);
        assert_eq!(config.storage.sample_seconds, 900);
        assert!(
            config
                .storage
                .required_writable_mounts
                .contains(&"/".into())
        );
    }

    #[test]
    fn storage_policy_rejects_unsafe_ranges_and_parent_paths() {
        let mut config = Config::default();
        config.storage.high_used_percent = 79.0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.storage.required_writable_mounts = vec!["/mnt/../home".into()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn database_budget_partitions_sum_to_total_and_reserve_a_bounded_history_share() {
        for total in [50, 100, 500, 2048] {
            let (main, history) = database_budget_partitions_mb(total);
            assert_eq!(main + history, total);
            assert!(history > 0);
            assert!(history * 100 <= total * 15);
        }
        assert_eq!(database_budget_partitions_mb(500), (425, 75));
    }
}

fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
}
fn data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_is_valid_and_wildcard_binding_is_rejected() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());
        config.server.interface = "0.0.0.0".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn notification_endpoints_are_restricted_by_provider() {
        assert!(valid_notification_endpoint(
            "ntfy",
            "https://ntfy.example/private-topic"
        ));
        assert!(valid_notification_endpoint(
            "ntfy",
            "http://127.0.0.1:8080/topic"
        ));
        assert!(!valid_notification_endpoint(
            "ntfy",
            "http://ntfy.example/topic"
        ));
        assert!(!valid_notification_endpoint(
            "ntfy",
            "https://user:pass@ntfy.example/topic"
        ));
        assert!(valid_notification_endpoint(
            "discord",
            "https://discord.com/api/webhooks/123/token"
        ));
        assert!(!valid_notification_endpoint(
            "discord",
            "https://evil.example/api/webhooks/123/token"
        ));
    }
}
