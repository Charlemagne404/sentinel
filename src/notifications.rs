use crate::{config::Config, storage::Store};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone)]
pub struct IncidentNotice {
    pub incident_id: Option<i64>,
    pub signature: String,
    pub severity: String,
    pub title: String,
    pub recovered: bool,
    pub escalated: bool,
}

#[derive(Clone)]
pub struct Dispatcher {
    sender: mpsc::Sender<Job>,
    dropped_jobs: Arc<AtomicU64>,
}

struct Job {
    config: Config,
    notice: IncidentNotice,
    reply: Option<oneshot::Sender<Result<String, String>>>,
    test: bool,
}

impl Dispatcher {
    pub fn start(store: Store) -> Self {
        let (sender, receiver) = mpsc::channel(16);
        tokio::spawn(worker(receiver, store));
        Self {
            sender,
            dropped_jobs: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn queue_depth(&self) -> usize {
        self.sender
            .max_capacity()
            .saturating_sub(self.sender.capacity())
    }

    pub fn dropped_jobs(&self) -> u64 {
        self.dropped_jobs.load(Ordering::Relaxed)
    }

    pub async fn notify(&self, config: &Config, notice: IncidentNotice) {
        if !config.notifications.enabled
            || severity_rank(&notice.severity)
                < severity_rank(&config.notifications.minimum_severity)
        {
            return;
        }
        if self
            .sender
            .try_send(Job {
                config: config.clone(),
                notice,
                reply: None,
                test: false,
            })
            .is_err()
        {
            self.dropped_jobs.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub async fn send_test(&self, config: &Config) -> Result<String, String> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .try_send(Job {
                config: config.clone(),
                notice: IncidentNotice {
                    incident_id: None,
                    signature: "__sentinel_test__".into(),
                    severity: "informational".into(),
                    title: "Sentinel test notification".into(),
                    recovered: false,
                    escalated: false,
                },
                reply: Some(reply),
                test: true,
            })
            .map_err(|_| "notification queue is full or the worker is unavailable".to_string())?;
        receiver
            .await
            .map_err(|_| "notification worker stopped before replying".to_string())?
    }
}

async fn worker(mut receiver: mpsc::Receiver<Job>, store: Store) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
    {
        Ok(client) => Arc::new(client),
        Err(_) => return,
    };
    while let Some(job) = receiver.recv().await {
        let result = deliver(&client, &store, &job).await;
        if let Some(reply) = job.reply {
            let _ = reply.send(result);
        }
    }
}

async fn deliver(client: &reqwest::Client, store: &Store, job: &Job) -> Result<String, String> {
    let config = &job.config.notifications;
    let provider = config.provider.as_str();
    let now = crate::storage::unix_now();
    if !config.enabled {
        return fail(store, job, provider, now, "notifications are disabled");
    }
    let endpoint = match config.endpoint.as_deref() {
        Some(endpoint) => endpoint,
        None => {
            return fail(
                store,
                job,
                provider,
                now,
                "provider endpoint is not configured",
            );
        }
    };
    if !job.test && !job.notice.recovered && !job.notice.escalated && config.cooldown_minutes > 0 {
        match store.last_notification_at(&job.notice.signature) {
            Ok(Some(last)) if now.saturating_sub(last) < config.cooldown_minutes as i64 * 60 => {
                let _ = store.log_notification(
                    job.notice.incident_id,
                    &job.notice.signature,
                    now,
                    provider,
                    "suppressed",
                    Some("suppressed by the configured incident cooldown"),
                );
                return Ok("This incident is inside the configured notification cooldown.".into());
            }
            Err(_) => {
                return fail(
                    store,
                    job,
                    provider,
                    now,
                    "notification history is unavailable",
                );
            }
            _ => {}
        }
    }

    let mut last_error = "provider request failed";
    for attempt in 1..=3 {
        match send_provider(client, config, endpoint, &job.notice).await {
            Ok(()) => {
                let detail = format!("delivered after {attempt} attempt(s)");
                if store
                    .log_notification(
                        job.notice.incident_id,
                        &job.notice.signature,
                        now,
                        provider,
                        "sent",
                        Some(&detail),
                    )
                    .is_err()
                {
                    return Err(
                        "delivery succeeded, but notification history could not be saved".into(),
                    );
                }
                return Ok(if job.test {
                    format!("Test delivered via {provider}.")
                } else {
                    format!("Delivered via {provider}.")
                });
            }
            Err(reason) => last_error = reason,
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(300 * (1 << (attempt - 1)))).await;
        }
    }
    let detail = format!("{last_error}; stopped after three attempts");
    let _ = store.log_notification(
        job.notice.incident_id,
        &job.notice.signature,
        now,
        provider,
        "failed",
        Some(&detail),
    );
    Err(format!("Notification delivery failed: {last_error}."))
}

async fn send_provider(
    client: &reqwest::Client,
    config: &crate::config::NotificationConfig,
    endpoint: &str,
    notice: &IncidentNotice,
) -> Result<(), &'static str> {
    let state = if notice.recovered {
        "recovered"
    } else if notice.escalated {
        "escalated"
    } else {
        "active"
    };
    let title = clean_title(&notice.title);
    let body = format!(
        "Sentinel {} · {}\n{}\nState: {}",
        notice.severity.to_ascii_uppercase(),
        state,
        title,
        state
    );
    let response = if config.provider == "ntfy" {
        let mut request = client
            .post(endpoint)
            .header("Title", "Sentinel server incident")
            .header("Priority", ntfy_priority(&notice.severity))
            .header(
                "Tags",
                if notice.recovered {
                    "white_check_mark"
                } else {
                    "warning"
                },
            )
            .body(body);
        if let Some(secret) = config.secret.as_deref().filter(|s| !s.is_empty()) {
            request = request.bearer_auth(secret);
        }
        request
            .send()
            .await
            .map_err(|_| "provider connection failed")?
    } else if config.provider == "discord" {
        client
            .post(endpoint)
            .json(&serde_json::json!({"content":body}))
            .send()
            .await
            .map_err(|_| "provider connection failed")?
    } else {
        return Err("unsupported provider");
    };
    if response.status().is_success() {
        Ok(())
    } else if response.status().is_server_error() || response.status().as_u16() == 429 {
        Err("provider temporarily unavailable")
    } else {
        Err("provider rejected the request")
    }
}

fn clean_title(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(180)
        .collect::<String>()
}
fn ntfy_priority(severity: &str) -> &'static str {
    match severity {
        "critical" => "5",
        "warning" => "4",
        _ => "3",
    }
}
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 3,
        "warning" => 2,
        "informational" | "info" => 1,
        _ => 0,
    }
}
fn fail(
    store: &Store,
    job: &Job,
    provider: &str,
    now: i64,
    detail: &str,
) -> Result<String, String> {
    let _ = store.log_notification(
        job.notice.incident_id,
        &job.notice.signature,
        now,
        provider,
        "failed",
        Some(detail),
    );
    Err(format!("Notification could not be sent: {detail}."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, NotificationConfig};
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    #[test]
    fn severity_filter_orders_levels() {
        assert!(severity_rank("critical") > severity_rank("warning"));
        assert!(severity_rank("warning") > severity_rank("informational"));
    }

    #[tokio::test]
    async fn test_delivery_is_logged_without_exposing_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let length = socket.read(&mut request).unwrap();
            let data = String::from_utf8_lossy(&request[..length]);
            assert!(data.contains("Sentinel test notification"));
            assert!(
                data.to_ascii_lowercase()
                    .contains("authorization: bearer test-secret")
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(&directory.path().join("notify.sqlite3")).unwrap();
        let dispatcher = Dispatcher::start(store.clone());
        let mut config = Config::default();
        config.notifications = NotificationConfig {
            enabled: true,
            provider: "ntfy".into(),
            endpoint: Some(format!("http://{address}/topic")),
            secret: Some("test-secret".into()),
            minimum_severity: "warning".into(),
            cooldown_minutes: 30,
        };
        let result = dispatcher.send_test(&config).await.unwrap();
        assert!(result.contains("ntfy"));
        server.join().unwrap();
        let history = store.notifications(10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, "sent");
        assert!(
            !history[0]
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("test-secret")
        );
    }

    #[tokio::test]
    async fn severity_escalation_bypasses_cooldown_and_is_identified_to_provider() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut data = Vec::new();
            let mut chunk = [0u8; 2048];
            loop {
                let length = socket.read(&mut chunk).unwrap();
                if length == 0 {
                    break;
                }
                data.extend_from_slice(&chunk[..length]);
                if let Some(header_end) = data.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&data[..header_end]);
                    let content_length = headers.lines().find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    });
                    if content_length
                        .is_some_and(|body_len| data.len() >= header_end + 4 + body_len)
                    {
                        break;
                    }
                }
            }
            let data = String::from_utf8_lossy(&data);
            assert!(data.contains("State: escalated"));
            assert!(data.contains("CRITICAL"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(&directory.path().join("escalation.sqlite3")).unwrap();
        let now = crate::storage::unix_now();
        store
            .log_notification(Some(1), "resource-pressure", now, "ntfy", "sent", None)
            .unwrap();
        let mut config = Config::default();
        config.notifications = NotificationConfig {
            enabled: true,
            provider: "ntfy".into(),
            endpoint: Some(format!("http://{address}/topic")),
            secret: None,
            minimum_severity: "warning".into(),
            cooldown_minutes: 30,
        };
        let job = Job {
            config: config.clone(),
            notice: IncidentNotice {
                incident_id: Some(1),
                signature: "resource-pressure".into(),
                severity: "critical".into(),
                title: "Incident escalated: host pressure".into(),
                recovered: false,
                escalated: true,
            },
            reply: None,
            test: false,
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        assert!(deliver(&client, &store, &job).await.is_ok());
        server.join().unwrap();
        assert_eq!(store.notifications(10).unwrap()[0].status, "sent");
    }

    #[tokio::test]
    async fn full_notification_queue_drops_without_waiting_for_the_monitor() {
        let (sender, _receiver) = mpsc::channel(1);
        let dispatcher = Dispatcher {
            sender,
            dropped_jobs: Arc::new(AtomicU64::new(0)),
        };
        let mut config = Config::default();
        config.notifications.enabled = true;
        config.notifications.minimum_severity = "warning".into();
        let notice = || IncidentNotice {
            incident_id: Some(1),
            signature: "resource-pressure".into(),
            severity: "warning".into(),
            title: "Synthetic test".into(),
            recovered: false,
            escalated: false,
        };

        dispatcher.notify(&config, notice()).await;
        assert_eq!(dispatcher.queue_depth(), 1);
        dispatcher.notify(&config, notice()).await;

        assert_eq!(dispatcher.queue_depth(), 1);
        assert_eq!(dispatcher.dropped_jobs(), 1);
    }
}
