use crate::{
    auth::Auth,
    collector::{LiveState, Monitor},
    config::{Config, ThresholdConfig},
    model::{Incident, ProcessSnapshot},
    notifications::Dispatcher,
    storage::{Store, unix_now},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Extension, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post, put},
};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, Semaphore};
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing::warn;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub auth: Auth,
    pub notifications: Dispatcher,
    pub monitor: Monitor,
    pub live: LiveState,
    pub config: Arc<RwLock<Config>>,
    asset_dir: PathBuf,
    attempts: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
    ai_slots: Arc<Semaphore>,
}
impl AppState {
    pub fn new(config: Config, store: Store, notifications: Dispatcher) -> anyhow::Result<Self> {
        let monitor = Monitor::new(config.clone(), store.clone(), notifications.clone());
        let live = monitor.live();
        let shared_config = monitor.config();
        let auth = Auth::new(&config, store.clone());
        let asset_dir = config.server.asset_dir.clone();
        Ok(Self {
            store,
            auth,
            notifications,
            monitor,
            live,
            config: shared_config,
            asset_dir,
            attempts: Arc::new(Mutex::new(HashMap::new())),
            ai_slots: Arc::new(Semaphore::new(1)),
        })
    }
}

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/events", get(events))
        .route("/api/v1/metrics/{name}", get(metric_history))
        .route("/api/v1/processes", get(processes))
        .route("/api/v1/process-lifecycle", get(process_lifecycle))
        .route("/api/v1/processes/{key}", get(process_detail))
        .route("/api/v1/workloads", get(workloads))
        .route(
            "/api/v1/workloads/{workload}/label",
            put(save_workload_label),
        )
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/incidents/{id}", get(incident_detail))
        .route("/api/v1/incidents/{id}/investigate", post(investigate))
        .route("/api/v1/anomalies", get(anomalies))
        .route(
            "/api/v1/intelligence",
            get(intelligence).delete(reset_intelligence),
        )
        .route("/api/v1/services", get(services))
        .route("/api/v1/config", get(public_config).put(update_config))
        .route("/api/v1/notifications", get(notification_history))
        .route("/api/v1/notifications/test", post(test_notification))
        .route("/api/v1/auth/me", get(auth_me))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let asset_dir = state.asset_dir.clone();
    let index = asset_dir.join("index.html");
    Router::new()
        .route("/api/v1/health",get(health))
        .route("/api/v1/auth/status",get(auth_status))
        .route("/api/v1/auth/setup",post(auth_setup))
        .route("/api/v1/auth/login",post(auth_login))
        .route("/api/v1/auth/logout",post(auth_logout))
        .merge(protected)
        .fallback_service(ServeDir::new(asset_dir).not_found_service(ServeFile::new(index)))
        .layer(axum::extract::DefaultBodyLimit::max(64*1024))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_CONTENT_TYPE_OPTIONS,HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::if_not_present(header::X_FRAME_OPTIONS,HeaderValue::from_static("DENY")))
        .layer(SetResponseHeaderLayer::if_not_present(header::REFERRER_POLICY,HeaderValue::from_static("no-referrer")))
        .layer(SetResponseHeaderLayer::if_not_present(header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn require_auth(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok());
    let expected = state.config.read().await.clone();
    if !host.is_some_and(|h| host_is_allowed(h, &expected)) {
        return api_error(StatusCode::BAD_REQUEST, "unrecognized Host header");
    }
    let session = match state.auth.session(request.headers()) {
        Ok(Some(s)) => s,
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "authentication required"),
        Err(e) => {
            warn!(error=%e,"session lookup failed");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "authentication unavailable",
            );
        }
    };
    if request.method() != Method::GET
        && request.method() != Method::HEAD
        && request.method() != Method::OPTIONS
    {
        if !origin_matches(request.headers()) {
            return api_error(StatusCode::FORBIDDEN, "same-origin request required");
        }
        let csrf = request
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok());
        if !csrf.is_some_and(|v| constant_equal(v, &session.csrf)) {
            return api_error(StatusCode::FORBIDDEN, "CSRF token missing or invalid");
        }
    }
    request.extensions_mut().insert(session);
    next.run(request).await
}

fn host_is_allowed(host: &str, config: &Config) -> bool {
    let addr = config.listen_address().parse::<IpAddr>().ok();
    let expected = addr
        .map(|a| SocketAddr::new(a, config.server.port).to_string())
        .unwrap_or_else(|| format!("127.0.0.1:{}", config.server.port));
    host.eq_ignore_ascii_case(&expected)
        || host.eq_ignore_ascii_case(&format!("localhost:{}", config.server.port))
}
fn origin_matches(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    (scheme == "http" || scheme == "https")
        && authority
            .split('/')
            .next()
            .is_some_and(|a| a.eq_ignore_ascii_case(host))
}
fn constant_equal(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().len() == b.as_bytes().len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
fn api_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({"error":message}))).into_response()
}

async fn health(State(s): State<AppState>) -> impl IntoResponse {
    let latest = s.live.latest.read().await.clone();
    Json(
        serde_json::json!({"status":"ok","version":env!("CARGO_PKG_VERSION"),"timestamp":unix_now(),"collector_started":latest.is_some()}),
    )
}
async fn auth_status(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let configured = s.auth.is_configured().map_err(ApiError::internal)?;
    if !configured {
        s.auth
            .ensure_bootstrap_token()
            .map_err(ApiError::internal)?;
    }
    Ok(Json(
        serde_json::json!({"configured":configured,"setup_required":!configured,"bootstrap_file":if configured { None::<String> } else { s.auth.bootstrap_path().map(|p|p.display().to_string()) }}),
    ))
}
async fn auth_me(Extension(session): Extension<crate::auth::Session>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"username":"admin","csrf_token":session.csrf}))
}
#[derive(Deserialize)]
struct SetupInput {
    token: String,
    password: String,
}
async fn auth_setup(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SetupInput>,
) -> Result<Response, ApiError> {
    if !origin_matches(&headers) || !request_host_valid(&headers, &s).await {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "same-origin setup required",
        ));
    }
    if s.auth.is_configured().map_err(ApiError::internal)? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "administrator already configured",
        ));
    }
    crate::auth::validate_password(&input.password)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let result = s
        .auth
        .setup(&input.token, &input.password)
        .await
        .map_err(ApiError::internal)?;
    let Some((token, csrf, expires)) = result else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "setup token is invalid or expired",
        ));
    };
    let secure = false;
    let cookie = Auth::cookie(&token, expires - unix_now(), secure);
    let mut response =
        Json(serde_json::json!({"csrf_token":csrf,"username":"admin"})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid cookie")))?,
    );
    Ok(response)
}
#[derive(Deserialize)]
struct LoginInput {
    username: String,
    password: String,
}
async fn auth_login(
    State(s): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<LoginInput>,
) -> Result<Response, ApiError> {
    if input.username.len() > 64 || input.password.len() > 128 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "username or password is too long",
        ));
    }
    if !origin_matches(&headers) || !request_host_valid(&headers, &s).await {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "same-origin login required",
        ));
    }
    if !login_allowed(&s, peer.ip()) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many login attempts; retry in 15 minutes",
        ));
    }
    let result = s
        .auth
        .login(&input.username, &input.password)
        .await
        .map_err(ApiError::internal)?;
    let Some((token, csrf, expires)) = result else {
        record_login_failure(&s, peer.ip());
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid username or password",
        ));
    };
    clear_login_failures(&s, peer.ip());
    let cookie = Auth::cookie(&token, expires - unix_now(), false);
    let mut response =
        Json(serde_json::json!({"csrf_token":csrf,"username":input.username})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| ApiError::internal(anyhow::anyhow!("invalid cookie")))?,
    );
    Ok(response)
}
async fn auth_logout(State(s): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    if !origin_matches(&headers) || !request_host_valid(&headers, &s).await {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "same-origin logout required",
        ));
    }
    let session = s
        .auth
        .session(&headers)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "authentication required"))?;
    if !headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| constant_equal(v, &session.csrf))
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "CSRF token missing or invalid",
        ));
    }
    s.auth.logout(&headers).map_err(ApiError::internal)?;
    let mut r = Json(serde_json::json!({"ok":true})).into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("sentinel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
    );
    Ok(r)
}
async fn request_host_valid(headers: &HeaderMap, s: &AppState) -> bool {
    let config = s.config.read().await.clone();
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|host| host_is_allowed(host, &config))
}

fn login_allowed(s: &AppState, ip: IpAddr) -> bool {
    let Ok(mut map) = s.attempts.lock() else {
        return false;
    };
    let now = Instant::now();
    map.retain(|_, attempts| {
        while attempts
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(900))
        {
            attempts.pop_front();
        }
        !attempts.is_empty()
    });
    let q = map.entry(ip).or_default();
    q.len() < 5
}
fn record_login_failure(s: &AppState, ip: IpAddr) {
    if let Ok(mut m) = s.attempts.lock() {
        m.entry(ip).or_default().push_back(Instant::now());
    }
}
fn clear_login_failures(s: &AppState, ip: IpAddr) {
    if let Ok(mut m) = s.attempts.lock() {
        m.remove(&ip);
    }
}

async fn overview(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let host = s
        .live
        .latest
        .read()
        .await
        .clone()
        .or_else(|| s.store.latest_snapshot().ok().flatten());
    let procs = s.live.processes.read().await.clone();
    let services = s.live.services.read().await.clone();
    let incidents = s.store.incidents(true, 50).map_err(ApiError::internal)?;
    let labels = s.store.workload_labels().map_err(ApiError::internal)?;
    let workloads = aggregate_workloads(&procs, &labels);
    let failed = services.iter().filter(|u| u.active == "failed").count();
    let health = if !incidents.is_empty() {
        if incidents.iter().any(|i| i.severity == "critical") {
            "critical"
        } else {
            "warning"
        }
    } else {
        "healthy"
    };
    Ok(Json(
        serde_json::json!({"health":health,"host":host,"top_processes":procs.iter().take(12).collect::<Vec<_>>(),"workloads":workloads.iter().take(8).collect::<Vec<_>>(),"active_incidents":incidents,"service_summary":{"total":services.len(),"failed":failed},"database_bytes":s.store.database_size_bytes(),"updated_at":unix_now()}),
    ))
}
fn aggregate_workloads(
    processes: &[ProcessSnapshot],
    labels: &HashMap<String, (String, Vec<String>)>,
) -> Vec<serde_json::Value> {
    let mut v = Vec::new();
    for (name, items) in crate::workloads::group(processes) {
        let process_count = items.len();
        let cpu_percent = items.iter().map(|p| p.cpu_percent).sum::<f64>();
        let memory_bytes = items.iter().map(|p| p.rss_bytes).sum::<u64>();
        let parent_lost_count = items.iter().filter(|p| p.parent_disappeared).count();
        let (display_name, tags) = labels
            .get(&name)
            .cloned()
            .unwrap_or_else(|| (name.clone(), Vec::new()));
        v.push(serde_json::json!({"name":name,"display_name":display_name,"labels":tags,"process_count":process_count,"cpu_percent":cpu_percent,"memory_bytes":memory_bytes,"parent_lost_count":parent_lost_count}));
    }
    v.sort_by(|a, b| {
        b["cpu_percent"]
            .as_f64()
            .unwrap_or(0.0)
            .total_cmp(&a["cpu_percent"].as_f64().unwrap_or(0.0))
    });
    v
}
#[derive(Deserialize)]
struct MetricQuery {
    minutes: Option<u32>,
}
async fn metric_history(
    State(s): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<MetricQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let minutes = q.minutes.unwrap_or(360).clamp(1, 525_600);
    let points = s
        .store
        .chart(&name, unix_now() - minutes as i64 * 60, 1600)
        .map_err(ApiError::internal)?;
    Ok(Json(
        serde_json::json!({"name":name,"minutes":minutes,"points":points,"unit":metric_unit(&name)}),
    ))
}
fn metric_unit(metric: &str) -> &'static str {
    match metric {
        "cpu"
        | "cpu_user_percent"
        | "cpu_system_percent"
        | "cpu_iowait_percent"
        | "cpu_idle_percent"
        | "memory_used_percent"
        | "memory_available_percent"
        | "swap_used_percent"
        | "disk_used_percent"
        | "cpu_pressure"
        | "memory_pressure"
        | "memory_full_pressure"
        | "io_pressure"
        | "gpu_utilization_percent"
        | "gpu_memory_used_percent" => "%",
        "cpu_temperature_c" | "gpu_temperature_c" => "°C",
        "gpu_power_watts" => "W",
        "load_1m" | "load_5m" | "load_15m" => "load",
        m if m.starts_with("cpu_core_") => "%",
        "network_rx_bytes_per_sec"
        | "network_tx_bytes_per_sec"
        | "disk_read_bytes_per_sec"
        | "disk_write_bytes_per_sec"
        | "swap_in_bytes_per_sec"
        | "swap_out_bytes_per_sec" => "bytes/s",
        "disk_read_iops" | "disk_write_iops" => "IOPS",
        m if m.starts_with("workload::") && m.ends_with("::cpu_percent") => "%",
        m if m.starts_with("workload::") && m.ends_with("::rss_bytes") => "bytes",
        _ => "value",
    }
}
#[derive(Deserialize)]
struct ProcessQuery {
    q: Option<String>,
    sort: Option<String>,
    limit: Option<usize>,
}
#[derive(Deserialize)]
struct ProcessLifecycleQuery {
    minutes: Option<u32>,
    limit: Option<usize>,
}

async fn process_lifecycle(
    State(s): State<AppState>,
    Query(q): Query<ProcessLifecycleQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let minutes = q.minutes.unwrap_or(1440).clamp(1, 7 * 24 * 60);
    let events = s
        .store
        .process_lifecycle(unix_now() - minutes as i64 * 60, q.limit.unwrap_or(250))
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({"minutes":minutes,"events":events})))
}

async fn processes(
    State(s): State<AppState>,
    Query(q): Query<ProcessQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut p = s.live.processes.read().await.clone();
    let all = p.len();
    if let Some(query) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if query.len() > 256 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "process search is limited to 256 bytes",
            ));
        }
        let q = query.to_lowercase();
        p.retain(|x| {
            x.name.to_lowercase().contains(&q)
                || x.workload.to_lowercase().contains(&q)
                || x.executable
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&q)
                || x.pid.to_string() == q
        });
    }
    match q.sort.as_deref() {
        Some("memory") => p.sort_by_key(|x| std::cmp::Reverse(x.rss_bytes)),
        Some("runtime") => p.sort_by_key(|x| std::cmp::Reverse(x.runtime_seconds)),
        Some("tree") => p.sort_by_key(|x| x.pid),
        _ => p.sort_by(|a, b| b.cpu_percent.total_cmp(&a.cpu_percent)),
    }
    p.truncate(q.limit.unwrap_or(500).clamp(1, 1000));
    Ok(Json(
        serde_json::json!({"total":all,"filtered":p.len(),"processes":p}),
    ))
}
async fn process_detail(
    State(s): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let current = s
        .live
        .processes
        .read()
        .await
        .iter()
        .find(|p| p.key == key)
        .cloned();
    let history = s
        .store
        .process_history(&key, unix_now() - 48 * 3600, 1000)
        .map_err(ApiError::internal)?;
    if current.is_none() && history.is_empty() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "process history not found",
        ));
    }
    Ok(Json(
        serde_json::json!({"current":current,"history":history}),
    ))
}
async fn workloads(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let p = s.live.processes.read().await.clone();
    let labels = s.store.workload_labels().map_err(ApiError::internal)?;
    Ok(Json(
        serde_json::json!({"workloads":aggregate_workloads(&p,&labels)}),
    ))
}
async fn incidents(
    State(s): State<AppState>,
    Query(q): Query<IncidentQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let items = s
        .store
        .incidents(q.active.unwrap_or(false), q.limit.unwrap_or(100))
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({"incidents":items})))
}
#[derive(Deserialize)]
struct IncidentQuery {
    active: Option<bool>,
    limit: Option<usize>,
}
async fn incident_detail(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Incident>, ApiError> {
    let item = s
        .store
        .incidents(false, 500)
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "incident not found"))?;
    Ok(Json(item))
}
async fn anomalies(
    State(s): State<AppState>,
    Query(q): Query<AnomalyQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let since = unix_now() - q.hours.unwrap_or(24).clamp(1, 720) as i64 * 3600;
    Ok(Json(
        serde_json::json!({"anomalies":s.store.anomalies(since,q.limit.unwrap_or(250)).map_err(ApiError::internal)?}),
    ))
}
#[derive(Deserialize)]
struct AnomalyQuery {
    hours: Option<u32>,
    limit: Option<usize>,
}
async fn intelligence(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let (baseline_version, baseline_reset_at) =
        s.store.baseline_state().map_err(ApiError::internal)?;
    Ok(Json(
        serde_json::json!({"baselines":s.store.baselines().map_err(ApiError::internal)?,"baseline_version":baseline_version,"baseline_reset_at":baseline_reset_at,"anomalies":s.store.anomalies(unix_now()-7*86400,250).map_err(ApiError::internal)?,"learning":{"basic_hours":48,"weekly_patterns_available":false,"maturity":"confidence grows with clean observations; no reliable baseline is claimed before 48 hours"}}),
    ))
}
async fn reset_intelligence(
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (version, reset_at) = s
        .store
        .reset_baselines(unix_now())
        .map_err(ApiError::internal)?;
    Ok(Json(
        serde_json::json!({"baseline_version":version,"baseline_reset_at":reset_at,"baselines":[]}),
    ))
}
async fn services(State(s): State<AppState>) -> Json<serde_json::Value> {
    let u = s.live.services.read().await.clone();
    Json(
        serde_json::json!({"services":u,"available":!u.is_empty(),"source":"systemctl read-only inventory; permissions may limit unit visibility"}),
    )
}
async fn notification_history(
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(
        serde_json::json!({"notifications":s.store.notifications(100).map_err(ApiError::internal)?}),
    ))
}
async fn test_notification(State(s): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let config = s.config.read().await.clone();
    if !config.notifications.enabled {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "enable and configure a notification provider first",
        ));
    }
    config
        .validate()
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let detail = s
        .notifications
        .send_test(&config)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, &e))?;
    Ok(Json(serde_json::json!({"ok":true,"detail":detail})))
}

#[derive(Serialize)]
struct PublicConfig {
    host_seconds: u64,
    process_seconds: u64,
    hardware_seconds: u64,
    service_seconds: u64,
    retention_hours: u64,
    database_budget_mb: u64,
    thresholds: ThresholdConfig,
    notification_enabled: bool,
    notification_provider: String,
    ai_enabled: bool,
    ai_provider: String,
    interface: String,
    port: u16,
    config_path: String,
    notification_configured: bool,
    ai_configured: bool,
}
async fn public_config(State(s): State<AppState>) -> Json<PublicConfig> {
    let c = s.config.read().await;
    Json(PublicConfig {
        host_seconds: c.collection.host_seconds,
        process_seconds: c.collection.process_seconds,
        hardware_seconds: c.collection.hardware_seconds,
        service_seconds: c.collection.service_seconds,
        retention_hours: c.collection.retention_hours,
        database_budget_mb: c.server.database_budget_mb,
        thresholds: c.thresholds.clone(),
        notification_enabled: c.notifications.enabled,
        notification_provider: c.notifications.provider.clone(),
        ai_enabled: c.ai.enabled,
        ai_provider: c.ai.provider.clone(),
        interface: c.server.interface.clone(),
        port: c.server.port,
        config_path: c.path.display().to_string(),
        notification_configured: c.notifications.endpoint.is_some(),
        ai_configured: c.ai.endpoint.is_some(),
    })
}
#[derive(Deserialize)]
struct ConfigPatch {
    host_seconds: Option<u64>,
    process_seconds: Option<u64>,
    hardware_seconds: Option<u64>,
    service_seconds: Option<u64>,
    retention_hours: Option<u64>,
    thresholds: Option<ThresholdConfig>,
    notification_enabled: Option<bool>,
    ai_enabled: Option<bool>,
}
async fn update_config(
    State(s): State<AppState>,
    Json(patch): Json<ConfigPatch>,
) -> Result<Json<PublicConfig>, ApiError> {
    let mut current = s.config.write().await;
    let mut cfg = current.clone();
    if let Some(v) = patch.host_seconds {
        cfg.collection.host_seconds = v;
    }
    if let Some(v) = patch.process_seconds {
        cfg.collection.process_seconds = v;
    }
    if let Some(v) = patch.hardware_seconds {
        cfg.collection.hardware_seconds = v;
    }
    if let Some(v) = patch.service_seconds {
        cfg.collection.service_seconds = v;
    }
    if let Some(v) = patch.retention_hours {
        cfg.collection.retention_hours = v;
    }
    if let Some(v) = patch.thresholds {
        cfg.thresholds = v;
    }
    if let Some(v) = patch.notification_enabled {
        cfg.notifications.enabled = v;
    }
    if let Some(v) = patch.ai_enabled {
        cfg.ai.enabled = v;
    }
    cfg.validate()
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, &e.to_string()))?;
    persist_config(&cfg).map_err(ApiError::internal)?;
    *current = cfg.clone();
    let result = PublicConfig {
        host_seconds: cfg.collection.host_seconds,
        process_seconds: cfg.collection.process_seconds,
        hardware_seconds: cfg.collection.hardware_seconds,
        service_seconds: cfg.collection.service_seconds,
        retention_hours: cfg.collection.retention_hours,
        database_budget_mb: cfg.server.database_budget_mb,
        thresholds: cfg.thresholds.clone(),
        notification_enabled: cfg.notifications.enabled,
        notification_provider: cfg.notifications.provider.clone(),
        ai_enabled: cfg.ai.enabled,
        ai_provider: cfg.ai.provider.clone(),
        interface: cfg.server.interface.clone(),
        port: cfg.server.port,
        config_path: cfg.path.display().to_string(),
        notification_configured: cfg.notifications.endpoint.is_some(),
        ai_configured: cfg.ai.endpoint.is_some(),
    };
    Ok(Json(result))
}
fn persist_config(config: &Config) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = config.path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let content = toml::to_string_pretty(config)?;
    let mut temp = config.path.as_os_str().to_os_string();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(temp, &config.path)?;
    Ok(())
}

#[derive(Deserialize)]
struct LabelInput {
    display_name: String,
    labels: Option<Vec<String>>,
}
async fn save_workload_label(
    State(s): State<AppState>,
    Path(workload): Path<String>,
    Json(input): Json<LabelInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if workload.len() > 256 || input.display_name.trim().len() > 80 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "label too long"));
    }
    s.store
        .save_workload_label(
            &workload,
            input.display_name.trim(),
            input.labels.unwrap_or_default(),
        )
        .map_err(ApiError::internal)?;
    Ok(Json(serde_json::json!({"saved":true})))
}

async fn events(State(s): State<AppState>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = s.live.subscribe();
    let state = s.clone();
    let stream = async_stream::stream! {loop{if rx.changed().await.is_err(){break;}let snapshot=state.live.latest.read().await.clone();let data=serde_json::json!({"snapshot":snapshot,"active_incidents":state.store.incidents(true,50).unwrap_or_default()});let text=serde_json::to_string(&data).unwrap_or_else(|_|"{}".into());yield Ok(Event::default().event("update").data(text));}};
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn investigate(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cfg = s.config.read().await.clone();
    if !cfg.ai.enabled {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "local AI investigation is disabled",
        ));
    }
    let endpoint = cfg.ai.endpoint.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "configure a local inference endpoint first",
        )
    })?;
    if !loopback_url(endpoint) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "AI endpoint must be a local loopback URL",
        ));
    }
    let _ai_permit = s.ai_slots.clone().try_acquire_owned().map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "another local AI investigation is already running",
        )
    })?;
    let host = s.live.latest.read().await.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "collector has no sample yet",
        )
    })?;
    let available = if host.memory_total_bytes > 0 {
        host.memory_available_bytes as f64 / host.memory_total_bytes as f64
    } else {
        0.0
    };
    if available < 0.15
        || host.psi_memory_some_percent.unwrap_or(0.0) > 10.0
        || host.psi_cpu_some_percent.unwrap_or(0.0) > 30.0
        || host
            .cpu_temperature_c
            .zip(host.cpu_temperature_limit_c)
            .is_some_and(|(t, l)| t > l * 0.9)
    {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "local host pressure is too high for an AI investigation",
        ));
    }
    let incident = s
        .store
        .incidents(false, 500)
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|i| i.id == id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "incident not found"))?;
    let process_set = s.live.processes.read().await.clone();
    let processes = process_set
        .iter()
        .filter(|p| {
            incident.signature == "orphan-browser" && p.parent_disappeared
                || incident
                    .evidence
                    .get("observed_processes")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|rows| {
                        rows.iter().any(|row| {
                            row.get("pid").and_then(serde_json::Value::as_u64) == Some(p.pid as u64)
                        })
                    })
        })
        .take(12)
        .map(|p| {
            serde_json::json!({
                "pid":p.pid,
                "parent_pid":p.ppid,
                "name":p.name,
                "workload":p.workload,
                "cpu_percent":p.cpu_percent,
                "rss_bytes":p.rss_bytes,
                "runtime_seconds":p.runtime_seconds,
                "parent_disappeared":p.parent_disappeared,
            })
        })
        .collect::<Vec<_>>();
    let services = s
        .live
        .services
        .read()
        .await
        .iter()
        .filter(|service| service.active == "failed")
        .take(12)
        .map(|service| {
            serde_json::json!({
                "name":service.name,
                "active":service.active,
                "sub":service.sub,
                "description":service.description,
            })
        })
        .collect::<Vec<_>>();
    let mut metric_history = serde_json::Map::new();
    for metric in [
        "cpu",
        "memory_used_percent",
        "swap_used_percent",
        "cpu_pressure",
        "memory_pressure",
        "io_pressure",
        "disk_used_percent",
    ] {
        let points = s
            .store
            .chart(metric, unix_now() - 60 * 60, 60)
            .map_err(ApiError::internal)?;
        metric_history.insert(metric.to_string(), serde_json::json!(points));
    }
    let evidence = serde_json::json!({
        "incident":{"title":incident.title,"severity":incident.severity,"first_seen":incident.first_seen,"last_seen":incident.last_seen,"confidence":incident.confidence,"facts":incident.evidence,"explanation":incident.explanation},
        "current_host":{"timestamp":host.timestamp,"cpu_percent":host.cpu_percent,"load":host.load,"memory_available_bytes":host.memory_available_bytes,"memory_total_bytes":host.memory_total_bytes,"swap_in_bytes_per_sec":host.swap_in_bytes_per_sec,"swap_out_bytes_per_sec":host.swap_out_bytes_per_sec,"cpu_pressure_percent":host.psi_cpu_some_percent,"memory_pressure_percent":host.psi_memory_some_percent,"io_pressure_percent":host.psi_io_some_percent,"cpu_temperature_c":host.cpu_temperature_c,"cpu_temperature_limit_c":host.cpu_temperature_limit_c,"disk_available_bytes":host.disk_available_bytes,"process_count":host.process_count},
        "metric_history_last_hour":metric_history,
        "related_processes":processes,
        "currently_failed_services":services,
        "log_excerpt":null,
    });
    let prompt = format!(
        "Investigate this local server incident using only the supplied sanitized evidence. Separate observed facts, likely explanations, alternatives, confidence, and safe diagnostic steps. Never claim certainty beyond evidence and never suggest executing commands automatically.\nEvidence: {}",
        serde_json::to_string(&evidence).unwrap_or_default()
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.ai.timeout_seconds.clamp(5, 180)))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(ApiError::internal)?;
    let model = cfg.ai.model.unwrap_or_default();
    let provider = cfg.ai.provider.to_ascii_lowercase();
    let request = if provider == "ollama" {
        client
            .post(endpoint)
            .json(&serde_json::json!({"model":model,"prompt":prompt,"stream":false,"keep_alive":0}))
    } else {
        client.post(endpoint).json(&serde_json::json!({"model":model,"messages":[{"role":"user","content":prompt}],"stream":false}))
    };
    let mut response = request
        .send()
        .await
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "local AI request failed"))?;
    if !response.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "local AI provider returned an error",
        ));
    }
    const MAX_AI_RESPONSE_BYTES: usize = 1024 * 1024;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AI_RESPONSE_BYTES as u64)
    {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "local AI response exceeded the 1 MiB limit",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "local AI response failed"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_AI_RESPONSE_BYTES {
            return Err(ApiError::new(
                StatusCode::BAD_GATEWAY,
                "local AI response exceeded the 1 MiB limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "local AI returned invalid JSON"))?;
    let text = if provider == "ollama" {
        value.get("response").and_then(|x| x.as_str())
    } else {
        value
            .pointer("/choices/0/message/content")
            .and_then(|x| x.as_str())
    }
    .unwrap_or("The provider returned no text.");
    Ok(Json(
        serde_json::json!({"incident_id":id,"provider":provider,"interpretation":text.chars().take(8000).collect::<String>(),"measured_facts":evidence,"ai_generated":true}),
    ))
}
fn loopback_url(value: &str) -> bool {
    let Ok(u) = url::Url::parse(value) else {
        return false;
    };
    if u.scheme() != "http" && u.scheme() != "https" {
        return false;
    }
    if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return false;
    }
    let Some(host) = u.host_str() else {
        return false;
    };
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[derive(Clone)]
struct ApiError {
    status: StatusCode,
    message: String,
}
impl ApiError {
    fn new(status: StatusCode, message: &str) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn internal<E: std::fmt::Display>(e: E) -> Self {
        warn!(error=%e,"API operation failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "request failed")
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({"error":self.message}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt;
    #[test]
    fn origin_requires_exact_host_authority() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("100.64.0.2:8765"));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://100.64.0.2:8765"),
        );
        assert!(origin_matches(&h));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://evil.example"),
        );
        assert!(!origin_matches(&h));
    }
    #[test]
    fn loopback_guard_rejects_remote_endpoints() {
        assert!(loopback_url("http://127.0.0.1:11434/api/generate"));
        assert!(!loopback_url("https://example.com/api"));
    }

    #[tokio::test]
    async fn setup_login_csrf_logout_and_protected_reset_work_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.server.interface = "lo".into();
        config.server.port = 8765;
        config.server.database_dir = temp.path().join("data");
        config.server.asset_dir = temp.path().join("web");
        config.server.bootstrap_file = temp.path().join("config/bootstrap-token");
        config.path = temp.path().join("config/config.toml");
        let store = Store::open(&config.database_path()).unwrap();
        let dispatcher = Dispatcher::start(store.clone());
        let app = router(AppState::new(config, store.clone(), dispatcher).unwrap());
        let authority = "127.0.0.1:8765";
        let origin = "http://127.0.0.1:8765";

        let setup_status = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/auth/status")
                    .header(header::HOST, authority)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(setup_status.status(), StatusCode::OK);
        let token = std::fs::read_to_string(temp.path().join("config/bootstrap-token")).unwrap();
        let setup_request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/setup")
            .header(header::HOST, authority)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "token":token.trim(),
                    "password":"strong test password! 42"
                })
                .to_string(),
            ))
            .unwrap();
        let setup = app.clone().oneshot(setup_request).await.unwrap();
        assert_eq!(setup.status(), StatusCode::OK);
        let setup_cookie = setup
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let setup_bytes = to_bytes(setup.into_body(), 64 * 1024).await.unwrap();
        let setup_json: serde_json::Value = serde_json::from_slice(&setup_bytes).unwrap();
        let setup_csrf = setup_json["csrf_token"].as_str().unwrap().to_string();
        assert!(!temp.path().join("config/bootstrap-token").exists());

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/v1/intelligence")
                    .header(header::HOST, authority)
                    .header(header::ORIGIN, origin)
                    .header(header::COOKIE, &setup_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let logout = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/logout")
                    .header(header::HOST, authority)
                    .header(header::ORIGIN, origin)
                    .header(header::COOKIE, &setup_cookie)
                    .header("x-csrf-token", &setup_csrf)
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::OK);

        let mut login_request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::HOST, authority)
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "username":"admin",
                    "password":"strong test password! 42"
                })
                .to_string(),
            ))
            .unwrap();
        login_request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43210))));
        let login = app.clone().oneshot(login_request).await.unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let login_cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let login_bytes = to_bytes(login.into_body(), 64 * 1024).await.unwrap();
        let login_json: serde_json::Value = serde_json::from_slice(&login_bytes).unwrap();
        let csrf = login_json["csrf_token"].as_str().unwrap();

        let reset = app
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/api/v1/intelligence")
                    .header(header::HOST, authority)
                    .header(header::ORIGIN, origin)
                    .header(header::COOKIE, login_cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reset.status(), StatusCode::OK);
        let reset_bytes = to_bytes(reset.into_body(), 64 * 1024).await.unwrap();
        let reset_json: serde_json::Value = serde_json::from_slice(&reset_bytes).unwrap();
        assert_eq!(reset_json["baseline_version"], 2);
        assert!(store.has_account().unwrap());
    }
}
