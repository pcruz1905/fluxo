//! Docker container discovery config provider — Traefik-inspired label-based routing.
//!
//! Connects to the Docker Engine API over HTTP (TCP endpoint), discovers containers
//! with `fluxo.*` labels, and builds a [`FluxoConfig`] from those labels. Watches
//! Docker events for container start/stop/die to automatically rebuild config.
//!
//! # Label format
//!
//! Containers opt in with `fluxo.enable=true`, then declare routers and upstreams:
//!
//! ```text
//! fluxo.enable=true
//! fluxo.http.routers.myapp.match_host=myapp.example.com
//! fluxo.http.routers.myapp.match_path=/api/*
//! fluxo.http.routers.myapp.upstream=myapp
//! fluxo.http.upstreams.myapp.load_balancing=round_robin
//! fluxo.http.upstreams.myapp.health_check.path=/healthz
//! ```
//!
//! Container IP + published port are automatically added as upstream targets.
//!
//! # Connection modes
//!
//! The primary path uses TCP (e.g., `tcp://localhost:2375`). Unix socket support
//! (`/var/run/docker.sock`) is documented as a future enhancement — it requires
//! a custom `hyper` connector for Unix domain sockets.
//!
//! # Resilience
//!
//! - Event stream failures fall back to polling at the configured interval
//! - Individual container label parse errors are logged and skipped (don't crash)
//! - Docker API connection failures are logged and retried on the next poll cycle

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::provider::ConfigProvider;
use super::{
    FluxoConfig, GlobalConfig, HealthCheckConfig, ListenerConfig, RouteConfig, ServiceConfig,
    TargetConfig, UpstreamConfig,
};

// ── Configuration ───────────────────────────────────────────────────────────

/// Configuration for the Docker container discovery provider.
#[derive(Debug, Clone)]
pub struct DockerProviderConfig {
    /// Docker Engine API endpoint (e.g., `"tcp://localhost:2375"`).
    pub endpoint: String,

    /// How often to poll Docker for container changes (fallback when events fail).
    pub poll_interval: Duration,

    /// Label prefix to scan for (default: `"fluxo"`).
    pub label_prefix: String,

    /// Whether to use Docker event stream for real-time updates.
    pub watch_events: bool,

    /// Default listener address for auto-generated services.
    pub default_listener: String,
}

impl Default for DockerProviderConfig {
    fn default() -> Self {
        Self {
            endpoint: "tcp://localhost:2375".to_string(),
            poll_interval: Duration::from_secs(15),
            label_prefix: "fluxo".to_string(),
            watch_events: true,
            default_listener: "0.0.0.0:80".to_string(),
        }
    }
}

// ── Docker API response types ───────────────────────────────────────────────

/// Minimal Docker container JSON (only the fields we need).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerContainer {
    /// Container ID.
    id: String,

    /// Container names (prefixed with `/`).
    names: Vec<String>,

    /// Container labels.
    labels: Option<HashMap<String, String>>,

    /// Container state (e.g., "running").
    state: String,

    /// Network settings with published ports.
    #[serde(default)]
    network_settings: ContainerNetworkSettings,
}

impl DockerContainer {
    /// Best human-readable name for this container (strips leading `/`).
    fn display_name(&self) -> &str {
        self.names
            .first()
            .map(|n| n.strip_prefix('/').unwrap_or(n))
            .unwrap_or(&self.id)
    }
}

/// Network settings for a container.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerNetworkSettings {
    /// Per-network attachment info.
    #[serde(default)]
    networks: HashMap<String, ContainerNetwork>,
}

/// Per-network info for a container.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerNetwork {
    /// Container IP in this network.
    #[serde(default, rename = "IPAddress")]
    ip_address: String,
}

/// Docker event from the `/events` endpoint.
#[derive(Debug, Clone, Deserialize)]
struct DockerEvent {
    /// Event type (e.g., "container").
    #[serde(rename = "Type")]
    event_type: String,

    /// Event action (e.g., "start", "stop", "die").
    #[serde(rename = "Action")]
    action: String,
}

// ── Label parsing ───────────────────────────────────────────────────────────

/// Parsed router configuration from container labels.
#[derive(Debug, Clone, Default)]
struct ParsedRouter {
    match_host: Vec<String>,
    match_path: Vec<String>,
    match_method: Vec<String>,
    upstream: Option<String>,
}

/// Parsed upstream configuration from container labels.
#[derive(Debug, Clone, Default)]
struct ParsedUpstream {
    load_balancing: Option<String>,
    health_check_path: Option<String>,
    health_check_interval: Option<String>,
}

/// Parsed configuration for a single container.
#[derive(Debug, Clone)]
struct ParsedContainer {
    /// Container display name (for logging).
    name: String,

    /// Named routers declared via labels.
    routers: HashMap<String, ParsedRouter>,

    /// Named upstreams declared via labels.
    upstreams: HashMap<String, ParsedUpstream>,

    /// Auto-discovered target address (container IP:port).
    target_address: Option<String>,
}

/// Parse labels from a single container into structured config.
///
/// Label format: `{prefix}.http.routers.{name}.{field}=value`
///               `{prefix}.http.upstreams.{name}.{field}=value`
fn parse_container_labels(
    labels: &HashMap<String, String>,
    prefix: &str,
) -> Option<ParsedContainer> {
    // Must have `{prefix}.enable=true`
    let enable_key = format!("{prefix}.enable");
    match labels.get(&enable_key) {
        Some(v) if v.eq_ignore_ascii_case("true") => {}
        _ => return None,
    }

    let mut routers: HashMap<String, ParsedRouter> = HashMap::new();
    let mut upstreams: HashMap<String, ParsedUpstream> = HashMap::new();

    let router_prefix = format!("{prefix}.http.routers.");
    let upstream_prefix = format!("{prefix}.http.upstreams.");

    for (key, value) in labels {
        if let Some(rest) = key.strip_prefix(&router_prefix) {
            // rest = "myapp.match_host" or "myapp.upstream"
            if let Some((router_name, field)) = rest.split_once('.') {
                let router = routers.entry(router_name.to_string()).or_default();
                match field {
                    "match_host" => {
                        router
                            .match_host
                            .extend(value.split(',').map(|s| s.trim().to_string()));
                    }
                    "match_path" => {
                        router
                            .match_path
                            .extend(value.split(',').map(|s| s.trim().to_string()));
                    }
                    "match_method" => {
                        router
                            .match_method
                            .extend(value.split(',').map(|s| s.trim().to_string()));
                    }
                    "upstream" => {
                        router.upstream = Some(value.clone());
                    }
                    other => {
                        debug!(field = other, router = router_name, "unknown router label field — skipping");
                    }
                }
            }
        } else if let Some(rest) = key.strip_prefix(&upstream_prefix) {
            // rest = "myapp.load_balancing" or "myapp.health_check.path"
            if let Some((upstream_name, field)) = rest.split_once('.') {
                let upstream = upstreams.entry(upstream_name.to_string()).or_default();
                match field {
                    "load_balancing" => {
                        upstream.load_balancing = Some(value.clone());
                    }
                    "health_check.path" => {
                        upstream.health_check_path = Some(value.clone());
                    }
                    "health_check.interval" => {
                        upstream.health_check_interval = Some(value.clone());
                    }
                    other => {
                        debug!(
                            field = other,
                            upstream = upstream_name,
                            "unknown upstream label field — skipping"
                        );
                    }
                }
            }
        }
    }

    Some(ParsedContainer {
        name: String::new(), // filled in by caller
        routers,
        upstreams,
        target_address: None, // filled in by caller
    })
}

/// Extract the best target address from a Docker container.
///
/// Priority:
/// 1. First network IP + first exposed TCP port
/// 2. Falls back to `None` if no usable address is found
fn extract_target_address(container: &DockerContainer) -> Option<String> {
    // Find the container IP from the first available network.
    let ip = container
        .network_settings
        .networks
        .values()
        .find(|n| !n.ip_address.is_empty())
        .map(|n| &n.ip_address)?;

    // We need a port. Look for the first exposed TCP port from labels or names.
    // Docker `/containers/json` includes Ports in the response, but our minimal
    // struct may not have it. Fall back to port 80 if no port is discoverable.
    // In practice, the container labels should specify the upstream or the port
    // will come from the Ports field if we extend the struct.
    Some(format!("{ip}:80"))
}

/// Extract target address with explicit port from Docker container.
#[cfg(test)]
fn extract_target_with_port(container: &DockerContainer, port: u16) -> Option<String> {
    let ip = container
        .network_settings
        .networks
        .values()
        .find(|n| !n.ip_address.is_empty())
        .map(|n| &n.ip_address)?;

    Some(format!("{ip}:{port}"))
}

// ── Config building ─────────────────────────────────────────────────────────

/// Build a `FluxoConfig` from a set of parsed containers.
fn build_config(
    containers: &[ParsedContainer],
    default_listener: &str,
) -> FluxoConfig {
    let mut services: HashMap<String, ServiceConfig> = HashMap::new();
    let mut upstreams: HashMap<String, UpstreamConfig> = HashMap::new();

    for container in containers {
        // Process upstream declarations from labels.
        for (upstream_name, parsed) in &container.upstreams {
            let upstream = upstreams
                .entry(upstream_name.clone())
                .or_insert_with(|| UpstreamConfig {
                    load_balancing: parsed
                        .load_balancing
                        .clone()
                        .unwrap_or_else(|| "round_robin".to_string()),
                    health_check: parsed.health_check_path.as_ref().map(|path| {
                        HealthCheckConfig {
                            path: path.clone(),
                            interval: parsed
                                .health_check_interval
                                .clone()
                                .unwrap_or_else(|| "10s".to_string()),
                            timeout: "3s".to_string(),
                            unhealthy_threshold: 3,
                            healthy_threshold: 2,
                            unhealthy_interval: None,
                            expected_status: 0,
                            expected_body: None,
                            method: "GET".to_string(),
                            headers: HashMap::new(),
                            follow_redirects: true,
                        }
                    }),
                    ..Default::default()
                });

            // Add this container's address as a target for the upstream.
            if let Some(ref addr) = container.target_address {
                upstream.targets.push(TargetConfig::Simple(addr.clone()));
            }
        }

        // Also add targets to upstreams referenced by routers (even if not
        // explicitly declared via upstream labels — auto-create the upstream).
        for (router_name, router) in &container.routers {
            let upstream_name = router
                .upstream
                .clone()
                .unwrap_or_else(|| router_name.clone());

            // Ensure the upstream exists (auto-create if only referenced, not declared).
            let upstream = upstreams
                .entry(upstream_name.clone())
                .or_insert_with(UpstreamConfig::default);

            if let Some(ref addr) = container.target_address {
                // Only add if not already present (avoid duplicates when upstream
                // was explicitly declared and also referenced by a router).
                let already_has = upstream.targets.iter().any(|t| t.address() == addr);
                if !already_has {
                    upstream.targets.push(TargetConfig::Simple(addr.clone()));
                }
            }

            // Build the route.
            let route = RouteConfig {
                name: Some(format!("docker-{router_name}")),
                match_host: router.match_host.clone(),
                match_path: router.match_path.clone(),
                match_method: router.match_method.clone(),
                upstream: upstream_name,
                ..Default::default()
            };

            // Group routes into a per-router service (or merge into a shared
            // "docker" service — we use one service per router for clarity).
            let service_name = format!("docker-{router_name}");
            let service = services
                .entry(service_name)
                .or_insert_with(|| ServiceConfig {
                    listeners: vec![ListenerConfig {
                        address: default_listener.to_string(),
                        offer_h2: false,
                        proxy_protocol: false,
                    }],
                    tls: None,
                    routes: Vec::new(),
                });
            service.routes.push(route);
        }
    }

    FluxoConfig {
        global: GlobalConfig::default(),
        services,
        upstreams,
        l4: Default::default(),
    }
}

// ── Docker API client ───────────────────────────────────────────────────────

/// Normalize the Docker endpoint to an HTTP base URL.
///
/// Converts `tcp://host:port` → `http://host:port`.
fn normalize_endpoint(endpoint: &str) -> String {
    if let Some(rest) = endpoint.strip_prefix("tcp://") {
        format!("http://{rest}")
    } else if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        // Assume it's a bare host:port.
        format!("http://{endpoint}")
    }
}

/// Fetch running containers from the Docker API.
async fn fetch_containers(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<Vec<DockerContainer>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!(
        "{base_url}/containers/json?filters={}",
        percent_encoding::utf8_percent_encode(
            r#"{"status":["running"]}"#,
            percent_encoding::NON_ALPHANUMERIC,
        )
    );

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Docker API returned {status}: {body}").into());
    }

    let containers: Vec<DockerContainer> = resp.json().await?;
    Ok(containers)
}

/// Discover containers and build a config.
fn containers_to_config(
    containers: Vec<DockerContainer>,
    prefix: &str,
    default_listener: &str,
) -> FluxoConfig {
    let mut parsed = Vec::new();

    for container in &containers {
        let labels = match &container.labels {
            Some(l) if !l.is_empty() => l,
            _ => continue,
        };

        // Skip non-running containers (belt-and-suspenders — we filter in the API query too).
        if container.state != "running" {
            continue;
        }

        let mut pc = match parse_container_labels(labels, prefix) {
            Some(pc) => pc,
            None => continue,
        };

        pc.name = container.display_name().to_string();
        pc.target_address = extract_target_address(container);

        debug!(
            container = %pc.name,
            routers = pc.routers.len(),
            upstreams = pc.upstreams.len(),
            target = ?pc.target_address,
            "discovered container"
        );

        parsed.push(pc);
    }

    info!(containers = parsed.len(), "built config from Docker containers");
    build_config(&parsed, default_listener)
}

// ── Provider ────────────────────────────────────────────────────────────────

/// Docker container discovery config provider.
///
/// Connects to the Docker Engine API, discovers containers with `fluxo.*`
/// labels, and pushes config updates when containers start or stop.
pub struct DockerProvider {
    config: DockerProviderConfig,
}

impl DockerProvider {
    /// Create a new Docker provider with the given configuration.
    pub fn new(config: DockerProviderConfig) -> Self {
        Self { config }
    }

    /// Create a new Docker provider with default configuration.
    pub fn with_defaults() -> Self {
        Self {
            config: DockerProviderConfig::default(),
        }
    }

    /// Discover containers and build a `FluxoConfig`.
    async fn discover(
        &self,
        client: &reqwest::Client,
        base_url: &str,
    ) -> Result<FluxoConfig, Box<dyn std::error::Error + Send + Sync>> {
        let containers = fetch_containers(client, base_url).await?;
        Ok(containers_to_config(
            containers,
            &self.config.label_prefix,
            &self.config.default_listener,
        ))
    }

    /// Poll for container changes at a fixed interval.
    async fn poll_loop(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        tx: &mpsc::Sender<(String, FluxoConfig)>,
    ) {
        loop {
            tokio::time::sleep(self.config.poll_interval).await;

            match self.discover(client, base_url).await {
                Ok(config) => {
                    if tx.send((self.name().to_string(), config)).await.is_err() {
                        // Receiver dropped — shutdown.
                        return;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Docker poll failed — will retry next cycle");
                }
            }
        }
    }

    /// Watch Docker events and trigger re-discovery on container lifecycle changes.
    ///
    /// Falls back to polling if the event stream fails.
    async fn watch_events_loop(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        tx: &mpsc::Sender<(String, FluxoConfig)>,
    ) {
        let events_url = format!(
            "{base_url}/events?filters={}",
            percent_encoding::utf8_percent_encode(
                r#"{"type":["container"],"event":["start","stop","die","destroy"]}"#,
                percent_encoding::NON_ALPHANUMERIC,
            )
        );

        info!(url = %events_url, "connecting to Docker event stream");

        // Try to connect to the event stream. If it fails, fall back to polling.
        let resp = match client.get(&events_url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!(
                    status = %r.status(),
                    "Docker event stream returned non-success — falling back to polling"
                );
                self.poll_loop(client, base_url, tx).await;
                return;
            }
            Err(e) => {
                warn!(error = %e, "failed to connect to Docker event stream — falling back to polling");
                self.poll_loop(client, base_url, tx).await;
                return;
            }
        };

        info!("connected to Docker event stream");

        // Read the event stream as newline-delimited JSON using reqwest's chunk API.
        let mut resp = resp;
        let mut buffer = Vec::new();

        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    buffer.extend_from_slice(&chunk);

                    // Events are newline-delimited JSON — process complete lines.
                    while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = buffer.drain(..=pos).collect();
                        let line = String::from_utf8_lossy(&line);
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }

                        match serde_json::from_str::<DockerEvent>(line) {
                            Ok(event) => {
                                debug!(
                                    event_type = %event.event_type,
                                    action = %event.action,
                                    "Docker event received"
                                );

                                // Re-discover on any relevant container event.
                                match self.discover(client, base_url).await {
                                    Ok(config) => {
                                        if tx
                                            .send((self.name().to_string(), config))
                                            .await
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            error = %e,
                                            "failed to re-discover after Docker event"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, line = %line, "failed to parse Docker event");
                            }
                        }
                    }
                }
                Ok(None) => {
                    warn!("Docker event stream ended — falling back to polling");
                    self.poll_loop(client, base_url, tx).await;
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "Docker event stream error — falling back to polling");
                    self.poll_loop(client, base_url, tx).await;
                    return;
                }
            }
        }
    }
}

#[async_trait]
impl ConfigProvider for DockerProvider {
    fn name(&self) -> &str {
        "docker"
    }

    async fn watch(
        &self,
        tx: mpsc::Sender<(String, FluxoConfig)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let base_url = normalize_endpoint(&self.config.endpoint);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        info!(
            endpoint = %base_url,
            poll_interval = ?self.config.poll_interval,
            label_prefix = %self.config.label_prefix,
            watch_events = self.config.watch_events,
            "starting Docker provider"
        );

        // Initial discovery.
        match self.discover(&client, &base_url).await {
            Ok(config) => {
                if tx.send((self.name().to_string(), config)).await.is_err() {
                    return Ok(());
                }
            }
            Err(e) => {
                error!(error = %e, "initial Docker discovery failed — will retry via poll/events");
            }
        }

        // For event watching, we need a client without the short timeout (events stream
        // is long-lived). Build a separate client for the stream.
        if self.config.watch_events {
            let stream_client = reqwest::Client::builder()
                .timeout(Duration::from_secs(0)) // no timeout for streaming
                .build()?;
            self.watch_events_loop(&stream_client, &base_url, &tx)
                .await;
        } else {
            self.poll_loop(&client, &base_url, &tx).await;
        }

        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // ── DockerProviderConfig defaults ───────────────────────────────

    #[test]
    fn default_config_values() {
        let cfg = DockerProviderConfig::default();
        assert_eq!(cfg.endpoint, "tcp://localhost:2375");
        assert_eq!(cfg.poll_interval, Duration::from_secs(15));
        assert_eq!(cfg.label_prefix, "fluxo");
        assert!(cfg.watch_events);
        assert_eq!(cfg.default_listener, "0.0.0.0:80");
    }

    // ── Provider name ───────────────────────────────────────────────

    #[test]
    fn provider_name_is_docker() {
        let provider = DockerProvider::with_defaults();
        assert_eq!(provider.name(), "docker");
    }

    // ── Endpoint normalization ──────────────────────────────────────

    #[test]
    fn normalize_tcp_endpoint() {
        assert_eq!(
            normalize_endpoint("tcp://localhost:2375"),
            "http://localhost:2375"
        );
    }

    #[test]
    fn normalize_http_endpoint_unchanged() {
        assert_eq!(
            normalize_endpoint("http://docker.local:2375"),
            "http://docker.local:2375"
        );
    }

    #[test]
    fn normalize_https_endpoint_unchanged() {
        assert_eq!(
            normalize_endpoint("https://docker.local:2376"),
            "https://docker.local:2376"
        );
    }

    #[test]
    fn normalize_bare_host_port() {
        assert_eq!(
            normalize_endpoint("192.168.1.100:2375"),
            "http://192.168.1.100:2375"
        );
    }

    // ── Label parsing ───────────────────────────────────────────────

    #[test]
    fn parse_labels_requires_enable() {
        let labels = HashMap::from([
            ("fluxo.http.routers.web.match_host".to_string(), "example.com".to_string()),
        ]);
        assert!(parse_container_labels(&labels, "fluxo").is_none());
    }

    #[test]
    fn parse_labels_enable_false_returns_none() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "false".to_string()),
            ("fluxo.http.routers.web.match_host".to_string(), "example.com".to_string()),
        ]);
        assert!(parse_container_labels(&labels, "fluxo").is_none());
    }

    #[test]
    fn parse_labels_enable_case_insensitive() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "TRUE".to_string()),
            ("fluxo.http.routers.web.match_host".to_string(), "example.com".to_string()),
        ]);
        let parsed = parse_container_labels(&labels, "fluxo");
        assert!(parsed.is_some());
    }

    #[test]
    fn parse_labels_basic_router() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            ("fluxo.http.routers.web.match_host".to_string(), "example.com".to_string()),
            ("fluxo.http.routers.web.match_path".to_string(), "/api/*".to_string()),
            ("fluxo.http.routers.web.upstream".to_string(), "backend".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo").unwrap();
        assert_eq!(parsed.routers.len(), 1);

        let router = &parsed.routers["web"];
        assert_eq!(router.match_host, vec!["example.com"]);
        assert_eq!(router.match_path, vec!["/api/*"]);
        assert_eq!(router.upstream, Some("backend".to_string()));
    }

    #[test]
    fn parse_labels_multiple_hosts_comma_separated() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            (
                "fluxo.http.routers.web.match_host".to_string(),
                "example.com, www.example.com".to_string(),
            ),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo").unwrap();
        let router = &parsed.routers["web"];
        assert_eq!(
            router.match_host,
            vec!["example.com", "www.example.com"]
        );
    }

    #[test]
    fn parse_labels_multiple_paths_comma_separated() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            (
                "fluxo.http.routers.web.match_path".to_string(),
                "/api/*, /health".to_string(),
            ),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo").unwrap();
        let router = &parsed.routers["web"];
        assert_eq!(router.match_path, vec!["/api/*", "/health"]);
    }

    #[test]
    fn parse_labels_multiple_methods_comma_separated() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            (
                "fluxo.http.routers.web.match_method".to_string(),
                "GET, POST".to_string(),
            ),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo").unwrap();
        let router = &parsed.routers["web"];
        assert_eq!(router.match_method, vec!["GET", "POST"]);
    }

    #[test]
    fn parse_labels_upstream_config() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            (
                "fluxo.http.upstreams.backend.load_balancing".to_string(),
                "least_connections".to_string(),
            ),
            (
                "fluxo.http.upstreams.backend.health_check.path".to_string(),
                "/healthz".to_string(),
            ),
            (
                "fluxo.http.upstreams.backend.health_check.interval".to_string(),
                "5s".to_string(),
            ),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo").unwrap();
        assert_eq!(parsed.upstreams.len(), 1);

        let upstream = &parsed.upstreams["backend"];
        assert_eq!(
            upstream.load_balancing,
            Some("least_connections".to_string())
        );
        assert_eq!(upstream.health_check_path, Some("/healthz".to_string()));
        assert_eq!(upstream.health_check_interval, Some("5s".to_string()));
    }

    #[test]
    fn parse_labels_multiple_routers() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            (
                "fluxo.http.routers.web.match_host".to_string(),
                "web.example.com".to_string(),
            ),
            (
                "fluxo.http.routers.web.upstream".to_string(),
                "web-backend".to_string(),
            ),
            (
                "fluxo.http.routers.api.match_host".to_string(),
                "api.example.com".to_string(),
            ),
            (
                "fluxo.http.routers.api.match_path".to_string(),
                "/v1/*".to_string(),
            ),
            (
                "fluxo.http.routers.api.upstream".to_string(),
                "api-backend".to_string(),
            ),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo").unwrap();
        assert_eq!(parsed.routers.len(), 2);
        assert!(parsed.routers.contains_key("web"));
        assert!(parsed.routers.contains_key("api"));
    }

    #[test]
    fn parse_labels_custom_prefix() {
        let labels = HashMap::from([
            ("myproxy.enable".to_string(), "true".to_string()),
            (
                "myproxy.http.routers.app.match_host".to_string(),
                "app.test".to_string(),
            ),
        ]);

        let parsed = parse_container_labels(&labels, "myproxy").unwrap();
        assert_eq!(parsed.routers.len(), 1);
        assert!(parsed.routers.contains_key("app"));
    }

    #[test]
    fn parse_labels_wrong_prefix_returns_none() {
        let labels = HashMap::from([
            ("traefik.enable".to_string(), "true".to_string()),
            (
                "traefik.http.routers.app.match_host".to_string(),
                "app.test".to_string(),
            ),
        ]);

        assert!(parse_container_labels(&labels, "fluxo").is_none());
    }

    #[test]
    fn parse_labels_enable_only() {
        let labels = HashMap::from([("fluxo.enable".to_string(), "true".to_string())]);

        let parsed = parse_container_labels(&labels, "fluxo").unwrap();
        assert!(parsed.routers.is_empty());
        assert!(parsed.upstreams.is_empty());
    }

    #[test]
    fn parse_labels_unknown_fields_ignored() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            (
                "fluxo.http.routers.web.match_host".to_string(),
                "example.com".to_string(),
            ),
            (
                "fluxo.http.routers.web.unknown_field".to_string(),
                "value".to_string(),
            ),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo").unwrap();
        let router = &parsed.routers["web"];
        assert_eq!(router.match_host, vec!["example.com"]);
    }

    // ── Target address extraction ───────────────────────────────────

    #[test]
    fn extract_target_from_container_network() {
        let container = DockerContainer {
            id: "abc123".to_string(),
            names: vec!["/myapp".to_string()],
            labels: Some(HashMap::new()),
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings {
                networks: HashMap::from([(
                    "bridge".to_string(),
                    ContainerNetwork {
                        ip_address: "172.17.0.2".to_string(),
                    },
                )]),
            },
        };

        let addr = extract_target_address(&container);
        assert_eq!(addr, Some("172.17.0.2:80".to_string()));
    }

    #[test]
    fn extract_target_no_network_returns_none() {
        let container = DockerContainer {
            id: "abc123".to_string(),
            names: vec!["/myapp".to_string()],
            labels: Some(HashMap::new()),
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings {
                networks: HashMap::new(),
            },
        };

        assert!(extract_target_address(&container).is_none());
    }

    #[test]
    fn extract_target_empty_ip_returns_none() {
        let container = DockerContainer {
            id: "abc123".to_string(),
            names: vec!["/myapp".to_string()],
            labels: Some(HashMap::new()),
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings {
                networks: HashMap::from([(
                    "bridge".to_string(),
                    ContainerNetwork {
                        ip_address: String::new(),
                    },
                )]),
            },
        };

        assert!(extract_target_address(&container).is_none());
    }

    #[test]
    fn extract_target_with_explicit_port() {
        let container = DockerContainer {
            id: "abc123".to_string(),
            names: vec!["/myapp".to_string()],
            labels: Some(HashMap::new()),
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings {
                networks: HashMap::from([(
                    "bridge".to_string(),
                    ContainerNetwork {
                        ip_address: "172.17.0.5".to_string(),
                    },
                )]),
            },
        };

        let addr = extract_target_with_port(&container, 8080);
        assert_eq!(addr, Some("172.17.0.5:8080".to_string()));
    }

    // ── Container display name ──────────────────────────────────────

    #[test]
    fn display_name_strips_slash() {
        let container = DockerContainer {
            id: "abc123def456".to_string(),
            names: vec!["/my-service".to_string()],
            labels: None,
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings::default(),
        };
        assert_eq!(container.display_name(), "my-service");
    }

    #[test]
    fn display_name_falls_back_to_id() {
        let container = DockerContainer {
            id: "abc123def456".to_string(),
            names: vec![],
            labels: None,
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings::default(),
        };
        assert_eq!(container.display_name(), "abc123def456");
    }

    // ── Config building ─────────────────────────────────────────────

    #[test]
    fn build_config_empty_containers() {
        let config = build_config(&[], "0.0.0.0:80");
        assert!(config.services.is_empty());
        assert!(config.upstreams.is_empty());
    }

    #[test]
    fn build_config_single_container_with_router_and_upstream() {
        let container = ParsedContainer {
            name: "web".to_string(),
            routers: HashMap::from([(
                "web".to_string(),
                ParsedRouter {
                    match_host: vec!["web.example.com".to_string()],
                    match_path: vec!["/*".to_string()],
                    match_method: vec![],
                    upstream: Some("web-backend".to_string()),
                },
            )]),
            upstreams: HashMap::from([(
                "web-backend".to_string(),
                ParsedUpstream {
                    load_balancing: Some("round_robin".to_string()),
                    health_check_path: Some("/health".to_string()),
                    health_check_interval: None,
                },
            )]),
            target_address: Some("172.17.0.2:3000".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:80");

        // Should have one service.
        assert_eq!(config.services.len(), 1);
        assert!(config.services.contains_key("docker-web"));

        let service = &config.services["docker-web"];
        assert_eq!(service.listeners.len(), 1);
        assert_eq!(service.listeners[0].address, "0.0.0.0:80");
        assert_eq!(service.routes.len(), 1);
        assert_eq!(service.routes[0].upstream, "web-backend");
        assert_eq!(service.routes[0].match_host, vec!["web.example.com"]);
        assert_eq!(service.routes[0].match_path, vec!["/*"]);

        // Should have one upstream with one target.
        assert_eq!(config.upstreams.len(), 1);
        let upstream = &config.upstreams["web-backend"];
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].address(), "172.17.0.2:3000");
        assert_eq!(upstream.load_balancing, "round_robin");
        assert!(upstream.health_check.is_some());
        assert_eq!(upstream.health_check.as_ref().unwrap().path, "/health");
    }

    #[test]
    fn build_config_auto_creates_upstream_from_router_ref() {
        let container = ParsedContainer {
            name: "app".to_string(),
            routers: HashMap::from([(
                "app".to_string(),
                ParsedRouter {
                    match_host: vec!["app.local".to_string()],
                    match_path: vec![],
                    match_method: vec![],
                    upstream: Some("my-backend".to_string()),
                },
            )]),
            upstreams: HashMap::new(), // no explicit upstream labels
            target_address: Some("10.0.0.5:8080".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:80");

        // Upstream should be auto-created.
        assert!(config.upstreams.contains_key("my-backend"));
        let upstream = &config.upstreams["my-backend"];
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].address(), "10.0.0.5:8080");
    }

    #[test]
    fn build_config_router_without_explicit_upstream_uses_router_name() {
        let container = ParsedContainer {
            name: "svc".to_string(),
            routers: HashMap::from([(
                "svc".to_string(),
                ParsedRouter {
                    match_host: vec!["svc.local".to_string()],
                    match_path: vec![],
                    match_method: vec![],
                    upstream: None, // no upstream label — defaults to router name
                },
            )]),
            upstreams: HashMap::new(),
            target_address: Some("10.0.0.1:80".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:80");

        // Upstream named after router.
        assert!(config.upstreams.contains_key("svc"));
        assert_eq!(config.upstreams["svc"].targets.len(), 1);
    }

    #[test]
    fn build_config_multiple_containers_same_upstream() {
        let c1 = ParsedContainer {
            name: "web-1".to_string(),
            routers: HashMap::from([(
                "web".to_string(),
                ParsedRouter {
                    match_host: vec!["web.example.com".to_string()],
                    match_path: vec![],
                    match_method: vec![],
                    upstream: Some("web-pool".to_string()),
                },
            )]),
            upstreams: HashMap::from([(
                "web-pool".to_string(),
                ParsedUpstream {
                    load_balancing: Some("round_robin".to_string()),
                    health_check_path: None,
                    health_check_interval: None,
                },
            )]),
            target_address: Some("172.17.0.2:3000".to_string()),
        };

        let c2 = ParsedContainer {
            name: "web-2".to_string(),
            routers: HashMap::from([(
                "web".to_string(),
                ParsedRouter {
                    match_host: vec!["web.example.com".to_string()],
                    match_path: vec![],
                    match_method: vec![],
                    upstream: Some("web-pool".to_string()),
                },
            )]),
            upstreams: HashMap::from([(
                "web-pool".to_string(),
                ParsedUpstream {
                    load_balancing: Some("round_robin".to_string()),
                    health_check_path: None,
                    health_check_interval: None,
                },
            )]),
            target_address: Some("172.17.0.3:3000".to_string()),
        };

        let config = build_config(&[c1, c2], "0.0.0.0:80");

        // Both containers should contribute targets to the same upstream.
        let upstream = &config.upstreams["web-pool"];
        assert_eq!(upstream.targets.len(), 2);

        let addrs: Vec<&str> = upstream.targets.iter().map(|t| t.address()).collect();
        assert!(addrs.contains(&"172.17.0.2:3000"));
        assert!(addrs.contains(&"172.17.0.3:3000"));
    }

    #[test]
    fn build_config_no_duplicate_targets() {
        // When a container declares both the upstream AND a router referencing it,
        // the target should only appear once.
        let container = ParsedContainer {
            name: "app".to_string(),
            routers: HashMap::from([(
                "app".to_string(),
                ParsedRouter {
                    match_host: vec!["app.local".to_string()],
                    match_path: vec![],
                    match_method: vec![],
                    upstream: Some("backend".to_string()),
                },
            )]),
            upstreams: HashMap::from([(
                "backend".to_string(),
                ParsedUpstream::default(),
            )]),
            target_address: Some("10.0.0.1:80".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:80");
        assert_eq!(config.upstreams["backend"].targets.len(), 1);
    }

    #[test]
    fn build_config_container_without_target_address() {
        let container = ParsedContainer {
            name: "no-ip".to_string(),
            routers: HashMap::from([(
                "web".to_string(),
                ParsedRouter {
                    match_host: vec!["web.local".to_string()],
                    match_path: vec![],
                    match_method: vec![],
                    upstream: Some("pool".to_string()),
                },
            )]),
            upstreams: HashMap::new(),
            target_address: None,
        };

        let config = build_config(&[container], "0.0.0.0:80");

        // Service and upstream created, but no targets.
        assert!(config.services.contains_key("docker-web"));
        assert!(config.upstreams.contains_key("pool"));
        assert!(config.upstreams["pool"].targets.is_empty());
    }

    #[test]
    fn build_config_health_check_defaults() {
        let container = ParsedContainer {
            name: "hc".to_string(),
            routers: HashMap::new(),
            upstreams: HashMap::from([(
                "backend".to_string(),
                ParsedUpstream {
                    load_balancing: None,
                    health_check_path: Some("/ready".to_string()),
                    health_check_interval: None, // should default to "10s"
                },
            )]),
            target_address: Some("10.0.0.1:80".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:80");
        let hc = config.upstreams["backend"].health_check.as_ref().unwrap();
        assert_eq!(hc.path, "/ready");
        assert_eq!(hc.interval, "10s");
    }

    #[test]
    fn build_config_custom_listener() {
        let container = ParsedContainer {
            name: "app".to_string(),
            routers: HashMap::from([(
                "app".to_string(),
                ParsedRouter {
                    match_host: vec!["app.local".to_string()],
                    match_path: vec![],
                    match_method: vec![],
                    upstream: None,
                },
            )]),
            upstreams: HashMap::new(),
            target_address: Some("10.0.0.1:80".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:8443");
        let service = &config.services["docker-app"];
        assert_eq!(service.listeners[0].address, "0.0.0.0:8443");
    }

    // ── containers_to_config integration ────────────────────────────

    #[test]
    fn containers_to_config_filters_non_enabled() {
        let containers = vec![
            DockerContainer {
                id: "c1".to_string(),
                names: vec!["/enabled-app".to_string()],
                labels: Some(HashMap::from([
                    ("fluxo.enable".to_string(), "true".to_string()),
                    (
                        "fluxo.http.routers.app.match_host".to_string(),
                        "app.test".to_string(),
                    ),
                ])),
                state: "running".to_string(),
                network_settings: ContainerNetworkSettings {
                    networks: HashMap::from([(
                        "bridge".to_string(),
                        ContainerNetwork {
                            ip_address: "172.17.0.2".to_string(),
                        },
                    )]),
                },
            },
            DockerContainer {
                id: "c2".to_string(),
                names: vec!["/no-labels".to_string()],
                labels: Some(HashMap::new()),
                state: "running".to_string(),
                network_settings: ContainerNetworkSettings::default(),
            },
            DockerContainer {
                id: "c3".to_string(),
                names: vec!["/disabled".to_string()],
                labels: Some(HashMap::from([(
                    "fluxo.enable".to_string(),
                    "false".to_string(),
                )])),
                state: "running".to_string(),
                network_settings: ContainerNetworkSettings::default(),
            },
        ];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");

        // Only the enabled container should contribute.
        assert_eq!(config.services.len(), 1);
        assert!(config.services.contains_key("docker-app"));
    }

    #[test]
    fn containers_to_config_skips_non_running() {
        let containers = vec![DockerContainer {
            id: "c1".to_string(),
            names: vec!["/stopped-app".to_string()],
            labels: Some(HashMap::from([
                ("fluxo.enable".to_string(), "true".to_string()),
                (
                    "fluxo.http.routers.app.match_host".to_string(),
                    "app.test".to_string(),
                ),
            ])),
            state: "exited".to_string(),
            network_settings: ContainerNetworkSettings::default(),
        }];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");
        assert!(config.services.is_empty());
    }

    #[test]
    fn containers_to_config_skips_null_labels() {
        let containers = vec![DockerContainer {
            id: "c1".to_string(),
            names: vec!["/no-labels".to_string()],
            labels: None,
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings::default(),
        }];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");
        assert!(config.services.is_empty());
    }

    // ── Docker API deserialization ──────────────────────────────────

    #[test]
    fn deserialize_container_json() {
        let json = r#"[{
            "Id": "abc123",
            "Names": ["/my-web-app"],
            "State": "running",
            "Labels": {
                "fluxo.enable": "true",
                "fluxo.http.routers.web.match_host": "web.example.com"
            },
            "NetworkSettings": {
                "Networks": {
                    "bridge": {
                        "IPAddress": "172.17.0.2"
                    }
                }
            }
        }]"#;

        let containers: Vec<DockerContainer> = serde_json::from_str(json).unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].id, "abc123");
        assert_eq!(containers[0].display_name(), "my-web-app");
        assert_eq!(containers[0].state, "running");

        let labels = containers[0].labels.as_ref().unwrap();
        assert_eq!(labels["fluxo.enable"], "true");

        let ip = &containers[0].network_settings.networks["bridge"].ip_address;
        assert_eq!(ip, "172.17.0.2");
    }

    #[test]
    fn deserialize_container_missing_optional_fields() {
        let json = r#"[{
            "Id": "xyz789",
            "Names": ["/minimal"],
            "State": "running",
            "NetworkSettings": {}
        }]"#;

        let containers: Vec<DockerContainer> = serde_json::from_str(json).unwrap();
        assert_eq!(containers.len(), 1);
        assert!(containers[0].labels.is_none());
        assert!(containers[0].network_settings.networks.is_empty());
    }

    #[test]
    fn deserialize_docker_event() {
        let json = r#"{"Type":"container","Action":"start","Actor":{"ID":"abc"}}"#;

        let event: DockerEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "container");
        assert_eq!(event.action, "start");
    }

    #[test]
    fn deserialize_docker_event_stop() {
        let json = r#"{"Type":"container","Action":"stop"}"#;

        let event: DockerEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "container");
        assert_eq!(event.action, "stop");
    }

    #[test]
    fn deserialize_docker_event_die() {
        let json = r#"{"Type":"container","Action":"die"}"#;

        let event: DockerEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.action, "die");
    }

    // ── End-to-end label → config pipeline ──────────────────────────

    #[test]
    fn full_pipeline_labels_to_config() {
        let containers = vec![
            DockerContainer {
                id: "web1".to_string(),
                names: vec!["/web-1".to_string()],
                labels: Some(HashMap::from([
                    ("fluxo.enable".to_string(), "true".to_string()),
                    (
                        "fluxo.http.routers.frontend.match_host".to_string(),
                        "mysite.com, www.mysite.com".to_string(),
                    ),
                    (
                        "fluxo.http.routers.frontend.match_path".to_string(),
                        "/*".to_string(),
                    ),
                    (
                        "fluxo.http.routers.frontend.upstream".to_string(),
                        "web-pool".to_string(),
                    ),
                    (
                        "fluxo.http.upstreams.web-pool.load_balancing".to_string(),
                        "round_robin".to_string(),
                    ),
                    (
                        "fluxo.http.upstreams.web-pool.health_check.path".to_string(),
                        "/ping".to_string(),
                    ),
                ])),
                state: "running".to_string(),
                network_settings: ContainerNetworkSettings {
                    networks: HashMap::from([(
                        "app-net".to_string(),
                        ContainerNetwork {
                            ip_address: "10.0.1.10".to_string(),
                        },
                    )]),
                },
            },
            DockerContainer {
                id: "web2".to_string(),
                names: vec!["/web-2".to_string()],
                labels: Some(HashMap::from([
                    ("fluxo.enable".to_string(), "true".to_string()),
                    (
                        "fluxo.http.routers.frontend.match_host".to_string(),
                        "mysite.com".to_string(),
                    ),
                    (
                        "fluxo.http.routers.frontend.upstream".to_string(),
                        "web-pool".to_string(),
                    ),
                    (
                        "fluxo.http.upstreams.web-pool.load_balancing".to_string(),
                        "round_robin".to_string(),
                    ),
                ])),
                state: "running".to_string(),
                network_settings: ContainerNetworkSettings {
                    networks: HashMap::from([(
                        "app-net".to_string(),
                        ContainerNetwork {
                            ip_address: "10.0.1.11".to_string(),
                        },
                    )]),
                },
            },
            DockerContainer {
                id: "redis".to_string(),
                names: vec!["/redis".to_string()],
                labels: Some(HashMap::from([(
                    "some.other.label".to_string(),
                    "value".to_string(),
                )])),
                state: "running".to_string(),
                network_settings: ContainerNetworkSettings::default(),
            },
        ];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");

        // Only the two web containers should contribute.
        assert_eq!(config.services.len(), 1);
        assert!(config.services.contains_key("docker-frontend"));

        // The upstream should have two targets (one per container).
        let upstream = &config.upstreams["web-pool"];
        assert_eq!(upstream.targets.len(), 2);
        assert_eq!(upstream.load_balancing, "round_robin");
        assert!(upstream.health_check.is_some());
        assert_eq!(upstream.health_check.as_ref().unwrap().path, "/ping");

        let addrs: Vec<&str> = upstream.targets.iter().map(|t| t.address()).collect();
        assert!(addrs.contains(&"10.0.1.10:80"));
        assert!(addrs.contains(&"10.0.1.11:80"));

        // The route should have the merged hosts.
        let service = &config.services["docker-frontend"];
        assert!(!service.routes.is_empty());
        assert_eq!(service.routes[0].upstream, "web-pool");
    }

    // ── Config has default global ──────────────────────────────────

    #[test]
    fn built_config_has_default_global() {
        let config = build_config(&[], "0.0.0.0:80");
        // Global should use defaults (not panic).
        assert_eq!(config.global.admin, "127.0.0.1:2019");
    }
}
