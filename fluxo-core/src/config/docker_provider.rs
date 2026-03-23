//! Docker container discovery config provider — simplified label-based routing.
//!
//! Connects to the Docker Engine API over HTTP (TCP endpoint), discovers containers
//! with `{prefix}.*` labels, and builds a [`FluxoConfig`] from those labels. Optionally
//! watches Docker events for container start/stop/die to automatically rebuild config,
//! falling back to polling when events are unavailable.
//!
//! # Label format (simplified)
//!
//! Containers opt in with `{prefix}.enable=true`, then declare routing via flat labels:
//!
//! ```text
//! fluxo.enable=true
//! fluxo.host=myapp.example.com
//! fluxo.path=/api/*
//! fluxo.port=8080
//! fluxo.upstream=my-backend
//! fluxo.service=my-service
//! ```
//!
//! - `{prefix}.enable` — required, must be `"true"` (case-insensitive)
//! - `{prefix}.host` — host match (comma-separated for multiple)
//! - `{prefix}.path` — path match (default: `"/*"`)
//! - `{prefix}.port` — container port (auto-detect from exposed ports if missing)
//! - `{prefix}.upstream` — upstream name (default: container name)
//! - `{prefix}.service` — service name (default: container name)
//!
//! Container IP + port are automatically added as upstream targets.
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
    DockerProviderConfig, FluxoConfig, GlobalConfig, ListenerConfig, RouteConfig, ServiceConfig,
    TargetConfig, UpstreamConfig,
};

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

    /// Exposed/published ports.
    #[serde(default)]
    ports: Vec<DockerPort>,
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

/// A port mapping from the Docker API.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerPort {
    /// Private (container) port.
    #[serde(default)]
    private_port: u16,

    /// Protocol (tcp/udp).
    #[serde(default, rename = "Type")]
    protocol: String,
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

/// Parsed configuration for a single container from simplified labels.
#[derive(Debug, Clone)]
struct ParsedContainer {
    /// Container display name (for logging).
    name: String,

    /// Host patterns to match (from `{prefix}.host`).
    hosts: Vec<String>,

    /// Path patterns to match (from `{prefix}.path`, default `"/*"`).
    paths: Vec<String>,

    /// Explicit port from `{prefix}.port` label.
    port: Option<u16>,

    /// Upstream name (from `{prefix}.upstream`, default: container name).
    upstream_name: String,

    /// Service name (from `{prefix}.service`, default: container name).
    service_name: String,

    /// Auto-discovered target address (container IP:port).
    target_address: Option<String>,
}

/// Parse simplified labels from a single container.
///
/// Label format:
/// - `{prefix}.enable` = "true" (required, case-insensitive)
/// - `{prefix}.host` = "example.com" or "a.com, b.com"
/// - `{prefix}.path` = "/api/*" (default: "/*")
/// - `{prefix}.port` = "8080"
/// - `{prefix}.upstream` = "my-backend" (default: container name)
/// - `{prefix}.service` = "my-service" (default: container name)
fn parse_container_labels(
    labels: &HashMap<String, String>,
    prefix: &str,
    container_name: &str,
) -> Option<ParsedContainer> {
    // Must have `{prefix}.enable=true`.
    let enable_key = format!("{prefix}.enable");
    match labels.get(&enable_key) {
        Some(v) if v.eq_ignore_ascii_case("true") => {}
        _ => return None,
    }

    // Parse host(s).
    let host_key = format!("{prefix}.host");
    let hosts: Vec<String> = labels
        .get(&host_key)
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    // Parse path(s) — default to "/*".
    let path_key = format!("{prefix}.path");
    let paths: Vec<String> = labels
        .get(&path_key)
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| vec!["/*".to_string()]);

    // Parse explicit port.
    let port_key = format!("{prefix}.port");
    let port: Option<u16> = labels.get(&port_key).and_then(|v| {
        v.trim().parse::<u16>().ok().or_else(|| {
            warn!(
                container = container_name,
                value = v,
                "invalid port label — ignoring"
            );
            None
        })
    });

    // Upstream name — default to container name.
    let upstream_key = format!("{prefix}.upstream");
    let upstream_name = labels
        .get(&upstream_key)
        .cloned()
        .unwrap_or_else(|| container_name.to_string());

    // Service name — default to container name.
    let service_key = format!("{prefix}.service");
    let service_name = labels
        .get(&service_key)
        .cloned()
        .unwrap_or_else(|| container_name.to_string());

    Some(ParsedContainer {
        name: container_name.to_string(),
        hosts,
        paths,
        port,
        upstream_name,
        service_name,
        target_address: None, // filled in by caller
    })
}

/// Extract the best target address from a Docker container.
///
/// Priority:
/// 1. Container IP + explicit port from labels
/// 2. Container IP + first exposed TCP port from Docker API
/// 3. Container IP + port 80 as fallback
/// 4. `None` if no usable IP is found
fn extract_target_address(container: &DockerContainer, explicit_port: Option<u16>) -> Option<String> {
    // Find the container IP from the first available network.
    let ip = container
        .network_settings
        .networks
        .values()
        .find(|n| !n.ip_address.is_empty())
        .map(|n| &n.ip_address)?;

    // Determine port: explicit label > first exposed TCP port > 80.
    let port = explicit_port.unwrap_or_else(|| {
        container
            .ports
            .iter()
            .find(|p| p.protocol == "tcp" && p.private_port > 0)
            .map(|p| p.private_port)
            .unwrap_or(80)
    });

    Some(format!("{ip}:{port}"))
}

// ── Config building ─────────────────────────────────────────────────────────

/// Build a `FluxoConfig` from a set of parsed containers.
fn build_config(containers: &[ParsedContainer], default_listener: &str) -> FluxoConfig {
    let mut services: HashMap<String, ServiceConfig> = HashMap::new();
    let mut upstreams: HashMap<String, UpstreamConfig> = HashMap::new();

    for container in containers {
        // Ensure the upstream exists and add this container as a target.
        let upstream = upstreams
            .entry(container.upstream_name.clone())
            .or_insert_with(UpstreamConfig::default);

        if let Some(ref addr) = container.target_address {
            let already_has = upstream.targets.iter().any(|t| t.address() == addr);
            if !already_has {
                upstream.targets.push(TargetConfig::Simple(addr.clone()));
            }
        }

        // Build the route.
        let route = RouteConfig {
            name: Some(format!("docker-{}", container.name)),
            match_host: container.hosts.clone(),
            match_path: container.paths.clone(),
            upstream: container.upstream_name.clone(),
            ..Default::default()
        };

        // Group routes into a per-service service.
        let service = services
            .entry(container.service_name.clone())
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
/// Converts `tcp://host:port` -> `http://host:port`.
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

        let display = container.display_name().to_string();

        let mut pc = match parse_container_labels(labels, prefix, &display) {
            Some(pc) => pc,
            None => continue,
        };

        pc.target_address = extract_target_address(container, pc.port);

        debug!(
            container = %pc.name,
            hosts = ?pc.hosts,
            paths = ?pc.paths,
            upstream = %pc.upstream_name,
            service = %pc.service_name,
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
/// Connects to the Docker Engine API, discovers containers with `{prefix}.*`
/// labels, and pushes config updates when containers start or stop.
pub struct DockerProvider {
    config: super::DockerProviderConfig,
    client: reqwest::Client,
}

impl DockerProvider {
    /// Create a new Docker provider from the TOML-level `DockerProviderConfig`.
    pub fn new(config: super::DockerProviderConfig) -> Self {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.tls_skip_verify)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { config, client }
    }

    /// Resolve the poll interval from the string config field.
    fn poll_interval(&self) -> Duration {
        super::parse_duration(&self.config.poll_interval)
            .unwrap_or_else(|_| Duration::from_secs(5))
    }

    /// Discover containers and build a `FluxoConfig`.
    async fn discover(
        &self,
        base_url: &str,
    ) -> Result<FluxoConfig, Box<dyn std::error::Error + Send + Sync>> {
        let containers = fetch_containers(&self.client, base_url).await?;
        Ok(containers_to_config(
            containers,
            &self.config.label_prefix,
            &self.config.default_listener,
        ))
    }

    /// Poll for container changes at a fixed interval.
    async fn poll_loop(
        &self,
        base_url: &str,
        tx: &mpsc::Sender<(String, FluxoConfig)>,
    ) {
        let interval = self.poll_interval();
        loop {
            tokio::time::sleep(interval).await;

            match self.discover(base_url).await {
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

        // The event stream is long-lived — build a client without request timeout.
        let stream_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.config.tls_skip_verify)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        // Try to connect to the event stream. If it fails, fall back to polling.
        let mut resp = match stream_client.get(&events_url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!(
                    status = %r.status(),
                    "Docker event stream returned non-success — falling back to polling"
                );
                self.poll_loop(base_url, tx).await;
                return;
            }
            Err(e) => {
                warn!(error = %e, "failed to connect to Docker event stream — falling back to polling");
                self.poll_loop(base_url, tx).await;
                return;
            }
        };

        info!("connected to Docker event stream");

        // Read the event stream as newline-delimited JSON using reqwest's chunk API.
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
                                match self.discover(base_url).await {
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
                    self.poll_loop(base_url, tx).await;
                    return;
                }
                Err(e) => {
                    warn!(error = %e, "Docker event stream error — falling back to polling");
                    self.poll_loop(base_url, tx).await;
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
        let poll_interval = self.poll_interval();

        info!(
            endpoint = %base_url,
            poll_interval = ?poll_interval,
            label_prefix = %self.config.label_prefix,
            watch_events = self.config.watch_events,
            "starting Docker provider"
        );

        // Initial discovery.
        match self.discover(&base_url).await {
            Ok(config) => {
                if tx.send((self.name().to_string(), config)).await.is_err() {
                    return Ok(());
                }
            }
            Err(e) => {
                error!(error = %e, "initial Docker discovery failed — will retry via poll/events");
            }
        }

        if self.config.watch_events {
            self.watch_events_loop(&base_url, &tx).await;
        } else {
            self.poll_loop(&base_url, &tx).await;
        }

        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // ── Helper: build a DockerProviderConfig for tests ────────────────

    fn test_docker_config() -> super::super::DockerProviderConfig {
        super::super::DockerProviderConfig {
            endpoint: "tcp://localhost:2375".to_string(),
            label_prefix: "fluxo".to_string(),
            poll_interval: "5s".to_string(),
            watch_events: true,
            default_listener: "0.0.0.0:80".to_string(),
            tls_skip_verify: false,
        }
    }

    // ── Provider name ───────────────────────────────────────────────

    #[test]
    fn provider_name_is_docker() {
        let provider = DockerProvider::new(test_docker_config());
        assert_eq!(provider.name(), "docker");
    }

    // ── Poll interval parsing ───────────────────────────────────────

    #[test]
    fn poll_interval_parses_correctly() {
        let mut cfg = test_docker_config();
        cfg.poll_interval = "10s".to_string();
        let provider = DockerProvider::new(cfg);
        assert_eq!(provider.poll_interval(), Duration::from_secs(10));
    }

    #[test]
    fn poll_interval_invalid_falls_back_to_5s() {
        let mut cfg = test_docker_config();
        cfg.poll_interval = "garbage".to_string();
        let provider = DockerProvider::new(cfg);
        assert_eq!(provider.poll_interval(), Duration::from_secs(5));
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
        let labels = HashMap::from([("fluxo.host".to_string(), "example.com".to_string())]);
        assert!(parse_container_labels(&labels, "fluxo", "myapp").is_none());
    }

    #[test]
    fn parse_labels_enable_false_returns_none() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "false".to_string()),
            ("fluxo.host".to_string(), "example.com".to_string()),
        ]);
        assert!(parse_container_labels(&labels, "fluxo", "myapp").is_none());
    }

    #[test]
    fn parse_labels_enable_case_insensitive() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "TRUE".to_string()),
            ("fluxo.host".to_string(), "example.com".to_string()),
        ]);
        let parsed = parse_container_labels(&labels, "fluxo", "myapp");
        assert!(parsed.is_some());
    }

    #[test]
    fn parse_labels_enable_mixed_case() {
        let labels = HashMap::from([("fluxo.enable".to_string(), "True".to_string())]);
        assert!(parse_container_labels(&labels, "fluxo", "myapp").is_some());
    }

    #[test]
    fn parse_labels_basic_host() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            ("fluxo.host".to_string(), "example.com".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.hosts, vec!["example.com"]);
    }

    #[test]
    fn parse_labels_multiple_hosts_comma_separated() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            (
                "fluxo.host".to_string(),
                "example.com, www.example.com".to_string(),
            ),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.hosts, vec!["example.com", "www.example.com"]);
    }

    #[test]
    fn parse_labels_path_default() {
        let labels = HashMap::from([("fluxo.enable".to_string(), "true".to_string())]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.paths, vec!["/*"]);
    }

    #[test]
    fn parse_labels_explicit_path() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            ("fluxo.path".to_string(), "/api/*".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.paths, vec!["/api/*"]);
    }

    #[test]
    fn parse_labels_multiple_paths_comma_separated() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            ("fluxo.path".to_string(), "/api/*, /health".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.paths, vec!["/api/*", "/health"]);
    }

    #[test]
    fn parse_labels_explicit_port() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            ("fluxo.port".to_string(), "8080".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.port, Some(8080));
    }

    #[test]
    fn parse_labels_invalid_port_returns_none() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            ("fluxo.port".to_string(), "not-a-number".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert!(parsed.port.is_none());
    }

    #[test]
    fn parse_labels_no_port_returns_none() {
        let labels = HashMap::from([("fluxo.enable".to_string(), "true".to_string())]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert!(parsed.port.is_none());
    }

    #[test]
    fn parse_labels_explicit_upstream() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            ("fluxo.upstream".to_string(), "my-backend".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.upstream_name, "my-backend");
    }

    #[test]
    fn parse_labels_upstream_defaults_to_container_name() {
        let labels = HashMap::from([("fluxo.enable".to_string(), "true".to_string())]);

        let parsed = parse_container_labels(&labels, "fluxo", "web-server").unwrap();
        assert_eq!(parsed.upstream_name, "web-server");
    }

    #[test]
    fn parse_labels_explicit_service() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            ("fluxo.service".to_string(), "my-service".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.service_name, "my-service");
    }

    #[test]
    fn parse_labels_service_defaults_to_container_name() {
        let labels = HashMap::from([("fluxo.enable".to_string(), "true".to_string())]);

        let parsed = parse_container_labels(&labels, "fluxo", "web-server").unwrap();
        assert_eq!(parsed.service_name, "web-server");
    }

    #[test]
    fn parse_labels_custom_prefix() {
        let labels = HashMap::from([
            ("myproxy.enable".to_string(), "true".to_string()),
            ("myproxy.host".to_string(), "app.test".to_string()),
            ("myproxy.port".to_string(), "3000".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "myproxy", "app").unwrap();
        assert_eq!(parsed.hosts, vec!["app.test"]);
        assert_eq!(parsed.port, Some(3000));
    }

    #[test]
    fn parse_labels_wrong_prefix_returns_none() {
        let labels = HashMap::from([
            ("traefik.enable".to_string(), "true".to_string()),
            ("traefik.host".to_string(), "app.test".to_string()),
        ]);

        assert!(parse_container_labels(&labels, "fluxo", "app").is_none());
    }

    #[test]
    fn parse_labels_enable_only_minimal() {
        let labels = HashMap::from([("fluxo.enable".to_string(), "true".to_string())]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert!(parsed.hosts.is_empty());
        assert_eq!(parsed.paths, vec!["/*"]);
        assert!(parsed.port.is_none());
        assert_eq!(parsed.upstream_name, "myapp");
        assert_eq!(parsed.service_name, "myapp");
    }

    #[test]
    fn parse_labels_full_config() {
        let labels = HashMap::from([
            ("fluxo.enable".to_string(), "true".to_string()),
            (
                "fluxo.host".to_string(),
                "example.com, www.example.com".to_string(),
            ),
            ("fluxo.path".to_string(), "/api/*".to_string()),
            ("fluxo.port".to_string(), "8080".to_string()),
            ("fluxo.upstream".to_string(), "api-backend".to_string()),
            ("fluxo.service".to_string(), "api-service".to_string()),
        ]);

        let parsed = parse_container_labels(&labels, "fluxo", "myapp").unwrap();
        assert_eq!(parsed.hosts, vec!["example.com", "www.example.com"]);
        assert_eq!(parsed.paths, vec!["/api/*"]);
        assert_eq!(parsed.port, Some(8080));
        assert_eq!(parsed.upstream_name, "api-backend");
        assert_eq!(parsed.service_name, "api-service");
    }

    // ── Target address extraction ───────────────────────────────────

    fn make_container_with_network(ip: &str) -> DockerContainer {
        DockerContainer {
            id: "abc123".to_string(),
            names: vec!["/myapp".to_string()],
            labels: Some(HashMap::new()),
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings {
                networks: HashMap::from([(
                    "bridge".to_string(),
                    ContainerNetwork {
                        ip_address: ip.to_string(),
                    },
                )]),
            },
            ports: vec![],
        }
    }

    #[test]
    fn extract_target_explicit_port() {
        let container = make_container_with_network("172.17.0.2");
        let addr = extract_target_address(&container, Some(8080));
        assert_eq!(addr, Some("172.17.0.2:8080".to_string()));
    }

    #[test]
    fn extract_target_from_exposed_port() {
        let mut container = make_container_with_network("172.17.0.2");
        container.ports = vec![DockerPort {
            private_port: 3000,
            protocol: "tcp".to_string(),
        }];
        let addr = extract_target_address(&container, None);
        assert_eq!(addr, Some("172.17.0.2:3000".to_string()));
    }

    #[test]
    fn extract_target_skips_udp_ports() {
        let mut container = make_container_with_network("172.17.0.2");
        container.ports = vec![
            DockerPort {
                private_port: 53,
                protocol: "udp".to_string(),
            },
            DockerPort {
                private_port: 8080,
                protocol: "tcp".to_string(),
            },
        ];
        let addr = extract_target_address(&container, None);
        assert_eq!(addr, Some("172.17.0.2:8080".to_string()));
    }

    #[test]
    fn extract_target_falls_back_to_port_80() {
        let container = make_container_with_network("172.17.0.2");
        let addr = extract_target_address(&container, None);
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
            ports: vec![],
        };

        assert!(extract_target_address(&container, None).is_none());
    }

    #[test]
    fn extract_target_empty_ip_returns_none() {
        let container = make_container_with_network("");
        assert!(extract_target_address(&container, None).is_none());
    }

    #[test]
    fn extract_target_explicit_port_overrides_exposed() {
        let mut container = make_container_with_network("172.17.0.5");
        container.ports = vec![DockerPort {
            private_port: 3000,
            protocol: "tcp".to_string(),
        }];
        // Explicit port should win over exposed port.
        let addr = extract_target_address(&container, Some(9090));
        assert_eq!(addr, Some("172.17.0.5:9090".to_string()));
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
            ports: vec![],
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
            ports: vec![],
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
    fn build_config_single_container() {
        let container = ParsedContainer {
            name: "web".to_string(),
            hosts: vec!["web.example.com".to_string()],
            paths: vec!["/*".to_string()],
            port: Some(3000),
            upstream_name: "web-backend".to_string(),
            service_name: "web-service".to_string(),
            target_address: Some("172.17.0.2:3000".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:80");

        // Should have one service.
        assert_eq!(config.services.len(), 1);
        assert!(config.services.contains_key("web-service"));

        let service = &config.services["web-service"];
        assert_eq!(service.listeners.len(), 1);
        assert_eq!(service.listeners[0].address, "0.0.0.0:80");
        assert_eq!(service.routes.len(), 1);
        assert_eq!(service.routes[0].upstream, "web-backend");
        assert_eq!(service.routes[0].match_host, vec!["web.example.com"]);
        assert_eq!(service.routes[0].match_path, vec!["/*"]);
        assert_eq!(service.routes[0].name, Some("docker-web".to_string()));

        // Should have one upstream with one target.
        assert_eq!(config.upstreams.len(), 1);
        let upstream = &config.upstreams["web-backend"];
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].address(), "172.17.0.2:3000");
    }

    #[test]
    fn build_config_multiple_containers_same_upstream() {
        let c1 = ParsedContainer {
            name: "web-1".to_string(),
            hosts: vec!["web.example.com".to_string()],
            paths: vec!["/*".to_string()],
            port: Some(3000),
            upstream_name: "web-pool".to_string(),
            service_name: "web".to_string(),
            target_address: Some("172.17.0.2:3000".to_string()),
        };

        let c2 = ParsedContainer {
            name: "web-2".to_string(),
            hosts: vec!["web.example.com".to_string()],
            paths: vec!["/*".to_string()],
            port: Some(3000),
            upstream_name: "web-pool".to_string(),
            service_name: "web".to_string(),
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
        let c1 = ParsedContainer {
            name: "web-1".to_string(),
            hosts: vec!["web.local".to_string()],
            paths: vec!["/*".to_string()],
            port: None,
            upstream_name: "pool".to_string(),
            service_name: "web".to_string(),
            target_address: Some("10.0.0.1:80".to_string()),
        };

        let c2 = ParsedContainer {
            name: "web-2".to_string(),
            hosts: vec!["web.local".to_string()],
            paths: vec!["/*".to_string()],
            port: None,
            upstream_name: "pool".to_string(),
            service_name: "web".to_string(),
            // Same address as c1 — should not duplicate.
            target_address: Some("10.0.0.1:80".to_string()),
        };

        let config = build_config(&[c1, c2], "0.0.0.0:80");
        assert_eq!(config.upstreams["pool"].targets.len(), 1);
    }

    #[test]
    fn build_config_container_without_target_address() {
        let container = ParsedContainer {
            name: "no-ip".to_string(),
            hosts: vec!["web.local".to_string()],
            paths: vec!["/*".to_string()],
            port: None,
            upstream_name: "pool".to_string(),
            service_name: "web".to_string(),
            target_address: None,
        };

        let config = build_config(&[container], "0.0.0.0:80");

        // Service and upstream created, but no targets.
        assert!(config.services.contains_key("web"));
        assert!(config.upstreams.contains_key("pool"));
        assert!(config.upstreams["pool"].targets.is_empty());
    }

    #[test]
    fn build_config_custom_listener() {
        let container = ParsedContainer {
            name: "app".to_string(),
            hosts: vec!["app.local".to_string()],
            paths: vec!["/*".to_string()],
            port: None,
            upstream_name: "app".to_string(),
            service_name: "app".to_string(),
            target_address: Some("10.0.0.1:80".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:8443");
        let service = &config.services["app"];
        assert_eq!(service.listeners[0].address, "0.0.0.0:8443");
    }

    #[test]
    fn build_config_different_services_same_upstream() {
        let c1 = ParsedContainer {
            name: "api".to_string(),
            hosts: vec!["api.example.com".to_string()],
            paths: vec!["/v1/*".to_string()],
            port: Some(3000),
            upstream_name: "shared-pool".to_string(),
            service_name: "api-service".to_string(),
            target_address: Some("172.17.0.2:3000".to_string()),
        };

        let c2 = ParsedContainer {
            name: "web".to_string(),
            hosts: vec!["www.example.com".to_string()],
            paths: vec!["/*".to_string()],
            port: Some(3000),
            upstream_name: "shared-pool".to_string(),
            service_name: "web-service".to_string(),
            target_address: Some("172.17.0.3:3000".to_string()),
        };

        let config = build_config(&[c1, c2], "0.0.0.0:80");

        // Two separate services.
        assert_eq!(config.services.len(), 2);
        assert!(config.services.contains_key("api-service"));
        assert!(config.services.contains_key("web-service"));

        // But one shared upstream with both targets.
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams["shared-pool"].targets.len(), 2);
    }

    #[test]
    fn build_config_route_name_includes_container() {
        let container = ParsedContainer {
            name: "my-app".to_string(),
            hosts: vec!["app.local".to_string()],
            paths: vec!["/*".to_string()],
            port: None,
            upstream_name: "my-app".to_string(),
            service_name: "my-app".to_string(),
            target_address: Some("10.0.0.1:80".to_string()),
        };

        let config = build_config(&[container], "0.0.0.0:80");
        let route = &config.services["my-app"].routes[0];
        assert_eq!(route.name, Some("docker-my-app".to_string()));
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
                    ("fluxo.host".to_string(), "app.test".to_string()),
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
                ports: vec![],
            },
            DockerContainer {
                id: "c2".to_string(),
                names: vec!["/no-labels".to_string()],
                labels: Some(HashMap::new()),
                state: "running".to_string(),
                network_settings: ContainerNetworkSettings::default(),
                ports: vec![],
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
                ports: vec![],
            },
        ];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");

        // Only the enabled container should contribute.
        assert_eq!(config.services.len(), 1);
        assert!(config.services.contains_key("enabled-app"));
    }

    #[test]
    fn containers_to_config_skips_non_running() {
        let containers = vec![DockerContainer {
            id: "c1".to_string(),
            names: vec!["/stopped-app".to_string()],
            labels: Some(HashMap::from([
                ("fluxo.enable".to_string(), "true".to_string()),
                ("fluxo.host".to_string(), "app.test".to_string()),
            ])),
            state: "exited".to_string(),
            network_settings: ContainerNetworkSettings::default(),
            ports: vec![],
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
            ports: vec![],
        }];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");
        assert!(config.services.is_empty());
    }

    #[test]
    fn containers_to_config_uses_explicit_port() {
        let containers = vec![DockerContainer {
            id: "c1".to_string(),
            names: vec!["/web".to_string()],
            labels: Some(HashMap::from([
                ("fluxo.enable".to_string(), "true".to_string()),
                ("fluxo.host".to_string(), "web.test".to_string()),
                ("fluxo.port".to_string(), "8080".to_string()),
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
            ports: vec![DockerPort {
                private_port: 3000,
                protocol: "tcp".to_string(),
            }],
        }];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");
        let upstream = &config.upstreams["web"];
        // Should use explicit port 8080, not exposed port 3000.
        assert_eq!(upstream.targets[0].address(), "172.17.0.2:8080");
    }

    #[test]
    fn containers_to_config_uses_exposed_port_when_no_label() {
        let containers = vec![DockerContainer {
            id: "c1".to_string(),
            names: vec!["/web".to_string()],
            labels: Some(HashMap::from([
                ("fluxo.enable".to_string(), "true".to_string()),
                ("fluxo.host".to_string(), "web.test".to_string()),
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
            ports: vec![DockerPort {
                private_port: 3000,
                protocol: "tcp".to_string(),
            }],
        }];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");
        let upstream = &config.upstreams["web"];
        assert_eq!(upstream.targets[0].address(), "172.17.0.2:3000");
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
                "fluxo.host": "web.example.com"
            },
            "NetworkSettings": {
                "Networks": {
                    "bridge": {
                        "IPAddress": "172.17.0.2"
                    }
                }
            },
            "Ports": [
                {"PrivatePort": 8080, "Type": "tcp"}
            ]
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

        assert_eq!(containers[0].ports.len(), 1);
        assert_eq!(containers[0].ports[0].private_port, 8080);
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
        assert!(containers[0].ports.is_empty());
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

    // ── End-to-end label -> config pipeline ──────────────────────────

    #[test]
    fn full_pipeline_labels_to_config() {
        let containers = vec![
            DockerContainer {
                id: "web1".to_string(),
                names: vec!["/web-1".to_string()],
                labels: Some(HashMap::from([
                    ("fluxo.enable".to_string(), "true".to_string()),
                    (
                        "fluxo.host".to_string(),
                        "mysite.com, www.mysite.com".to_string(),
                    ),
                    ("fluxo.path".to_string(), "/*".to_string()),
                    ("fluxo.port".to_string(), "3000".to_string()),
                    ("fluxo.upstream".to_string(), "web-pool".to_string()),
                    ("fluxo.service".to_string(), "frontend".to_string()),
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
                ports: vec![],
            },
            DockerContainer {
                id: "web2".to_string(),
                names: vec!["/web-2".to_string()],
                labels: Some(HashMap::from([
                    ("fluxo.enable".to_string(), "true".to_string()),
                    ("fluxo.host".to_string(), "mysite.com".to_string()),
                    ("fluxo.port".to_string(), "3000".to_string()),
                    ("fluxo.upstream".to_string(), "web-pool".to_string()),
                    ("fluxo.service".to_string(), "frontend".to_string()),
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
                ports: vec![],
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
                ports: vec![],
            },
        ];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");

        // Only the two web containers should contribute, both to the "frontend" service.
        assert_eq!(config.services.len(), 1);
        assert!(config.services.contains_key("frontend"));

        // The upstream should have two targets (one per container).
        let upstream = &config.upstreams["web-pool"];
        assert_eq!(upstream.targets.len(), 2);

        let addrs: Vec<&str> = upstream.targets.iter().map(|t| t.address()).collect();
        assert!(addrs.contains(&"10.0.1.10:3000"));
        assert!(addrs.contains(&"10.0.1.11:3000"));

        // The service should have routes from both containers.
        let service = &config.services["frontend"];
        assert_eq!(service.routes.len(), 2);
        assert!(service.routes.iter().all(|r| r.upstream == "web-pool"));
    }

    #[test]
    fn full_pipeline_defaults_only() {
        // Container with only fluxo.enable=true — everything else is defaulted.
        let containers = vec![DockerContainer {
            id: "minimal".to_string(),
            names: vec!["/my-app".to_string()],
            labels: Some(HashMap::from([(
                "fluxo.enable".to_string(),
                "true".to_string(),
            )])),
            state: "running".to_string(),
            network_settings: ContainerNetworkSettings {
                networks: HashMap::from([(
                    "bridge".to_string(),
                    ContainerNetwork {
                        ip_address: "172.17.0.5".to_string(),
                    },
                )]),
            },
            ports: vec![DockerPort {
                private_port: 8080,
                protocol: "tcp".to_string(),
            }],
        }];

        let config = containers_to_config(containers, "fluxo", "0.0.0.0:80");

        // Service and upstream named after container ("my-app").
        assert!(config.services.contains_key("my-app"));
        assert!(config.upstreams.contains_key("my-app"));

        let service = &config.services["my-app"];
        assert_eq!(service.routes.len(), 1);
        assert_eq!(service.routes[0].match_path, vec!["/*"]);
        assert!(service.routes[0].match_host.is_empty());

        // Should auto-detect exposed port 8080.
        let upstream = &config.upstreams["my-app"];
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(upstream.targets[0].address(), "172.17.0.5:8080");
    }

    // ── Config has default global ──────────────────────────────────

    #[test]
    fn built_config_has_default_global() {
        let config = build_config(&[], "0.0.0.0:80");
        // Global should use defaults (not panic).
        assert_eq!(config.global.admin, "127.0.0.1:2019");
    }
}
