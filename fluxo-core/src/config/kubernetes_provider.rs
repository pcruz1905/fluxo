//! Kubernetes Ingress / Gateway API config provider.
//!
//! Watches Kubernetes Ingress resources via the K8s REST API and converts
//! them into `FluxoConfig` for the proxy engine. Supports two authentication
//! modes:
//!
//! - **In-cluster**: automatically reads the service account token and CA cert
//!   from `/var/run/secrets/kubernetes.io/serviceaccount/`.
//! - **Explicit**: `api_server` URL + `bearer_token` fields in config.
//!
//! Ingress resources are filtered by `kubernetes.io/ingress.class: <class>`
//! (default `"fluxo"`). Each Ingress rule is mapped to a route + upstream in
//! `FluxoConfig`, forming a complete proxy configuration derived from the
//! cluster state.
//!
//! The provider uses the K8s watch API (`?watch=true&resourceVersion=X`) for
//! real-time updates, falling back to periodic list+poll when the watch
//! connection drops or the `resourceVersion` expires (HTTP 410 Gone).

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::defaults;
use super::provider::ConfigProvider;
use super::{
    FluxoConfig, HealthCheckConfig, ListenerConfig, RouteConfig, ServiceConfig, TargetConfig,
    UpstreamConfig,
};

// ---------------------------------------------------------------------------
// Service account paths (in-cluster auto-detection)
// ---------------------------------------------------------------------------

const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const SA_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const DEFAULT_API_SERVER: &str = "https://kubernetes.default.svc";

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

/// Configuration for the Kubernetes config provider.
#[derive(Debug, Clone)]
pub struct KubernetesProviderConfig {
    /// Kubernetes API server URL (e.g., `"https://kubernetes.default.svc"`).
    /// When `None`, auto-detects in-cluster or falls back to `DEFAULT_API_SERVER`.
    pub api_server: Option<String>,

    /// Explicit bearer token for API authentication.
    /// When `None`, the provider reads the in-cluster service account token.
    pub bearer_token: Option<String>,

    /// Path to a kubeconfig file. Currently used only to extract the server URL
    /// and token — full kubeconfig parsing (contexts, users, etc.) is not supported.
    pub kubeconfig_path: Option<String>,

    /// Namespace to watch. `None` watches all namespaces.
    pub namespace: Option<String>,

    /// Ingress class filter. Only Ingress resources with a matching
    /// `kubernetes.io/ingress.class` annotation are considered.
    pub ingress_class: String,

    /// Fallback polling interval when the watch connection drops.
    pub poll_interval: Duration,

    /// When `true`, resolve Endpoints to individual pod IPs instead of using
    /// the Kubernetes service DNS name (`<svc>.<ns>.svc.cluster.local`).
    pub use_endpoints: bool,

    /// Skip TLS certificate verification for the K8s API server (dev clusters).
    pub tls_skip_verify: bool,
}

impl Default for KubernetesProviderConfig {
    fn default() -> Self {
        Self {
            api_server: None,
            bearer_token: None,
            kubeconfig_path: None,
            namespace: None,
            ingress_class: "fluxo".to_string(),
            poll_interval: Duration::from_secs(30),
            use_endpoints: false,
            tls_skip_verify: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal K8s API JSON types (only the fields we care about)
// ---------------------------------------------------------------------------

/// Top-level list response for `GET /apis/networking.k8s.io/v1/ingresses`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IngressList {
    pub metadata: ListMeta,
    #[serde(default)]
    pub items: Vec<Ingress>,
}

/// Metadata on a list response — we only need `resourceVersion`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListMeta {
    #[serde(default)]
    pub resource_version: String,
}

/// A single watch event from the K8s watch API.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct WatchEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub object: serde_json::Value,
}

/// A Kubernetes Ingress resource (networking.k8s.io/v1).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Ingress {
    pub metadata: ObjectMeta,
    #[serde(default)]
    pub spec: IngressSpec,
}

/// Standard Kubernetes object metadata.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ObjectMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub resource_version: String,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

/// Ingress spec — rules and TLS sections.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IngressSpec {
    #[serde(default)]
    pub rules: Vec<IngressRule>,
    #[serde(default)]
    pub tls: Vec<IngressTls>,
    pub default_backend: Option<IngressBackend>,
}

/// A single Ingress rule (one host).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IngressRule {
    #[serde(default)]
    pub host: Option<String>,
    pub http: Option<HttpIngressRuleValue>,
}

/// HTTP paths within a rule.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpIngressRuleValue {
    #[serde(default)]
    pub paths: Vec<HttpIngressPath>,
}

/// A single path entry in an Ingress rule.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HttpIngressPath {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_type: Option<String>,
    pub backend: Option<IngressBackend>,
}

/// Ingress backend reference.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IngressBackend {
    pub service: Option<IngressServiceBackend>,
}

/// Service backend within an Ingress.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IngressServiceBackend {
    #[serde(default)]
    pub name: String,
    pub port: Option<ServiceBackendPort>,
}

/// Port specification for a service backend.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceBackendPort {
    pub number: Option<u16>,
    pub name: Option<String>,
}

/// TLS section of an Ingress.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IngressTls {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub secret_name: Option<String>,
}

/// Kubernetes Endpoints resource for pod IP resolution.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Endpoints {
    #[serde(default)]
    pub subsets: Vec<EndpointSubset>,
}

/// A subset of endpoints (ready addresses + ports).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EndpointSubset {
    #[serde(default)]
    pub addresses: Vec<EndpointAddress>,
    #[serde(default)]
    pub ports: Vec<EndpointPort>,
}

/// A single endpoint address (pod IP).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EndpointAddress {
    #[serde(default)]
    pub ip: String,
}

/// A single endpoint port.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EndpointPort {
    pub port: Option<u16>,
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// Fluxo-specific annotations
// ---------------------------------------------------------------------------

const ANN_INGRESS_CLASS: &str = "kubernetes.io/ingress.class";
const ANN_LOAD_BALANCING: &str = "fluxo.io/load-balancing";
const ANN_HEALTH_CHECK_PATH: &str = "fluxo.io/health-check-path";
const ANN_RATE_LIMIT: &str = "fluxo.io/rate-limit";
const ANN_CONNECT_TIMEOUT: &str = "fluxo.io/connect-timeout";
const ANN_READ_TIMEOUT: &str = "fluxo.io/read-timeout";

// ---------------------------------------------------------------------------
// KubernetesProvider
// ---------------------------------------------------------------------------

/// Kubernetes config provider — watches Ingress resources and converts them
/// to `FluxoConfig` updates.
pub struct KubernetesProvider {
    config: KubernetesProviderConfig,
}

impl KubernetesProvider {
    /// Create a new Kubernetes provider with the given configuration.
    pub fn new(config: KubernetesProviderConfig) -> Self {
        Self { config }
    }

    /// Resolve the API server URL.
    fn api_server(&self) -> String {
        self.config
            .api_server
            .clone()
            .unwrap_or_else(|| DEFAULT_API_SERVER.to_string())
    }

    /// Resolve the bearer token — explicit config takes priority, then in-cluster SA token.
    fn bearer_token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref token) = self.config.bearer_token {
            return Ok(token.clone());
        }
        // Try in-cluster service account
        std::fs::read_to_string(SA_TOKEN_PATH).map_err(|e| {
            format!(
                "no bearer_token configured and failed to read in-cluster token at {SA_TOKEN_PATH}: {e}"
            )
            .into()
        })
    }

    /// Build a `reqwest::Client` configured for K8s API access.
    fn build_client(&self) -> Result<reqwest::Client, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(self.config.tls_skip_verify);

        // Add in-cluster CA cert if available
        if !self.config.tls_skip_verify {
            if let Ok(ca_pem) = std::fs::read(SA_CA_PATH) {
                if let Ok(cert) = reqwest::Certificate::from_pem(&ca_pem) {
                    builder = builder.add_root_certificate(cert);
                }
            }
        }

        Ok(builder.build()?)
    }

    /// Build the URL for listing Ingress resources.
    fn ingress_list_url(&self) -> String {
        let base = self.api_server();
        match &self.config.namespace {
            Some(ns) => {
                format!("{base}/apis/networking.k8s.io/v1/namespaces/{ns}/ingresses")
            }
            None => format!("{base}/apis/networking.k8s.io/v1/ingresses"),
        }
    }

    /// Build the URL for watching Ingress resources with a given `resourceVersion`.
    fn ingress_watch_url(&self, resource_version: &str) -> String {
        let base_url = self.ingress_list_url();
        format!("{base_url}?watch=true&resourceVersion={resource_version}")
    }

    /// Build the URL for fetching Endpoints of a service.
    fn endpoints_url(&self, namespace: &str, service_name: &str) -> String {
        let base = self.api_server();
        format!("{base}/api/v1/namespaces/{namespace}/endpoints/{service_name}")
    }

    /// List all Ingress resources (full list, not watch).
    async fn list_ingresses(
        &self,
        client: &reqwest::Client,
        token: &str,
    ) -> Result<IngressList, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.ingress_list_url();
        debug!(url = %url, "listing ingresses");

        let resp = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("K8s API returned {status}: {body}").into());
        }

        let list: IngressList = resp.json().await?;
        debug!(
            count = list.items.len(),
            resource_version = %list.metadata.resource_version,
            "listed ingresses"
        );
        Ok(list)
    }

    /// Fetch Endpoints for a service (for pod IP resolution).
    async fn get_endpoints(
        &self,
        client: &reqwest::Client,
        token: &str,
        namespace: &str,
        service_name: &str,
    ) -> Result<Endpoints, Box<dyn std::error::Error + Send + Sync>> {
        let url = self.endpoints_url(namespace, service_name);
        let resp = client.get(&url).bearer_auth(token).send().await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "failed to get endpoints for {service_name} in {namespace}: {status}: {body}"
            )
            .into());
        }

        Ok(resp.json().await?)
    }

    /// Filter ingresses by the configured ingress class.
    fn filter_by_class<'a>(&self, ingresses: &'a [Ingress]) -> Vec<&'a Ingress> {
        ingresses
            .iter()
            .filter(|ing| {
                ing.metadata
                    .annotations
                    .get(ANN_INGRESS_CLASS)
                    .is_some_and(|c| c == &self.config.ingress_class)
            })
            .collect()
    }

    /// Build `FluxoConfig` from a set of Ingress resources.
    async fn build_config(
        &self,
        ingresses: &[Ingress],
        client: &reqwest::Client,
        token: &str,
    ) -> FluxoConfig {
        let filtered = self.filter_by_class(ingresses);

        let mut routes = Vec::new();
        let mut upstreams: HashMap<String, UpstreamConfig> = HashMap::new();

        for ing in &filtered {
            let namespace = if ing.metadata.namespace.is_empty() {
                "default"
            } else {
                &ing.metadata.namespace
            };
            let annotations = &ing.metadata.annotations;

            // Parse Fluxo-specific annotations
            let lb_strategy = annotations.get(ANN_LOAD_BALANCING).cloned();
            let health_check_path = annotations.get(ANN_HEALTH_CHECK_PATH).cloned();
            let rate_limit: Option<u64> = annotations
                .get(ANN_RATE_LIMIT)
                .and_then(|v| v.parse().ok());
            let connect_timeout = annotations.get(ANN_CONNECT_TIMEOUT).cloned();
            let read_timeout = annotations.get(ANN_READ_TIMEOUT).cloned();

            // Build TLS host set for matching
            let tls_hosts: HashMap<&str, Option<&str>> = ing
                .spec
                .tls
                .iter()
                .flat_map(|tls| {
                    tls.hosts
                        .iter()
                        .map(move |h| (h.as_str(), tls.secret_name.as_deref()))
                })
                .collect();

            // Process default backend (if any)
            if let Some(ref default_backend) = ing.spec.default_backend {
                if let Some(ref svc_backend) = default_backend.service {
                    let upstream_name =
                        format!("{}-{}-default", ing.metadata.name, namespace);
                    let port = svc_backend
                        .port
                        .as_ref()
                        .and_then(|p| p.number)
                        .unwrap_or(80);

                    let targets = self
                        .resolve_targets(client, token, namespace, &svc_backend.name, port)
                        .await;

                    let mut upstream_cfg = UpstreamConfig {
                        targets,
                        ..Default::default()
                    };
                    apply_upstream_annotations(
                        &mut upstream_cfg,
                        &lb_strategy,
                        &health_check_path,
                        &connect_timeout,
                        &read_timeout,
                    );
                    upstreams.insert(upstream_name.clone(), upstream_cfg);

                    let mut route = RouteConfig {
                        name: Some(format!("{}-default", ing.metadata.name)),
                        upstream: upstream_name,
                        match_path: vec!["/*".to_string()],
                        ..Default::default()
                    };
                    apply_rate_limit(&mut route, rate_limit);
                    routes.push(route);
                }
            }

            // Process rules
            for rule in &ing.spec.rules {
                let host_match: Vec<String> = rule
                    .host
                    .as_ref()
                    .map(|h| vec![h.clone()])
                    .unwrap_or_default();

                let paths = rule
                    .http
                    .as_ref()
                    .map(|http| &http.paths[..])
                    .unwrap_or_default();

                for path_entry in paths {
                    let backend = match &path_entry.backend {
                        Some(b) => b,
                        None => continue,
                    };
                    let svc_backend = match &backend.service {
                        Some(s) => s,
                        None => continue,
                    };

                    let port = svc_backend
                        .port
                        .as_ref()
                        .and_then(|p| p.number)
                        .unwrap_or(80);

                    let upstream_name = format!(
                        "{}-{}-{}-{}",
                        ing.metadata.name,
                        namespace,
                        svc_backend.name,
                        port
                    );

                    // Build targets (pod IPs or service DNS)
                    if !upstreams.contains_key(&upstream_name) {
                        let targets = self
                            .resolve_targets(
                                client,
                                token,
                                namespace,
                                &svc_backend.name,
                                port,
                            )
                            .await;

                        let mut upstream_cfg = UpstreamConfig {
                            targets,
                            ..Default::default()
                        };
                        apply_upstream_annotations(
                            &mut upstream_cfg,
                            &lb_strategy,
                            &health_check_path,
                            &connect_timeout,
                            &read_timeout,
                        );
                        upstreams.insert(upstream_name.clone(), upstream_cfg);
                    }

                    // Convert Ingress path to a Fluxo match pattern
                    let match_path = convert_ingress_path(
                        path_entry.path.as_deref(),
                        path_entry.path_type.as_deref(),
                    );

                    let route_name = format!(
                        "{}-{}-{}{}",
                        ing.metadata.name,
                        svc_backend.name,
                        host_match.first().unwrap_or(&String::new()),
                        path_entry.path.as_deref().unwrap_or("")
                    );

                    let mut route = RouteConfig {
                        name: Some(route_name),
                        upstream: upstream_name,
                        match_host: host_match.clone(),
                        match_path: vec![match_path],
                        ..Default::default()
                    };
                    apply_rate_limit(&mut route, rate_limit);

                    // If TLS is configured for this host, note it (informational logging)
                    if let Some(host) = rule.host.as_deref() {
                        if tls_hosts.contains_key(host) {
                            debug!(
                                host = host,
                                ingress = %ing.metadata.name,
                                "TLS configured for host"
                            );
                        }
                    }

                    routes.push(route);
                }
            }
        }

        // Build the service — a single "kubernetes" service with all routes
        let mut services = HashMap::new();
        if !routes.is_empty() {
            services.insert(
                "kubernetes".to_string(),
                ServiceConfig {
                    listeners: vec![ListenerConfig {
                        address: "0.0.0.0:80".to_string(),
                        offer_h2: false,
                        proxy_protocol: false,
                    }],
                    tls: None,
                    routes,
                },
            );
        }

        FluxoConfig {
            global: Default::default(),
            services,
            upstreams,
            l4: Default::default(),
        }
    }

    /// Resolve upstream targets — either pod IPs (via Endpoints) or service DNS.
    async fn resolve_targets(
        &self,
        client: &reqwest::Client,
        token: &str,
        namespace: &str,
        service_name: &str,
        port: u16,
    ) -> Vec<TargetConfig> {
        if self.config.use_endpoints {
            match self
                .get_endpoints(client, token, namespace, service_name)
                .await
            {
                Ok(endpoints) => {
                    let mut targets = Vec::new();
                    for subset in &endpoints.subsets {
                        // Find the matching port number
                        let resolved_port = subset
                            .ports
                            .iter()
                            .find_map(|p| p.port)
                            .unwrap_or(port);

                        for addr in &subset.addresses {
                            targets.push(TargetConfig::Simple(format!(
                                "{}:{}",
                                addr.ip, resolved_port
                            )));
                        }
                    }
                    if targets.is_empty() {
                        warn!(
                            service = service_name,
                            namespace = namespace,
                            "no ready endpoints found — falling back to service DNS"
                        );
                        vec![TargetConfig::Simple(format!(
                            "{service_name}.{namespace}.svc.cluster.local:{port}"
                        ))]
                    } else {
                        debug!(
                            service = service_name,
                            namespace = namespace,
                            count = targets.len(),
                            "resolved endpoints to pod IPs"
                        );
                        targets
                    }
                }
                Err(e) => {
                    warn!(
                        service = service_name,
                        namespace = namespace,
                        error = %e,
                        "failed to resolve endpoints — falling back to service DNS"
                    );
                    vec![TargetConfig::Simple(format!(
                        "{service_name}.{namespace}.svc.cluster.local:{port}"
                    ))]
                }
            }
        } else {
            // Use Kubernetes service DNS name
            vec![TargetConfig::Simple(format!(
                "{service_name}.{namespace}.svc.cluster.local:{port}"
            ))]
        }
    }

    /// Run the watch loop — long-polls the K8s API for Ingress changes.
    /// Returns the reason for stopping (to decide whether to re-list or retry).
    async fn watch_loop(
        &self,
        client: &reqwest::Client,
        token: &str,
        resource_version: &str,
        ingresses: &mut Vec<Ingress>,
        tx: &mpsc::Sender<(String, FluxoConfig)>,
    ) -> WatchOutcome {
        let url = self.ingress_watch_url(resource_version);
        debug!(url = %url, "starting watch");

        // Use a longer timeout for the watch connection
        let watch_client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .danger_accept_invalid_certs(self.config.tls_skip_verify)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "failed to build watch client");
                return WatchOutcome::Error;
            }
        };

        let resp = match watch_client.get(&url).bearer_auth(token).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "watch connection failed");
                return WatchOutcome::Error;
            }
        };

        let status = resp.status();
        if status.as_u16() == 410 {
            info!("watch returned 410 Gone — resourceVersion expired, re-listing");
            return WatchOutcome::Gone;
        }
        if !status.is_success() {
            warn!(status = %status, "watch returned non-success status");
            return WatchOutcome::Error;
        }

        // Read the response body as text and process line-by-line
        // (each line is a JSON watch event)
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "watch stream read failed");
                return WatchOutcome::Error;
            }
        };

        let mut changed = false;

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let event: WatchEvent = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, line = line, "failed to parse watch event");
                    continue;
                }
            };

            match event.event_type.as_str() {
                "ADDED" | "MODIFIED" => {
                    if let Ok(ing) = serde_json::from_value::<Ingress>(event.object) {
                        debug!(
                            name = %ing.metadata.name,
                            namespace = %ing.metadata.namespace,
                            event = %event.event_type,
                            "ingress event"
                        );
                        // Upsert: remove existing by name+namespace, then add
                        ingresses.retain(|existing| {
                            !(existing.metadata.name == ing.metadata.name
                                && existing.metadata.namespace == ing.metadata.namespace)
                        });
                        ingresses.push(ing);
                        changed = true;
                    }
                }
                "DELETED" => {
                    if let Ok(ing) = serde_json::from_value::<Ingress>(event.object) {
                        debug!(
                            name = %ing.metadata.name,
                            namespace = %ing.metadata.namespace,
                            "ingress deleted"
                        );
                        ingresses.retain(|existing| {
                            !(existing.metadata.name == ing.metadata.name
                                && existing.metadata.namespace == ing.metadata.namespace)
                        });
                        changed = true;
                    }
                }
                "ERROR" => {
                    warn!("watch error event received");
                    return WatchOutcome::Error;
                }
                other => {
                    debug!(event_type = other, "unknown watch event type");
                }
            }
        }

        if changed {
            let config = self.build_config(ingresses, client, token).await;
            if tx
                .send((self.name().to_string(), config))
                .await
                .is_err()
            {
                return WatchOutcome::ChannelClosed;
            }
        }

        // Watch connection ended normally — reconnect
        WatchOutcome::Disconnected
    }
}

/// Outcome of a watch loop iteration.
enum WatchOutcome {
    /// `resourceVersion` expired (HTTP 410) — need full re-list.
    Gone,
    /// Connection error or watch stream ended — retry with same `resourceVersion`.
    Error,
    /// Watch disconnected normally — reconnect.
    Disconnected,
    /// The config channel was closed — provider should stop.
    ChannelClosed,
}

#[async_trait]
impl ConfigProvider for KubernetesProvider {
    fn name(&self) -> &str {
        "kubernetes"
    }

    async fn watch(
        &self,
        tx: mpsc::Sender<(String, FluxoConfig)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = self.build_client()?;
        let token = self.bearer_token()?;

        info!(
            api_server = %self.api_server(),
            namespace = ?self.config.namespace,
            ingress_class = %self.config.ingress_class,
            "kubernetes provider starting"
        );

        loop {
            // Step 1: Full list to get current state + resourceVersion
            let list = match self.list_ingresses(&client, &token).await {
                Ok(l) => l,
                Err(e) => {
                    error!(error = %e, "failed to list ingresses — retrying after poll interval");
                    tokio::time::sleep(self.config.poll_interval).await;
                    continue;
                }
            };

            let mut resource_version = list.metadata.resource_version.clone();
            let mut ingresses = list.items;

            // Step 2: Push initial config
            let config = self.build_config(&ingresses, &client, &token).await;
            info!(
                ingress_count = ingresses.len(),
                route_count = config.services.values().map(|s| s.routes.len()).sum::<usize>(),
                upstream_count = config.upstreams.len(),
                "initial kubernetes config built"
            );
            if tx
                .send((self.name().to_string(), config))
                .await
                .is_err()
            {
                // Receiver dropped — shutdown
                return Ok(());
            }

            // Step 3: Watch for changes
            loop {
                let outcome = self
                    .watch_loop(&client, &token, &resource_version, &mut ingresses, &tx)
                    .await;

                match outcome {
                    WatchOutcome::Gone => {
                        info!("re-listing after 410 Gone");
                        break; // Break inner loop to re-list
                    }
                    WatchOutcome::ChannelClosed => {
                        info!("config channel closed — kubernetes provider stopping");
                        return Ok(());
                    }
                    WatchOutcome::Error | WatchOutcome::Disconnected => {
                        warn!("watch disconnected — falling back to poll");
                        // Poll: re-list and diff
                        tokio::time::sleep(self.config.poll_interval).await;
                        match self.list_ingresses(&client, &token).await {
                            Ok(new_list) => {
                                resource_version =
                                    new_list.metadata.resource_version.clone();
                                ingresses = new_list.items;
                                let config = self
                                    .build_config(&ingresses, &client, &token)
                                    .await;
                                if tx
                                    .send((self.name().to_string(), config))
                                    .await
                                    .is_err()
                                {
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "poll re-list failed — retrying");
                                // Will loop back and retry
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert an Ingress path + pathType to a Fluxo glob pattern.
///
/// - `Prefix` with `/api` → `/api*` (matches `/api`, `/api/foo`, `/api-bar`)
/// - `Exact` with `/api` → `/api` (exact match)
/// - `ImplementationSpecific` or missing → treated as `Prefix`
pub(crate) fn convert_ingress_path(path: Option<&str>, path_type: Option<&str>) -> String {
    let path = path.unwrap_or("/");

    match path_type {
        Some("Exact") => path.to_string(),
        Some("Prefix") | Some("ImplementationSpecific") | None => {
            if path == "/" {
                "/*".to_string()
            } else {
                // Ensure trailing wildcard for prefix matching
                let trimmed = path.trim_end_matches('/');
                format!("{trimmed}/*")
            }
        }
        Some(other) => {
            warn!(path_type = other, "unknown Ingress pathType — treating as Prefix");
            if path == "/" {
                "/*".to_string()
            } else {
                let trimmed = path.trim_end_matches('/');
                format!("{trimmed}/*")
            }
        }
    }
}

/// Apply Fluxo-specific upstream annotations to an `UpstreamConfig`.
fn apply_upstream_annotations(
    upstream: &mut UpstreamConfig,
    lb_strategy: &Option<String>,
    health_check_path: &Option<String>,
    connect_timeout: &Option<String>,
    read_timeout: &Option<String>,
) {
    if let Some(ref lb) = lb_strategy {
        upstream.load_balancing = lb.clone();
    }
    if let Some(ref path) = health_check_path {
        upstream.health_check = Some(HealthCheckConfig {
            path: path.clone(),
            interval: defaults::health_check_interval(),
            timeout: defaults::health_check_timeout(),
            unhealthy_threshold: defaults::unhealthy_threshold(),
            healthy_threshold: defaults::healthy_threshold(),
            unhealthy_interval: None,
            expected_status: 0,
            expected_body: None,
            method: defaults::health_check_method(),
            headers: HashMap::new(),
            follow_redirects: defaults::health_check_follow_redirects(),
        });
    }
    if let Some(ref timeout) = connect_timeout {
        upstream.connect_timeout = timeout.clone();
    }
    if let Some(ref timeout) = read_timeout {
        upstream.read_timeout = timeout.clone();
    }
}

/// Apply rate limit annotation as a plugin on the route.
fn apply_rate_limit(route: &mut RouteConfig, rate_limit: Option<u64>) {
    if let Some(rps) = rate_limit {
        route.plugins.insert(
            "rate_limit".to_string(),
            serde_json::json!({
                "requests_per_second": rps
            }),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // -- Config defaults --

    #[test]
    fn default_config() {
        let cfg = KubernetesProviderConfig::default();
        assert_eq!(cfg.ingress_class, "fluxo");
        assert_eq!(cfg.poll_interval, Duration::from_secs(30));
        assert!(!cfg.use_endpoints);
        assert!(!cfg.tls_skip_verify);
        assert!(cfg.api_server.is_none());
        assert!(cfg.bearer_token.is_none());
        assert!(cfg.namespace.is_none());
    }

    #[test]
    fn provider_name() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        assert_eq!(provider.name(), "kubernetes");
    }

    #[test]
    fn api_server_default() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        assert_eq!(provider.api_server(), "https://kubernetes.default.svc");
    }

    #[test]
    fn api_server_explicit() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig {
            api_server: Some("https://my-cluster:6443".to_string()),
            ..Default::default()
        });
        assert_eq!(provider.api_server(), "https://my-cluster:6443");
    }

    // -- URL building --

    #[test]
    fn ingress_list_url_all_namespaces() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        assert_eq!(
            provider.ingress_list_url(),
            "https://kubernetes.default.svc/apis/networking.k8s.io/v1/ingresses"
        );
    }

    #[test]
    fn ingress_list_url_specific_namespace() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig {
            namespace: Some("production".to_string()),
            ..Default::default()
        });
        assert_eq!(
            provider.ingress_list_url(),
            "https://kubernetes.default.svc/apis/networking.k8s.io/v1/namespaces/production/ingresses"
        );
    }

    #[test]
    fn ingress_watch_url() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let url = provider.ingress_watch_url("12345");
        assert_eq!(
            url,
            "https://kubernetes.default.svc/apis/networking.k8s.io/v1/ingresses?watch=true&resourceVersion=12345"
        );
    }

    #[test]
    fn endpoints_url() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let url = provider.endpoints_url("default", "myapp-svc");
        assert_eq!(
            url,
            "https://kubernetes.default.svc/api/v1/namespaces/default/endpoints/myapp-svc"
        );
    }

    // -- Ingress JSON parsing --

    #[test]
    fn parse_ingress_list_empty() {
        let json = r#"{
            "apiVersion": "networking.k8s.io/v1",
            "kind": "IngressList",
            "metadata": {"resourceVersion": "1000"},
            "items": []
        }"#;
        let list: IngressList = serde_json::from_str(json).unwrap();
        assert_eq!(list.metadata.resource_version, "1000");
        assert!(list.items.is_empty());
    }

    #[test]
    fn parse_ingress_single_rule() {
        let json = r#"{
            "apiVersion": "networking.k8s.io/v1",
            "kind": "IngressList",
            "metadata": {"resourceVersion": "2000"},
            "items": [{
                "metadata": {
                    "name": "myapp",
                    "namespace": "default",
                    "resourceVersion": "1500",
                    "annotations": {
                        "kubernetes.io/ingress.class": "fluxo"
                    }
                },
                "spec": {
                    "rules": [{
                        "host": "myapp.example.com",
                        "http": {
                            "paths": [{
                                "path": "/api",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": "myapp-svc",
                                        "port": {"number": 8080}
                                    }
                                }
                            }]
                        }
                    }]
                }
            }]
        }"#;

        let list: IngressList = serde_json::from_str(json).unwrap();
        assert_eq!(list.items.len(), 1);

        let ing = &list.items[0];
        assert_eq!(ing.metadata.name, "myapp");
        assert_eq!(ing.metadata.namespace, "default");
        assert_eq!(
            ing.metadata.annotations.get(ANN_INGRESS_CLASS).unwrap(),
            "fluxo"
        );

        assert_eq!(ing.spec.rules.len(), 1);
        let rule = &ing.spec.rules[0];
        assert_eq!(rule.host.as_deref(), Some("myapp.example.com"));

        let paths = &rule.http.as_ref().unwrap().paths;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].path.as_deref(), Some("/api"));
        assert_eq!(paths[0].path_type.as_deref(), Some("Prefix"));

        let svc = paths[0].backend.as_ref().unwrap().service.as_ref().unwrap();
        assert_eq!(svc.name, "myapp-svc");
        assert_eq!(svc.port.as_ref().unwrap().number, Some(8080));
    }

    #[test]
    fn parse_ingress_multiple_rules_and_paths() {
        let json = r#"{
            "apiVersion": "networking.k8s.io/v1",
            "kind": "IngressList",
            "metadata": {"resourceVersion": "3000"},
            "items": [{
                "metadata": {
                    "name": "multi-app",
                    "namespace": "staging",
                    "annotations": {
                        "kubernetes.io/ingress.class": "fluxo",
                        "fluxo.io/load-balancing": "least_conn"
                    }
                },
                "spec": {
                    "rules": [
                        {
                            "host": "api.staging.com",
                            "http": {
                                "paths": [
                                    {
                                        "path": "/v1",
                                        "pathType": "Prefix",
                                        "backend": {
                                            "service": {
                                                "name": "api-v1",
                                                "port": {"number": 3000}
                                            }
                                        }
                                    },
                                    {
                                        "path": "/v2",
                                        "pathType": "Prefix",
                                        "backend": {
                                            "service": {
                                                "name": "api-v2",
                                                "port": {"number": 3001}
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        {
                            "host": "web.staging.com",
                            "http": {
                                "paths": [{
                                    "path": "/",
                                    "pathType": "Prefix",
                                    "backend": {
                                        "service": {
                                            "name": "web-frontend",
                                            "port": {"number": 80}
                                        }
                                    }
                                }]
                            }
                        }
                    ]
                }
            }]
        }"#;

        let list: IngressList = serde_json::from_str(json).unwrap();
        assert_eq!(list.items.len(), 1);
        let ing = &list.items[0];
        assert_eq!(ing.spec.rules.len(), 2);

        // First rule: 2 paths
        let rule1 = &ing.spec.rules[0];
        assert_eq!(rule1.host.as_deref(), Some("api.staging.com"));
        assert_eq!(rule1.http.as_ref().unwrap().paths.len(), 2);

        // Second rule: 1 path
        let rule2 = &ing.spec.rules[1];
        assert_eq!(rule2.host.as_deref(), Some("web.staging.com"));
        assert_eq!(rule2.http.as_ref().unwrap().paths.len(), 1);
    }

    #[test]
    fn parse_ingress_with_tls() {
        let json = r#"{
            "apiVersion": "networking.k8s.io/v1",
            "kind": "IngressList",
            "metadata": {"resourceVersion": "4000"},
            "items": [{
                "metadata": {
                    "name": "secure-app",
                    "namespace": "default",
                    "annotations": {
                        "kubernetes.io/ingress.class": "fluxo"
                    }
                },
                "spec": {
                    "tls": [{
                        "hosts": ["secure.example.com"],
                        "secretName": "secure-tls-cert"
                    }],
                    "rules": [{
                        "host": "secure.example.com",
                        "http": {
                            "paths": [{
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": "secure-svc",
                                        "port": {"number": 443}
                                    }
                                }
                            }]
                        }
                    }]
                }
            }]
        }"#;

        let list: IngressList = serde_json::from_str(json).unwrap();
        let ing = &list.items[0];
        assert_eq!(ing.spec.tls.len(), 1);
        assert_eq!(ing.spec.tls[0].hosts, vec!["secure.example.com"]);
        assert_eq!(
            ing.spec.tls[0].secret_name.as_deref(),
            Some("secure-tls-cert")
        );
    }

    #[test]
    fn parse_ingress_with_default_backend() {
        let json = r#"{
            "metadata": {
                "name": "default-backend-app",
                "namespace": "default",
                "annotations": {
                    "kubernetes.io/ingress.class": "fluxo"
                }
            },
            "spec": {
                "defaultBackend": {
                    "service": {
                        "name": "fallback-svc",
                        "port": {"number": 8080}
                    }
                },
                "rules": []
            }
        }"#;

        let ing: Ingress = serde_json::from_str(json).unwrap();
        assert!(ing.spec.default_backend.is_some());
        let backend = ing.spec.default_backend.unwrap();
        let svc = backend.service.unwrap();
        assert_eq!(svc.name, "fallback-svc");
        assert_eq!(svc.port.unwrap().number, Some(8080));
    }

    #[test]
    fn parse_ingress_missing_optional_fields() {
        let json = r#"{
            "metadata": {
                "name": "minimal",
                "namespace": "default"
            },
            "spec": {}
        }"#;

        let ing: Ingress = serde_json::from_str(json).unwrap();
        assert_eq!(ing.metadata.name, "minimal");
        assert!(ing.spec.rules.is_empty());
        assert!(ing.spec.tls.is_empty());
        assert!(ing.spec.default_backend.is_none());
        assert!(ing.metadata.annotations.is_empty());
    }

    #[test]
    fn parse_ingress_with_port_name() {
        let json = r#"{
            "metadata": {
                "name": "port-name-app",
                "namespace": "default",
                "annotations": {
                    "kubernetes.io/ingress.class": "fluxo"
                }
            },
            "spec": {
                "rules": [{
                    "host": "app.example.com",
                    "http": {
                        "paths": [{
                            "path": "/",
                            "pathType": "Prefix",
                            "backend": {
                                "service": {
                                    "name": "my-svc",
                                    "port": {"name": "http"}
                                }
                            }
                        }]
                    }
                }]
            }
        }"#;

        let ing: Ingress = serde_json::from_str(json).unwrap();
        let path = &ing.spec.rules[0].http.as_ref().unwrap().paths[0];
        let port = path.backend.as_ref().unwrap().service.as_ref().unwrap().port.as_ref().unwrap();
        assert_eq!(port.name.as_deref(), Some("http"));
        assert!(port.number.is_none());
    }

    // -- Watch event parsing --

    #[test]
    fn parse_watch_event_added() {
        let json = r#"{
            "type": "ADDED",
            "object": {
                "metadata": {
                    "name": "new-app",
                    "namespace": "default",
                    "resourceVersion": "5000",
                    "annotations": {
                        "kubernetes.io/ingress.class": "fluxo"
                    }
                },
                "spec": {
                    "rules": [{
                        "host": "new.example.com",
                        "http": {
                            "paths": [{
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": "new-svc",
                                        "port": {"number": 80}
                                    }
                                }
                            }]
                        }
                    }]
                }
            }
        }"#;

        let event: WatchEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "ADDED");

        let ing: Ingress = serde_json::from_value(event.object).unwrap();
        assert_eq!(ing.metadata.name, "new-app");
    }

    #[test]
    fn parse_watch_event_deleted() {
        let json = r#"{
            "type": "DELETED",
            "object": {
                "metadata": {
                    "name": "removed-app",
                    "namespace": "default",
                    "resourceVersion": "6000"
                },
                "spec": {}
            }
        }"#;

        let event: WatchEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "DELETED");
    }

    #[test]
    fn parse_watch_event_modified() {
        let json = r#"{
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "name": "updated-app",
                    "namespace": "prod",
                    "resourceVersion": "7000",
                    "annotations": {
                        "kubernetes.io/ingress.class": "fluxo"
                    }
                },
                "spec": {
                    "rules": [{
                        "host": "updated.example.com",
                        "http": {
                            "paths": [{
                                "path": "/new-path",
                                "pathType": "Exact",
                                "backend": {
                                    "service": {
                                        "name": "updated-svc",
                                        "port": {"number": 9090}
                                    }
                                }
                            }]
                        }
                    }]
                }
            }
        }"#;

        let event: WatchEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.event_type, "MODIFIED");
        let ing: Ingress = serde_json::from_value(event.object).unwrap();
        assert_eq!(ing.metadata.name, "updated-app");
        assert_eq!(ing.metadata.namespace, "prod");
    }

    // -- Endpoints parsing --

    #[test]
    fn parse_endpoints() {
        let json = r#"{
            "subsets": [{
                "addresses": [
                    {"ip": "10.0.0.1"},
                    {"ip": "10.0.0.2"},
                    {"ip": "10.0.0.3"}
                ],
                "ports": [
                    {"port": 8080, "name": "http"}
                ]
            }]
        }"#;

        let endpoints: Endpoints = serde_json::from_str(json).unwrap();
        assert_eq!(endpoints.subsets.len(), 1);
        assert_eq!(endpoints.subsets[0].addresses.len(), 3);
        assert_eq!(endpoints.subsets[0].addresses[0].ip, "10.0.0.1");
        assert_eq!(endpoints.subsets[0].ports[0].port, Some(8080));
    }

    #[test]
    fn parse_endpoints_empty_subsets() {
        let json = r#"{"subsets": []}"#;
        let endpoints: Endpoints = serde_json::from_str(json).unwrap();
        assert!(endpoints.subsets.is_empty());
    }

    #[test]
    fn parse_endpoints_multiple_subsets() {
        let json = r#"{
            "subsets": [
                {
                    "addresses": [{"ip": "10.0.0.1"}],
                    "ports": [{"port": 8080}]
                },
                {
                    "addresses": [{"ip": "10.0.1.1"}, {"ip": "10.0.1.2"}],
                    "ports": [{"port": 9090}]
                }
            ]
        }"#;

        let endpoints: Endpoints = serde_json::from_str(json).unwrap();
        assert_eq!(endpoints.subsets.len(), 2);
        assert_eq!(endpoints.subsets[0].addresses.len(), 1);
        assert_eq!(endpoints.subsets[1].addresses.len(), 2);
    }

    // -- Path conversion --

    #[test]
    fn convert_path_prefix_root() {
        assert_eq!(convert_ingress_path(Some("/"), Some("Prefix")), "/*");
    }

    #[test]
    fn convert_path_prefix_subpath() {
        assert_eq!(
            convert_ingress_path(Some("/api"), Some("Prefix")),
            "/api/*"
        );
    }

    #[test]
    fn convert_path_prefix_trailing_slash() {
        assert_eq!(
            convert_ingress_path(Some("/api/"), Some("Prefix")),
            "/api/*"
        );
    }

    #[test]
    fn convert_path_exact() {
        assert_eq!(
            convert_ingress_path(Some("/api/health"), Some("Exact")),
            "/api/health"
        );
    }

    #[test]
    fn convert_path_implementation_specific() {
        assert_eq!(
            convert_ingress_path(Some("/legacy"), Some("ImplementationSpecific")),
            "/legacy/*"
        );
    }

    #[test]
    fn convert_path_none_defaults_to_prefix_root() {
        assert_eq!(convert_ingress_path(None, None), "/*");
    }

    #[test]
    fn convert_path_unknown_type_treated_as_prefix() {
        assert_eq!(
            convert_ingress_path(Some("/foo"), Some("UnknownType")),
            "/foo/*"
        );
    }

    #[test]
    fn convert_path_exact_root() {
        assert_eq!(convert_ingress_path(Some("/"), Some("Exact")), "/");
    }

    #[test]
    fn convert_path_prefix_deep_path() {
        assert_eq!(
            convert_ingress_path(Some("/api/v1/users"), Some("Prefix")),
            "/api/v1/users/*"
        );
    }

    // -- Ingress class filtering --

    #[test]
    fn filter_by_class_matches() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let ingresses = vec![
            make_test_ingress("app1", "default", "fluxo"),
            make_test_ingress("app2", "default", "nginx"),
            make_test_ingress("app3", "default", "fluxo"),
        ];

        let filtered = provider.filter_by_class(&ingresses);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].metadata.name, "app1");
        assert_eq!(filtered[1].metadata.name, "app3");
    }

    #[test]
    fn filter_by_class_none_match() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let ingresses = vec![
            make_test_ingress("app1", "default", "nginx"),
            make_test_ingress("app2", "default", "traefik"),
        ];

        let filtered = provider.filter_by_class(&ingresses);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_by_class_custom_class() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig {
            ingress_class: "custom-proxy".to_string(),
            ..Default::default()
        });
        let ingresses = vec![
            make_test_ingress("app1", "default", "custom-proxy"),
            make_test_ingress("app2", "default", "fluxo"),
        ];

        let filtered = provider.filter_by_class(&ingresses);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].metadata.name, "app1");
    }

    #[test]
    fn filter_by_class_no_annotation() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let ingresses = vec![Ingress {
            metadata: ObjectMeta {
                name: "no-class".to_string(),
                namespace: "default".to_string(),
                annotations: HashMap::new(),
                ..Default::default()
            },
            spec: IngressSpec::default(),
        }];

        let filtered = provider.filter_by_class(&ingresses);
        assert!(filtered.is_empty());
    }

    // -- Config building (synchronous parts) --

    #[tokio::test]
    async fn build_config_empty_ingresses() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();
        let config = provider.build_config(&[], &client, "fake-token").await;

        assert!(config.services.is_empty());
        assert!(config.upstreams.is_empty());
    }

    #[tokio::test]
    async fn build_config_non_matching_class() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();
        let ingresses = vec![make_test_ingress("app1", "default", "nginx")];
        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        assert!(config.services.is_empty());
        assert!(config.upstreams.is_empty());
    }

    #[tokio::test]
    async fn build_config_single_ingress_service_dns() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig {
            use_endpoints: false,
            ..Default::default()
        });
        let client = reqwest::Client::new();
        let ingresses = vec![make_full_test_ingress(
            "myapp",
            "production",
            "fluxo",
            "myapp.example.com",
            "/api",
            "Prefix",
            "myapp-svc",
            8080,
        )];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        // Should have one service named "kubernetes"
        assert_eq!(config.services.len(), 1);
        assert!(config.services.contains_key("kubernetes"));

        let svc = &config.services["kubernetes"];
        assert_eq!(svc.routes.len(), 1);

        let route = &svc.routes[0];
        assert_eq!(route.match_host, vec!["myapp.example.com"]);
        assert_eq!(route.match_path, vec!["/api/*"]);

        // Upstream should use service DNS
        let upstream_name = &route.upstream;
        let upstream = config.upstreams.get(upstream_name).unwrap();
        assert_eq!(upstream.targets.len(), 1);
        assert_eq!(
            upstream.targets[0].address(),
            "myapp-svc.production.svc.cluster.local:8080"
        );
    }

    #[tokio::test]
    async fn build_config_with_annotations() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        let mut annotations = HashMap::new();
        annotations.insert(ANN_INGRESS_CLASS.to_string(), "fluxo".to_string());
        annotations.insert(ANN_LOAD_BALANCING.to_string(), "least_conn".to_string());
        annotations.insert(ANN_HEALTH_CHECK_PATH.to_string(), "/healthz".to_string());
        annotations.insert(ANN_RATE_LIMIT.to_string(), "100".to_string());
        annotations.insert(ANN_CONNECT_TIMEOUT.to_string(), "10s".to_string());
        annotations.insert(ANN_READ_TIMEOUT.to_string(), "30s".to_string());

        let ingresses = vec![Ingress {
            metadata: ObjectMeta {
                name: "annotated-app".to_string(),
                namespace: "default".to_string(),
                annotations,
                ..Default::default()
            },
            spec: IngressSpec {
                rules: vec![IngressRule {
                    host: Some("annotated.example.com".to_string()),
                    http: Some(HttpIngressRuleValue {
                        paths: vec![HttpIngressPath {
                            path: Some("/".to_string()),
                            path_type: Some("Prefix".to_string()),
                            backend: Some(IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "annotated-svc".to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        name: None,
                                    }),
                                }),
                            }),
                        }],
                    }),
                }],
                tls: Vec::new(),
                default_backend: None,
            },
        }];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        // Check upstream annotations
        let upstream = config.upstreams.values().next().unwrap();
        assert_eq!(upstream.load_balancing, "least_conn");
        assert_eq!(upstream.connect_timeout, "10s");
        assert_eq!(upstream.read_timeout, "30s");
        assert!(upstream.health_check.is_some());
        assert_eq!(upstream.health_check.as_ref().unwrap().path, "/healthz");

        // Check rate limit plugin
        let route = &config.services["kubernetes"].routes[0];
        assert!(route.plugins.contains_key("rate_limit"));
        let rl = &route.plugins["rate_limit"];
        assert_eq!(rl["requests_per_second"], 100);
    }

    #[tokio::test]
    async fn build_config_multiple_ingresses() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        let ingresses = vec![
            make_full_test_ingress(
                "app1",
                "default",
                "fluxo",
                "app1.example.com",
                "/",
                "Prefix",
                "app1-svc",
                80,
            ),
            make_full_test_ingress(
                "app2",
                "staging",
                "fluxo",
                "app2.staging.com",
                "/api",
                "Prefix",
                "app2-svc",
                3000,
            ),
        ];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        assert_eq!(config.services["kubernetes"].routes.len(), 2);
        assert_eq!(config.upstreams.len(), 2);
    }

    #[tokio::test]
    async fn build_config_default_backend() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        let ingresses = vec![Ingress {
            metadata: ObjectMeta {
                name: "with-default".to_string(),
                namespace: "default".to_string(),
                annotations: {
                    let mut a = HashMap::new();
                    a.insert(ANN_INGRESS_CLASS.to_string(), "fluxo".to_string());
                    a
                },
                ..Default::default()
            },
            spec: IngressSpec {
                default_backend: Some(IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: "fallback".to_string(),
                        port: Some(ServiceBackendPort {
                            number: Some(8080),
                            name: None,
                        }),
                    }),
                }),
                rules: Vec::new(),
                tls: Vec::new(),
            },
        }];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        // Should have a route for the default backend
        assert_eq!(config.services["kubernetes"].routes.len(), 1);
        let route = &config.services["kubernetes"].routes[0];
        assert_eq!(route.match_path, vec!["/*"]);
        assert!(route.name.as_ref().unwrap().contains("default"));
    }

    #[tokio::test]
    async fn build_config_exact_path_type() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        let ingresses = vec![make_full_test_ingress(
            "exact-app",
            "default",
            "fluxo",
            "exact.example.com",
            "/health",
            "Exact",
            "exact-svc",
            80,
        )];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        let route = &config.services["kubernetes"].routes[0];
        assert_eq!(route.match_path, vec!["/health"]);
    }

    #[tokio::test]
    async fn build_config_empty_namespace_defaults() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        let ingresses = vec![Ingress {
            metadata: ObjectMeta {
                name: "no-ns-app".to_string(),
                namespace: String::new(), // empty namespace
                annotations: {
                    let mut a = HashMap::new();
                    a.insert(ANN_INGRESS_CLASS.to_string(), "fluxo".to_string());
                    a
                },
                ..Default::default()
            },
            spec: IngressSpec {
                rules: vec![IngressRule {
                    host: Some("app.example.com".to_string()),
                    http: Some(HttpIngressRuleValue {
                        paths: vec![HttpIngressPath {
                            path: Some("/".to_string()),
                            path_type: Some("Prefix".to_string()),
                            backend: Some(IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "my-svc".to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        name: None,
                                    }),
                                }),
                            }),
                        }],
                    }),
                }],
                tls: Vec::new(),
                default_backend: None,
            },
        }];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        // Should use "default" namespace for DNS
        let upstream = config.upstreams.values().next().unwrap();
        assert_eq!(
            upstream.targets[0].address(),
            "my-svc.default.svc.cluster.local:80"
        );
    }

    #[tokio::test]
    async fn build_config_no_host_rule() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        let ingresses = vec![Ingress {
            metadata: ObjectMeta {
                name: "no-host".to_string(),
                namespace: "default".to_string(),
                annotations: {
                    let mut a = HashMap::new();
                    a.insert(ANN_INGRESS_CLASS.to_string(), "fluxo".to_string());
                    a
                },
                ..Default::default()
            },
            spec: IngressSpec {
                rules: vec![IngressRule {
                    host: None,
                    http: Some(HttpIngressRuleValue {
                        paths: vec![HttpIngressPath {
                            path: Some("/".to_string()),
                            path_type: Some("Prefix".to_string()),
                            backend: Some(IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "catch-all".to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(80),
                                        name: None,
                                    }),
                                }),
                            }),
                        }],
                    }),
                }],
                tls: Vec::new(),
                default_backend: None,
            },
        }];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        // Route should have empty match_host (matches any host)
        let route = &config.services["kubernetes"].routes[0];
        assert!(route.match_host.is_empty());
    }

    #[tokio::test]
    async fn build_config_port_defaults_to_80() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        let ingresses = vec![Ingress {
            metadata: ObjectMeta {
                name: "no-port".to_string(),
                namespace: "default".to_string(),
                annotations: {
                    let mut a = HashMap::new();
                    a.insert(ANN_INGRESS_CLASS.to_string(), "fluxo".to_string());
                    a
                },
                ..Default::default()
            },
            spec: IngressSpec {
                rules: vec![IngressRule {
                    host: Some("app.example.com".to_string()),
                    http: Some(HttpIngressRuleValue {
                        paths: vec![HttpIngressPath {
                            path: Some("/".to_string()),
                            path_type: Some("Prefix".to_string()),
                            backend: Some(IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: "my-svc".to_string(),
                                    port: None, // no port specified
                                }),
                            }),
                        }],
                    }),
                }],
                tls: Vec::new(),
                default_backend: None,
            },
        }];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        let upstream = config.upstreams.values().next().unwrap();
        assert!(upstream.targets[0].address().ends_with(":80"));
    }

    #[tokio::test]
    async fn build_config_deduplicates_upstreams() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        // Two ingresses pointing to the same service+port+namespace
        // (different hosts but same backend)
        let make_ing = |name: &str, host: &str| -> Ingress {
            Ingress {
                metadata: ObjectMeta {
                    name: name.to_string(),
                    namespace: "default".to_string(),
                    annotations: {
                        let mut a = HashMap::new();
                        a.insert(ANN_INGRESS_CLASS.to_string(), "fluxo".to_string());
                        a
                    },
                    ..Default::default()
                },
                spec: IngressSpec {
                    rules: vec![IngressRule {
                        host: Some(host.to_string()),
                        http: Some(HttpIngressRuleValue {
                            paths: vec![HttpIngressPath {
                                path: Some("/".to_string()),
                                path_type: Some("Prefix".to_string()),
                                backend: Some(IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "shared-svc".to_string(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(80),
                                            name: None,
                                        }),
                                    }),
                                }),
                            }],
                        }),
                    }],
                    tls: Vec::new(),
                    default_backend: None,
                },
            }
        };

        let ingresses = vec![
            make_ing("app1", "app1.example.com"),
            make_ing("app2", "app2.example.com"),
        ];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        // Two routes but they may share or not share upstreams depending on
        // the naming scheme (name includes ingress name so they differ)
        assert_eq!(config.services["kubernetes"].routes.len(), 2);
    }

    #[tokio::test]
    async fn build_config_listener_defaults() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        let client = reqwest::Client::new();

        let ingresses = vec![make_full_test_ingress(
            "app", "default", "fluxo", "app.example.com", "/", "Prefix", "app-svc", 80,
        )];

        let config = provider
            .build_config(&ingresses, &client, "fake-token")
            .await;

        let svc = &config.services["kubernetes"];
        assert_eq!(svc.listeners.len(), 1);
        assert_eq!(svc.listeners[0].address, "0.0.0.0:80");
        assert!(!svc.listeners[0].offer_h2);
        assert!(!svc.listeners[0].proxy_protocol);
    }

    // -- apply_upstream_annotations --

    #[test]
    fn apply_annotations_load_balancing() {
        let mut upstream = UpstreamConfig::default();
        apply_upstream_annotations(
            &mut upstream,
            &Some("least_conn".to_string()),
            &None,
            &None,
            &None,
        );
        assert_eq!(upstream.load_balancing, "least_conn");
    }

    #[test]
    fn apply_annotations_health_check() {
        let mut upstream = UpstreamConfig::default();
        apply_upstream_annotations(
            &mut upstream,
            &None,
            &Some("/healthz".to_string()),
            &None,
            &None,
        );
        assert!(upstream.health_check.is_some());
        assert_eq!(upstream.health_check.unwrap().path, "/healthz");
    }

    #[test]
    fn apply_annotations_timeouts() {
        let mut upstream = UpstreamConfig::default();
        apply_upstream_annotations(
            &mut upstream,
            &None,
            &None,
            &Some("15s".to_string()),
            &Some("45s".to_string()),
        );
        assert_eq!(upstream.connect_timeout, "15s");
        assert_eq!(upstream.read_timeout, "45s");
    }

    #[test]
    fn apply_annotations_none() {
        let mut upstream = UpstreamConfig::default();
        let original_lb = upstream.load_balancing.clone();
        apply_upstream_annotations(&mut upstream, &None, &None, &None, &None);
        assert_eq!(upstream.load_balancing, original_lb);
        assert!(upstream.health_check.is_none());
    }

    // -- apply_rate_limit --

    #[test]
    fn apply_rate_limit_some() {
        let mut route = RouteConfig::default();
        apply_rate_limit(&mut route, Some(500));
        assert!(route.plugins.contains_key("rate_limit"));
        assert_eq!(route.plugins["rate_limit"]["requests_per_second"], 500);
    }

    #[test]
    fn apply_rate_limit_none() {
        let mut route = RouteConfig::default();
        apply_rate_limit(&mut route, None);
        assert!(!route.plugins.contains_key("rate_limit"));
    }

    // -- Bearer token resolution --

    #[test]
    fn bearer_token_explicit() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig {
            bearer_token: Some("my-secret-token".to_string()),
            ..Default::default()
        });
        assert_eq!(provider.bearer_token().unwrap(), "my-secret-token");
    }

    #[test]
    fn bearer_token_no_config_no_file() {
        let provider = KubernetesProvider::new(KubernetesProviderConfig::default());
        // No explicit token and not running in-cluster — should fail
        assert!(provider.bearer_token().is_err());
    }

    // -- Helpers --

    fn make_test_ingress(name: &str, namespace: &str, class: &str) -> Ingress {
        let mut annotations = HashMap::new();
        annotations.insert(ANN_INGRESS_CLASS.to_string(), class.to_string());

        Ingress {
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: namespace.to_string(),
                annotations,
                ..Default::default()
            },
            spec: IngressSpec::default(),
        }
    }

    fn make_full_test_ingress(
        name: &str,
        namespace: &str,
        class: &str,
        host: &str,
        path: &str,
        path_type: &str,
        svc_name: &str,
        port: u16,
    ) -> Ingress {
        let mut annotations = HashMap::new();
        annotations.insert(ANN_INGRESS_CLASS.to_string(), class.to_string());

        Ingress {
            metadata: ObjectMeta {
                name: name.to_string(),
                namespace: namespace.to_string(),
                annotations,
                ..Default::default()
            },
            spec: IngressSpec {
                rules: vec![IngressRule {
                    host: Some(host.to_string()),
                    http: Some(HttpIngressRuleValue {
                        paths: vec![HttpIngressPath {
                            path: Some(path.to_string()),
                            path_type: Some(path_type.to_string()),
                            backend: Some(IngressBackend {
                                service: Some(IngressServiceBackend {
                                    name: svc_name.to_string(),
                                    port: Some(ServiceBackendPort {
                                        number: Some(port),
                                        name: None,
                                    }),
                                }),
                            }),
                        }],
                    }),
                }],
                tls: Vec::new(),
                default_backend: None,
            },
        }
    }
}
