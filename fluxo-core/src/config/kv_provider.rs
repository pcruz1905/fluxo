//! KV-store config provider — Consul and etcd backend support.
//!
//! Supports two KV backends for storing and watching Fluxo configuration:
//!
//! - **Consul KV**: Reads a full TOML config from a single Consul key, watches
//!   for changes via Consul blocking queries (`?index=X&wait=5m`). Optionally
//!   discovers upstreams from the Consul service catalog (healthy instances only).
//!
//! - **etcd**: Reads a full TOML config from a single etcd key via the v3
//!   HTTP gateway (`/v3/`). Watches for changes via the etcd watch API.
//!
//! Both modes store the entire Fluxo TOML configuration as a single key's value
//! at `{prefix}/config`. Consul catalog mode builds upstream targets from healthy
//! service instances and uses service tags for routing metadata.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::provider::ConfigProvider;
use super::{
    FluxoConfig, KvBackend, KvProviderConfig, ListenerConfig, RouteConfig, ServiceConfig,
    TargetConfig, UpstreamConfig,
};

// ---------------------------------------------------------------------------
// Runtime configuration
// ---------------------------------------------------------------------------

/// Resolved runtime config for the KV provider.
///
/// Wraps the TOML-level `KvProviderConfig` with parsed durations and
/// additional runtime fields not stored in the config file.
#[derive(Debug, Clone)]
pub struct KvRuntimeConfig {
    /// The raw TOML-level config.
    pub inner: KvProviderConfig,
    /// Parsed poll interval.
    pub poll_interval: Duration,
    /// Service names to discover from Consul catalog.
    /// Empty means discover all services with `fluxo-` prefixed tags.
    pub discovery_services: Vec<String>,
    /// Listener address for auto-generated services from catalog discovery.
    pub discovery_listener: String,
}

impl KvRuntimeConfig {
    /// Build runtime config from the TOML-level config, parsing durations.
    pub fn from_toml(inner: KvProviderConfig) -> Self {
        let poll_interval = super::parse_duration(&inner.poll_interval)
            .unwrap_or(Duration::from_secs(10));
        Self {
            inner,
            poll_interval,
            discovery_services: Vec::new(),
            discovery_listener: "0.0.0.0:80".to_string(),
        }
    }

    /// Set the services to discover from Consul catalog.
    #[must_use]
    pub fn with_discovery_services(mut self, services: Vec<String>) -> Self {
        self.discovery_services = services;
        self
    }

    /// Set the listener address for catalog-discovered services.
    #[must_use]
    pub fn with_discovery_listener(mut self, listener: String) -> Self {
        self.discovery_listener = listener;
        self
    }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// KV-store configuration provider.
///
/// Implements `ConfigProvider` to watch Consul KV or etcd for configuration
/// changes and push updates into the shared channel.
pub struct KvProvider {
    config: KvRuntimeConfig,
    client: reqwest::Client,
}

impl KvProvider {
    /// Create a new KV provider with the given runtime configuration.
    pub fn new(
        config: KvRuntimeConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.inner.tls_skip_verify)
            .timeout(Duration::from_secs(310)) // > Consul's max blocking wait (5m = 300s)
            .build()?;
        Ok(Self { config, client })
    }

    /// Create from a TOML-level config with default runtime settings.
    pub fn from_toml(
        toml_config: KvProviderConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::new(KvRuntimeConfig::from_toml(toml_config))
    }

    /// Pick the next endpoint, cycling through the list for failover.
    fn endpoint(&self, attempt: usize) -> &str {
        let idx = attempt % self.config.inner.endpoints.len();
        &self.config.inner.endpoints[idx]
    }

    // --- Consul KV ---

    /// Fetch config from Consul KV at `{prefix}/config`.
    ///
    /// Returns `(modify_index, raw_toml)`. The `modify_index` is used for
    /// subsequent blocking queries to detect changes.
    async fn consul_kv_get(
        &self,
        endpoint: &str,
        wait_index: Option<u64>,
    ) -> Result<(u64, Option<String>), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("{}/config", self.config.inner.prefix);
        let mut url = format!("{endpoint}/v1/kv/{key}?raw=false");

        // Blocking query: wait up to 5 minutes for changes.
        if let Some(idx) = wait_index {
            url.push_str(&format!("&index={idx}&wait=5m"));
        }

        if let Some(dc) = &self.config.inner.consul_datacenter {
            url.push_str(&format!("&dc={dc}"));
        }
        if let Some(ns) = &self.config.inner.consul_namespace {
            url.push_str(&format!("&ns={ns}"));
        }

        let mut req = self.client.get(&url);
        if let Some(token) = &self.config.inner.token {
            req = req.header("X-Consul-Token", token);
        }

        let resp = req.send().await?;
        let status = resp.status();

        // Extract the X-Consul-Index header before consuming the body.
        let new_index: u64 = resp
            .headers()
            .get("X-Consul-Index")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok((new_index, None));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Consul KV returned {status}: {body}").into());
        }

        let entries: Vec<ConsulKvEntry> = resp.json().await?;
        let value = entries.first().and_then(|e| {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&e.value)
                .ok()?;
            String::from_utf8(decoded).ok()
        });

        Ok((new_index, value))
    }

    /// Watch Consul KV for config changes using blocking queries.
    async fn watch_consul_kv(
        &self,
        tx: &mpsc::Sender<(String, FluxoConfig)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut last_index: Option<u64> = None;
        let mut attempt: usize = 0;
        let mut backoff = ExponentialBackoff::new();

        loop {
            let endpoint = self.endpoint(attempt);
            match self.consul_kv_get(endpoint, last_index).await {
                Ok((new_index, Some(toml_str))) => {
                    backoff.reset();

                    // Only push if the index actually changed.
                    if last_index != Some(new_index) {
                        last_index = Some(new_index);
                        match super::load_from_str(&toml_str) {
                            Ok(config) => {
                                info!(
                                    index = new_index,
                                    "consul KV config changed — pushing update"
                                );
                                if tx.send((self.name().to_string(), config)).await.is_err() {
                                    return Ok(()); // receiver dropped
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "failed to parse Consul KV config — skipping");
                            }
                        }
                    }
                }
                Ok((new_index, None)) => {
                    backoff.reset();
                    debug!(index = new_index, "consul KV key not found — waiting");
                    last_index = Some(new_index);
                }
                Err(e) => {
                    attempt += 1;
                    let delay = backoff.next_delay();
                    warn!(
                        error = %e,
                        endpoint,
                        retry_in = ?delay,
                        "consul KV request failed — retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    // --- Consul Catalog ---

    /// Fetch healthy instances of a service from Consul catalog.
    async fn consul_catalog_service(
        &self,
        endpoint: &str,
        service: &str,
        wait_index: Option<u64>,
    ) -> Result<(u64, Vec<ConsulHealthEntry>), Box<dyn std::error::Error + Send + Sync>> {
        let mut url = format!("{endpoint}/v1/health/service/{service}?passing=true");

        if let Some(idx) = wait_index {
            url.push_str(&format!("&index={idx}&wait=5m"));
        }
        if let Some(dc) = &self.config.inner.consul_datacenter {
            url.push_str(&format!("&dc={dc}"));
        }
        if let Some(ns) = &self.config.inner.consul_namespace {
            url.push_str(&format!("&ns={ns}"));
        }

        let mut req = self.client.get(&url);
        if let Some(token) = &self.config.inner.token {
            req = req.header("X-Consul-Token", token);
        }

        let resp = req.send().await?;
        let new_index: u64 = resp
            .headers()
            .get("X-Consul-Index")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Consul catalog returned {status}: {body}").into());
        }

        let entries: Vec<ConsulHealthEntry> = resp.json().await?;
        Ok((new_index, entries))
    }

    /// Build a `FluxoConfig` from Consul catalog service discovery results.
    ///
    /// Maps healthy service instances to upstream targets. Service tags control
    /// routing metadata:
    /// - `fluxo-host=api.example.com` -> `match_host`
    /// - `fluxo-path=/api/*` -> `match_path`
    /// - `fluxo-lb=round_robin` -> load balancing strategy
    fn build_config_from_catalog(
        &self,
        catalog_data: &HashMap<String, Vec<ConsulHealthEntry>>,
    ) -> FluxoConfig {
        let mut upstreams = HashMap::new();
        let mut services = HashMap::new();
        let mut all_routes = Vec::new();

        for (svc_name, entries) in catalog_data {
            let targets: Vec<TargetConfig> = entries
                .iter()
                .map(|entry| {
                    let addr = entry.service_address();
                    TargetConfig::Simple(addr)
                })
                .collect();

            if targets.is_empty() {
                continue;
            }

            // Extract routing metadata from service tags.
            let tags = Self::merged_tags(entries);
            let lb = tags
                .get("fluxo-lb")
                .cloned()
                .unwrap_or_else(|| "round_robin".to_string());

            upstreams.insert(
                svc_name.clone(),
                UpstreamConfig {
                    targets,
                    load_balancing: lb,
                    ..Default::default()
                },
            );

            // Build route from tags.
            let match_host: Vec<String> = tags
                .get("fluxo-host")
                .map(|h| h.split(',').map(str::trim).map(String::from).collect())
                .unwrap_or_default();
            let match_path: Vec<String> = tags
                .get("fluxo-path")
                .map(|p| p.split(',').map(str::trim).map(String::from).collect())
                .unwrap_or_default();

            let route = RouteConfig {
                name: Some(format!("consul-{svc_name}")),
                upstream: svc_name.clone(),
                match_host,
                match_path,
                ..Default::default()
            };
            all_routes.push(route);
        }

        if !all_routes.is_empty() {
            services.insert(
                "consul-discovery".to_string(),
                ServiceConfig {
                    listeners: vec![ListenerConfig {
                        address: self.config.discovery_listener.clone(),
                        offer_h2: false,
                        proxy_protocol: false,
                    }],
                    tls: None,
                    routes: all_routes,
                },
            );
        }

        FluxoConfig {
            services,
            upstreams,
            ..Default::default()
        }
    }

    /// Merge all `fluxo-*` tags across all healthy entries for a service.
    ///
    /// Tags are expected in `key=value` format. The last occurrence wins
    /// for duplicate keys (consistent across instances).
    fn merged_tags(entries: &[ConsulHealthEntry]) -> HashMap<String, String> {
        let mut tags = HashMap::new();
        for entry in entries {
            for tag in &entry.service.tags {
                if let Some(kv) = tag.strip_prefix("fluxo-") {
                    if let Some((k, v)) = kv.split_once('=') {
                        tags.insert(format!("fluxo-{k}"), v.to_string());
                    }
                }
            }
        }
        tags
    }

    /// Watch Consul catalog for changes and build config from healthy services.
    async fn watch_consul_catalog(
        &self,
        tx: &mpsc::Sender<(String, FluxoConfig)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Track per-service indices for blocking queries.
        let mut service_indices: HashMap<String, u64> = HashMap::new();
        let mut backoff = ExponentialBackoff::new();
        let mut attempt: usize = 0;

        loop {
            let endpoint = self.endpoint(attempt);
            let target_services = if self.config.discovery_services.is_empty() {
                // Discover all services, then filter to those with fluxo tags.
                match self.consul_list_services(endpoint).await {
                    Ok(svc_list) => svc_list,
                    Err(e) => {
                        attempt += 1;
                        let delay = backoff.next_delay();
                        warn!(
                            error = %e,
                            retry_in = ?delay,
                            "failed to list Consul services — retrying"
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
            } else {
                self.config.discovery_services.clone()
            };

            let mut catalog_data: HashMap<String, Vec<ConsulHealthEntry>> = HashMap::new();
            let mut any_changed = false;
            let mut had_error = false;

            for svc in &target_services {
                let wait_index = service_indices.get(svc).copied();
                match self.consul_catalog_service(endpoint, svc, wait_index).await {
                    Ok((new_index, entries)) => {
                        if service_indices.get(svc) != Some(&new_index) {
                            any_changed = true;
                            service_indices.insert(svc.clone(), new_index);
                        }
                        catalog_data.insert(svc.clone(), entries);
                    }
                    Err(e) => {
                        warn!(service = svc, error = %e, "failed to query Consul catalog service");
                        had_error = true;
                    }
                }
            }

            if had_error && catalog_data.is_empty() {
                attempt += 1;
                let delay = backoff.next_delay();
                warn!(
                    retry_in = ?delay,
                    "all Consul catalog queries failed — retrying"
                );
                tokio::time::sleep(delay).await;
                continue;
            }

            backoff.reset();

            if any_changed && !catalog_data.is_empty() {
                let config = self.build_config_from_catalog(&catalog_data);
                info!(
                    services = catalog_data.len(),
                    "consul catalog changed — pushing discovery update"
                );
                if tx.send((self.name().to_string(), config)).await.is_err() {
                    return Ok(());
                }
            }

            // If no blocking query triggered a change, sleep the poll interval.
            if !any_changed {
                tokio::time::sleep(self.config.poll_interval).await;
            }
        }
    }

    /// List all Consul services, returning those that have at least one `fluxo-` tag.
    async fn consul_list_services(
        &self,
        endpoint: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let mut url = format!("{endpoint}/v1/catalog/services");
        let mut sep = '?';

        if let Some(dc) = &self.config.inner.consul_datacenter {
            url.push_str(&format!("{sep}dc={dc}"));
            sep = '&';
        }
        if let Some(ns) = &self.config.inner.consul_namespace {
            url.push_str(&format!("{sep}ns={ns}"));
        }

        let mut req = self.client.get(&url);
        if let Some(token) = &self.config.inner.token {
            req = req.header("X-Consul-Token", token);
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Consul catalog/services returned: {body}").into());
        }

        // Response: { "service-name": ["tag1", "tag2"], ... }
        let catalog: HashMap<String, Vec<String>> = resp.json().await?;
        let filtered: Vec<String> = catalog
            .into_iter()
            .filter(|(_, tags)| tags.iter().any(|t| t.starts_with("fluxo-")))
            .map(|(name, _)| name)
            .collect();

        Ok(filtered)
    }

    // --- etcd ---

    /// Fetch config from etcd at `{prefix}/config` via the v3 HTTP gateway.
    async fn etcd_range_get(
        &self,
        endpoint: &str,
    ) -> Result<(i64, Option<String>), Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("{}/config", self.config.inner.prefix);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());

        let url = format!("{endpoint}/v3/kv/range");

        let body = serde_json::json!({
            "key": key_b64,
        });

        let mut req = self.client.post(&url).json(&body);
        if let Some(token) = &self.config.inner.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("etcd range GET failed: {body}").into());
        }

        let range_resp: EtcdRangeResponse = resp.json().await?;

        Ok(range_resp.kvs.first().map_or((0, None), |kv| {
            let revision = kv.mod_revision;
            let value = base64::engine::general_purpose::STANDARD
                .decode(&kv.value)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok());
            (revision, value)
        }))
    }

    /// Watch etcd for changes via the v3 watch API.
    async fn watch_etcd(
        &self,
        tx: &mpsc::Sender<(String, FluxoConfig)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut last_revision: i64 = 0;
        let mut attempt: usize = 0;
        let mut backoff = ExponentialBackoff::new();

        // Initial load.
        loop {
            let endpoint = self.endpoint(attempt);
            match self.etcd_range_get(endpoint).await {
                Ok((rev, Some(toml_str))) => {
                    last_revision = rev;
                    backoff.reset();
                    match super::load_from_str(&toml_str) {
                        Ok(config) => {
                            info!(revision = rev, "etcd initial config loaded");
                            if tx.send((self.name().to_string(), config)).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "failed to parse etcd config — skipping");
                        }
                    }
                    break;
                }
                Ok((_, None)) => {
                    debug!("etcd key not found — waiting for creation");
                    backoff.reset();
                    break;
                }
                Err(e) => {
                    attempt += 1;
                    let delay = backoff.next_delay();
                    warn!(
                        error = %e,
                        retry_in = ?delay,
                        "etcd initial load failed — retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }

        // Watch loop: use etcd watch API, fall back to polling on error.
        backoff.reset();
        loop {
            let endpoint = self.endpoint(attempt);
            match self
                .etcd_watch_once(endpoint, last_revision + 1)
                .await
            {
                Ok(Some((rev, toml_str))) => {
                    last_revision = rev;
                    backoff.reset();
                    match super::load_from_str(&toml_str) {
                        Ok(config) => {
                            info!(revision = rev, "etcd config changed — pushing update");
                            if tx.send((self.name().to_string(), config)).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "failed to parse etcd config — skipping");
                        }
                    }
                }
                Ok(None) => {
                    // No change detected (key deleted or no events).
                    debug!("etcd watch returned no events — polling fallback");
                    tokio::time::sleep(self.config.poll_interval).await;

                    // Fall back to range GET to pick up any missed changes.
                    if let Ok((rev, Some(toml_str))) = self.etcd_range_get(endpoint).await {
                        if rev > last_revision {
                            last_revision = rev;
                            if let Ok(config) = super::load_from_str(&toml_str) {
                                info!(
                                    revision = rev,
                                    "etcd poll detected change — pushing update"
                                );
                                if tx.send((self.name().to_string(), config)).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    attempt += 1;
                    let delay = backoff.next_delay();
                    warn!(
                        error = %e,
                        retry_in = ?delay,
                        "etcd watch failed — retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Execute a single etcd watch request.
    ///
    /// The etcd v3 watch API is a streaming endpoint. For simplicity in this
    /// HTTP-based implementation, we issue a single watch request and read
    /// one response (which may contain multiple events). Returns the latest
    /// revision and value if a PUT event was observed.
    async fn etcd_watch_once(
        &self,
        endpoint: &str,
        start_revision: i64,
    ) -> Result<Option<(i64, String)>, Box<dyn std::error::Error + Send + Sync>> {
        let key = format!("{}/config", self.config.inner.prefix);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());

        let url = format!("{endpoint}/v3/watch");
        let body = serde_json::json!({
            "create_request": {
                "key": key_b64,
                "start_revision": start_revision,
            }
        });

        let mut req = self.client.post(&url).json(&body);
        if let Some(token) = &self.config.inner.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }

        let resp = req
            .timeout(Duration::from_secs(305)) // slightly > etcd default watch timeout
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("etcd watch failed: {body}").into());
        }

        let watch_resp: EtcdWatchResponse = resp.json().await?;

        // Find the latest PUT event (we care about the most recent value).
        let mut latest: Option<(i64, String)> = None;
        if let Some(result) = watch_resp.result {
            for event in &result.events {
                if event.event_type != "DELETE" {
                    if let Some(kv) = &event.kv {
                        let rev = kv.mod_revision;
                        if let Ok(bytes) =
                            base64::engine::general_purpose::STANDARD.decode(&kv.value)
                        {
                            if let Ok(val) = String::from_utf8(bytes) {
                                match &latest {
                                    Some((prev_rev, _)) if rev <= *prev_rev => {}
                                    _ => latest = Some((rev, val)),
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(latest)
    }
}

#[async_trait]
impl ConfigProvider for KvProvider {
    fn name(&self) -> &str {
        match self.config.inner.backend {
            KvBackend::Consul => "consul",
            KvBackend::Etcd => "etcd",
        }
    }

    async fn watch(
        &self,
        tx: mpsc::Sender<(String, FluxoConfig)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            backend = ?self.config.inner.backend,
            endpoints = ?self.config.inner.endpoints,
            prefix = %self.config.inner.prefix,
            service_discovery = self.config.inner.service_discovery,
            "starting KV config provider"
        );

        match self.config.inner.backend {
            KvBackend::Consul => {
                if self.config.inner.service_discovery {
                    // Run both KV watch and catalog watch concurrently.
                    // The KV watch provides the base config, catalog provides upstreams.
                    let tx_kv = tx.clone();
                    let tx_catalog = tx;

                    tokio::select! {
                        result = self.watch_consul_kv(&tx_kv) => result,
                        result = self.watch_consul_catalog(&tx_catalog) => result,
                    }
                } else {
                    self.watch_consul_kv(&tx).await
                }
            }
            KvBackend::Etcd => self.watch_etcd(&tx).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Exponential backoff
// ---------------------------------------------------------------------------

/// Simple exponential backoff with jitter for retry logic.
struct ExponentialBackoff {
    current: Duration,
    base: Duration,
    max: Duration,
}

impl ExponentialBackoff {
    fn new() -> Self {
        Self {
            current: Duration::from_secs(1),
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
        }
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = (self.current * 2).min(self.max);
        // Add ~25% jitter.
        let jitter_ms = (delay.as_millis() as u64) / 4;
        let jitter = if jitter_ms > 0 {
            Duration::from_millis(fastrand::u64(0..jitter_ms))
        } else {
            Duration::ZERO
        };
        delay + jitter
    }

    fn reset(&mut self) {
        self.current = self.base;
    }
}

// ---------------------------------------------------------------------------
// Consul response types
// ---------------------------------------------------------------------------

/// A single Consul KV entry from `GET /v1/kv/{key}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ConsulKvEntry {
    /// Base64-encoded value.
    #[serde(default)]
    value: String,
    /// Consul modification index (used in tests for assertions).
    #[serde(default)]
    #[allow(dead_code)]
    modify_index: u64,
}

/// A health service entry from `GET /v1/health/service/{service}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ConsulHealthEntry {
    /// Node information.
    #[serde(default)]
    node: ConsulNode,
    /// Service registration info.
    #[serde(default)]
    service: ConsulService,
}

impl ConsulHealthEntry {
    /// Build the `host:port` address for this service instance.
    ///
    /// Prefers `Service.Address` over `Node.Address`, falling back when empty.
    fn service_address(&self) -> String {
        let host = if self.service.address.is_empty() {
            &self.node.address
        } else {
            &self.service.address
        };
        format!("{}:{}", host, self.service.port)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ConsulNode {
    #[serde(default)]
    address: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ConsulService {
    #[serde(default)]
    #[allow(dead_code)]
    service: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// etcd response types
// ---------------------------------------------------------------------------

/// Response from `POST /v3/kv/range`.
#[derive(Debug, Deserialize)]
struct EtcdRangeResponse {
    #[serde(default)]
    kvs: Vec<EtcdKeyValue>,
}

/// A key-value pair in an etcd response. Values and keys are base64-encoded.
#[derive(Debug, Deserialize)]
struct EtcdKeyValue {
    #[serde(default)]
    #[allow(dead_code)]
    key: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    mod_revision: i64,
}

/// Response from `POST /v3/watch`.
#[derive(Debug, Deserialize)]
struct EtcdWatchResponse {
    result: Option<EtcdWatchResult>,
}

#[derive(Debug, Deserialize)]
struct EtcdWatchResult {
    #[serde(default)]
    events: Vec<EtcdEvent>,
}

#[derive(Debug, Deserialize)]
struct EtcdEvent {
    /// `"PUT"` or `"DELETE"`.
    #[serde(default, rename = "type")]
    event_type: String,
    /// The key-value pair (present for PUT events).
    kv: Option<EtcdKeyValue>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Helper: build a default Consul `KvProviderConfig` for tests.
    fn consul_toml_config() -> KvProviderConfig {
        KvProviderConfig {
            backend: KvBackend::Consul,
            endpoints: vec!["http://127.0.0.1:8500".to_string()],
            prefix: "fluxo".to_string(),
            token: None,
            poll_interval: "10s".to_string(),
            consul_datacenter: None,
            consul_namespace: None,
            service_discovery: false,
            tls_skip_verify: false,
        }
    }

    /// Helper: build a default etcd `KvProviderConfig` for tests.
    fn etcd_toml_config() -> KvProviderConfig {
        KvProviderConfig {
            backend: KvBackend::Etcd,
            endpoints: vec!["http://127.0.0.1:2379".to_string()],
            prefix: "fluxo".to_string(),
            token: None,
            poll_interval: "10s".to_string(),
            consul_datacenter: None,
            consul_namespace: None,
            service_discovery: false,
            tls_skip_verify: false,
        }
    }

    /// Helper: build a `KvRuntimeConfig` from a TOML config.
    fn runtime(toml_cfg: KvProviderConfig) -> KvRuntimeConfig {
        KvRuntimeConfig::from_toml(toml_cfg)
    }

    // --- KvRuntimeConfig defaults ---

    #[test]
    fn runtime_config_parses_poll_interval() {
        let rt = runtime(consul_toml_config());
        assert_eq!(rt.poll_interval, Duration::from_secs(10));
    }

    #[test]
    fn runtime_config_default_discovery_listener() {
        let rt = runtime(consul_toml_config());
        assert_eq!(rt.discovery_listener, "0.0.0.0:80");
    }

    #[test]
    fn runtime_config_default_discovery_services_empty() {
        let rt = runtime(consul_toml_config());
        assert!(rt.discovery_services.is_empty());
    }

    #[test]
    fn runtime_config_with_discovery_services() {
        let rt = runtime(consul_toml_config())
            .with_discovery_services(vec!["web".to_string(), "api".to_string()]);
        assert_eq!(rt.discovery_services.len(), 2);
    }

    #[test]
    fn runtime_config_with_discovery_listener() {
        let rt = runtime(consul_toml_config())
            .with_discovery_listener("0.0.0.0:443".to_string());
        assert_eq!(rt.discovery_listener, "0.0.0.0:443");
    }

    // --- Provider name ---

    #[test]
    fn consul_provider_name() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();
        assert_eq!(provider.name(), "consul");
    }

    #[test]
    fn etcd_provider_name() {
        let provider = KvProvider::new(runtime(etcd_toml_config())).unwrap();
        assert_eq!(provider.name(), "etcd");
    }

    // --- Endpoint failover ---

    #[test]
    fn endpoint_cycles_through_list() {
        let mut cfg = consul_toml_config();
        cfg.endpoints = vec![
            "http://consul-1:8500".to_string(),
            "http://consul-2:8500".to_string(),
            "http://consul-3:8500".to_string(),
        ];
        let provider = KvProvider::new(runtime(cfg)).unwrap();
        assert_eq!(provider.endpoint(0), "http://consul-1:8500");
        assert_eq!(provider.endpoint(1), "http://consul-2:8500");
        assert_eq!(provider.endpoint(2), "http://consul-3:8500");
        assert_eq!(provider.endpoint(3), "http://consul-1:8500");
        assert_eq!(provider.endpoint(4), "http://consul-2:8500");
    }

    #[test]
    fn single_endpoint_always_returns_same() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();
        assert_eq!(provider.endpoint(0), "http://127.0.0.1:8500");
        assert_eq!(provider.endpoint(5), "http://127.0.0.1:8500");
        assert_eq!(provider.endpoint(100), "http://127.0.0.1:8500");
    }

    // --- Consul KV response parsing ---

    #[test]
    fn parse_consul_kv_entry() {
        let json = r#"[
            {
                "LockIndex": 0,
                "Key": "fluxo/config",
                "Flags": 0,
                "Value": "W2dsb2JhbF0KYWRtaW4gPSAiMTI3LjAuMC4xOjIwMTki",
                "CreateIndex": 100,
                "ModifyIndex": 200
            }
        ]"#;
        let entries: Vec<ConsulKvEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].modify_index, 200);

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&entries[0].value)
            .unwrap();
        let value = String::from_utf8(decoded).unwrap();
        assert!(value.contains("[global]"));
        assert!(value.contains("admin"));
    }

    #[test]
    fn parse_consul_kv_empty_response() {
        let json = "[]";
        let entries: Vec<ConsulKvEntry> = serde_json::from_str(json).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_consul_kv_entry_with_missing_fields() {
        let json = r#"[{"Value": "dGVzdA=="}]"#;
        let entries: Vec<ConsulKvEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].modify_index, 0);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&entries[0].value)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "test");
    }

    // --- Consul health entry parsing ---

    #[test]
    fn parse_consul_health_entry() {
        let json = r#"[
            {
                "Node": {
                    "Node": "node-1",
                    "Address": "10.0.1.1"
                },
                "Service": {
                    "Service": "web",
                    "Address": "10.0.1.10",
                    "Port": 8080,
                    "Tags": ["fluxo-host=api.example.com", "fluxo-path=/api/*", "fluxo-lb=round_robin"]
                },
                "Checks": []
            }
        ]"#;
        let entries: Vec<ConsulHealthEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].service.service, "web");
        assert_eq!(entries[0].service.port, 8080);
        assert_eq!(entries[0].service_address(), "10.0.1.10:8080");
    }

    #[test]
    fn consul_health_entry_falls_back_to_node_address() {
        let json = r#"[
            {
                "Node": { "Address": "10.0.1.1" },
                "Service": { "Service": "web", "Address": "", "Port": 3000, "Tags": [] }
            }
        ]"#;
        let entries: Vec<ConsulHealthEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries[0].service_address(), "10.0.1.1:3000");
    }

    #[test]
    fn consul_health_entry_prefers_service_address() {
        let json = r#"[
            {
                "Node": { "Address": "10.0.1.1" },
                "Service": { "Service": "web", "Address": "10.0.2.5", "Port": 9090, "Tags": [] }
            }
        ]"#;
        let entries: Vec<ConsulHealthEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries[0].service_address(), "10.0.2.5:9090");
    }

    #[test]
    fn parse_multiple_consul_health_entries() {
        let json = r#"[
            {
                "Node": { "Address": "10.0.1.1" },
                "Service": { "Service": "api", "Address": "10.0.1.1", "Port": 8080, "Tags": [] }
            },
            {
                "Node": { "Address": "10.0.1.2" },
                "Service": { "Service": "api", "Address": "10.0.1.2", "Port": 8080, "Tags": [] }
            },
            {
                "Node": { "Address": "10.0.1.3" },
                "Service": { "Service": "api", "Address": "10.0.1.3", "Port": 8080, "Tags": [] }
            }
        ]"#;
        let entries: Vec<ConsulHealthEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 3);
    }

    // --- Consul catalog -> config mapping ---

    #[test]
    fn merged_tags_extracts_fluxo_tags() {
        let entries = vec![
            ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.1".to_string(),
                },
                service: ConsulService {
                    service: "web".to_string(),
                    address: "10.0.1.1".to_string(),
                    port: 8080,
                    tags: vec![
                        "fluxo-host=api.example.com".to_string(),
                        "fluxo-lb=round_robin".to_string(),
                        "unrelated-tag".to_string(),
                    ],
                },
            },
            ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.2".to_string(),
                },
                service: ConsulService {
                    service: "web".to_string(),
                    address: "10.0.1.2".to_string(),
                    port: 8080,
                    tags: vec![
                        "fluxo-host=api.example.com".to_string(),
                        "fluxo-path=/api/*".to_string(),
                    ],
                },
            },
        ];

        let tags = KvProvider::merged_tags(&entries);
        assert_eq!(tags.get("fluxo-host").unwrap(), "api.example.com");
        assert_eq!(tags.get("fluxo-lb").unwrap(), "round_robin");
        assert_eq!(tags.get("fluxo-path").unwrap(), "/api/*");
        assert!(!tags.contains_key("unrelated-tag"));
    }

    #[test]
    fn merged_tags_empty_when_no_fluxo_tags() {
        let entries = vec![ConsulHealthEntry {
            node: ConsulNode {
                address: "10.0.1.1".to_string(),
            },
            service: ConsulService {
                service: "web".to_string(),
                address: "10.0.1.1".to_string(),
                port: 8080,
                tags: vec!["v1".to_string(), "production".to_string()],
            },
        }];

        let tags = KvProvider::merged_tags(&entries);
        assert!(tags.is_empty());
    }

    #[test]
    fn merged_tags_last_value_wins() {
        let entries = vec![
            ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.1".to_string(),
                },
                service: ConsulService {
                    service: "web".to_string(),
                    address: "10.0.1.1".to_string(),
                    port: 8080,
                    tags: vec!["fluxo-lb=round_robin".to_string()],
                },
            },
            ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.2".to_string(),
                },
                service: ConsulService {
                    service: "web".to_string(),
                    address: "10.0.1.2".to_string(),
                    port: 8080,
                    tags: vec!["fluxo-lb=least_conn".to_string()],
                },
            },
        ];

        let tags = KvProvider::merged_tags(&entries);
        assert_eq!(tags.get("fluxo-lb").unwrap(), "least_conn");
    }

    #[test]
    fn build_config_from_catalog_single_service() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();

        let mut catalog = HashMap::new();
        catalog.insert(
            "backend".to_string(),
            vec![
                ConsulHealthEntry {
                    node: ConsulNode {
                        address: "10.0.1.1".to_string(),
                    },
                    service: ConsulService {
                        service: "backend".to_string(),
                        address: "10.0.1.1".to_string(),
                        port: 8080,
                        tags: vec![
                            "fluxo-host=api.example.com".to_string(),
                            "fluxo-path=/api/*".to_string(),
                        ],
                    },
                },
                ConsulHealthEntry {
                    node: ConsulNode {
                        address: "10.0.1.2".to_string(),
                    },
                    service: ConsulService {
                        service: "backend".to_string(),
                        address: "10.0.1.2".to_string(),
                        port: 8080,
                        tags: vec!["fluxo-host=api.example.com".to_string()],
                    },
                },
            ],
        );

        let config = provider.build_config_from_catalog(&catalog);

        // Should have one upstream.
        assert_eq!(config.upstreams.len(), 1);
        let upstream = config.upstreams.get("backend").unwrap();
        assert_eq!(upstream.targets.len(), 2);
        assert_eq!(upstream.targets[0].address(), "10.0.1.1:8080");
        assert_eq!(upstream.targets[1].address(), "10.0.1.2:8080");

        // Should have one service with routes.
        assert_eq!(config.services.len(), 1);
        let svc = config.services.get("consul-discovery").unwrap();
        assert_eq!(svc.routes.len(), 1);
        assert_eq!(svc.routes[0].upstream, "backend");
        assert!(svc.routes[0].match_host.contains(&"api.example.com".to_string()));
        assert!(svc.routes[0].match_path.contains(&"/api/*".to_string()));
    }

    #[test]
    fn build_config_from_catalog_multiple_services() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();

        let mut catalog = HashMap::new();
        catalog.insert(
            "web".to_string(),
            vec![ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.1".to_string(),
                },
                service: ConsulService {
                    service: "web".to_string(),
                    address: "10.0.1.1".to_string(),
                    port: 3000,
                    tags: vec!["fluxo-host=www.example.com".to_string()],
                },
            }],
        );
        catalog.insert(
            "api".to_string(),
            vec![ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.2.1".to_string(),
                },
                service: ConsulService {
                    service: "api".to_string(),
                    address: "10.0.2.1".to_string(),
                    port: 8080,
                    tags: vec![
                        "fluxo-host=api.example.com".to_string(),
                        "fluxo-lb=least_conn".to_string(),
                    ],
                },
            }],
        );

        let config = provider.build_config_from_catalog(&catalog);

        assert_eq!(config.upstreams.len(), 2);
        assert!(config.upstreams.contains_key("web"));
        assert!(config.upstreams.contains_key("api"));

        let api_upstream = config.upstreams.get("api").unwrap();
        assert_eq!(api_upstream.load_balancing, "least_conn");

        let svc = config.services.get("consul-discovery").unwrap();
        assert_eq!(svc.routes.len(), 2);
    }

    #[test]
    fn build_config_from_catalog_empty_services_skipped() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();

        let mut catalog = HashMap::new();
        catalog.insert("empty-svc".to_string(), vec![]);
        catalog.insert(
            "active-svc".to_string(),
            vec![ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.1".to_string(),
                },
                service: ConsulService {
                    service: "active-svc".to_string(),
                    address: "10.0.1.1".to_string(),
                    port: 8080,
                    tags: vec![],
                },
            }],
        );

        let config = provider.build_config_from_catalog(&catalog);
        assert_eq!(config.upstreams.len(), 1);
        assert!(config.upstreams.contains_key("active-svc"));
        assert!(!config.upstreams.contains_key("empty-svc"));
    }

    #[test]
    fn build_config_from_catalog_all_empty_produces_no_service() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();

        let mut catalog = HashMap::new();
        catalog.insert("empty".to_string(), vec![]);

        let config = provider.build_config_from_catalog(&catalog);
        assert!(config.upstreams.is_empty());
        assert!(config.services.is_empty());
    }

    #[test]
    fn build_config_from_catalog_default_lb_is_round_robin() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();

        let mut catalog = HashMap::new();
        catalog.insert(
            "svc".to_string(),
            vec![ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.1".to_string(),
                },
                service: ConsulService {
                    service: "svc".to_string(),
                    address: "10.0.1.1".to_string(),
                    port: 80,
                    tags: vec![], // no fluxo-lb tag
                },
            }],
        );

        let config = provider.build_config_from_catalog(&catalog);
        let upstream = config.upstreams.get("svc").unwrap();
        assert_eq!(upstream.load_balancing, "round_robin");
    }

    #[test]
    fn build_config_from_catalog_custom_listener() {
        let rt = runtime(consul_toml_config())
            .with_discovery_listener("0.0.0.0:443".to_string());
        let provider = KvProvider::new(rt).unwrap();

        let mut catalog = HashMap::new();
        catalog.insert(
            "web".to_string(),
            vec![ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.1".to_string(),
                },
                service: ConsulService {
                    service: "web".to_string(),
                    address: "10.0.1.1".to_string(),
                    port: 8080,
                    tags: vec!["fluxo-host=example.com".to_string()],
                },
            }],
        );

        let config = provider.build_config_from_catalog(&catalog);
        let svc = config.services.get("consul-discovery").unwrap();
        assert_eq!(svc.listeners[0].address, "0.0.0.0:443");
    }

    #[test]
    fn build_config_from_catalog_multi_host_tag() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();

        let mut catalog = HashMap::new();
        catalog.insert(
            "web".to_string(),
            vec![ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.1".to_string(),
                },
                service: ConsulService {
                    service: "web".to_string(),
                    address: "10.0.1.1".to_string(),
                    port: 8080,
                    tags: vec!["fluxo-host=example.com, www.example.com".to_string()],
                },
            }],
        );

        let config = provider.build_config_from_catalog(&catalog);
        let svc = config.services.get("consul-discovery").unwrap();
        let route = &svc.routes[0];
        assert_eq!(route.match_host.len(), 2);
        assert!(route.match_host.contains(&"example.com".to_string()));
        assert!(route.match_host.contains(&"www.example.com".to_string()));
    }

    // --- etcd response parsing ---

    #[test]
    fn parse_etcd_range_response_with_value() {
        let key_b64 = base64::engine::general_purpose::STANDARD.encode("fluxo/config");
        let value_b64 =
            base64::engine::general_purpose::STANDARD.encode("[global]\nadmin = \"127.0.0.1:2019\"");

        let json = format!(
            r#"{{
                "header": {{"cluster_id": "1234", "member_id": "5678", "revision": "42"}},
                "kvs": [
                    {{
                        "key": "{key_b64}",
                        "value": "{value_b64}",
                        "create_revision": "10",
                        "mod_revision": 42,
                        "version": "3"
                    }}
                ],
                "count": "1"
            }}"#
        );

        let resp: EtcdRangeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp.kvs.len(), 1);
        assert_eq!(resp.kvs[0].mod_revision, 42);

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&resp.kvs[0].value)
            .unwrap();
        let value = String::from_utf8(decoded).unwrap();
        assert!(value.contains("[global]"));
    }

    #[test]
    fn parse_etcd_range_response_empty() {
        let json = r#"{"header": {}, "kvs": []}"#;
        let resp: EtcdRangeResponse = serde_json::from_str(json).unwrap();
        assert!(resp.kvs.is_empty());
    }

    #[test]
    fn parse_etcd_range_response_missing_kvs() {
        let json = r#"{"header": {}}"#;
        let resp: EtcdRangeResponse = serde_json::from_str(json).unwrap();
        assert!(resp.kvs.is_empty());
    }

    #[test]
    fn parse_etcd_watch_response_put_event() {
        let key_b64 = base64::engine::general_purpose::STANDARD.encode("fluxo/config");
        let value_b64 = base64::engine::general_purpose::STANDARD.encode("updated config");

        let json = format!(
            r#"{{
                "result": {{
                    "events": [
                        {{
                            "type": "PUT",
                            "kv": {{
                                "key": "{key_b64}",
                                "value": "{value_b64}",
                                "mod_revision": 55
                            }}
                        }}
                    ]
                }}
            }}"#
        );

        let resp: EtcdWatchResponse = serde_json::from_str(&json).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].event_type, "PUT");
        let kv = result.events[0].kv.as_ref().unwrap();
        assert_eq!(kv.mod_revision, 55);
    }

    #[test]
    fn parse_etcd_watch_response_delete_event() {
        let key_b64 = base64::engine::general_purpose::STANDARD.encode("fluxo/config");

        let json = format!(
            r#"{{
                "result": {{
                    "events": [
                        {{
                            "type": "DELETE",
                            "kv": {{
                                "key": "{key_b64}",
                                "value": "",
                                "mod_revision": 60
                            }}
                        }}
                    ]
                }}
            }}"#
        );

        let resp: EtcdWatchResponse = serde_json::from_str(&json).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result.events[0].event_type, "DELETE");
    }

    #[test]
    fn parse_etcd_watch_response_no_result() {
        let json = r#"{}"#;
        let resp: EtcdWatchResponse = serde_json::from_str(json).unwrap();
        assert!(resp.result.is_none());
    }

    #[test]
    fn parse_etcd_watch_response_empty_events() {
        let json = r#"{"result": {"events": []}}"#;
        let resp: EtcdWatchResponse = serde_json::from_str(json).unwrap();
        let result = resp.result.unwrap();
        assert!(result.events.is_empty());
    }

    // --- Exponential backoff ---

    #[test]
    fn backoff_starts_at_1_second() {
        let mut backoff = ExponentialBackoff::new();
        let delay = backoff.next_delay();
        // Base is 1s, with up to 250ms jitter.
        assert!(delay >= Duration::from_secs(1));
        assert!(delay <= Duration::from_millis(1250));
    }

    #[test]
    fn backoff_doubles() {
        let mut backoff = ExponentialBackoff::new();
        let _ = backoff.next_delay(); // 1s
        let delay = backoff.next_delay(); // 2s + jitter
        assert!(delay >= Duration::from_secs(2));
        assert!(delay <= Duration::from_millis(2500));
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut backoff = ExponentialBackoff::new();
        // Advance past max (1 -> 2 -> 4 -> 8 -> 16 -> 32 -> 60 -> 60).
        for _ in 0..10 {
            let _ = backoff.next_delay();
        }
        let delay = backoff.next_delay();
        // Should be capped at 60s + jitter.
        assert!(delay <= Duration::from_secs(75));
    }

    #[test]
    fn backoff_reset_restarts() {
        let mut backoff = ExponentialBackoff::new();
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();
        backoff.reset();
        let delay = backoff.next_delay();
        assert!(delay >= Duration::from_secs(1));
        assert!(delay <= Duration::from_millis(1250));
    }

    // --- KvBackend enum ---

    #[test]
    fn kv_backend_equality() {
        assert_eq!(KvBackend::Consul, KvBackend::Consul);
        assert_eq!(KvBackend::Etcd, KvBackend::Etcd);
        assert_ne!(KvBackend::Consul, KvBackend::Etcd);
    }

    #[test]
    fn kv_backend_clone() {
        let a = KvBackend::Consul;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn kv_backend_debug() {
        assert_eq!(format!("{:?}", KvBackend::Consul), "Consul");
        assert_eq!(format!("{:?}", KvBackend::Etcd), "Etcd");
    }

    // --- Provider construction ---

    #[test]
    fn kv_provider_new_succeeds() {
        let provider = KvProvider::new(runtime(consul_toml_config()));
        assert!(provider.is_ok());
    }

    #[test]
    fn kv_provider_from_toml_succeeds() {
        let provider = KvProvider::from_toml(consul_toml_config());
        assert!(provider.is_ok());
        assert_eq!(provider.unwrap().name(), "consul");
    }

    #[test]
    fn kv_provider_new_with_custom_config() {
        let cfg = KvProviderConfig {
            backend: KvBackend::Etcd,
            endpoints: vec![
                "http://etcd-1:2379".to_string(),
                "http://etcd-2:2379".to_string(),
            ],
            prefix: "myapp".to_string(),
            token: Some("secret-token".to_string()),
            poll_interval: "5s".to_string(),
            tls_skip_verify: true,
            consul_datacenter: None,
            consul_namespace: None,
            service_discovery: false,
        };
        let provider = KvProvider::new(runtime(cfg)).unwrap();
        assert_eq!(provider.name(), "etcd");
        assert_eq!(provider.config.inner.prefix, "myapp");
        assert_eq!(provider.config.inner.endpoints.len(), 2);
        assert!(provider.config.inner.token.is_some());
    }

    // --- Consul service catalog JSON ---

    #[test]
    fn parse_consul_catalog_services_response() {
        let json = r#"{
            "web": ["fluxo-host=example.com", "v1"],
            "api": ["fluxo-host=api.example.com", "fluxo-path=/api/*"],
            "internal": ["monitoring"]
        }"#;

        let catalog: HashMap<String, Vec<String>> = serde_json::from_str(json).unwrap();
        let filtered: Vec<String> = catalog
            .into_iter()
            .filter(|(_, tags)| tags.iter().any(|t| t.starts_with("fluxo-")))
            .map(|(name, _)| name)
            .collect();

        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"web".to_string()));
        assert!(filtered.contains(&"api".to_string()));
        assert!(!filtered.contains(&"internal".to_string()));
    }

    // --- Route name generation ---

    #[test]
    fn catalog_route_names_have_consul_prefix() {
        let provider = KvProvider::new(runtime(consul_toml_config())).unwrap();

        let mut catalog = HashMap::new();
        catalog.insert(
            "my-service".to_string(),
            vec![ConsulHealthEntry {
                node: ConsulNode {
                    address: "10.0.1.1".to_string(),
                },
                service: ConsulService {
                    service: "my-service".to_string(),
                    address: "10.0.1.1".to_string(),
                    port: 8080,
                    tags: vec![],
                },
            }],
        );

        let config = provider.build_config_from_catalog(&catalog);
        let svc = config.services.get("consul-discovery").unwrap();
        assert_eq!(
            svc.routes[0].name.as_deref(),
            Some("consul-my-service")
        );
    }

    // --- Base64 encoding for etcd ---

    #[test]
    fn etcd_key_encoding() {
        let key = "fluxo/config";
        let encoded = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), key);
    }

    #[test]
    fn etcd_value_roundtrip() {
        let toml_str = r#"[global]
admin = "127.0.0.1:2019"

[upstreams.backend]
targets = ["10.0.1.1:8080"]
"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(toml_str.as_bytes());
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), toml_str);
    }

    // --- Full TOML config round-trip via KV ---

    #[test]
    fn consul_kv_value_parses_as_fluxo_config() {
        let toml_str = r#"
[global]
admin = "127.0.0.1:2019"

[services.web]
listeners = [{ address = "0.0.0.0:8080" }]

[[services.web.routes]]
match_path = ["/*"]
upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = super::super::load_from_str(toml_str);
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(config.upstreams.contains_key("backend"));
        assert!(config.services.contains_key("web"));
    }

    #[test]
    fn consul_kv_invalid_toml_returns_error() {
        let bad_toml = "this is {{ not valid toml [[";
        let result = super::super::load_from_str(bad_toml);
        assert!(result.is_err());
    }

    // --- KvProviderConfig edge cases ---

    #[test]
    fn config_with_consul_enterprise_fields() {
        let cfg = KvProviderConfig {
            consul_datacenter: Some("dc1".to_string()),
            consul_namespace: Some("production".to_string()),
            ..consul_toml_config()
        };
        assert_eq!(cfg.consul_datacenter.as_deref(), Some("dc1"));
        assert_eq!(cfg.consul_namespace.as_deref(), Some("production"));
    }

    #[test]
    fn config_with_service_discovery_enabled() {
        let mut cfg = consul_toml_config();
        cfg.service_discovery = true;
        let rt = runtime(cfg)
            .with_discovery_services(vec![
                "web".to_string(),
                "api".to_string(),
                "grpc-backend".to_string(),
            ]);
        assert_eq!(rt.discovery_services.len(), 3);
        assert!(rt.inner.service_discovery);
    }

    // --- KvProviderConfig serde ---

    #[test]
    fn kv_backend_deserializes_from_lowercase() {
        let json = r#""consul""#;
        let backend: KvBackend = serde_json::from_str(json).unwrap();
        assert_eq!(backend, KvBackend::Consul);

        let json = r#""etcd""#;
        let backend: KvBackend = serde_json::from_str(json).unwrap();
        assert_eq!(backend, KvBackend::Etcd);
    }

    #[test]
    fn kv_provider_config_deserializes_from_toml() {
        let toml_str = r#"
backend = "consul"
endpoints = ["http://consul:8500"]
prefix = "myapp"
poll_interval = "30s"
service_discovery = true
"#;
        let cfg: KvProviderConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.backend, KvBackend::Consul);
        assert_eq!(cfg.endpoints, vec!["http://consul:8500"]);
        assert_eq!(cfg.prefix, "myapp");
        assert_eq!(cfg.poll_interval, "30s");
        assert!(cfg.service_discovery);
    }
}
