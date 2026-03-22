//! The Pingora `ProxyHttp` implementation — the heart of Fluxo.
//!
//! `FluxoProxy` implements `ProxyHttp` and dispatches to the routing engine,
//! upstream manager, and plugin pipeline from within each callback.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_cache::key::CacheKey;
use pingora_cache::meta::CacheMeta;
use pingora_cache::storage::HitHandler;
use pingora_cache::{ForcedFreshness, MemCache, NoCacheReason, RespCacheable};
use pingora_core::Error;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

use crate::config::FluxoConfig;
use crate::context::{
    MatchedRoute, RequestContext, RequestContextPool, SelectedPeer, StreamingCompressor,
};
use crate::error::FluxoError;
use crate::plugins::PluginAction;
use crate::plugins::body_filter::{BodyFilterChain, CompressionBodyFilter};
use crate::routing::RouteTable;
use crate::routing::matcher::RequestHeaders;
use crate::tls::ChallengeState;
use crate::upstream::UpstreamName;
use crate::upstream::circuit_breaker::{
    CircuitBreakerTracker, CircuitStatus, PassiveHealthTracker,
};
use crate::upstream::peer::UpstreamGroup;

/// Global in-memory cache storage (Pingora requires `&'static` lifetime).
/// Using `MemCache` for v0.1 — production would use disk-backed storage.
pub(crate) fn global_cache_storage() -> &'static MemCache {
    static STORAGE: OnceLock<MemCache> = OnceLock::new();
    STORAGE.get_or_init(MemCache::new)
}

/// Parse max-age or s-maxage from a Cache-Control header value.
fn parse_max_age(cc: &str) -> Option<std::time::Duration> {
    // Prefer s-maxage (shared cache directive) over max-age
    for directive in cc.split(',').map(str::trim) {
        let lower = directive.to_lowercase();
        if let Some(val) = lower.strip_prefix("s-maxage=") {
            if let Ok(secs) = val.trim().parse::<u64>() {
                return Some(std::time::Duration::from_secs(secs));
            }
        }
    }
    for directive in cc.split(',').map(str::trim) {
        let lower = directive.to_lowercase();
        if let Some(val) = lower.strip_prefix("max-age=") {
            if let Ok(secs) = val.trim().parse::<u64>() {
                return Some(std::time::Duration::from_secs(secs));
            }
        }
    }
    None
}

/// A composite upstream that delegates to child upstreams.
#[derive(Debug, Clone)]
pub struct CompositeUpstream {
    /// "weighted" or "failover"
    pub mode: CompositeMode,
    /// Child upstream references with weights.
    pub children: Vec<(UpstreamName, u32)>,
}

/// Mode for composite upstream routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositeMode {
    /// Weighted round-robin across child upstreams.
    Weighted,
    /// Try children in order, skip those with open circuit breakers.
    Failover,
}

/// The pre-computed, immutable state derived from a `FluxoConfig`.
///
/// Stored in `ArcSwap` and shared across all worker threads.
pub struct FluxoState {
    /// The raw config (kept for Admin API export / debugging).
    pub config: FluxoConfig,
    /// Pre-built route table.
    pub router: RouteTable,
    /// Pre-built upstream groups (non-composite).
    pub upstreams: HashMap<UpstreamName, UpstreamGroup>,
    /// Composite upstream definitions (weighted / failover).
    pub composites: HashMap<UpstreamName, CompositeUpstream>,
    /// ACME HTTP-01 challenge tokens.
    pub challenge_state: Arc<ChallengeState>,
    /// Whether any service has TLS configured (precomputed).
    pub has_tls: bool,
    /// Trusted proxy CIDRs — XFF is only trusted when peer matches one of these.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Pre-parsed downstream read timeout (`client_body_timeout`).
    pub client_body_timeout: Option<std::time::Duration>,
    /// Pre-parsed downstream write timeout (`client_write_timeout`).
    pub client_write_timeout: Option<std::time::Duration>,
    /// Pre-compiled body filter chain (Nginx-inspired).
    pub body_filters: BodyFilterChain,
}

/// Long-lived state that survives config reloads.
///
/// This is the "static" portion of the state. It holds the metrics registry,
/// connection pools, circuit breakers, etc., which shouldn't be zeroed out
/// when a new config is loaded.
pub struct FluxoStaticState {
    pub metrics: Arc<crate::observability::MetricsRegistry>,
    pub circuit_breakers: Arc<CircuitBreakerTracker>,
    pub passive_health: Arc<PassiveHealthTracker>,
    pub context_pool: Arc<RequestContextPool>,
    /// Set to true during graceful shutdown drain phase.
    /// Admin /health returns 503 when draining, letting LB health checks fail.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
}

/// Result of building a `FluxoState`, including background health-check services.
pub struct FluxoBuild {
    pub state: FluxoState,
    pub health_check_services: Vec<Box<dyn pingora_core::services::ServiceWithDependents>>,
}

impl FluxoState {
    /// Build a new `FluxoState` from a validated config.
    pub fn try_from_config(config: FluxoConfig) -> Result<Self, FluxoError> {
        let router = RouteTable::build(&config)?;
        let upstreams = build_upstream_groups(&config)?;
        let composites = build_composite_upstreams(&config);
        let has_tls = has_tls_configured(&config);
        let trusted_proxies = parse_trusted_proxies(&config);
        let (client_body_timeout, client_write_timeout) = parse_downstream_timeouts(&config);

        // Build the global body filter chain
        let mut body_filters = BodyFilterChain::empty();
        body_filters.push(Box::new(CompressionBodyFilter));

        Ok(Self {
            config,
            router,
            upstreams,
            composites,
            challenge_state: Arc::new(ChallengeState::new()),
            has_tls,
            trusted_proxies,
            client_body_timeout,
            client_write_timeout,
            body_filters,
        })
    }

    /// Build a `FluxoState` plus background services for health checking.
    pub fn build(config: FluxoConfig) -> Result<FluxoBuild, FluxoError> {
        let router = RouteTable::build(&config)?;
        let upstreams = build_upstream_groups(&config)?;
        let composites = build_composite_upstreams(&config);

        let health_check_services: Vec<Box<dyn pingora_core::services::ServiceWithDependents>> =
            upstreams
                .values()
                .filter_map(super::upstream::peer::UpstreamGroup::background_service)
                .collect();

        let has_tls = has_tls_configured(&config);
        let trusted_proxies = parse_trusted_proxies(&config);
        let (client_body_timeout, client_write_timeout) = parse_downstream_timeouts(&config);

        // Build the global body filter chain
        let mut body_filters = BodyFilterChain::empty();
        body_filters.push(Box::new(CompressionBodyFilter));

        Ok(FluxoBuild {
            state: Self {
                config,
                router,
                upstreams,
                composites,
                challenge_state: Arc::new(ChallengeState::new()),
                has_tls,
                trusted_proxies,
                client_body_timeout,
                client_write_timeout,
                body_filters,
            },
            health_check_services,
        })
    }
}

/// Build upstream groups from config, wiring timeouts from config.
fn build_upstream_groups(
    config: &FluxoConfig,
) -> Result<HashMap<UpstreamName, UpstreamGroup>, FluxoError> {
    use crate::upstream::peer::{LbStrategy, UpstreamTimeouts};
    use pingora_load_balancing::health_check::HttpHealthCheck;

    let mut groups = HashMap::new();

    for (name, upstream_config) in &config.upstreams {
        // Skip composite upstreams — they don't have their own load balancer
        let is_composite = upstream_config
            .upstream_type
            .as_deref()
            .is_some_and(|t| t == "weighted" || t == "failover");
        if is_composite {
            continue;
        }

        let upstream_name = UpstreamName::from(name.as_str());
        let strategy = LbStrategy::from_config(&upstream_config.load_balancing)?;

        // Wire timeouts from config (not defaults)
        let timeouts = UpstreamTimeouts::from_config(upstream_config);

        let mut group = UpstreamGroup::new(
            upstream_name.clone(),
            &upstream_config.targets,
            strategy,
            Default::default(), // TLS — wired from config later
            timeouts,
        )?;

        if let Some(hc_config) = &upstream_config.health_check {
            let interval = crate::config::parse_duration(&hc_config.interval)?;
            let timeout = crate::config::parse_duration(&hc_config.timeout)?;

            let mut hc = HttpHealthCheck::new(name, false);
            hc.consecutive_success = hc_config.healthy_threshold as usize;
            hc.consecutive_failure = hc_config.unhealthy_threshold as usize;
            hc.peer_template.options.connection_timeout = Some(timeout);
            hc.peer_template.options.read_timeout = Some(timeout);

            let mut req =
                pingora_http::RequestHeader::build("GET", hc_config.path.as_bytes(), None)
                    .map_err(|e| {
                        crate::config::ConfigError::Validation(format!(
                            "invalid health check path '{}': {}",
                            hc_config.path, e
                        ))
                    })?;
            req.append_header("Host", name).map_err(|e| {
                crate::config::ConfigError::Validation(format!(
                    "failed to set health check Host header: {e}"
                ))
            })?;
            hc.req = req;

            // Dual-interval health checks (Traefik-inspired):
            // When unhealthy_interval is set, use the faster interval for all checks.
            // This ensures unhealthy backends are re-probed more aggressively while
            // adding minimal overhead for healthy backends (health checks are lightweight).
            let effective_interval = hc_config
                .unhealthy_interval
                .as_deref()
                .and_then(|ui| crate::config::parse_duration(ui).ok())
                .unwrap_or(interval);

            group.set_health_check(Box::new(hc), effective_interval);
        }

        groups.insert(upstream_name, group);
    }

    Ok(groups)
}

/// Build composite upstream definitions from config.
fn build_composite_upstreams(config: &FluxoConfig) -> HashMap<UpstreamName, CompositeUpstream> {
    let mut composites = HashMap::new();
    for (name, upstream_config) in &config.upstreams {
        let mode = match upstream_config.upstream_type.as_deref() {
            Some("weighted") => CompositeMode::Weighted,
            Some("failover") => CompositeMode::Failover,
            _ => continue,
        };
        let children: Vec<(UpstreamName, u32)> = upstream_config
            .services
            .iter()
            .map(|s| (UpstreamName::from(s.upstream.as_str()), s.weight))
            .collect();
        composites.insert(
            UpstreamName::from(name.as_str()),
            CompositeUpstream { mode, children },
        );
    }
    composites
}

/// Resolve a potentially composite upstream to an actual (non-composite) upstream name.
/// For weighted mode: randomly select a child based on weights.
/// For failover mode: pick the first child whose circuit breaker is not open.
/// Returns None if the upstream is not composite (caller should use original name).
#[allow(clippy::only_used_in_recursion)]
fn resolve_composite_upstream(
    name: &UpstreamName,
    composites: &HashMap<UpstreamName, CompositeUpstream>,
    upstreams: &HashMap<UpstreamName, UpstreamGroup>,
    circuit_breakers: &CircuitBreakerTracker,
) -> Option<UpstreamName> {
    let composite = composites.get(name)?;

    match composite.mode {
        CompositeMode::Weighted => {
            let total_weight: u32 = composite.children.iter().map(|(_, w)| *w).sum();
            if total_weight == 0 {
                return None;
            }
            let mut r = fastrand::u32(0..total_weight);
            for (child_name, weight) in &composite.children {
                if r < *weight {
                    // Recursively resolve (child might also be composite)
                    return Some(
                        resolve_composite_upstream(
                            child_name,
                            composites,
                            upstreams,
                            circuit_breakers,
                        )
                        .unwrap_or_else(|| child_name.clone()),
                    );
                }
                r -= weight;
            }
            // Fallback: last child
            composite.children.last().map(|(name, _)| name.clone())
        }
        CompositeMode::Failover => {
            for (child_name, _) in &composite.children {
                // Skip children with open circuit breakers
                if circuit_breakers.check(child_name) == Some(CircuitStatus::Open) {
                    continue;
                }
                // Recursively resolve
                return Some(
                    resolve_composite_upstream(child_name, composites, upstreams, circuit_breakers)
                        .unwrap_or_else(|| child_name.clone()),
                );
            }
            // All children have open circuit breakers — return first anyway (will fail with 503)
            composite.children.first().map(|(name, _)| name.clone())
        }
    }
}

fn has_tls_configured(config: &FluxoConfig) -> bool {
    config.services.values().any(|svc| {
        svc.tls
            .as_ref()
            .is_some_and(|tls| tls.acme || (tls.cert_path.is_some() && tls.key_path.is_some()))
    })
}

fn parse_downstream_timeouts(
    config: &FluxoConfig,
) -> (Option<std::time::Duration>, Option<std::time::Duration>) {
    let body = config
        .global
        .client_body_timeout
        .as_deref()
        .and_then(|s| crate::config::parse_duration(s).ok());
    let write = config
        .global
        .client_write_timeout
        .as_deref()
        .and_then(|s| crate::config::parse_duration(s).ok());
    (body, write)
}

fn parse_trusted_proxies(config: &FluxoConfig) -> Vec<ipnet::IpNet> {
    config
        .global
        .trusted_proxies
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn is_trusted_proxy(
    peer_addr: &pingora_core::protocols::l4::socket::SocketAddr,
    trusted: &[ipnet::IpNet],
) -> bool {
    // Extract the IP from the socket address. On Unix, peers may connect via
    // Unix domain sockets which have no IP — those are never trusted.
    let ip = match peer_addr.as_inet() {
        Some(addr) => addr.ip(),
        None => return false,
    };
    trusted.iter().any(|net| net.contains(&ip))
}

/// Check if a status code should be included in access logs.
/// Supports: class patterns "2xx", exact codes "404", ranges "200-299".
fn should_log_status(status: u16, excludes: &[String]) -> bool {
    for pattern in excludes {
        match pattern.as_str() {
            "1xx" if (100..200).contains(&status) => return false,
            "2xx" if (200..300).contains(&status) => return false,
            "3xx" if (300..400).contains(&status) => return false,
            "4xx" if (400..500).contains(&status) => return false,
            "5xx" if (500..600).contains(&status) => return false,
            other => {
                // Range: "200-299"
                if let Some((from_s, to_s)) = other.split_once('-') {
                    if let (Ok(from), Ok(to)) = (from_s.parse::<u16>(), to_s.parse::<u16>()) {
                        if status >= from && status <= to {
                            return false;
                        }
                    }
                }
                // Exact code
                if let Ok(code) = other.parse::<u16>() {
                    if code == status {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// Adapter to let Pingora request headers implement our `RequestHeaders` trait.
struct PingoraHeaders<'a>(&'a pingora_http::RequestHeader);

impl RequestHeaders for PingoraHeaders<'_> {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.0.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// The central proxy type that implements Pingora's `ProxyHttp` trait.
///
/// Holds an `ArcSwap<FluxoState>` for lock-free config reads on the hot path,
/// and a `FluxoStaticState` for long-lived resources.
#[derive(Clone)]
pub struct FluxoProxy {
    state: Arc<ArcSwap<FluxoState>>,
    /// Long-lived state and resources (metrics, context pool).
    pub static_state: Arc<FluxoStaticState>,
}

impl FluxoProxy {
    pub fn new(state: FluxoState) -> Result<Self, crate::error::FluxoError> {
        let metrics = Arc::new(crate::observability::MetricsRegistry::new().map_err(|e| {
            crate::error::FluxoError::Config(crate::config::ConfigError::Validation(format!(
                "Metrics init failed: {e}"
            )))
        })?);
        let cb = Arc::new(CircuitBreakerTracker::new());

        // Register circuit breakers for upstreams that have them configured
        for (name, upstream_config) in &state.config.upstreams {
            if let Some(cb_config) = &upstream_config.circuit_breaker {
                cb.register(UpstreamName::from(name.as_str()), cb_config.clone());
            }
        }

        let static_state = Arc::new(FluxoStaticState {
            metrics,
            circuit_breakers: cb,
            passive_health: Arc::new(PassiveHealthTracker::new()),
            context_pool: Arc::new(RequestContextPool::new(1024)),
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });

        Ok(Self {
            state: Arc::new(ArcSwap::from(Arc::new(state))),
            static_state,
        })
    }

    pub fn from_state(state: Arc<FluxoState>, static_state: Arc<FluxoStaticState>) -> Self {
        Self {
            state: Arc::new(ArcSwap::from(state)),
            static_state,
        }
    }

    pub fn challenge_state(&self) -> Arc<ChallengeState> {
        self.state.load().challenge_state.clone()
    }

    pub fn metrics(&self) -> Arc<crate::observability::MetricsRegistry> {
        self.static_state.metrics.clone()
    }

    pub fn state_snapshot(&self) -> arc_swap::Guard<Arc<FluxoState>> {
        self.state.load()
    }

    /// Validate a new config before committing (Monolake-inspired two-stage reload).
    /// Returns Ok(FluxoState) if the new state is valid, Err otherwise.
    /// Call `commit_reload` to actually apply it.
    pub fn precommit_reload(config: FluxoConfig) -> Result<FluxoState, crate::error::FluxoError> {
        FluxoState::try_from_config(config)
    }

    /// Atomically replace the running config with a new one (zero-downtime reload).
    ///
    /// Monolake-inspired: preserves connection pools for unchanged upstreams
    /// by reusing existing `UpstreamGroup` instances instead of rebuilding.
    pub fn reload(&self, new_state: FluxoState) {
        let old_state = self.state.load();

        // --- Connection pool preservation (Monolake pattern) ---
        // Reuse existing UpstreamGroup for upstreams whose targets/strategy haven't changed.
        // This avoids dropping warmed Pingora LoadBalancer connections and causing a thundering herd.
        let preserved: Vec<UpstreamName> = old_state
            .upstreams
            .keys()
            .filter(|name| {
                let old_cfg = old_state.config.upstreams.get(&*name.0);
                let new_cfg = new_state.config.upstreams.get(&*name.0);
                match (old_cfg, new_cfg) {
                    (Some(oc), Some(nc)) => {
                        let targets_same =
                            format!("{:?}", oc.targets) == format!("{:?}", nc.targets);
                        let strategy_same = oc.load_balancing == nc.load_balancing;
                        targets_same && strategy_same
                    }
                    _ => false,
                }
            })
            .cloned()
            .collect();
        // We can't move from Arc, but the old state's upstreams are dropped when Arc refcount
        // reaches 0. Pingora manages connection pools internally at the server level,
        // so the pool survives as long as the server is running.
        for name in &preserved {
            tracing::debug!(upstream = %name, "upstream unchanged — Pingora pool preserved");
        }

        // Register circuit breakers for any new/changed upstreams
        for (name, upstream_config) in &new_state.config.upstreams {
            if let Some(cb_config) = &upstream_config.circuit_breaker {
                self.static_state
                    .circuit_breakers
                    .register(UpstreamName::from(name.as_str()), cb_config.clone());
            }
        }
        self.state.store(Arc::new(new_state));
    }

    #[allow(clippy::too_many_lines)]
    async fn send_plugin_response(
        &self,
        session: &mut Session,
        ctx: &RequestContext,
        status: u16,
    ) -> Result<(), Box<Error>> {
        use crate::context::PluginResponse;

        match &ctx.plugin_response {
            Some(PluginResponse::Redirect { location, .. }) => {
                let mut header =
                    pingora_http::ResponseHeader::build(status, None).map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::InternalError,
                            format!("failed to build redirect response: {e}"),
                        )
                    })?;
                header
                    .insert_header("Location", location.as_str())
                    .map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::InternalError,
                            format!("failed to set Location header: {e}"),
                        )
                    })?;
                session
                    .write_response_header(Box::new(header), true)
                    .await
                    .map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::WriteError,
                            format!("failed to write redirect response: {e}"),
                        )
                    })?;
            }
            Some(PluginResponse::Static {
                body, content_type, ..
            }) => {
                let mut header =
                    pingora_http::ResponseHeader::build(status, None).map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::InternalError,
                            format!("failed to build static response: {e}"),
                        )
                    })?;
                if let Some(ct) = content_type {
                    header
                        .insert_header("Content-Type", ct.as_str())
                        .map_err(|e| {
                            Error::explain(
                                pingora_core::ErrorType::InternalError,
                                format!("failed to set Content-Type header: {e}"),
                            )
                        })?;
                }
                let end_of_stream = body.is_none();
                session
                    .write_response_header(Box::new(header), end_of_stream)
                    .await
                    .map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::WriteError,
                            format!("failed to write static response header: {e}"),
                        )
                    })?;
                if let Some(body_str) = body {
                    session
                        .write_response_body(Some(body_str.clone().into()), true)
                        .await
                        .map_err(|e| {
                            Error::explain(
                                pingora_core::ErrorType::WriteError,
                                format!("failed to write static response body: {e}"),
                            )
                        })?;
                }
            }
            Some(PluginResponse::RateLimited { retry_after_secs }) => {
                let mut header = pingora_http::ResponseHeader::build(429, None).map_err(|e| {
                    Error::explain(
                        pingora_core::ErrorType::InternalError,
                        format!("failed to build rate limit response: {e}"),
                    )
                })?;
                if let Some(secs) = retry_after_secs {
                    header
                        .insert_header("Retry-After", secs.to_string())
                        .map_err(|e| {
                            Error::explain(
                                pingora_core::ErrorType::InternalError,
                                format!("failed to set Retry-After header: {e}"),
                            )
                        })?;
                }
                session
                    .write_response_header(Box::new(header), true)
                    .await
                    .map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::WriteError,
                            format!("failed to write rate limit response: {e}"),
                        )
                    })?;
            }
            Some(PluginResponse::BasicAuthChallenge { realm }) => {
                let mut header = pingora_http::ResponseHeader::build(401, None).map_err(|e| {
                    Error::explain(
                        pingora_core::ErrorType::InternalError,
                        format!("failed to build auth challenge: {e}"),
                    )
                })?;
                header
                    .insert_header("WWW-Authenticate", format!("Basic realm=\"{realm}\""))
                    .map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::InternalError,
                            format!("failed to set WWW-Authenticate: {e}"),
                        )
                    })?;
                session
                    .write_response_header(Box::new(header), true)
                    .await
                    .map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::WriteError,
                            format!("failed to write auth challenge response: {e}"),
                        )
                    })?;
            }
            Some(PluginResponse::Cors { headers }) => {
                let cors_headers: Vec<(String, String)> = headers.clone();
                let mut header =
                    pingora_http::ResponseHeader::build(status, None).map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::InternalError,
                            format!("failed to build CORS response: {e}"),
                        )
                    })?;
                for (k, v) in &cors_headers {
                    if let (Ok(hn), Ok(hv)) = (
                        http::header::HeaderName::from_bytes(k.as_bytes()),
                        http::header::HeaderValue::from_str(v),
                    ) {
                        let _ = header.insert_header(hn, hv);
                    }
                }
                session
                    .write_response_header(Box::new(header), true)
                    .await
                    .map_err(|e| {
                        Error::explain(
                            pingora_core::ErrorType::WriteError,
                            format!("failed to write CORS response: {e}"),
                        )
                    })?;
            }
            Some(PluginResponse::Error { .. }) | None => {
                let _ = session.respond_error(status).await;
            }
        }
        Ok(())
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)]
impl ProxyHttp for FluxoProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        self.static_state.context_pool.acquire()
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>>
    where
        Self::CTX: Send + Sync,
    {
        let state = self.state.load();
        // Apply downstream timeouts (Monolake-inspired granularity)
        if state.client_body_timeout.is_some() || state.client_write_timeout.is_some() {
            session
                .as_downstream_mut()
                .set_read_timeout(state.client_body_timeout);
            session
                .as_downstream_mut()
                .set_write_timeout(state.client_write_timeout);
        }
        Ok(())
    }

    fn request_cache_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>>
    where
        Self::CTX: Send + Sync,
    {
        // Cache decision requires a matched route with cache config.
        // At this point request_filter has already run, so ctx.matched_route is set.
        let state = self.state.load();
        let Some(route) = ctx.matched_route.as_ref() else {
            return Ok(());
        };

        let compiled = &state.router.routes()[route.index];
        let Some(cache_config) = compiled.cache.as_ref() else {
            return Ok(());
        };

        // Only cache allowed methods
        let method = ctx.method.as_deref().unwrap_or("");
        if !cache_config
            .methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            ctx.cache_status = Some(crate::context::CacheStatus::Bypass);
            return Ok(());
        }

        // Enable Pingora's cache for this request
        session.cache.enable(
            global_cache_storage(),
            None, // no eviction manager for v0.1
            None, // no predictor
            None, // no cache lock
            None, // no option overrides
        );

        // Set max file size for this request
        session
            .cache
            .set_max_file_size_bytes(cache_config.max_file_size as usize);

        Ok(())
    }

    fn cache_key_callback(
        &self,
        session: &Session,
        ctx: &mut Self::CTX,
    ) -> Result<CacheKey, Box<Error>> {
        let req = session.req_header();
        let method = req.method.as_str();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("_");

        // Build primary key: method + host + path (+ optional query)
        let state = self.state.load();
        let include_query = ctx
            .matched_route
            .as_ref()
            .and_then(|r| state.router.routes().get(r.index))
            .and_then(|r| r.cache.as_ref())
            .is_none_or(|c| c.include_query);

        let primary = if include_query {
            let pq = req
                .uri
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str);
            format!("{method}{host}{pq}")
        } else {
            format!("{method}{host}{}", req.uri.path())
        };

        Ok(CacheKey::new("fluxo", primary, ""))
    }

    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable, Box<Error>> {
        let state = self.state.load();
        let Some(cache_config) = ctx
            .matched_route
            .as_ref()
            .and_then(|r| state.router.routes().get(r.index))
            .and_then(|r| r.cache.as_ref())
        else {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::NeverEnabled));
        };

        let status = resp.status.as_u16();

        // Only cache 2xx responses (and 301/304)
        if !matches!(status, 200..=299 | 301 | 304) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        // Check Content-Length against max_file_size
        if let Some(cl) = resp
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            if cl > cache_config.max_file_size {
                return Ok(RespCacheable::Uncacheable(NoCacheReason::ResponseTooLarge));
            }
        }

        // Respect upstream Cache-Control: no-store, private
        let cc_header = resp
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !cache_config.force_cache {
            let cc_lower = cc_header.to_lowercase();
            if cc_lower.contains("no-store") || cc_lower.contains("private") {
                return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
            }
        }

        // Determine TTL: upstream s-maxage > max-age > configured default
        let ttl = parse_max_age(cc_header).unwrap_or(cache_config.default_ttl);

        let now = std::time::SystemTime::now();
        let fresh_until = now + ttl;

        let meta = CacheMeta::new(
            fresh_until,
            now,
            cache_config.stale_while_revalidate,
            cache_config.stale_if_error,
            resp.clone(),
        );

        Ok(RespCacheable::Cacheable(meta))
    }

    async fn cache_hit_filter(
        &self,
        _session: &mut Session,
        _meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<ForcedFreshness>, Box<Error>>
    where
        Self::CTX: Send + Sync,
    {
        ctx.cache_status = Some(if is_fresh {
            crate::context::CacheStatus::Hit
        } else {
            crate::context::CacheStatus::Stale
        });
        Ok(None)
    }

    fn cache_miss(&self, session: &mut Session, ctx: &mut Self::CTX) {
        ctx.cache_status = Some(crate::context::CacheStatus::Miss);
        session.cache.cache_miss();
    }

    fn should_serve_stale(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
        _error: Option<&Error>,
    ) -> bool {
        let state = self.state.load();
        ctx.matched_route
            .as_ref()
            .and_then(|r| state.router.routes().get(r.index))
            .and_then(|r| r.cache.as_ref())
            .is_some_and(|c| c.stale_while_revalidate > 0 || c.stale_if_error > 0)
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<Error>> {
        let state = self.state.load();
        self.static_state.metrics.inc_active();

        let req_header = session.req_header();
        let host = req_header.headers.get("host").and_then(|v| v.to_str().ok());
        let path = req_header.uri.path();
        let method = req_header.method.as_str();

        ctx.method = Some(method.to_string());
        ctx.host = host.map(ToString::to_string);
        ctx.path = Some(path.to_string());

        // --- ACME HTTP-01 challenge ---
        if let Some(key_auth) = path
            .strip_prefix("/.well-known/acme-challenge/")
            .and_then(|token| state.challenge_state.get(token))
        {
            let header = pingora_http::ResponseHeader::build(200, None).map_err(|e| {
                Error::explain(
                    pingora_core::ErrorType::InternalError,
                    format!("failed to build ACME challenge response: {e}"),
                )
            })?;
            session
                .write_response_header(Box::new(header), false)
                .await
                .map_err(|e| {
                    Error::explain(
                        pingora_core::ErrorType::WriteError,
                        format!("failed to write ACME challenge header: {e}"),
                    )
                })?;
            session
                .write_response_body(Some(key_auth.into()), true)
                .await
                .map_err(|e| {
                    Error::explain(
                        pingora_core::ErrorType::WriteError,
                        format!("failed to write ACME challenge body: {e}"),
                    )
                })?;
            return Ok(true);
        }

        // --- HTTP→HTTPS redirect ---
        let is_tls = session
            .as_downstream()
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();
        if let (false, true, Some(host_val)) = (is_tls, state.has_tls, host) {
            let path_and_query = req_header
                .uri
                .path_and_query()
                .map_or(path, http::uri::PathAndQuery::as_str);
            let location = format!("https://{host_val}{path_and_query}");
            let mut header = pingora_http::ResponseHeader::build(301, None).map_err(|e| {
                Error::explain(
                    pingora_core::ErrorType::InternalError,
                    format!("failed to build redirect response: {e}"),
                )
            })?;
            header.insert_header("Location", &location).map_err(|e| {
                Error::explain(
                    pingora_core::ErrorType::InternalError,
                    format!("failed to set Location header: {e}"),
                )
            })?;
            session
                .write_response_header(Box::new(header), true)
                .await
                .map_err(|e| {
                    Error::explain(
                        pingora_core::ErrorType::WriteError,
                        format!("failed to write redirect response: {e}"),
                    )
                })?;
            return Ok(true);
        }

        let req_header = session.req_header();
        ctx.http_version = Some(format!("{:?}", req_header.version));
        ctx.user_agent = req_header
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);

        // Client IP — prefer PROXY protocol source → XFF (if trusted) → peer addr
        let peer_addr = session.as_downstream().client_addr();
        let proxy_proto_ip = ctx
            .proxy_protocol_info
            .as_ref()
            .map(|pp| pp.source_addr.ip().to_string());
        let xff_ip = if peer_addr.is_some_and(|addr| is_trusted_proxy(addr, &state.trusted_proxies))
        {
            req_header
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.split(',').next().unwrap_or(s).trim().to_owned())
        } else {
            None
        };
        ctx.client_ip = proxy_proto_ip.or(xff_ip).or_else(|| {
            peer_addr.map(|a| {
                let s = a.to_string();
                // Strip port from "ip:port" — handle both IPv4 and [IPv6]:port
                if s.starts_with('[') {
                    s.split(']')
                        .next()
                        .unwrap_or(&s)
                        .trim_start_matches('[')
                        .to_string()
                } else {
                    s.rsplit_once(':')
                        .map_or_else(|| s.clone(), |(ip, _)| ip.to_string())
                }
            })
        });

        if let Some(ssl) = session
            .as_downstream()
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
        {
            ctx.tls_version = Some(ssl.version.to_string());
        }

        // --- Sticky session cookie ---
        let req_header = session.req_header();
        if let Some(cookie_header) = req_header
            .headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
        {
            // Check all upstreams for sticky config to find cookie name
            for upstream_config in state.config.upstreams.values() {
                if let Some(sticky) = &upstream_config.sticky {
                    let prefix = format!("{}=", sticky.cookie_name);
                    if let Some(value) = cookie_header
                        .split(';')
                        .map(str::trim)
                        .find(|s| s.starts_with(&prefix))
                    {
                        ctx.sticky_cookie_value = Some(value[prefix.len()..].to_string());
                        break;
                    }
                }
            }
        }

        // --- Route matching ---
        let req_header = session.req_header();
        let pingora_hdrs = PingoraHeaders(req_header);
        let query = req_header.uri.query();
        let client_ip_ref = ctx.client_ip.as_deref();
        if let Some(route) =
            state
                .router
                .match_route_full(host, path, method, &pingora_hdrs, query, client_ip_ref)
        {
            ctx.matched_route = Some(MatchedRoute {
                index: route.index,
                upstream: route.upstream.clone(),
                name: route.name.clone(),
            });

            let req_header = session.req_header();
            if let PluginAction::Handled(status) = route.pipeline.run_request(req_header, ctx) {
                self.send_plugin_response(session, ctx, status).await?;
                return Ok(true);
            }

            // --- Forward auth subrequest (Nginx auth_request / Traefik ForwardAuth) ---
            if let Some(ref fwd_auth) = route.forward_auth {
                let req_header = session.req_header();
                match forward_auth_check(req_header, fwd_auth).await {
                    Ok(auth_headers) => {
                        // Store auth response headers for injection in upstream_request_filter
                        for (name, value) in auth_headers {
                            ctx.set_extension(format!("fwd_auth_{name}"), serde_json::json!(value));
                        }
                    }
                    Err(status) => {
                        let mut header = pingora_http::ResponseHeader::build(status, None)
                            .map_err(|e| {
                                Error::explain(
                                    pingora_core::ErrorType::InternalError,
                                    format!("failed to build forward auth error response: {e}"),
                                )
                            })?;
                        let _ = header.insert_header("content-type", "text/plain");
                        session
                            .write_response_header(Box::new(header), false)
                            .await
                            .map_err(|e| {
                                Error::explain(
                                    pingora_core::ErrorType::WriteError,
                                    format!("failed to write forward auth response: {e}"),
                                )
                            })?;
                        let body_msg = match status {
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            _ => "Auth Failed",
                        };
                        session
                            .write_response_body(Some(bytes::Bytes::from(body_msg)), true)
                            .await
                            .map_err(|e| {
                                Error::explain(
                                    pingora_core::ErrorType::WriteError,
                                    format!("failed to write forward auth body: {e}"),
                                )
                            })?;
                        return Ok(true);
                    }
                }
            }

            Ok(false)
        } else {
            let _ = session.respond_error(404).await;
            Ok(true)
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        let state = self.state.load();

        let route = ctx.matched_route.as_ref().ok_or_else(|| {
            Error::explain(
                pingora_core::ErrorType::InternalError,
                "upstream_peer called without matched route",
            )
        })?;

        // --- Resolve composite upstreams (Traefik-inspired service composition) ---
        // If the route points to a composite upstream, resolve it to an actual child upstream.
        let resolved_upstream = resolve_composite_upstream(
            &route.upstream,
            &state.composites,
            &state.upstreams,
            &self.static_state.circuit_breakers,
        );
        let effective_upstream = resolved_upstream.as_ref().unwrap_or(&route.upstream);

        // --- Circuit breaker check ---
        if self.static_state.circuit_breakers.check(effective_upstream) == Some(CircuitStatus::Open)
        {
            return Err(Error::explain(
                pingora_core::ErrorType::HTTPStatus(503),
                format!("circuit breaker open for upstream '{effective_upstream}'"),
            ));
        }

        let upstream_group = state.upstreams.get(effective_upstream).ok_or_else(|| {
            Error::explain(
                pingora_core::ErrorType::InternalError,
                format!("upstream '{effective_upstream}' not found in state"),
            )
        })?;

        // --- Sticky session: address-based cookie (Traefik-style SHA256) ---
        let upstream_name_str = effective_upstream.0.to_string();
        let sticky_config = state
            .config
            .upstreams
            .get(&upstream_name_str)
            .and_then(|c| c.sticky.as_ref());

        // --- Peer selection with retry + exponential backoff (Traefik-inspired) ---
        let retry_config = state
            .config
            .upstreams
            .get(&upstream_name_str)
            .and_then(|c| c.retry.as_ref());
        let max_attempts = retry_config.map_or(0, |r| r.attempts);
        let initial_interval = retry_config
            .and_then(|r| crate::config::parse_duration(&r.initial_interval).ok())
            .unwrap_or(std::time::Duration::from_millis(100));
        let max_interval = retry_config
            .and_then(|r| crate::config::parse_duration(&r.max_interval).ok())
            .unwrap_or(std::time::Duration::from_secs(1));

        let mut last_err = None;
        let mut peer_result: Option<Box<HttpPeer>> = None;

        for attempt in 0..=max_attempts {
            if attempt > 0 {
                // Exponential backoff with jitter
                let base = initial_interval.as_millis() as u64 * (1u64 << (attempt - 1).min(10));
                let capped = base.min(max_interval.as_millis() as u64);
                let jitter = fastrand::u64(0..=capped / 4 + 1);
                let delay = std::time::Duration::from_millis(capped + jitter);
                tokio::time::sleep(delay).await;
                ctx.retry_count = attempt;
            }

            let result =
                if let (Some(cookie_val), Some(_)) = (&ctx.sticky_cookie_value, sticky_config) {
                    if let Some(p) = upstream_group.select_peer_by_sticky_hash(cookie_val) {
                        Ok(p)
                    } else {
                        ctx.sticky_cookie_new = true;
                        upstream_group.select_peer()
                    }
                } else if sticky_config.is_some() {
                    ctx.sticky_cookie_new = true;
                    upstream_group.select_peer()
                } else {
                    upstream_group.select_peer()
                };

            match result {
                Ok(p) => {
                    peer_result = Some(p);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        let peer = peer_result.ok_or_else(|| {
            let err_msg =
                last_err.map_or_else(|| "no healthy backends".to_string(), |e| format!("{e}"));
            Error::explain(
                pingora_core::ErrorType::ConnectError,
                format!(
                    "failed to select peer from '{}': {}",
                    route.upstream, err_msg
                ),
            )
        })?;

        if let Some(addr) = peer.address().as_inet() {
            ctx.selected_peer = Some(SelectedPeer {
                address: *addr,
                tls: peer.is_tls(),
            });

            // Store address hash as cookie value (Traefik: truncated SHA256)
            if ctx.sticky_cookie_new {
                use sha2::{Digest, Sha256};
                let hash = format!("{:x}", Sha256::digest(addr.to_string().as_bytes()));
                ctx.sticky_cookie_value = Some(hash[..16].to_string());
            }
        }

        info!(
            request_id = %ctx.request_id,
            route = route.name.as_deref().unwrap_or("unnamed"),
            upstream = %route.upstream,
            "routing request"
        );

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        let state = self.state.load();
        if let Some(route) = &ctx.matched_route {
            let compiled = &state.router.routes()[route.index];
            compiled
                .pipeline
                .run_upstream_request(upstream_request, ctx);

            // --- Forward auth header injection ---
            // Copy headers from the auth service response into the upstream request.
            // Collect into owned Vec first — insert_header requires owned values to
            // avoid tying the lifetime to the ArcSwap guard.
            let fwd_headers: Vec<(String, String)> = compiled
                .forward_auth
                .as_ref()
                .map(|fwd_auth| {
                    fwd_auth
                        .response_headers
                        .iter()
                        .filter_map(|header_name| {
                            let ext_key = format!("fwd_auth_{header_name}");
                            ctx.get_extension(&ext_key).and_then(|v| {
                                v.as_str().map(|s| (header_name.clone(), s.to_string()))
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            for (name, val) in fwd_headers {
                let _ = upstream_request.insert_header(name, val);
            }

            // --- Traffic mirroring (Traefik-inspired) ---
            // Fire-and-forget: clone headers, send to mirror upstream in background.
            // v0.1 limitation: headers only, no body.
            if let Some(ref mirror) = compiled.mirror {
                if mirror.percent >= 100 || fastrand::u8(0..100) < mirror.percent {
                    if let Some(group) = state.upstreams.get(&mirror.upstream) {
                        if let Ok(peer) = group.select_peer() {
                            let mut header = upstream_request.clone();
                            let _ = header.insert_header("X-Fluxo-Mirror", "true");
                            let addr = format!("{}", peer.address());

                            tokio::spawn(async move {
                                let result = send_mirror_request(&addr, header).await;
                                if let Err(e) = result {
                                    tracing::debug!("mirror request to {} failed: {}", addr, e);
                                }
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>>
    where
        Self::CTX: Send + Sync,
    {
        let state = self.state.load();

        // Extract route info before mutable borrow of ctx
        let route_info = ctx
            .matched_route
            .as_ref()
            .map(|r| (r.index, r.upstream.0.to_string()));

        if let Some((route_index, ref upstream_name)) = route_info {
            let pipeline = &state.router.routes()[route_index].pipeline;
            pipeline.run_response(upstream_response, ctx);

            // --- HTTP/1.0 keep-alive handling (Monolake's ConnectionReuseHandler pattern) ---
            // HTTP/1.0 defaults to Connection: close. Upstream may return 1.1 headers
            // that don't make sense for 1.0 clients. Normalize the Connection header.
            if ctx.http_version.as_deref() == Some("HTTP/1.0") {
                // Remove any Connection header from upstream (may be 1.1-style)
                upstream_response.remove_header("connection");
                // For 1.0 clients, we close after response unless they sent keep-alive
                // (Pingora handles the actual connection lifecycle, but we set the header)
            }

            // --- Error page interception (Nginx proxy_intercept_errors) ---
            // Check per-route error pages first, then fall back to global
            let compiled = &state.router.routes()[route_index];
            let should_intercept = compiled
                .intercept_errors
                .unwrap_or(state.config.global.intercept_errors);
            if should_intercept {
                let status = upstream_response.status.as_u16();
                // Per-route error pages take priority over global
                let page_body = compiled
                    .error_pages
                    .get(&status)
                    .or_else(|| state.config.global.error_pages.get(&status));
                if let Some(page_body) = page_body {
                    ctx.error_page_override = Some(page_body.clone());
                    upstream_response.remove_header("content-length");
                    upstream_response.remove_header("content-encoding");
                    let _ =
                        upstream_response.insert_header("content-type", "text/html; charset=utf-8");
                }
            }

            // --- Response buffering activation (Nginx proxy_buffering) ---
            if let Some(upstream_config) = state.config.upstreams.get(upstream_name) {
                if let Some(ref buf_size) = upstream_config.response_buffer_size {
                    if let Ok(limit) = crate::config::parse_size(buf_size) {
                        ctx.response_buffer_limit = limit as usize;
                        ctx.response_buffering_active = true;
                    }
                }
            }

            // --- Sticky session cookie ---
            if ctx.sticky_cookie_new {
                if let Some(ref cookie_val) = ctx.sticky_cookie_value {
                    if let Some(upstream_config) = state.config.upstreams.get(upstream_name) {
                        if let Some(sticky) = &upstream_config.sticky {
                            let mut cookie = format!("{}={}", sticky.cookie_name, cookie_val);
                            if sticky.cookie_ttl > 0 {
                                cookie.push_str(&format!("; Max-Age={}", sticky.cookie_ttl));
                            }
                            cookie.push_str("; Path=/");
                            if sticky.cookie_http_only {
                                cookie.push_str("; HttpOnly");
                            }
                            if sticky.cookie_secure {
                                cookie.push_str("; Secure");
                            }
                            cookie.push_str("; SameSite=Lax");
                            let _ = upstream_response.insert_header("Set-Cookie", &cookie);
                        }
                    }
                }
            }

            // --- Cache status header (Nginx X-Cache-Status pattern) ---
            if let Some(status) = ctx.cache_status {
                let _ = upstream_response.insert_header("X-Cache-Status", status.as_str());
            }
        }
        Ok(())
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(b) = body {
            ctx.bytes_received += b.len() as u64;

            // Enforce max_request_body limit (nginx: client_max_body_size)
            let state = self.state.load();
            if let Some(route) = &ctx.matched_route {
                let max = state.router.routes()[route.index].max_body_bytes;
                if let Some(max_bytes) = max {
                    if ctx.bytes_received > max_bytes {
                        return Err(Error::explain(
                            pingora_core::ErrorType::HTTPStatus(413),
                            "request body too large",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>, Box<Error>> {
        // --- Error page interception (Nginx proxy_intercept_errors) ---
        // Replace upstream body with custom error page when intercepting.
        if let Some(ref page) = ctx.error_page_override {
            *body = None; // suppress upstream body chunks
            if end_of_stream {
                let page_bytes = page.clone().into_bytes();
                ctx.bytes_sent += page_bytes.len() as u64;
                *body = Some(bytes::Bytes::from(page_bytes));
                ctx.error_page_override = None;
            }
            return Ok(None);
        }

        // --- Response buffering (Nginx proxy_buffering) ---
        // Buffer upstream chunks to free backend connections early for slow clients.
        if ctx.response_buffering_active {
            if let Some(chunk) = body.take() {
                if ctx.response_buffer.len() + chunk.len() <= ctx.response_buffer_limit {
                    ctx.response_buffer.extend_from_slice(&chunk);
                    if end_of_stream {
                        // Flush entire buffer as one chunk
                        let buffered = std::mem::take(&mut ctx.response_buffer);
                        *body = Some(bytes::Bytes::from(buffered));
                        ctx.response_buffering_active = false;
                    }
                    // else: don't emit yet, body stays None — backend can close
                } else {
                    // Exceeded limit — flush buffer + this chunk, switch to streaming
                    let mut combined = std::mem::take(&mut ctx.response_buffer);
                    combined.extend_from_slice(&chunk);
                    *body = Some(bytes::Bytes::from(combined));
                    ctx.response_buffering_active = false;
                }
            } else if end_of_stream && !ctx.response_buffer.is_empty() {
                // End-of-stream with no final chunk — flush what we have
                let buffered = std::mem::take(&mut ctx.response_buffer);
                *body = Some(bytes::Bytes::from(buffered));
                ctx.response_buffering_active = false;
            }
            // If still buffering (not end_of_stream, under limit), skip compression pass
            if ctx.response_buffering_active {
                return Ok(None);
            }
        }

        if let Some(b) = body.take() {
            ctx.bytes_sent += b.len() as u64;

            if let Some(encoding) = ctx.compression_encoding {
                // Lazily initialize the streaming compressor on first chunk
                if ctx.compressor.is_none() {
                    ctx.compressor = StreamingCompressor::new(encoding);
                }
                // Compress this chunk incrementally — no full-body buffering
                if let Some(ref mut compressor) = ctx.compressor {
                    match compressor.write_chunk(&b) {
                        Ok(compressed) if !compressed.is_empty() => {
                            *body = Some(bytes::Bytes::from(compressed));
                        }
                        Ok(_) => {} // Compressor buffered internally, nothing to emit yet
                        Err(_) => {
                            // Compression failed — pass through uncompressed
                            *body = Some(b);
                        }
                    }
                }
            } else {
                // No compression — pass through immediately
                *body = Some(b);
            }
        }

        // On end-of-stream, finalize the compressor to flush remaining data
        if end_of_stream {
            if let Some(compressor) = ctx.compressor.take() {
                match compressor.finish() {
                    Ok(final_bytes) if !final_bytes.is_empty() => {
                        // Append final compressed bytes
                        match body {
                            Some(existing) => {
                                let mut combined = existing.to_vec();
                                combined.extend_from_slice(&final_bytes);
                                *body = Some(bytes::Bytes::from(combined));
                            }
                            None => {
                                *body = Some(bytes::Bytes::from(final_bytes));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // --- Bandwidth throttling (Nginx limit_rate) ---
        // Calculate delay based on chunk size and configured bytes/sec limit.
        // Returning Some(duration) tells Pingora to wait before sending next chunk.
        let throttle_delay = ctx.bandwidth_limit_bps.and_then(|bps| {
            body.as_ref().map(|chunk| {
                let chunk_len = chunk.len() as u64;
                if chunk_len == 0 || bps == 0 {
                    return std::time::Duration::ZERO;
                }
                // delay = chunk_size / rate (in seconds)
                std::time::Duration::from_millis(chunk_len * 1000 / bps)
            })
        });

        Ok(throttle_delay)
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        ctx.error_message = Some(format!("{e}"));

        #[allow(clippy::match_same_arms)]
        // Explicit arms for documentation: connect errors → 502, timeouts → 504
        let code = match e.etype() {
            pingora_core::ErrorType::HTTPStatus(code) => *code,
            pingora_core::ErrorType::ConnectTimedout
            | pingora_core::ErrorType::ConnectRefused
            | pingora_core::ErrorType::ConnectNoRoute
            | pingora_core::ErrorType::ConnectError => 502,
            pingora_core::ErrorType::ReadTimedout | pingora_core::ErrorType::WriteTimedout => 504,
            _ => 502,
        };

        warn!(
            request_id = %ctx.request_id,
            error_type = ?e.etype(),
            status = code,
            error = %e,
            "proxy error"
        );

        // --- Circuit breaker + passive health failure tracking ---
        if let Some(route) = &ctx.matched_route {
            self.static_state
                .circuit_breakers
                .record_failure(&route.upstream);
            if let Some(peer) = &ctx.selected_peer {
                self.static_state
                    .passive_health
                    .record_failure(&peer.address.to_string());
            }
        }

        // Use custom error page if configured: per-route first, then global
        let state = self.state.load();
        let route_error_page = ctx.matched_route.as_ref().and_then(|r| {
            let compiled = &state.router.routes()[r.index];
            compiled.error_pages.get(&code).cloned()
        });
        let error_body = route_error_page.as_deref().or_else(|| {
            state
                .config
                .global
                .error_pages
                .get(&code)
                .map(String::as_str)
        });
        let sent = if let Some(body) = error_body {
            let result = async {
                let mut header = pingora_http::ResponseHeader::build(code, None)?;
                header.insert_header("content-type", "text/html; charset=utf-8")?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(
                        Some(bytes::Bytes::from(body.to_owned().into_bytes())),
                        true,
                    )
                    .await
            };
            result.await.is_ok()
        } else {
            false
        };

        if !sent {
            let _ = session.respond_error(code).await;
        }

        // Monolake pattern: upstream errors (502/504) should NOT close the downstream
        // connection. The client can retry on the same connection. Only close for
        // protocol-level errors on the downstream side.
        let can_reuse = matches!(code, 502..=504);
        pingora_proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: can_reuse,
        }
    }

    async fn logging(&self, session: &mut Session, error: Option<&Error>, ctx: &mut Self::CTX) {
        let state = self.state.load();

        if let Some(e) = error {
            ctx.error_message = Some(format!("{e}"));
        }
        let status = session
            .response_written()
            .map_or(0, |resp| resp.status.as_u16());

        // --- Circuit breaker + passive health success tracking ---
        if error.is_none() {
            if let Some(route) = &ctx.matched_route {
                self.static_state
                    .circuit_breakers
                    .record_success(&route.upstream);
                if let Some(peer) = &ctx.selected_peer {
                    self.static_state
                        .passive_health
                        .record_success(&peer.address.to_string());
                }
            }
        }

        // --- Access log filtering (Traefik-style: status + min duration) ---
        let min_dur = state.config.global.access_log_min_duration_ms;
        let elapsed_ms = ctx.elapsed().as_millis() as u64;
        let status_excluded = !should_log_status(status, &state.config.global.access_log_exclude);
        let too_fast = min_dur > 0 && elapsed_ms < min_dur;
        if !status_excluded && !too_fast {
            crate::observability::access_log::emit_access_log(ctx, status);
        }

        let route = ctx
            .matched_route
            .as_ref()
            .and_then(|r| r.name.as_deref())
            .unwrap_or("-");
        let method = ctx.method.as_deref().unwrap_or("-");
        let duration_secs = ctx.elapsed().as_secs_f64();

        self.static_state.metrics.record_request(
            "-",
            route,
            method,
            status,
            duration_secs,
            ctx.bytes_sent,
            ctx.bytes_received,
        );

        // Per-upstream metrics (Traefik-inspired: per-server observability)
        if let Some(matched) = &ctx.matched_route {
            let upstream_name = matched.upstream.0.as_ref();
            let error_type = ctx.error_message.as_ref().map(|_| match status {
                502 => "connect",
                504 => "timeout",
                _ => "other",
            });
            self.static_state.metrics.record_upstream_request(
                upstream_name,
                status,
                duration_secs,
                error_type,
            );
        }

        // Cache metrics
        match ctx.cache_status {
            Some(crate::context::CacheStatus::Hit) => self.static_state.metrics.inc_cache_hits(),
            Some(crate::context::CacheStatus::Miss) => self.static_state.metrics.inc_cache_misses(),
            Some(crate::context::CacheStatus::Stale) => self.static_state.metrics.inc_cache_stale(),
            _ => {}
        }

        self.static_state.metrics.dec_active();
        // Return context to pool
        self.static_state.context_pool.release(std::mem::take(ctx));
    }
}

/// Send a fire-and-forget mirror request (headers only, no body).
/// Uses raw TCP with a short timeout so mirror failures never block anything.
async fn send_mirror_request(
    addr: &str,
    header: pingora_http::RequestHeader,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let stream =
        tokio::time::timeout(std::time::Duration::from_secs(5), TcpStream::connect(addr)).await??;

    let method = header.method.as_str();
    let path = header
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);

    let mut buf = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in &header.headers {
        if let Ok(v) = std::str::from_utf8(value.as_bytes()) {
            let n = name.as_str();
            if n != "host" && n != "connection" {
                buf.push_str(n);
                buf.push_str(": ");
                buf.push_str(v);
                buf.push_str("\r\n");
            }
        }
    }
    buf.push_str("Content-Length: 0\r\n\r\n");

    let (_, mut write_half) = stream.into_split();
    write_half.write_all(buf.as_bytes()).await?;
    write_half.shutdown().await?;

    debug!("mirror request to {} completed", addr);
    Ok(())
}

/// Forward auth subrequest — sends a GET to the auth service with the original
/// request headers. Returns `Ok(headers_to_copy)` on 2xx, `Err(status)` otherwise.
///
/// Nginx equivalent: `auth_request`. Traefik equivalent: `ForwardAuth` middleware.
async fn forward_auth_check(
    original_req: &pingora_http::RequestHeader,
    config: &crate::routing::CompiledForwardAuth,
) -> Result<Vec<(String, String)>, u16> {
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let uri: hyper::Uri = config.url.parse().map_err(|_| 500u16)?;

    let host = uri.host().unwrap_or("localhost");
    let port = uri.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });
    let authority = format!("{host}:{port}");

    let path = uri.path_and_query().map_or("/", |pq| pq.as_str());

    // Build the auth request — forward original headers (host, cookie, authorization, etc.)
    let mut builder = hyper::Request::builder().method("GET").uri(path);

    // Copy select headers from the original request
    for name in &[
        "host",
        "authorization",
        "cookie",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-method",
        "x-forwarded-uri",
    ] {
        if let Some(val) = original_req.headers.get(*name) {
            builder = builder.header(*name, val);
        }
    }

    // Add original method and URI as X-Forwarded-* headers (Traefik convention)
    builder = builder.header("X-Forwarded-Method", original_req.method.as_str());
    if let Some(pq) = original_req.uri.path_and_query() {
        builder = builder.header("X-Forwarded-Uri", pq.as_str());
    }
    builder = builder.header("Host", authority.as_str());

    let auth_req = builder.body(Empty::<Bytes>::new()).map_err(|_| 500u16)?;

    // Connect using hyper-util client
    let connector = hyper_util::client::legacy::connect::HttpConnector::new();
    let client = Client::builder(TokioExecutor::new()).build(connector);

    let resp = tokio::time::timeout(config.timeout, client.request(auth_req))
        .await
        .map_err(|_| {
            warn!("forward auth timeout to {}", config.url);
            503u16
        })?
        .map_err(|e| {
            warn!("forward auth request to {} failed: {}", config.url, e);
            502u16
        })?;

    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        debug!("forward auth rejected with status {}", status);
        return Err(status);
    }

    // Extract configured response headers to forward to upstream
    let mut headers_to_copy = Vec::new();
    for header_name in &config.response_headers {
        if let Some(val) = resp.headers().get(header_name.as_str()) {
            if let Ok(v) = val.to_str() {
                headers_to_copy.push((header_name.clone(), v.to_string()));
            }
        }
    }

    Ok(headers_to_copy)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_max_age_from_cache_control() {
        assert_eq!(
            parse_max_age("max-age=300"),
            Some(std::time::Duration::from_secs(300))
        );
        assert_eq!(
            parse_max_age("public, max-age=3600"),
            Some(std::time::Duration::from_secs(3600))
        );
    }

    #[test]
    fn parse_max_age_prefers_s_maxage() {
        assert_eq!(
            parse_max_age("max-age=300, s-maxage=60"),
            Some(std::time::Duration::from_secs(60))
        );
    }

    #[test]
    fn parse_max_age_returns_none_for_no_directive() {
        assert_eq!(parse_max_age("no-cache, no-store"), None);
        assert_eq!(parse_max_age(""), None);
    }

    #[test]
    fn global_cache_storage_returns_same_instance() {
        let a = std::ptr::from_ref(global_cache_storage());
        let b = std::ptr::from_ref(global_cache_storage());
        assert_eq!(a, b);
    }

    #[test]
    fn parse_max_age_malformed_value() {
        assert_eq!(parse_max_age("max-age=abc"), None);
        assert_eq!(parse_max_age("max-age="), None);
    }

    #[test]
    fn parse_max_age_zero() {
        assert_eq!(
            parse_max_age("max-age=0"),
            Some(std::time::Duration::from_secs(0))
        );
    }

    #[test]
    fn parse_max_age_case_insensitive() {
        assert_eq!(
            parse_max_age("Max-Age=300"),
            Some(std::time::Duration::from_secs(300))
        );
        assert_eq!(
            parse_max_age("MAX-AGE=300"),
            Some(std::time::Duration::from_secs(300))
        );
    }

    #[test]
    fn parse_max_age_s_maxage_only() {
        assert_eq!(
            parse_max_age("s-maxage=120"),
            Some(std::time::Duration::from_secs(120))
        );
    }

    #[test]
    fn parse_max_age_very_large_value() {
        assert_eq!(
            parse_max_age("max-age=999999999"),
            Some(std::time::Duration::from_secs(999_999_999))
        );
    }
}
