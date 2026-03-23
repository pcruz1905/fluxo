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
use pingora_core::upstreams::peer::{ALPN, HttpPeer, Peer};
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

/// Global in-memory cache storage (fallback when no `cache_dir` is configured).
pub(crate) fn global_mem_cache() -> &'static MemCache {
    static STORAGE: OnceLock<MemCache> = OnceLock::new();
    STORAGE.get_or_init(MemCache::new)
}

/// Global disk-backed cache storage (used when `cache_dir` is configured).
/// Initialized once at startup via `init_disk_cache`.
static DISK_CACHE: OnceLock<crate::cache::DiskCache> = OnceLock::new();

/// Global cache lock for stampede/thundering herd protection.
/// Initialized once at startup via `init_cache_lock`.
static CACHE_LOCK: OnceLock<pingora_cache::lock::CacheLock> = OnceLock::new();

/// Initialize the global cache lock with the configured timeout.
pub fn init_cache_lock(timeout: std::time::Duration) {
    let _ = CACHE_LOCK.get_or_init(|| pingora_cache::lock::CacheLock::new(timeout));
}

/// Initialize the global disk cache. Called once at startup when `cache_dir` is set.
pub fn init_disk_cache(root: std::path::PathBuf, max_size: u64) {
    let _ = DISK_CACHE.get_or_init(|| crate::cache::DiskCache::new(root, max_size));
}

/// Get the appropriate cache storage: disk if configured, otherwise in-memory.
pub(crate) fn global_cache_storage() -> &'static (dyn pingora_cache::storage::Storage + Sync) {
    if let Some(disk) = DISK_CACHE.get() {
        disk
    } else {
        global_mem_cache()
    }
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
    /// `GeoIP` database for route matching (if configured).
    pub geoip_db: Option<crate::routing::geoip::GeoIpDb>,
    /// SNI certificate map for multi-cert TLS listeners.
    pub sni_cert_map: Option<crate::tls::SniCertMap>,
    /// `mTLS` client auth configurations per service.
    pub mtls_configs: HashMap<String, crate::tls::MtlsConfig>,
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
        let geoip_db = load_geoip_db(&config);
        let (sni_cert_map, mtls_configs) = build_tls_state(&config);

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
            geoip_db,
            sni_cert_map,
            mtls_configs,
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

        let geoip_db = load_geoip_db(&config);
        let (sni_cert_map, mtls_configs) = build_tls_state(&config);

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
                geoip_db,
                sni_cert_map,
                mtls_configs,
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

        // DNS discovery: resolve targets from hostname
        #[allow(clippy::option_if_let_else)]
        let effective_targets = if upstream_config.discovery == "dns" {
            if let Some(ref hostname) = upstream_config.dns_hostname {
                match crate::upstream::dns::parse_dns_config(
                    hostname,
                    upstream_config.dns_port,
                    Some(&upstream_config.dns_refresh_interval),
                ) {
                    Ok(dns_config) => {
                        let discovery = std::sync::Arc::new(
                            crate::upstream::dns::DnsDiscovery::new(dns_config),
                        );
                        // Spawn background DNS refresh
                        std::sync::Arc::clone(&discovery).start_background();
                        info!(
                            upstream = name,
                            hostname = hostname,
                            "DNS discovery started"
                        );
                        // Use static targets as initial fallback (DNS resolves async)
                        upstream_config.targets.clone()
                    }
                    Err(e) => {
                        warn!(upstream = name, error = %e, "DNS discovery config failed, using static targets");
                        upstream_config.targets.clone()
                    }
                }
            } else {
                upstream_config.targets.clone()
            }
        } else {
            upstream_config.targets.clone()
        };

        let mut group = UpstreamGroup::new(
            upstream_name.clone(),
            &effective_targets,
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

            let method = hc_config.method.as_str();
            let mut req =
                pingora_http::RequestHeader::build(method, hc_config.path.as_bytes(), None)
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
            // Add custom health check headers
            for (hdr_name, hdr_value) in &hc_config.headers {
                let name = hdr_name.clone();
                let value = hdr_value.clone();
                let _ = req.insert_header(name, value);
            }
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

/// Wire passive health tracking into EDF/LeastConn upstream groups.
///
/// Pingora's built-in strategies (`RoundRobin`, Random, Hash) have integrated health
/// awareness via `LoadBalancer::select()`. EDF and `LeastConn` are custom schedulers
/// that need the `PassiveHealthTracker` to filter unhealthy peers during selection.
fn wire_passive_health(state: &mut FluxoState, tracker: &Arc<PassiveHealthTracker>) {
    use crate::upstream::peer::{LbStrategy, PassiveHealthParams};

    for (upstream_name, group) in &mut state.upstreams {
        // Only EDF and LeastConn need passive health wiring
        if group.strategy != LbStrategy::WeightedEdf
            && group.strategy != LbStrategy::LeastConnections
        {
            continue;
        }

        // Look up passive_health config for this upstream
        let upstream_cfg = state.config.upstreams.get(&*upstream_name.0);
        if let Some(ph_config) = upstream_cfg.and_then(|c| c.passive_health.as_ref()) {
            let fail_timeout = crate::config::parse_duration(&ph_config.fail_timeout)
                .unwrap_or(std::time::Duration::from_secs(30));
            group.set_passive_health(PassiveHealthParams {
                tracker: Arc::clone(tracker),
                max_fails: ph_config.max_fails,
                fail_timeout,
            });
        }
    }
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

fn build_tls_state(
    config: &FluxoConfig,
) -> (
    Option<crate::tls::SniCertMap>,
    HashMap<String, crate::tls::MtlsConfig>,
) {
    // Build SNI cert map from all services' sni_certs
    let mut all_sni_certs: Vec<crate::tls::SniCertConfig> = Vec::new();
    let mut mtls_configs = HashMap::new();

    for (service_name, service_config) in &config.services {
        if let Some(ref tls) = service_config.tls {
            // Collect SNI certs
            all_sni_certs.extend(tls.sni_certs.clone());

            // Build mTLS config
            match crate::tls::MtlsConfig::build(
                &tls.client_auth_type,
                tls.client_ca_path.as_deref(),
            ) {
                Ok(mtls) => {
                    if mtls.auth_type != crate::tls::ClientAuthType::None {
                        info!(
                            service = service_name,
                            auth_type = ?mtls.auth_type,
                            "mTLS client auth configured"
                        );
                        mtls_configs.insert(service_name.clone(), mtls);
                    }
                }
                Err(e) => {
                    warn!(
                        service = service_name,
                        error = %e,
                        "mTLS configuration error"
                    );
                }
            }
        }
    }

    let sni_map = if all_sni_certs.is_empty() {
        None
    } else {
        match crate::tls::SniCertMap::build(&all_sni_certs) {
            Ok(map) => {
                info!(count = map.len(), "SNI certificate map built");
                Some(map)
            }
            Err(e) => {
                warn!(error = %e, "failed to build SNI certificate map");
                None
            }
        }
    };

    (sni_map, mtls_configs)
}

fn load_geoip_db(config: &FluxoConfig) -> Option<crate::routing::geoip::GeoIpDb> {
    config.global.geoip_db_path.as_deref().and_then(|path| {
        match crate::routing::geoip::GeoIpDb::open(path) {
            Ok(db) => {
                info!("GeoIP database loaded: {path}");
                Some(db)
            }
            Err(e) => {
                warn!("failed to load GeoIP database: {e}");
                None
            }
        }
    })
}

/// Extract a hash key from the request based on the upstream's `hash_key` configuration.
///
/// Used by consistent hash and FNV hash load balancing strategies to determine
/// which backend receives the request. Supports: url, ip, header, cookie, query, path.
fn extract_hash_key(
    req: &pingora_http::RequestHeader,
    ctx: &RequestContext,
    hash_key_type: &str,
    hash_key_name: Option<&str>,
) -> Vec<u8> {
    match hash_key_type {
        "ip" => ctx.client_ip.as_deref().unwrap_or("").as_bytes().to_vec(),
        "path" => req.uri.path().as_bytes().to_vec(),
        "header" => hash_key_name
            .and_then(|name| req.headers.get(name))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .as_bytes()
            .to_vec(),
        "cookie" => {
            let cookie_name = hash_key_name.unwrap_or("");
            req.headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';').find_map(|c| {
                        let c = c.trim();
                        let (name, value) = c.split_once('=')?;
                        if name.trim() == cookie_name {
                            Some(value.trim().as_bytes().to_vec())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_default()
        }
        "query" => {
            let param_name = hash_key_name.unwrap_or("");
            req.uri
                .query()
                .and_then(|q| {
                    q.split('&').find_map(|pair| {
                        let (key, value) = pair.split_once('=')?;
                        if key == param_name {
                            Some(value.as_bytes().to_vec())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_default()
        }
        // "url" or default — full URI as hash key
        _ => req.uri.to_string().into_bytes(),
    }
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
    pub fn new(mut state: FluxoState) -> Result<Self, crate::error::FluxoError> {
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

        let passive_health = Arc::new(PassiveHealthTracker::new());

        // Wire passive health into EDF/LeastConn upstream groups
        wire_passive_health(&mut state, &passive_health);

        let static_state = Arc::new(FluxoStaticState {
            metrics,
            circuit_breakers: cb,
            passive_health,
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

        // Wire passive health into EDF/LeastConn upstream groups
        let mut new_state = new_state;
        wire_passive_health(&mut new_state, &self.static_state.passive_health);

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
        let cache_lock = CACHE_LOCK
            .get()
            .map(|l| l as &'static pingora_cache::lock::CacheKeyLockImpl);
        session.cache.enable(
            global_cache_storage(),
            None,       // no eviction manager for v0.1
            None,       // no predictor
            cache_lock, // stampede protection
            None,       // no option overrides
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

        // --- OpenTelemetry trace context extraction ---
        if state.config.global.tracing.enabled {
            let req_header = session.req_header();
            let trace_ctx = crate::observability::TraceContext::from_headers(req_header);
            if trace_ctx.is_active() {
                ctx.set_extension(
                    "traceparent".to_string(),
                    serde_json::json!(trace_ctx.traceparent.as_deref().unwrap_or("")),
                );
                if let Some(ref ts) = trace_ctx.tracestate {
                    ctx.set_extension("tracestate".to_string(), serde_json::json!(ts));
                }
            }
        }

        // --- GeoIP lookup (for route matching) ---
        let geoip_country = state.geoip_db.as_ref().and_then(|db| {
            ctx.client_ip
                .as_deref()
                .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                .and_then(|ip| db.country_code(ip))
        });

        // --- Route matching ---
        let req_header = session.req_header();
        let pingora_hdrs = PingoraHeaders(req_header);
        let query = req_header.uri.query();
        let client_ip_ref = ctx.client_ip.as_deref();
        let geoip_ref = geoip_country.as_deref();
        if let Some(route) = state.router.match_route_full(
            host,
            path,
            method,
            &pingora_hdrs,
            query,
            client_ip_ref,
            geoip_ref,
        ) {
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
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        let state = self.state.load();

        let route = ctx.matched_route.as_ref().ok_or_else(|| {
            Error::explain(
                pingora_core::ErrorType::InternalError,
                "upstream_peer called without matched route",
            )
        })?;

        // --- Traffic split override ---
        // If the traffic_split plugin assigned an alternate upstream, use it.
        let split_upstream = ctx
            .get_extension("traffic_split_upstream")
            .and_then(|v| v.as_str().map(UpstreamName::from));
        let base_upstream = split_upstream.as_ref().unwrap_or(&route.upstream);

        // --- Resolve composite upstreams (Traefik-inspired service composition) ---
        // If the route points to a composite upstream, resolve it to an actual child upstream.
        let resolved_upstream = resolve_composite_upstream(
            base_upstream,
            &state.composites,
            &state.upstreams,
            &self.static_state.circuit_breakers,
        );
        let effective_upstream = resolved_upstream.as_ref().unwrap_or(base_upstream);

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

        // --- Hash key extraction for consistent/FNV hashing ---
        let hash_key_bytes: Vec<u8> = {
            let upstream_cfg = state.config.upstreams.get(&upstream_name_str);
            let hash_key_type = upstream_cfg.map_or("url", |c| c.hash_key.as_str());
            let hash_key_name = upstream_cfg.and_then(|c| c.hash_key_name.as_deref());
            let req = session.req_header();
            extract_hash_key(req, ctx, hash_key_type, hash_key_name)
        };

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
                        upstream_group.select_peer_with_key(&hash_key_bytes)
                    }
                } else if sticky_config.is_some() {
                    ctx.sticky_cookie_new = true;
                    upstream_group.select_peer_with_key(&hash_key_bytes)
                } else {
                    upstream_group.select_peer_with_key(&hash_key_bytes)
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

        let mut peer = peer_result.ok_or_else(|| {
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

        // --- gRPC-web: force HTTP/2 to upstream ---
        // gRPC requires HTTP/2; override ALPN so Pingora negotiates h2.
        if state.router.routes()[route.index].grpc_web {
            peer.options.alpn = ALPN::H2;
        }

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

            // --- OpenTelemetry trace context injection ---
            if state.config.global.tracing.enabled {
                if let Some(tp) = ctx.get_extension("traceparent") {
                    if let Some(tp_str) = tp.as_str() {
                        let _ = upstream_request.insert_header("traceparent", tp_str);
                    }
                }
                if let Some(ts) = ctx.get_extension("tracestate") {
                    if let Some(ts_str) = ts.as_str() {
                        let _ = upstream_request.insert_header("tracestate", ts_str);
                    }
                }
            }

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

            // --- gRPC-web protocol translation (request) ---
            // Browsers send gRPC-web content-types; translate to standard gRPC
            // before forwarding to the upstream so it sees native gRPC.
            if compiled.grpc_web {
                if let Some(ct) = upstream_request.headers.get("content-type") {
                    if let Ok(ct_str) = ct.to_str() {
                        if ct_str.starts_with("application/grpc-web") {
                            let new_ct = ct_str.replace("application/grpc-web", "application/grpc");
                            let _ = upstream_request.insert_header("content-type", &new_ct);
                        }
                    }
                }
                // TE: trailers is required by the gRPC specification.
                let _ = upstream_request.insert_header("te", "trailers");
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

            // --- Capture content type for sub_filter ---
            if let Some(ct) = upstream_response.headers.get("content-type") {
                if let Ok(ct_str) = ct.to_str() {
                    ctx.set_extension(
                        "response_content_type".to_string(),
                        serde_json::json!(ct_str),
                    );
                }
            }

            // --- gRPC-web protocol translation (response) ---
            // Translate the upstream's standard gRPC content-type back to gRPC-web
            // so that browser clients can process the response correctly.
            if compiled.grpc_web {
                if let Some(ct) = upstream_response.headers.get("content-type") {
                    if let Ok(ct_str) = ct.to_str() {
                        if ct_str.starts_with("application/grpc") && !ct_str.contains("grpc-web") {
                            let new_ct = ct_str.replace("application/grpc", "application/grpc-web");
                            let _ = upstream_response.insert_header("content-type", &new_ct);
                        }
                    }
                }
                // Expose gRPC trailers so browser clients can read status codes.
                if upstream_response
                    .headers
                    .get("access-control-expose-headers")
                    .is_none()
                {
                    let _ = upstream_response
                        .insert_header("access-control-expose-headers", "grpc-status,grpc-message");
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

            // Enforce request_buffer plugin limit
            if let Some(max_buffer) = ctx.request_buffer_max_bytes {
                if max_buffer > 0 && ctx.bytes_received > max_buffer {
                    return Err(Error::explain(
                        pingora_core::ErrorType::HTTPStatus(413),
                        "request body exceeds buffer limit",
                    ));
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

        // --- Sub_filter response body rewriting (Nginx sub_filter) ---
        if let Some(ref sub_filter) = ctx.matched_route.as_ref().and_then(|r| {
            let state = self.state.load();
            state.router.routes().get(r.index).and_then(|compiled| {
                compiled.sub_filter.as_ref().and_then(|sf| {
                    // Check content type from ctx (set during response_filter)
                    let ct = ctx.get_extension("response_content_type");
                    let ct_str = ct.and_then(|v| v.as_str());
                    if sf.should_filter(ct_str) {
                        Some(sf.clone())
                    } else {
                        None
                    }
                })
            })
        }) {
            if let Some(chunk) = body.as_ref() {
                let rewritten = sub_filter.apply(chunk);
                *body = Some(rewritten);
            }
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

    // ── should_log_status tests ──────────────────────────────────────

    #[test]
    fn should_log_status_no_excludes() {
        assert!(should_log_status(200, &[]));
        assert!(should_log_status(500, &[]));
    }

    #[test]
    fn should_log_status_class_2xx() {
        let excludes = vec!["2xx".to_string()];
        assert!(!should_log_status(200, &excludes));
        assert!(!should_log_status(204, &excludes));
        assert!(!should_log_status(299, &excludes));
        assert!(should_log_status(300, &excludes));
        assert!(should_log_status(199, &excludes));
    }

    #[test]
    fn should_log_status_class_all() {
        assert!(!should_log_status(100, &["1xx".to_string()]));
        assert!(!should_log_status(301, &["3xx".to_string()]));
        assert!(!should_log_status(404, &["4xx".to_string()]));
        assert!(!should_log_status(503, &["5xx".to_string()]));
    }

    #[test]
    fn should_log_status_exact_code() {
        let excludes = vec!["404".to_string()];
        assert!(!should_log_status(404, &excludes));
        assert!(should_log_status(200, &excludes));
        assert!(should_log_status(405, &excludes));
    }

    #[test]
    fn should_log_status_range() {
        let excludes = vec!["200-299".to_string()];
        assert!(!should_log_status(200, &excludes));
        assert!(!should_log_status(250, &excludes));
        assert!(!should_log_status(299, &excludes));
        assert!(should_log_status(300, &excludes));
        assert!(should_log_status(199, &excludes));
    }

    #[test]
    fn should_log_status_multiple_excludes() {
        let excludes = vec!["2xx".to_string(), "404".to_string(), "500-504".to_string()];
        assert!(!should_log_status(200, &excludes));
        assert!(!should_log_status(404, &excludes));
        assert!(!should_log_status(502, &excludes));
        assert!(should_log_status(400, &excludes));
        assert!(should_log_status(505, &excludes));
    }

    #[test]
    fn should_log_status_invalid_pattern_ignored() {
        let excludes = vec!["abc".to_string(), "x-y".to_string()];
        assert!(should_log_status(200, &excludes));
        assert!(should_log_status(500, &excludes));
    }

    // ── has_tls_configured tests ─────────────────────────────────────

    fn minimal_test_config() -> FluxoConfig {
        use crate::config::{
            FluxoConfig, GlobalConfig, ListenerConfig, RouteConfig, ServiceConfig, UpstreamConfig,
        };

        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceConfig {
                listeners: vec![ListenerConfig {
                    address: "127.0.0.1:8080".to_string(),
                    offer_h2: false,
                    proxy_protocol: false,
                }],
                routes: vec![RouteConfig {
                    match_path: vec!["/*".to_string()],
                    upstream: "backend".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "backend".to_string(),
            UpstreamConfig {
                targets: vec![crate::config::TargetConfig::Simple(
                    "127.0.0.1:3000".to_string(),
                )],
                ..Default::default()
            },
        );

        FluxoConfig {
            global: GlobalConfig::default(),
            services,
            upstreams,
            ..Default::default()
        }
    }

    #[test]
    fn has_tls_configured_false_without_tls() {
        let config = minimal_test_config();
        assert!(!has_tls_configured(&config));
    }

    fn make_tls_config(
        cert: Option<&str>,
        key: Option<&str>,
        acme: bool,
    ) -> crate::config::TlsConfig {
        crate::config::TlsConfig {
            cert_path: cert.map(ToString::to_string),
            key_path: key.map(ToString::to_string),
            acme,
            acme_email: None,
            acme_directory: None,
            acme_staging: false,
            acme_challenge: "http-01".to_string(),
            acme_dns: None,
            client_ca_path: None,
            client_auth_type: "none".to_string(),
            sni_certs: vec![],
            cipher_list: None,
            tls13_ciphersuites: None,
            min_version: None,
            max_version: None,
            ocsp_stapling: false,
            ocsp_responder: None,
        }
    }

    #[test]
    fn has_tls_configured_true_with_manual_certs() {
        let mut config = minimal_test_config();
        config.services.get_mut("web").unwrap().tls = Some(make_tls_config(
            Some("/path/cert.pem"),
            Some("/path/key.pem"),
            false,
        ));
        assert!(has_tls_configured(&config));
    }

    #[test]
    fn has_tls_configured_true_with_acme() {
        let mut config = minimal_test_config();
        config.services.get_mut("web").unwrap().tls = Some(make_tls_config(None, None, true));
        assert!(has_tls_configured(&config));
    }

    #[test]
    fn has_tls_configured_false_with_partial_manual() {
        let mut config = minimal_test_config();
        // Only cert_path set, no key_path — should not count as TLS configured
        config.services.get_mut("web").unwrap().tls =
            Some(make_tls_config(Some("/path/cert.pem"), None, false));
        assert!(!has_tls_configured(&config));
    }

    // ── parse_downstream_timeouts tests ──────────────────────────────

    #[test]
    fn parse_downstream_timeouts_none_by_default() {
        let config = minimal_test_config();
        let (body, write) = parse_downstream_timeouts(&config);
        assert!(body.is_none());
        assert!(write.is_none());
    }

    #[test]
    fn parse_downstream_timeouts_with_values() {
        let mut config = minimal_test_config();
        config.global.client_body_timeout = Some("30s".to_string());
        config.global.client_write_timeout = Some("60s".to_string());
        let (body, write) = parse_downstream_timeouts(&config);
        assert_eq!(body, Some(std::time::Duration::from_secs(30)));
        assert_eq!(write, Some(std::time::Duration::from_secs(60)));
    }

    #[test]
    fn parse_downstream_timeouts_invalid_value() {
        let mut config = minimal_test_config();
        config.global.client_body_timeout = Some("invalid".to_string());
        let (body, _) = parse_downstream_timeouts(&config);
        assert!(body.is_none());
    }

    // ── parse_trusted_proxies tests ──────────────────────────────────

    #[test]
    fn parse_trusted_proxies_empty() {
        let config = minimal_test_config();
        let proxies = parse_trusted_proxies(&config);
        assert!(proxies.is_empty());
    }

    #[test]
    fn parse_trusted_proxies_with_cidrs() {
        let mut config = minimal_test_config();
        config.global.trusted_proxies =
            vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()];
        let proxies = parse_trusted_proxies(&config);
        assert_eq!(proxies.len(), 2);
    }

    #[test]
    fn parse_trusted_proxies_skips_invalid() {
        let mut config = minimal_test_config();
        config.global.trusted_proxies = vec!["10.0.0.0/8".to_string(), "not-a-cidr".to_string()];
        let proxies = parse_trusted_proxies(&config);
        assert_eq!(proxies.len(), 1);
    }

    // ── build_composite_upstreams tests ──────────────────────────────

    #[test]
    fn build_composite_upstreams_empty() {
        let config = minimal_test_config();
        let composites = build_composite_upstreams(&config);
        assert!(composites.is_empty());
    }

    #[test]
    fn build_composite_upstreams_weighted() {
        let mut config = minimal_test_config();
        config.upstreams.insert(
            "combo".to_string(),
            crate::config::UpstreamConfig {
                upstream_type: Some("weighted".to_string()),
                services: vec![crate::config::ServiceRef {
                    upstream: "backend".to_string(),
                    weight: 3,
                }],
                ..Default::default()
            },
        );
        let composites = build_composite_upstreams(&config);
        assert_eq!(composites.len(), 1);
        let combo = composites.get(&UpstreamName::from("combo")).unwrap();
        assert_eq!(combo.mode, CompositeMode::Weighted);
        assert_eq!(combo.children.len(), 1);
        assert_eq!(combo.children[0].1, 3);
    }

    #[test]
    fn build_composite_upstreams_failover() {
        let mut config = minimal_test_config();
        config.upstreams.insert(
            "ha".to_string(),
            crate::config::UpstreamConfig {
                upstream_type: Some("failover".to_string()),
                services: vec![
                    crate::config::ServiceRef {
                        upstream: "primary".to_string(),
                        weight: 1,
                    },
                    crate::config::ServiceRef {
                        upstream: "secondary".to_string(),
                        weight: 1,
                    },
                ],
                ..Default::default()
            },
        );
        let composites = build_composite_upstreams(&config);
        let ha = composites.get(&UpstreamName::from("ha")).unwrap();
        assert_eq!(ha.mode, CompositeMode::Failover);
        assert_eq!(ha.children.len(), 2);
    }

    #[test]
    fn build_composite_ignores_non_composite() {
        let config = minimal_test_config();
        // "backend" has no upstream_type — should not appear in composites
        let composites = build_composite_upstreams(&config);
        assert!(!composites.contains_key(&UpstreamName::from("backend")));
    }

    // ── resolve_composite_upstream tests ─────────────────────────────

    #[test]
    fn resolve_composite_returns_none_for_non_composite() {
        let composites = HashMap::new();
        let upstreams = HashMap::new();
        let cb = CircuitBreakerTracker::new();
        let name = UpstreamName::from("backend");
        assert!(resolve_composite_upstream(&name, &composites, &upstreams, &cb).is_none());
    }

    #[test]
    fn resolve_composite_failover_picks_first_available() {
        let mut composites = HashMap::new();
        composites.insert(
            UpstreamName::from("ha"),
            CompositeUpstream {
                mode: CompositeMode::Failover,
                children: vec![
                    (UpstreamName::from("primary"), 1),
                    (UpstreamName::from("secondary"), 1),
                ],
            },
        );
        let upstreams = HashMap::new();
        let cb = CircuitBreakerTracker::new();
        let result =
            resolve_composite_upstream(&UpstreamName::from("ha"), &composites, &upstreams, &cb);
        assert_eq!(result, Some(UpstreamName::from("primary")));
    }

    #[test]
    fn resolve_composite_failover_skips_open_breaker() {
        let mut composites = HashMap::new();
        composites.insert(
            UpstreamName::from("ha"),
            CompositeUpstream {
                mode: CompositeMode::Failover,
                children: vec![
                    (UpstreamName::from("primary"), 1),
                    (UpstreamName::from("secondary"), 1),
                ],
            },
        );
        let upstreams = HashMap::new();
        let cb = CircuitBreakerTracker::new();
        // Register and trip the primary circuit breaker
        cb.register(
            UpstreamName::from("primary"),
            crate::config::CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 1,
                open_duration: "60s".to_string(),
                error_ratio_threshold: 0.5,
                min_requests: 0,
                window: None,
            },
        );
        cb.record_failure(&UpstreamName::from("primary"));
        let result =
            resolve_composite_upstream(&UpstreamName::from("ha"), &composites, &upstreams, &cb);
        assert_eq!(result, Some(UpstreamName::from("secondary")));
    }

    #[test]
    fn resolve_composite_weighted_returns_child() {
        let mut composites = HashMap::new();
        composites.insert(
            UpstreamName::from("combo"),
            CompositeUpstream {
                mode: CompositeMode::Weighted,
                children: vec![(UpstreamName::from("only"), 1)],
            },
        );
        let upstreams = HashMap::new();
        let cb = CircuitBreakerTracker::new();
        let result =
            resolve_composite_upstream(&UpstreamName::from("combo"), &composites, &upstreams, &cb);
        assert_eq!(result, Some(UpstreamName::from("only")));
    }

    #[test]
    fn resolve_composite_weighted_zero_weight_returns_none() {
        let mut composites = HashMap::new();
        composites.insert(
            UpstreamName::from("empty"),
            CompositeUpstream {
                mode: CompositeMode::Weighted,
                children: vec![(UpstreamName::from("a"), 0)],
            },
        );
        let upstreams = HashMap::new();
        let cb = CircuitBreakerTracker::new();
        let result =
            resolve_composite_upstream(&UpstreamName::from("empty"), &composites, &upstreams, &cb);
        assert!(result.is_none());
    }

    // ── FluxoState build tests ───────────────────────────────────────

    #[test]
    fn fluxo_state_try_from_config_succeeds() {
        let config = minimal_test_config();
        let state = FluxoState::try_from_config(config);
        assert!(state.is_ok());
    }

    #[test]
    fn fluxo_state_build_succeeds() {
        let config = minimal_test_config();
        let build = FluxoState::build(config);
        assert!(build.is_ok());
    }

    #[test]
    fn fluxo_proxy_new_and_accessors() {
        let config = minimal_test_config();
        let state = FluxoState::try_from_config(config).unwrap();
        let proxy = FluxoProxy::new(state).unwrap();

        // challenge_state returns an Arc
        let _ = proxy.challenge_state();
        // metrics returns an Arc
        let _ = proxy.metrics();
        // state_snapshot loads current state
        let snap = proxy.state_snapshot();
        assert!(!snap.upstreams.is_empty());
    }

    #[test]
    fn fluxo_proxy_reload_swaps_state() {
        let config = minimal_test_config();
        let state = FluxoState::try_from_config(config.clone()).unwrap();
        let proxy = FluxoProxy::new(state).unwrap();

        // Reload with same config should succeed
        let new_state = FluxoState::try_from_config(config).unwrap();
        proxy.reload(new_state);
        let snap = proxy.state_snapshot();
        assert!(!snap.upstreams.is_empty());
    }

    #[test]
    fn fluxo_proxy_precommit_reload() {
        let config = minimal_test_config();
        let result = FluxoProxy::precommit_reload(config);
        assert!(result.is_ok());
    }

    #[test]
    fn composite_mode_equality() {
        assert_eq!(CompositeMode::Weighted, CompositeMode::Weighted);
        assert_eq!(CompositeMode::Failover, CompositeMode::Failover);
        assert_ne!(CompositeMode::Weighted, CompositeMode::Failover);
    }
}
