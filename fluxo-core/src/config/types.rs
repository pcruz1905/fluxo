//! Configuration structs — the user-facing TOML contract.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::defaults;

/// Access log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessLogFormat {
    /// Structured JSON lines.
    Json,
    /// Compact human-readable format.
    Compact,
}

/// A single upstream target — supports simple string or weighted form.
///
/// Simple:   `targets = ["127.0.0.1:3000"]`
/// Weighted: `targets = [{address = "127.0.0.1:3000", weight = 3}]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TargetConfig {
    /// Simple string: `"127.0.0.1:3000"` — weight defaults to 1.
    Simple(String),
    /// Weighted: `{ address = "127.0.0.1:3000", weight = 3 }`.
    Weighted { address: String, weight: u32 },
}

impl TargetConfig {
    /// The target's socket address string.
    pub fn address(&self) -> &str {
        match self {
            Self::Simple(s) => s,
            Self::Weighted { address, .. } => address,
        }
    }

    /// The target's weight (default 1 for simple form).
    pub fn weight(&self) -> u32 {
        match self {
            Self::Simple(_) => 1,
            Self::Weighted { weight, .. } => *weight,
        }
    }
}

/// Top-level Fluxo configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FluxoConfig {
    /// Global server settings.
    #[serde(default)]
    pub global: GlobalConfig,

    /// Named services, each with listeners and routes.
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,

    /// Named upstream groups.
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,
}

impl FluxoConfig {
    /// Append a namespace (e.g., "@file") to all named resources.
    /// Used by multi-provider setups to prevent name collisions.
    pub fn qualify_namespace(&mut self, namespace: &str) {
        let suffix = format!("@{namespace}");

        // Qualify upstreams
        let mut new_upstreams = HashMap::new();
        for (name, cfg) in std::mem::take(&mut self.upstreams) {
            new_upstreams.insert(format!("{name}{suffix}"), cfg);
        }
        self.upstreams = new_upstreams;

        // Qualify routes and their upstream/parent references
        for service in self.services.values_mut() {
            for route in &mut service.routes {
                if let Some(name) = &mut route.name {
                    name.push_str(&suffix);
                }
                if let Some(parent) = &mut route.parent {
                    parent.push_str(&suffix);
                }
                route.upstream.push_str(&suffix);
            }
        }
    }

    /// Merge another `FluxoConfig` into this one.
    /// `global` settings clobber via `extend` (not deeply merged for simplicity yet),
    /// but `services` and `upstreams` are combined.
    pub fn merge(&mut self, other: Self) {
        self.services.extend(other.services);
        self.upstreams.extend(other.upstreams);
        // Note: Global settings are typically taken from the primary provider (file)
        // or the last one that sent an update. For simplicity, we only merge services/upstreams.
    }
}

/// Global server settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Admin API listen address.
    #[serde(default = "defaults::admin_addr")]
    pub admin: String,

    /// Number of worker threads (0 = auto-detect CPU count).
    #[serde(default)]
    pub threads: usize,

    /// Path to PID file.
    pub pid_file: Option<String>,

    /// Path to upgrade socket for graceful restarts.
    pub upgrade_socket: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "defaults::log_level")]
    pub log_level: String,

    /// Base directory for certificate storage (ACME certs, account keys).
    pub cert_dir: Option<String>,

    /// Access log format: json (default) or compact.
    #[serde(default = "defaults::access_log_format")]
    pub access_log_format: AccessLogFormat,

    /// Whether to expose Prometheus metrics at /metrics on the admin API.
    #[serde(default = "defaults::metrics_enabled")]
    pub metrics_enabled: bool,

    /// Trusted proxy CIDRs — only trust X-Forwarded-For from these sources.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Downstream read timeout — how long to wait for the client to send data.
    /// Nginx equivalent: `client_body_timeout`. Default: none (use Pingora default).
    /// Example: "60s".
    pub client_body_timeout: Option<String>,

    /// Downstream write timeout — how long to wait for data to be written to the client.
    /// Default: none (use Pingora default). Example: "60s".
    pub client_write_timeout: Option<String>,

    /// Global plugin configuration (applies to all routes, can be overridden per-route).
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,

    /// Custom error pages keyed by HTTP status code.
    /// Values are raw HTML/text bodies returned instead of the default Pingora error.
    /// Example: `{ 502 = "<html>Bad Gateway</html>" }`
    #[serde(default)]
    pub error_pages: HashMap<u16, String>,

    /// When true, intercept upstream error responses (matching `error_pages` status codes)
    /// and replace the body with the custom error page. Nginx equivalent: `proxy_intercept_errors`.
    #[serde(default)]
    pub intercept_errors: bool,

    /// Graceful shutdown timeout — total time to drain in-flight requests after SIGTERM.
    /// Pingora: `graceful_shutdown_timeout_seconds`. Default: "30s".
    pub shutdown_timeout: Option<String>,

    /// Delay before starting drain — lets load balancer health checks fail first.
    /// Pingora: `grace_period_seconds`. Default: "5s".
    /// Traefik equivalent: `requestAcceptGraceTimeout`.
    pub shutdown_drain_delay: Option<String>,

    /// Access log filter — exclude certain status codes from access logs.
    /// Supports ranges like "2xx", "3xx", "200-299" or exact codes like "200", "404".
    /// Example: `["2xx", "3xx"]` to suppress successful request logs.
    #[serde(default)]
    pub access_log_exclude: Vec<String>,

    /// Minimum request duration (ms) for access log inclusion.
    /// Requests faster than this are excluded. Useful for noisy health checks.
    /// Example: `100` to only log requests taking >= 100ms.
    /// Default: 0 (log everything).
    #[serde(default)]
    pub access_log_min_duration_ms: u64,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            admin: defaults::admin_addr(),
            threads: 0,
            pid_file: None,
            upgrade_socket: None,
            log_level: defaults::log_level(),
            cert_dir: None,
            access_log_format: AccessLogFormat::Json,
            metrics_enabled: defaults::metrics_enabled(),
            trusted_proxies: Vec::new(),
            plugins: HashMap::new(),
            error_pages: HashMap::new(),
            intercept_errors: false,
            shutdown_timeout: None,
            shutdown_drain_delay: None,
            client_body_timeout: None,
            client_write_timeout: None,
            access_log_exclude: Vec::new(),
            access_log_min_duration_ms: 0,
        }
    }
}

/// A service groups listeners and routes together.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceConfig {
    /// Listener addresses for this service.
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// TLS configuration for this service.
    pub tls: Option<TlsConfig>,

    /// Routes evaluated in order (first match wins).
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

/// A listener address and protocol settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// Listen address (e.g., "0.0.0.0:443").
    pub address: String,
    /// Whether to offer HTTP/2 via ALPN.
    #[serde(default)]
    pub offer_h2: bool,

    /// Enable PROXY protocol (`HAProxy`) on this listener.
    /// When enabled, the first bytes of each connection are expected to be
    /// a PROXY protocol V1 or V2 header containing the real client IP.
    ///
    /// **Note:** Requires Pingora transport-layer integration (not yet available
    /// in Pingora 0.8). The parsing infrastructure is ready — enable this
    /// when a custom transport wrapper or future Pingora version supports it.
    #[serde(default)]
    pub proxy_protocol: bool,
}

/// TLS settings for a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the TLS certificate file.
    pub cert_path: Option<String>,

    /// Path to the TLS private key file.
    pub key_path: Option<String>,

    /// Enable ACME (Let's Encrypt) automatic certificate management.
    #[serde(default)]
    pub acme: bool,

    /// ACME account email (required when acme = true).
    pub acme_email: Option<String>,

    /// Custom ACME directory URL. Defaults to Let's Encrypt production.
    pub acme_directory: Option<String>,

    /// Use Let's Encrypt staging environment for testing.
    #[serde(default)]
    pub acme_staging: bool,
}

/// A single route definition.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteConfig {
    /// Display name for logging.
    pub name: Option<String>,

    /// Name of the parent route whose matchers and plugins are inherited.
    ///
    /// Traefik-inspired: child routes inherit all matchers and plugins from
    /// parent routes. The child's own matchers/plugins are appended.
    /// Example: a parent "api-gateway" with auth → child "api-users" inherits auth.
    pub parent: Option<String>,

    /// Host patterns to match (exact or wildcard like "*.example.com").
    #[serde(default)]
    pub match_host: Vec<String>,

    /// Path patterns to match (exact, prefix with trailing `/`, or glob with `*`).
    #[serde(default)]
    pub match_path: Vec<String>,

    /// HTTP methods to match (e.g., "GET", "POST").
    #[serde(default)]
    pub match_method: Vec<String>,

    /// Header conditions to match (e.g., {"X-Debug": "true"}).
    #[serde(default)]
    pub match_header: std::collections::HashMap<String, String>,

    /// Name of the upstream group to forward to.
    pub upstream: String,

    /// Maximum request body size (e.g., "10mb", "1gb"). Returns 413 if exceeded.
    /// Nginx equivalent: `client_max_body_size`.
    pub max_request_body: Option<String>,

    /// Plugin configuration for this route.
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,

    /// Traffic mirroring — fire-and-forget request copies to a shadow upstream.
    /// Traefik-inspired: used for canary testing, shadow traffic, and gradual rollouts.
    pub mirror: Option<MirrorConfig>,
}

/// Configuration for traffic mirroring to a shadow upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorConfig {
    /// Name of the upstream group to mirror requests to.
    pub upstream: String,

    /// Percentage of requests to mirror (0-100). Default: 100.
    #[serde(default = "defaults::mirror_percent")]
    pub percent: u8,
}

/// Configuration for an upstream group.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpstreamConfig {
    /// Discovery method: "static" (v0.1 only).
    #[serde(default = "defaults::discovery")]
    pub discovery: String,

    /// Static list of upstream targets. Supports simple strings or weighted objects.
    #[serde(default)]
    pub targets: Vec<TargetConfig>,

    /// Load balancing strategy.
    #[serde(default = "defaults::load_balancing")]
    pub load_balancing: String,

    /// Health check configuration.
    pub health_check: Option<HealthCheckConfig>,

    /// Timeout for establishing a TCP connection to an upstream.
    /// Nginx equivalent: `proxy_connect_timeout`. Default: "5s".
    #[serde(default = "defaults::connect_timeout")]
    pub connect_timeout: String,

    /// Timeout for reading a response from an upstream.
    /// Nginx equivalent: `proxy_read_timeout`. Default: "60s".
    #[serde(default = "defaults::read_timeout")]
    pub read_timeout: String,

    /// Timeout for writing a request to an upstream.
    /// Nginx equivalent: `proxy_send_timeout`. Default: "60s".
    #[serde(default = "defaults::write_timeout")]
    pub write_timeout: String,

    /// Total connection timeout — upper bound for the entire connection attempt
    /// (including DNS, TCP handshake, TLS). Pingora: `total_connection_timeout`.
    pub total_connection_timeout: Option<String>,

    /// Retry configuration — retry failed requests on the next healthy backend.
    /// Nginx equivalent: `proxy_next_upstream`.
    pub retry: Option<RetryConfig>,

    /// Passive health check — mark a backend unhealthy after consecutive proxy failures.
    /// Nginx equivalent: `max_fails` / `fail_timeout`.
    pub passive_health: Option<PassiveHealthConfig>,

    /// Sticky session configuration — cookie-based session affinity.
    /// Traefik equivalent: sticky sessions.
    pub sticky: Option<StickySessionConfig>,

    /// Circuit breaker — stop sending traffic to failing upstreams.
    /// Traefik equivalent: circuit breaker middleware.
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Keepalive idle timeout for upstream connections.
    /// Nginx equivalent: `keepalive_timeout`. Default: "60s".
    #[serde(default = "defaults::keepalive_timeout")]
    pub keepalive_timeout: String,

    /// Maximum idle keepalive connections per upstream.
    /// Nginx equivalent: `keepalive`. Default: 128.
    #[serde(default = "defaults::keepalive_pool_size")]
    pub keepalive_pool_size: usize,

    /// TCP keepalive settings for upstream connections.
    /// Pingora: `tcp_keepalive`. Maps to OS-level `TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT`.
    pub tcp_keepalive: Option<TcpKeepaliveConfig>,

    /// Maximum concurrent HTTP/2 streams per connection.
    /// Pingora: `max_h2_streams`. Default: 1.
    pub max_h2_streams: Option<usize>,

    /// TCP receive buffer size in bytes.
    /// Pingora: `tcp_recv_buf`. Uses OS default if not set.
    pub tcp_recv_buf: Option<usize>,

    /// HTTP/2 ping interval for keepalive on idle connections.
    /// Pingora: `h2_ping_interval`. Example: "30s".
    pub h2_ping_interval: Option<String>,

    /// Response buffer size — buffer upstream responses in memory to free backend connections early.
    /// Nginx equivalent: `proxy_buffer_size` / `proxy_buffering`. Example: "64kb", "256kb".
    /// When set, response body chunks are accumulated up to this size before being flushed
    /// to the client. If the response exceeds this size, it switches to streaming mode.
    pub response_buffer_size: Option<String>,

    /// Upstream type: "static" (default, direct targets), "weighted" (WRR of child upstreams),
    /// "failover" (try children in order, skip those with open circuit breakers).
    /// Traefik equivalent: weighted round-robin service / failover service.
    #[serde(default)]
    pub upstream_type: Option<String>,

    /// Child upstream references for composite types ("weighted" / "failover").
    /// Each entry references another upstream by name, with an optional weight.
    #[serde(default)]
    pub services: Vec<ServiceRef>,
}

/// A reference to a child upstream in a composite upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRef {
    /// Name of the referenced upstream.
    pub upstream: String,
    /// Weight for weighted round-robin (ignored for failover). Default: 1.
    #[serde(default = "service_ref_default_weight")]
    pub weight: u32,
}

fn service_ref_default_weight() -> u32 {
    1
}

/// TCP keepalive settings — maps to OS socket options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpKeepaliveConfig {
    /// Time a connection needs to be idle before TCP begins sending keepalive probes.
    /// Default: "60s".
    #[serde(default = "defaults::tcp_keepalive_idle")]
    pub idle: String,

    /// Interval between TCP keepalive probes. Default: "15s".
    #[serde(default = "defaults::tcp_keepalive_interval")]
    pub interval: String,

    /// Max number of keepalive probes before giving up. Default: 5.
    #[serde(default = "defaults::tcp_keepalive_count")]
    pub count: usize,
}

/// Retry configuration for upstream failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (not counting the original request).
    #[serde(default = "defaults::retry_attempts")]
    pub attempts: u32,

    /// Conditions that trigger a retry.
    /// Valid values: "error" (connection error), "timeout", "5xx" (5xx responses).
    /// Default: ["error", "timeout"].
    #[serde(default = "defaults::retry_on")]
    pub on: Vec<String>,

    /// Initial backoff interval between retries. Default: "100ms".
    /// Traefik equivalent: `initialInterval`.
    #[serde(default = "defaults::retry_initial_interval")]
    pub initial_interval: String,

    /// Maximum backoff interval between retries. Default: "1s".
    /// Backoff is capped at this value. Formula: min(initial * 2^attempt, max).
    #[serde(default = "defaults::retry_max_interval")]
    pub max_interval: String,
}

/// Passive health check configuration — tracks failures during proxying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveHealthConfig {
    /// Number of consecutive proxy failures before marking backend unhealthy.
    /// Nginx equivalent: `max_fails`. Default: 3.
    #[serde(default = "defaults::passive_max_fails")]
    pub max_fails: u32,

    /// How long an unhealthy backend stays excluded.
    /// Nginx equivalent: `fail_timeout`. Default: "30s".
    #[serde(default = "defaults::passive_fail_timeout")]
    pub fail_timeout: String,
}

/// Sticky session configuration — cookie-based backend affinity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickySessionConfig {
    /// Name of the affinity cookie. Default: "`FLUXO_STICKY`".
    #[serde(default = "defaults::sticky_cookie_name")]
    pub cookie_name: String,

    /// Cookie TTL in seconds. 0 = session cookie (deleted when browser closes).
    #[serde(default)]
    pub cookie_ttl: u64,

    /// Whether to set the Secure flag on the cookie.
    #[serde(default)]
    pub cookie_secure: bool,

    /// Whether to set the `HttpOnly` flag on the cookie. Default: true.
    #[serde(default = "defaults::sticky_cookie_http_only")]
    pub cookie_http_only: bool,
}

/// Circuit breaker configuration — stop traffic to failing upstreams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures before opening the circuit. Default: 5.
    #[serde(default = "defaults::cb_failure_threshold")]
    pub failure_threshold: u32,

    /// Successful requests in half-open state before closing the circuit. Default: 3.
    #[serde(default = "defaults::cb_success_threshold")]
    pub success_threshold: u32,

    /// How long the circuit stays open before transitioning to half-open. Default: "30s".
    #[serde(default = "defaults::cb_open_duration")]
    pub open_duration: String,

    /// Error ratio threshold (0.0-1.0) for ratio-based tripping (Traefik's `NetworkErrorRatio`).
    /// When the error ratio in the sliding window exceeds this, the circuit opens.
    /// Default: 0.5 (50%).
    #[serde(default = "defaults::cb_error_ratio_threshold")]
    pub error_ratio_threshold: f64,

    /// Minimum requests in the sliding window before ratio-based tripping activates.
    /// Prevents tripping on small sample sizes. Default: 10.
    #[serde(default = "defaults::cb_min_requests")]
    pub min_requests: u32,

    /// Sliding window duration for error ratio calculation. Default: "30s".
    /// If not set, uses the same value as `open_duration`.
    pub window: Option<String>,
}

/// Active health check settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// HTTP path to probe.
    pub path: String,

    /// Probe interval (e.g., "10s").
    #[serde(default = "defaults::health_check_interval")]
    pub interval: String,

    /// Probe timeout (e.g., "3s").
    #[serde(default = "defaults::health_check_timeout")]
    pub timeout: String,

    /// Consecutive failures before marking unhealthy.
    #[serde(default = "defaults::unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Consecutive successes before marking healthy.
    #[serde(default = "defaults::healthy_threshold")]
    pub healthy_threshold: u32,

    /// Faster probe interval for unhealthy targets (Traefik-inspired dual-interval).
    /// Defaults to interval/3 if not set. Example: "3s".
    pub unhealthy_interval: Option<String>,
}
