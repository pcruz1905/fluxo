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

    /// Global plugin configuration (applies to all routes, can be overridden per-route).
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,

    /// Custom error pages keyed by HTTP status code.
    /// Values are raw HTML/text bodies returned instead of the default Pingora error.
    /// Example: `{ 502 = "<html>Bad Gateway</html>" }`
    #[serde(default)]
    pub error_pages: HashMap<u16, String>,

    /// Access log filter — exclude certain status codes from access logs.
    /// Supports ranges like "2xx", "3xx" or exact codes like "200", "404".
    /// Example: `["2xx", "3xx"]` to suppress successful request logs.
    #[serde(default)]
    pub access_log_exclude: Vec<String>,
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
            access_log_exclude: Vec::new(),
        }
    }
}

/// A service groups listeners and routes together.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Display name for logging.
    pub name: Option<String>,

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
}

/// Configuration for an upstream group.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Name of the affinity cookie. Default: "FLUXO_STICKY".
    #[serde(default = "defaults::sticky_cookie_name")]
    pub cookie_name: String,

    /// Cookie TTL in seconds. 0 = session cookie (deleted when browser closes).
    #[serde(default)]
    pub cookie_ttl: u64,

    /// Whether to set the Secure flag on the cookie.
    #[serde(default)]
    pub cookie_secure: bool,

    /// Whether to set the HttpOnly flag on the cookie. Default: true.
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
}
