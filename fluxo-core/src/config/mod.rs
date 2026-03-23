//! Configuration system — TOML parsing, validation, defaults, and merging.

mod defaults;
pub mod file_provider;
pub mod lint;
pub mod provider;
mod types;
pub mod watcher;

pub use types::*;

use std::path::Path;
use std::time::Duration;

use thiserror::Error;

/// Errors that can occur during configuration loading and validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read the config file from disk.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse TOML content.
    #[error("failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),

    /// Semantic validation failed (single error).
    #[error("validation error: {0}")]
    Validation(String),

    /// Multiple validation errors found.
    #[error("validation errors:\n{}", .0.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    ValidationMultiple(Vec<String>),

    /// A route references an upstream that doesn't exist.
    #[error("unknown upstream '{0}' referenced in route")]
    UnknownUpstream(String),
}

/// Load configuration from a TOML file at the given path.
pub fn load_from_file(path: &Path) -> Result<FluxoConfig, ConfigError> {
    let content = std::fs::read_to_string(path)?;
    let config: FluxoConfig = toml::from_str(&content)?;
    validate(&config)?;
    Ok(config)
}

/// Parse configuration from a TOML string (useful for testing).
pub fn load_from_str(content: &str) -> Result<FluxoConfig, ConfigError> {
    let config: FluxoConfig = toml::from_str(content)?;
    validate(&config)?;
    Ok(config)
}

/// Try loading config from default file paths in order:
/// 1. `./fluxo.toml`
/// 2. `/etc/fluxo/fluxo.toml`
///
/// Returns a default empty config if no file is found.
pub fn load_from_default_paths() -> Result<FluxoConfig, ConfigError> {
    let candidates = ["fluxo.toml", "/etc/fluxo/fluxo.toml"];

    for path in &candidates {
        let p = Path::new(path);
        if p.exists() {
            return load_from_file(p);
        }
    }

    Ok(FluxoConfig::default())
}

/// Create a minimal config for the `--upstream` CLI shorthand.
pub fn config_from_upstream(upstream: &str) -> Result<FluxoConfig, ConfigError> {
    use std::collections::HashMap;

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            discovery: "static".to_string(),
            targets: vec![TargetConfig::Simple(upstream.to_string())],
            ..Default::default()
        },
    );

    let mut services = HashMap::new();
    services.insert(
        "default".to_string(),
        ServiceConfig {
            listeners: vec![ListenerConfig {
                address: "0.0.0.0:80".to_string(),
                offer_h2: false,
                proxy_protocol: false,
            }],
            tls: None,
            routes: vec![RouteConfig {
                name: Some("default".to_string()),
                upstream: "default".to_string(),
                ..Default::default()
            }],
        },
    );

    let config = FluxoConfig {
        global: GlobalConfig::default(),
        services,
        upstreams,
        l4: Default::default(),
    };
    validate(&config)?;
    Ok(config)
}

/// Validate cross-references and semantic constraints in the config.
///
/// Collects ALL validation errors instead of stopping at the first one,
/// so users can fix everything in a single pass (Traefik-inspired).
pub fn validate(config: &FluxoConfig) -> Result<(), ConfigError> {
    let errors = collect_validation_errors(config);
    if errors.is_empty() {
        Ok(())
    } else if errors.len() == 1 {
        Err(ConfigError::Validation(
            errors.into_iter().next().unwrap_or_default(),
        ))
    } else {
        Err(ConfigError::ValidationMultiple(errors))
    }
}

/// Collect all validation errors from the config without short-circuiting.
#[allow(clippy::too_many_lines)]
fn collect_validation_errors(config: &FluxoConfig) -> Vec<String> {
    let mut errors = Vec::new();

    // Validate admin address
    if config.global.admin.parse::<std::net::SocketAddr>().is_err() {
        errors.push(format!("invalid admin address '{}'", config.global.admin));
    }

    // Validate log_level
    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    if !valid_levels.contains(&config.global.log_level.as_str()) {
        errors.push(format!(
            "invalid log_level '{}': must be one of {}",
            config.global.log_level,
            valid_levels.join(", ")
        ));
    }

    // Validate downstream timeouts
    if let Some(ref t) = config.global.client_body_timeout {
        if parse_duration(t).is_err() {
            errors.push(format!("invalid client_body_timeout: '{t}'"));
        }
    }
    if let Some(ref t) = config.global.client_write_timeout {
        if parse_duration(t).is_err() {
            errors.push(format!("invalid client_write_timeout: '{t}'"));
        }
    }

    // Validate graceful shutdown config
    if let Some(ref t) = config.global.shutdown_timeout {
        if parse_duration(t).is_err() {
            errors.push(format!("invalid shutdown_timeout: '{t}'"));
        }
    }
    if let Some(ref t) = config.global.shutdown_drain_delay {
        if parse_duration(t).is_err() {
            errors.push(format!("invalid shutdown_drain_delay: '{t}'"));
        }
    }

    // Validate trusted_proxies are valid CIDRs
    for cidr in &config.global.trusted_proxies {
        if cidr.parse::<ipnet::IpNet>().is_err() {
            errors.push(format!("invalid trusted_proxy CIDR '{cidr}'"));
        }
    }

    // Validate access_log_exclude patterns
    let valid_class_patterns = ["1xx", "2xx", "3xx", "4xx", "5xx"];
    for pattern in &config.global.access_log_exclude {
        if valid_class_patterns.contains(&pattern.as_str()) {
            continue;
        }
        let mut valid = false;
        // Try numeric range "200-299"
        if let Some((from, to)) = pattern.split_once('-') {
            if let (Ok(f), Ok(t)) = (from.parse::<u16>(), to.parse::<u16>()) {
                if f <= t && (100..=599).contains(&f) && (100..=599).contains(&t) {
                    valid = true;
                }
            }
        }
        // Try exact status code
        if !valid {
            if let Ok(code) = pattern.parse::<u16>() {
                if (100..=599).contains(&code) {
                    valid = true;
                }
            }
        }
        if !valid {
            errors.push(format!(
                "invalid access_log_exclude pattern '{pattern}': must be a status code (200), class (2xx), or range (200-299)"
            ));
        }
    }

    // Validate services
    for (service_name, service) in &config.services {
        // Every route's upstream must reference a key in config.upstreams
        for (i, route) in service.routes.iter().enumerate() {
            if !config.upstreams.contains_key(&route.upstream) {
                let fallback = format!("route[{i}]");
                let route_desc = route.name.as_deref().unwrap_or(&fallback);
                errors.push(format!(
                    "unknown upstream '{}' in service '{service_name}' route '{route_desc}'",
                    route.upstream
                ));
            }

            // Validate max_request_body size string if set
            if let Some(size_str) = &route.max_request_body {
                if parse_size(size_str).is_err() {
                    errors.push(format!(
                        "service '{service_name}' route {i}: invalid max_request_body '{size_str}': \
                         expected format like '10mb', '1gb', '512kb'"
                    ));
                }
            }

            // Validate cache config
            if let Some(ref cache) = route.cache {
                let route_desc = route.name.as_deref().unwrap_or("unnamed");
                if parse_duration(&cache.default_ttl).is_err() {
                    errors.push(format!(
                        "service '{service_name}' route '{route_desc}': invalid cache default_ttl '{}'",
                        cache.default_ttl
                    ));
                }
                if parse_size(&cache.max_file_size).is_err() {
                    errors.push(format!(
                        "service '{service_name}' route '{route_desc}': invalid cache max_file_size '{}'",
                        cache.max_file_size
                    ));
                }
                if parse_duration(&cache.stale_while_revalidate).is_err() {
                    errors.push(format!(
                        "service '{service_name}' route '{route_desc}': invalid cache stale_while_revalidate '{}'",
                        cache.stale_while_revalidate
                    ));
                }
                if parse_duration(&cache.stale_if_error).is_err() {
                    errors.push(format!(
                        "service '{service_name}' route '{route_desc}': invalid cache stale_if_error '{}'",
                        cache.stale_if_error
                    ));
                }
            }

            // Validate mirror config
            if let Some(mirror) = &route.mirror {
                if !config.upstreams.contains_key(&mirror.upstream) {
                    errors.push(format!(
                        "service '{service_name}' route {i}: mirror upstream '{}' not found",
                        mirror.upstream
                    ));
                }
                if mirror.percent > 100 {
                    errors.push(format!(
                        "service '{service_name}' route {i}: mirror.percent must be 0-100, got {}",
                        mirror.percent
                    ));
                }
            }
        }

        // Validate listener addresses
        for listener in &service.listeners {
            if listener.address.is_empty() {
                errors.push(format!(
                    "empty listener address in service '{service_name}'"
                ));
            } else if listener.address.parse::<std::net::SocketAddr>().is_err() {
                errors.push(format!(
                    "invalid listener address '{}' in service '{service_name}'",
                    listener.address
                ));
            }
        }

        // Validate plugin configuration per route
        for (i, route) in service.routes.iter().enumerate() {
            if let Err(e) =
                crate::plugins::config::compile_plugins(&route.plugins, &config.global.plugins)
            {
                errors.push(format!("service '{service_name}' route {i}: {e}"));
            }
        }

        // Must have at least one listener
        if service.listeners.is_empty() {
            errors.push(format!("service '{service_name}' has no listeners"));
        }

        // Validate TLS configuration
        if let Some(tls) = &service.tls {
            if tls.acme {
                if tls.acme_email.is_none() {
                    errors.push(format!(
                        "service '{service_name}': acme = true requires acme_email to be set"
                    ));
                }
                if tls.cert_path.is_some() || tls.key_path.is_some() {
                    errors.push(format!(
                        "service '{service_name}': cannot use both acme and cert_path/key_path"
                    ));
                }
            }
            match (&tls.cert_path, &tls.key_path) {
                (Some(_), None) => {
                    errors.push(format!(
                        "service '{service_name}': cert_path is set but key_path is missing"
                    ));
                }
                (None, Some(_)) => {
                    errors.push(format!(
                        "service '{service_name}': key_path is set but cert_path is missing"
                    ));
                }
                _ => {}
            }

            // Validate mTLS client auth settings
            if let Err(e) =
                crate::tls::MtlsConfig::build(&tls.client_auth_type, tls.client_ca_path.as_deref())
            {
                errors.push(format!("service '{service_name}': mTLS: {e}"));
            }
        }
    }

    // Validate upstream targets and timeouts
    for (name, upstream) in &config.upstreams {
        let is_composite = upstream
            .upstream_type
            .as_deref()
            .is_some_and(|t| t == "weighted" || t == "failover");

        if !is_composite && upstream.discovery == "static" && upstream.targets.is_empty() {
            errors.push(format!(
                "upstream '{name}' has static discovery but no targets"
            ));
        }

        // Validate each target address
        for target in &upstream.targets {
            if target.address().parse::<std::net::SocketAddr>().is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid target address '{}'",
                    target.address()
                ));
            }
            if target.weight() == 0 {
                errors.push(format!(
                    "upstream '{name}': target '{}' has weight 0 (must be >= 1)",
                    target.address()
                ));
            }
        }

        // Validate discovery method
        let valid_discoveries = ["static", "dns"];
        if !valid_discoveries.contains(&upstream.discovery.as_str()) {
            errors.push(format!(
                "upstream '{name}': unknown discovery '{}'. Valid: {}",
                upstream.discovery,
                valid_discoveries.join(", ")
            ));
        }

        // Validate DNS discovery fields
        if upstream.discovery == "dns" {
            if upstream.dns_hostname.is_none()
                || upstream.dns_hostname.as_ref().is_some_and(String::is_empty)
            {
                errors.push(format!(
                    "upstream '{name}': dns discovery requires a non-empty dns_hostname"
                ));
            }
            if parse_duration(&upstream.dns_refresh_interval).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid dns_refresh_interval '{}'",
                    upstream.dns_refresh_interval
                ));
            }
        }

        // Validate load balancing strategy
        let valid_strategies = [
            "round_robin",
            "random",
            "fnv_hash",
            "consistent_hash",
            "weighted_edf",
        ];
        if !valid_strategies.contains(&upstream.load_balancing.as_str()) {
            errors.push(format!(
                "upstream '{name}': unknown load_balancing '{}'. Valid: {}",
                upstream.load_balancing,
                valid_strategies.join(", ")
            ));
        }

        // Validate timeout strings
        for (field, value) in [
            ("connect_timeout", &upstream.connect_timeout),
            ("read_timeout", &upstream.read_timeout),
            ("write_timeout", &upstream.write_timeout),
        ] {
            if parse_duration(value).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid {field} '{value}': expected format like '5s', '500ms', '2m'"
                ));
            }
        }

        // Validate retry config
        if let Some(retry) = &upstream.retry {
            if retry.attempts == 0 {
                errors.push(format!("upstream '{name}': retry.attempts must be >= 1"));
            }
            let valid_conditions = ["error", "timeout", "5xx"];
            for condition in &retry.on {
                if !valid_conditions.contains(&condition.as_str()) {
                    errors.push(format!(
                        "upstream '{name}': invalid retry condition '{condition}'. Valid: {}",
                        valid_conditions.join(", ")
                    ));
                }
            }
            if parse_duration(&retry.initial_interval).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid retry.initial_interval '{}'",
                    retry.initial_interval
                ));
            }
            if parse_duration(&retry.max_interval).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid retry.max_interval '{}'",
                    retry.max_interval
                ));
            }
        }

        // Validate passive health check config
        if let Some(ph) = &upstream.passive_health {
            if parse_duration(&ph.fail_timeout).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid passive_health.fail_timeout '{}'",
                    ph.fail_timeout
                ));
            }
            if ph.max_fails == 0 {
                errors.push(format!(
                    "upstream '{name}': passive_health.max_fails must be >= 1"
                ));
            }
        }

        // Validate keepalive timeout
        if parse_duration(&upstream.keepalive_timeout).is_err() {
            errors.push(format!(
                "upstream '{name}': invalid keepalive_timeout '{}': expected format like '60s', '30s'",
                upstream.keepalive_timeout
            ));
        }

        // Validate total_connection_timeout
        if let Some(ref tct) = upstream.total_connection_timeout {
            if parse_duration(tct).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid total_connection_timeout '{tct}': expected format like '10s', '500ms'"
                ));
            }
        }

        // Validate tcp_keepalive
        if let Some(ref ka) = upstream.tcp_keepalive {
            if parse_duration(&ka.idle).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid tcp_keepalive.idle '{}'",
                    ka.idle
                ));
            }
            if parse_duration(&ka.interval).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid tcp_keepalive.interval '{}'",
                    ka.interval
                ));
            }
        }

        // Validate h2_ping_interval
        if let Some(ref h2pi) = upstream.h2_ping_interval {
            if parse_duration(h2pi).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid h2_ping_interval '{h2pi}'"
                ));
            }
        }

        // Validate response_buffer_size
        if let Some(ref rbs) = upstream.response_buffer_size {
            if parse_size(rbs).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid response_buffer_size '{rbs}': expected format like '64kb', '256kb', '1mb'"
                ));
            }
        }

        // Validate circuit breaker config
        if let Some(cb) = &upstream.circuit_breaker {
            if cb.failure_threshold == 0 {
                errors.push(format!(
                    "upstream '{name}': circuit_breaker.failure_threshold must be >= 1"
                ));
            }
            if cb.success_threshold == 0 {
                errors.push(format!(
                    "upstream '{name}': circuit_breaker.success_threshold must be >= 1"
                ));
            }
            if parse_duration(&cb.open_duration).is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid circuit_breaker.open_duration '{}'",
                    cb.open_duration
                ));
            }
            if cb.error_ratio_threshold < 0.0 || cb.error_ratio_threshold > 1.0 {
                errors.push(format!(
                    "upstream '{name}': circuit_breaker.error_ratio_threshold must be between 0.0 and 1.0"
                ));
            }
            if cb.min_requests == 0 {
                errors.push(format!(
                    "upstream '{name}': circuit_breaker.min_requests must be >= 1"
                ));
            }
            if let Some(ref w) = cb.window {
                if parse_duration(w).is_err() {
                    errors.push(format!(
                        "upstream '{name}': invalid circuit_breaker.window '{w}'"
                    ));
                }
            }
        }

        // Validate sticky session config
        if let Some(sticky) = &upstream.sticky {
            if sticky.cookie_name.is_empty() {
                errors.push(format!(
                    "upstream '{name}': sticky.cookie_name must not be empty"
                ));
            }
        }

        // Validate health check config
        if let Some(hc) = &upstream.health_check {
            if hc.path.is_empty() {
                errors.push(format!(
                    "upstream '{name}': health_check.path must not be empty"
                ));
            }
            if !hc.path.is_empty() && !hc.path.starts_with('/') {
                errors.push(format!(
                    "upstream '{name}': health_check.path must start with '/'"
                ));
            }
            let interval_ok = parse_duration(&hc.interval);
            let timeout_ok = parse_duration(&hc.timeout);
            if interval_ok.is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid health_check.interval '{}'",
                    hc.interval
                ));
            }
            if timeout_ok.is_err() {
                errors.push(format!(
                    "upstream '{name}': invalid health_check.timeout '{}'",
                    hc.timeout
                ));
            }
            if let (Ok(interval), Ok(timeout)) = (interval_ok, timeout_ok) {
                if timeout >= interval {
                    errors.push(format!(
                        "upstream '{name}': health_check.timeout ({}) must be less than interval ({})",
                        hc.timeout, hc.interval
                    ));
                }
            }
            if let Some(ref ui) = hc.unhealthy_interval {
                if parse_duration(ui).is_err() {
                    errors.push(format!(
                        "upstream '{name}': invalid health_check.unhealthy_interval '{ui}'"
                    ));
                }
            }
            if hc.expected_status != 0 && !(100..=599).contains(&hc.expected_status) {
                errors.push(format!(
                    "upstream '{name}': health_check.expected_status {} is not a valid HTTP status (100-599)",
                    hc.expected_status
                ));
            }
            if let Some(ref body) = hc.expected_body {
                if body.is_empty() {
                    errors.push(format!(
                        "upstream '{name}': health_check.expected_body must not be empty when set"
                    ));
                }
            }
            let valid_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];
            if !valid_methods.contains(&hc.method.as_str()) {
                errors.push(format!(
                    "upstream '{name}': health_check.method '{}' is not a valid HTTP method. Valid: {}",
                    hc.method,
                    valid_methods.join(", ")
                ));
            }
        }

        // Validate composite upstream config
        if let Some(ref ut) = upstream.upstream_type {
            let valid_types = ["static", "weighted", "failover"];
            if !valid_types.contains(&ut.as_str()) {
                errors.push(format!(
                    "upstream '{name}': invalid upstream_type '{}'. Valid: {}",
                    ut,
                    valid_types.join(", ")
                ));
            }
            if (ut == "weighted" || ut == "failover") && upstream.services.is_empty() {
                errors.push(format!(
                    "upstream '{name}': upstream_type '{ut}' requires at least one service"
                ));
            }
            if (ut == "weighted" || ut == "failover") && !upstream.targets.is_empty() {
                errors.push(format!(
                    "upstream '{name}': composite upstream_type '{ut}' should not have direct targets"
                ));
            }
        }
        for svc in &upstream.services {
            if !config.upstreams.contains_key(&svc.upstream) {
                errors.push(format!(
                    "upstream '{name}': service references unknown upstream '{}'",
                    svc.upstream
                ));
            }
            if svc.weight == 0 {
                errors.push(format!(
                    "upstream '{name}': service '{}' has weight 0 (must be >= 1)",
                    svc.upstream
                ));
            }
        }
    }

    // Detect cycles in composite upstreams via DFS
    {
        use std::collections::{HashMap, HashSet};
        fn has_cycle(
            name: &str,
            upstreams: &HashMap<String, UpstreamConfig>,
            visiting: &mut HashSet<String>,
        ) -> Option<String> {
            if !visiting.insert(name.to_string()) {
                return Some(format!("upstream cycle detected involving '{name}'"));
            }
            if let Some(u) = upstreams.get(name) {
                for svc in &u.services {
                    if let Some(err) = has_cycle(&svc.upstream, upstreams, visiting) {
                        return Some(err);
                    }
                }
            }
            visiting.remove(name);
            None
        }
        for name in config.upstreams.keys() {
            let mut visiting = HashSet::new();
            if let Some(err) = has_cycle(name, &config.upstreams, &mut visiting) {
                errors.push(err);
                break; // One cycle error is enough
            }
        }
    }

    errors
}

/// Generate a default example configuration as a TOML string.
pub fn default_config_toml() -> String {
    r#"# Fluxo configuration file
# See https://github.com/fluxo-dev/fluxo for documentation.

[global]
# admin = "127.0.0.1:2019"
# threads = 0              # 0 = auto-detect CPU count
# log_level = "info"
# access_log_file = "/var/log/fluxo/access.log"
# access_log_max_size = "100mb"   # Rotate when file exceeds this size
# access_log_max_backups = 5      # Keep N rotated backups
# [global.syslog]
# address = "127.0.0.1:514"
# facility = "local0"
# app_name = "fluxo"

[services.web]

  [[services.web.listeners]]
  address = "0.0.0.0:80"
  # offer_h2 = false
  # proxy_protocol = false   # Enable HAProxy PROXY protocol V1/V2

  # [services.web.tls]
  # cert_path = "/etc/fluxo/cert.pem"
  # key_path = "/etc/fluxo/key.pem"

  [[services.web.routes]]
  name = "default"
  # match_host = ["example.com"]
  # match_path = ["/api/*"]
  # max_request_body = "10mb"
  upstream = "backend"

[upstreams.backend]
discovery = "static"
targets = ["127.0.0.1:3000"]
load_balancing = "round_robin"
# connect_timeout = "5s"
# read_timeout = "60s"
# write_timeout = "60s"
# [upstreams.backend.retry]
# attempts = 2
# on = ["error", "timeout"]
# [upstreams.backend.health_check]
# path = "/healthz"
# interval = "10s"
"#
    .to_string()
}

/// Parse a duration string like "10s", "500ms", "1m" into a `Duration`.
pub fn parse_duration(s: &str) -> Result<Duration, ConfigError> {
    let s = s.trim();
    if let Some(val) = s.strip_suffix("ms") {
        let ms: u64 = val
            .parse()
            .map_err(|_| ConfigError::Validation(format!("invalid duration: '{s}'")))?;
        Ok(Duration::from_millis(ms))
    } else if let Some(val) = s.strip_suffix('s') {
        let secs: u64 = val
            .parse()
            .map_err(|_| ConfigError::Validation(format!("invalid duration: '{s}'")))?;
        Ok(Duration::from_secs(secs))
    } else if let Some(val) = s.strip_suffix('m') {
        let mins: u64 = val
            .parse()
            .map_err(|_| ConfigError::Validation(format!("invalid duration: '{s}'")))?;
        Ok(Duration::from_secs(mins * 60))
    } else {
        Err(ConfigError::Validation(format!(
            "invalid duration '{s}': expected suffix 's', 'ms', or 'm'"
        )))
    }
}

/// Parse a byte-size string like "10mb", "1gb", "512kb", "1024" (bytes) into a `u64`.
pub fn parse_size(s: &str) -> Result<u64, ConfigError> {
    let s = s.trim().to_lowercase();
    let err = || {
        ConfigError::Validation(format!(
            "invalid size '{s}': expected e.g. '10mb', '1gb', '512kb'"
        ))
    };

    if let Some(val) = s.strip_suffix("gb") {
        let n: u64 = val.trim().parse().map_err(|_| err())?;
        Ok(n * 1024 * 1024 * 1024)
    } else if let Some(val) = s.strip_suffix("mb") {
        let n: u64 = val.trim().parse().map_err(|_| err())?;
        Ok(n * 1024 * 1024)
    } else if let Some(val) = s.strip_suffix("kb") {
        let n: u64 = val.trim().parse().map_err(|_| err())?;
        Ok(n * 1024)
    } else if let Some(val) = s.strip_suffix('b') {
        let n: u64 = val.trim().parse().map_err(|_| err())?;
        Ok(n)
    } else {
        // Plain number = bytes
        s.parse::<u64>().map_err(|_| err())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).expect("should parse");
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(
            config.upstreams["backend"].targets[0].address(),
            "127.0.0.1:3000"
        );
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[global]
admin = "127.0.0.1:9000"
threads = 4
log_level = "debug"

[services.api]
  [[services.api.listeners]]
  address = "0.0.0.0:443"
  offer_h2 = true

  [services.api.tls]
  cert_path = "/etc/cert.pem"
  key_path = "/etc/key.pem"

  [[services.api.routes]]
  name = "api-v1"
  match_host = ["api.example.com"]
  match_path = ["/v1/*"]
  upstream = "api-servers"

[upstreams.api-servers]
targets = ["10.0.1.1:8080", "10.0.1.2:8080"]
load_balancing = "round_robin"
"#;
        let config = load_from_str(toml).expect("should parse");
        assert_eq!(config.global.threads, 4);
        assert_eq!(config.global.log_level, "debug");
        let svc = &config.services["api"];
        assert_eq!(svc.listeners.len(), 1);
        assert!(svc.listeners[0].offer_h2);
        assert!(svc.tls.is_some());
        assert_eq!(svc.routes[0].match_host, vec!["api.example.com"]);
    }

    #[test]
    fn reject_unknown_upstream() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  upstream = "nonexistent"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn reject_empty_targets() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = []
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("no targets"));
    }

    #[test]
    fn reject_tls_missing_key() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:443"

  [services.web.tls]
  cert_path = "/etc/cert.pem"

  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("key_path is missing"));
    }

    #[test]
    fn acme_requires_email() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:443"

  [services.web.tls]
  acme = true

  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("acme_email"));
    }

    #[test]
    fn acme_valid_config() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:443"

  [services.web.tls]
  acme = true
  acme_email = "ops@example.com"

  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).expect("should parse");
        let tls = config.services["web"].tls.as_ref().unwrap();
        assert!(tls.acme);
        assert_eq!(tls.acme_email.as_deref(), Some("ops@example.com"));
    }

    #[test]
    fn acme_and_cert_path_mutually_exclusive() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:443"

  [services.web.tls]
  acme = true
  acme_email = "ops@example.com"
  cert_path = "/etc/cert.pem"
  key_path = "/etc/key.pem"

  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot use both acme and cert_path")
        );
    }

    #[test]
    fn config_from_upstream_shorthand() {
        let config = config_from_upstream("127.0.0.1:3000").unwrap();
        assert_eq!(
            config.upstreams["default"].targets[0].address(),
            "127.0.0.1:3000"
        );
        assert_eq!(config.services["default"].routes[0].upstream, "default");
    }

    #[test]
    fn reject_no_listeners() {
        let toml = r#"
[services.web]
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("no listeners"));
    }

    #[test]
    fn parse_lb_strategies() {
        for strategy in &["round_robin", "random", "fnv_hash", "consistent_hash"] {
            let toml = format!(
                r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
load_balancing = "{strategy}"
"#
            );
            load_from_str(&toml)
                .unwrap_or_else(|e| panic!("strategy '{strategy}' should be valid: {e}"));
        }
    }

    #[test]
    fn reject_invalid_lb_strategy() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
load_balancing = "least_connections"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("least_connections"));
    }

    #[test]
    fn parse_health_check_config() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/healthz"
interval = "10s"
timeout = "3s"
unhealthy_threshold = 3
healthy_threshold = 2
"#;
        let config = load_from_str(toml).expect("should parse");
        let hc = config.upstreams["backend"].health_check.as_ref().unwrap();
        assert_eq!(hc.path, "/healthz");
        assert_eq!(hc.unhealthy_threshold, 3);
    }

    #[test]
    fn reject_empty_health_check_path() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = ""
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("path must not be empty"));
    }

    #[test]
    fn reject_invalid_health_check_interval() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/health"
interval = "not_a_duration"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("interval"));
    }

    #[test]
    fn parse_duration_values() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert!(parse_duration("bad").is_err());
    }

    #[test]
    fn parse_size_values() {
        assert_eq!(parse_size("1gb").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("10mb").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("512kb").unwrap(), 512 * 1024);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert!(parse_size("bad").is_err());
    }

    #[test]
    fn reject_unknown_plugin_name() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"
  [services.web.routes.plugins.nonexistent]
  foo = "bar"
[upstreams.backend]
targets = ["127.0.0.1:8080"]
"#;
        let result = load_from_str(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn accept_valid_plugin_config() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"
  [services.web.routes.plugins.headers]
  response_set = { "X-Foo" = "bar" }
[upstreams.backend]
targets = ["127.0.0.1:8080"]
"#;
        let result = load_from_str(toml);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_header_matcher_config() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  upstream = "backend"
  [services.web.routes.match_header]
  "X-Debug" = "true"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).expect("should parse");
        let route = &config.services["web"].routes[0];
        assert_eq!(route.match_header.get("X-Debug").unwrap(), "true");
    }

    #[test]
    fn default_config_has_correct_defaults() {
        let config = FluxoConfig::default();
        assert_eq!(config.global.admin, "127.0.0.1:2019");
        assert_eq!(config.global.log_level, "info");
        assert_eq!(config.global.threads, 0);
        assert_eq!(config.global.access_log_format, AccessLogFormat::Json);
        assert!(config.global.metrics_enabled);
    }

    #[test]
    fn access_log_format_defaults_to_json() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
match_path = ["/*"]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).unwrap();
        assert_eq!(config.global.access_log_format, AccessLogFormat::Json);
        assert!(config.global.metrics_enabled);
    }

    #[test]
    fn reject_invalid_access_log_format() {
        let toml = r#"
[global]
access_log_format = "xml"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
match_path = ["/*"]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("access_log_format"));
    }

    #[test]
    fn reject_invalid_admin_address() {
        let toml = r#"
[global]
admin = "not-an-address"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid admin address"));
    }

    #[test]
    fn reject_invalid_listener_address() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "foobar"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid listener address"));
    }

    #[test]
    fn reject_invalid_upstream_target() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["not-a-host"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid target address"));
    }

    #[test]
    fn reject_invalid_log_level() {
        let toml = r#"
[global]
log_level = "verbose"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid log_level"));
    }

    #[test]
    fn config_from_upstream_rejects_invalid_address() {
        let result = config_from_upstream("not-valid");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_trusted_proxy_cidr() {
        let toml = r#"
[global]
trusted_proxies = ["not-a-cidr"]
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid trusted_proxy CIDR"));
    }

    #[test]
    fn accept_valid_trusted_proxies() {
        let toml = r#"
[global]
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).unwrap();
        assert_eq!(config.global.trusted_proxies.len(), 3);
    }

    #[test]
    fn reject_health_check_path_without_leading_slash() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.health_check]
path = "healthz"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("must start with '/'"));
    }

    #[test]
    fn reject_health_check_timeout_exceeds_interval() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.health_check]
path = "/health"
interval = "5s"
timeout = "10s"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("must be less than interval"));
    }

    #[test]
    fn parse_weighted_targets() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = [
  {address = "127.0.0.1:3000", weight = 3},
  {address = "127.0.0.1:3001", weight = 1},
]
"#;
        let config = load_from_str(toml).expect("should parse");
        let targets = &config.upstreams["backend"].targets;
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].address(), "127.0.0.1:3000");
        assert_eq!(targets[0].weight(), 3);
        assert_eq!(targets[1].weight(), 1);
    }

    #[test]
    fn reject_zero_weight_target() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = [{address = "127.0.0.1:3000", weight = 0}]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("weight 0"));
    }

    #[test]
    fn parse_upstream_timeouts() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
connect_timeout = "3s"
read_timeout = "30s"
write_timeout = "30s"
"#;
        let config = load_from_str(toml).expect("should parse");
        let up = &config.upstreams["backend"];
        assert_eq!(up.connect_timeout, "3s");
        assert_eq!(up.read_timeout, "30s");
    }

    #[test]
    fn reject_invalid_upstream_timeout() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
connect_timeout = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("connect_timeout"));
    }

    #[test]
    fn parse_retry_config() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.retry]
attempts = 3
on = ["error", "timeout", "5xx"]
"#;
        let config = load_from_str(toml).expect("should parse");
        let retry = config.upstreams["backend"].retry.as_ref().unwrap();
        assert_eq!(retry.attempts, 3);
        assert!(retry.on.contains(&"5xx".to_string()));
    }

    #[test]
    fn reject_invalid_retry_condition() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.retry]
attempts = 2
on = ["error", "badcondition"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("badcondition"));
    }

    #[test]
    fn parse_max_request_body() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
max_request_body = "10mb"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).expect("should parse");
        let route = &config.services["web"].routes[0];
        assert_eq!(route.max_request_body.as_deref(), Some("10mb"));
    }

    #[test]
    fn reject_invalid_max_request_body() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
max_request_body = "bigfile"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("max_request_body"));
    }

    #[test]
    fn reject_multiple_errors_at_once() {
        let toml = r#"
[global]
admin = "not-an-address"
log_level = "verbose"
trusted_proxies = ["bad-cidr"]

[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        let msg = err.to_string();
        // All three errors should be reported, not just the first one
        assert!(
            msg.contains("invalid admin address"),
            "missing admin error: {msg}"
        );
        assert!(
            msg.contains("invalid log_level"),
            "missing log_level error: {msg}"
        );
        assert!(
            msg.contains("invalid trusted_proxy CIDR"),
            "missing CIDR error: {msg}"
        );
        // Should be a ValidationMultiple
        assert!(matches!(err, ConfigError::ValidationMultiple(_)));
    }

    #[test]
    fn composite_upstream_weighted_valid() {
        let toml = r#"
[global]
admin = "127.0.0.1:2019"

[upstreams.v1]
targets = ["127.0.0.1:3001"]

[upstreams.v2]
targets = ["127.0.0.1:3002"]

[upstreams.canary]
upstream_type = "weighted"
services = [
    { upstream = "v1", weight = 90 },
    { upstream = "v2", weight = 10 },
]

[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "canary"
"#;
        let config = load_from_str(toml).unwrap();
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn composite_upstream_rejects_unknown_child() {
        let toml = r#"
[global]
admin = "127.0.0.1:2019"

[upstreams.canary]
upstream_type = "weighted"
services = [
    { upstream = "nonexistent", weight = 1 },
]

[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "canary"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("unknown upstream 'nonexistent'"));
    }

    #[test]
    fn composite_upstream_rejects_cycle() {
        let toml = r#"
[global]
admin = "127.0.0.1:2019"

[upstreams.a]
upstream_type = "weighted"
services = [{ upstream = "b", weight = 1 }]

[upstreams.b]
upstream_type = "failover"
services = [{ upstream = "a", weight = 1 }]

[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "a"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("cycle detected"));
    }

    #[test]
    fn composite_upstream_rejects_targets_with_weighted() {
        let toml = r#"
[global]
admin = "127.0.0.1:2019"

[upstreams.v1]
targets = ["127.0.0.1:3001"]

[upstreams.canary]
upstream_type = "weighted"
targets = ["127.0.0.1:3003"]
services = [{ upstream = "v1", weight = 1 }]

[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "canary"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("should not have direct targets"));
    }

    #[test]
    fn cache_config_valid() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "cached-api"
  match_path = ["/api/*"]
  upstream = "backend"
  [services.web.routes.cache]
  default_ttl = "5m"
  max_file_size = "10mb"
  stale_while_revalidate = "60s"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).unwrap();
        let route = &config.services["web"].routes[0];
        assert!(route.cache.is_some());
        let cache = route.cache.as_ref().unwrap();
        assert_eq!(cache.default_ttl, "5m");
        assert_eq!(cache.max_file_size, "10mb");
        assert_eq!(cache.stale_while_revalidate, "60s");
    }

    #[test]
    fn cache_config_defaults() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"
  [services.web.routes.cache]

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).unwrap();
        let cache = config.services["web"].routes[0].cache.as_ref().unwrap();
        assert_eq!(cache.default_ttl, "300s");
        assert_eq!(cache.max_file_size, "50mb");
        assert_eq!(cache.methods, vec!["GET", "HEAD"]);
        assert!(cache.include_query);
        assert!(!cache.force_cache);
    }

    #[test]
    fn cache_config_invalid_ttl() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"
  [services.web.routes.cache]
  default_ttl = "invalid"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid cache default_ttl"));
    }

    #[test]
    fn route_without_cache_is_valid() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let config = load_from_str(toml).unwrap();
        assert!(config.services["web"].routes[0].cache.is_none());
    }

    #[test]
    fn parse_health_check_extended_fields() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/healthz"
interval = "10s"
timeout = "3s"
expected_status = 200
expected_body = "OK"
method = "POST"
follow_redirects = false
headers = { "Host" = "example.com", "Authorization" = "Bearer token" }
"#;
        let config = load_from_str(toml).expect("should parse");
        let hc = config.upstreams["backend"].health_check.as_ref().unwrap();
        assert_eq!(hc.expected_status, 200);
        assert_eq!(hc.expected_body.as_deref(), Some("OK"));
        assert_eq!(hc.method, "POST");
        assert!(!hc.follow_redirects);
        assert_eq!(hc.headers.get("Host").unwrap(), "example.com");
        assert_eq!(hc.headers.get("Authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn health_check_extended_fields_have_defaults() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/healthz"
"#;
        let config = load_from_str(toml).expect("should parse");
        let hc = config.upstreams["backend"].health_check.as_ref().unwrap();
        assert_eq!(hc.expected_status, 0);
        assert!(hc.expected_body.is_none());
        assert_eq!(hc.method, "GET");
        assert!(hc.follow_redirects);
        assert!(hc.headers.is_empty());
    }

    #[test]
    fn reject_invalid_health_check_expected_status() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/healthz"
expected_status = 999
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("expected_status"));
    }

    #[test]
    fn reject_empty_health_check_expected_body() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/healthz"
expected_body = ""
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("expected_body"));
    }

    #[test]
    fn reject_invalid_health_check_method() {
        let toml = r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/healthz"
method = "INVALID"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("method"));
    }

    #[test]
    fn accept_valid_health_check_expected_status_range() {
        for status in [100, 200, 301, 404, 503, 599] {
            let toml = format!(
                r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/healthz"
expected_status = {status}
"#
            );
            load_from_str(&toml).unwrap_or_else(|e| panic!("status {status} should be valid: {e}"));
        }
    }

    #[test]
    fn accept_all_valid_health_check_methods() {
        for method in ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            let toml = format!(
                r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"
  [[services.web.routes]]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]

[upstreams.backend.health_check]
path = "/healthz"
method = "{method}"
"#
            );
            load_from_str(&toml)
                .unwrap_or_else(|e| panic!("method '{method}' should be valid: {e}"));
        }
    }

    // --- parse_duration edge cases ---

    #[test]
    fn parse_duration_with_whitespace() {
        assert_eq!(parse_duration("  10s  ").unwrap(), Duration::from_secs(10));
        assert_eq!(
            parse_duration("  500ms  ").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(parse_duration("  2m  ").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn parse_duration_zero_values() {
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("0ms").unwrap(), Duration::from_millis(0));
        assert_eq!(parse_duration("0m").unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn parse_duration_empty_string() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn parse_duration_no_suffix() {
        assert!(parse_duration("123").is_err());
    }

    #[test]
    fn parse_duration_invalid_number_with_suffix() {
        assert!(parse_duration("abcs").is_err());
        assert!(parse_duration("xms").is_err());
        assert!(parse_duration("ym").is_err());
    }

    #[test]
    fn parse_duration_large_values() {
        assert_eq!(
            parse_duration("86400s").unwrap(),
            Duration::from_secs(86400)
        );
        assert_eq!(
            parse_duration("1440m").unwrap(),
            Duration::from_secs(1440 * 60)
        );
    }

    #[test]
    fn parse_duration_negative_rejected() {
        assert!(parse_duration("-5s").is_err());
        assert!(parse_duration("-100ms").is_err());
    }

    // --- parse_size edge cases ---

    #[test]
    fn parse_size_with_b_suffix() {
        assert_eq!(parse_size("1024b").unwrap(), 1024);
    }

    #[test]
    fn parse_size_uppercase() {
        assert_eq!(parse_size("10MB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512KB").unwrap(), 512 * 1024);
    }

    #[test]
    fn parse_size_with_whitespace() {
        assert_eq!(parse_size("  10mb  ").unwrap(), 10 * 1024 * 1024);
    }

    #[test]
    fn parse_size_zero() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("0mb").unwrap(), 0);
        assert_eq!(parse_size("0kb").unwrap(), 0);
    }

    #[test]
    fn parse_size_empty_string() {
        assert!(parse_size("").is_err());
    }

    #[test]
    fn parse_size_invalid_number() {
        assert!(parse_size("abcmb").is_err());
        assert!(parse_size("xgb").is_err());
        assert!(parse_size("ykb").is_err());
        assert!(parse_size("zb").is_err());
    }

    #[test]
    fn parse_size_plain_bytes_large() {
        assert_eq!(parse_size("999999").unwrap(), 999_999);
    }

    // --- default_config_toml ---

    #[test]
    fn default_config_toml_is_parseable() {
        let toml_str = default_config_toml();
        let config: FluxoConfig = toml::from_str(&toml_str).unwrap();
        assert!(config.services.contains_key("web"));
        assert!(config.upstreams.contains_key("backend"));
    }

    // --- config_from_upstream structure ---

    #[test]
    fn config_from_upstream_has_expected_structure() {
        let config = config_from_upstream("127.0.0.1:8080").unwrap();
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.upstreams.len(), 1);
        let svc = &config.services["default"];
        assert_eq!(svc.listeners.len(), 1);
        assert_eq!(svc.listeners[0].address, "0.0.0.0:80");
        assert!(!svc.listeners[0].offer_h2);
        assert!(!svc.listeners[0].proxy_protocol);
        assert!(svc.tls.is_none());
        assert_eq!(svc.routes.len(), 1);
        assert_eq!(svc.routes[0].name.as_deref(), Some("default"));
        let up = &config.upstreams["default"];
        assert_eq!(up.discovery, "static");
        assert_eq!(up.targets.len(), 1);
    }

    // --- validate() single error path ---

    #[test]
    fn validate_single_error_returns_validation_variant() {
        let toml = r#"
[global]
admin = "not-an-address"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
        assert!(err.to_string().contains("invalid admin address"));
    }

    // --- Global timeout validation ---

    #[test]
    fn reject_invalid_client_body_timeout() {
        let toml = r#"
[global]
client_body_timeout = "nope"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("client_body_timeout"));
    }

    #[test]
    fn reject_invalid_client_write_timeout() {
        let toml = r#"
[global]
client_write_timeout = "nope"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("client_write_timeout"));
    }

    #[test]
    fn reject_invalid_shutdown_timeout() {
        let toml = r#"
[global]
shutdown_timeout = "bad"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("shutdown_timeout"));
    }

    #[test]
    fn reject_invalid_shutdown_drain_delay() {
        let toml = r#"
[global]
shutdown_drain_delay = "bad"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("shutdown_drain_delay"));
    }

    // --- access_log_exclude validation ---

    #[test]
    fn accept_valid_access_log_exclude_class_patterns() {
        for pattern in ["1xx", "2xx", "3xx", "4xx", "5xx"] {
            let toml = format!(
                r#"
[global]
access_log_exclude = ["{pattern}"]
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#
            );
            load_from_str(&toml)
                .unwrap_or_else(|e| panic!("pattern '{pattern}' should be valid: {e}"));
        }
    }

    #[test]
    fn accept_valid_access_log_exclude_range() {
        let toml = r#"
[global]
access_log_exclude = ["200-299"]
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        load_from_str(toml).unwrap();
    }

    #[test]
    fn accept_valid_access_log_exclude_exact_code() {
        let toml = r#"
[global]
access_log_exclude = ["404"]
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        load_from_str(toml).unwrap();
    }

    #[test]
    fn reject_invalid_access_log_exclude_pattern() {
        let toml = r#"
[global]
access_log_exclude = ["garbage"]
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid access_log_exclude"));
    }

    #[test]
    fn reject_access_log_exclude_reversed_range() {
        let toml = r#"
[global]
access_log_exclude = ["500-200"]
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid access_log_exclude"));
    }

    #[test]
    fn reject_access_log_exclude_out_of_range_code() {
        let toml = r#"
[global]
access_log_exclude = ["999"]
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid access_log_exclude"));
    }

    // --- Empty listener address ---

    #[test]
    fn reject_empty_listener_address() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = ""
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("empty listener address"));
    }

    // --- TLS key_path set but cert_path missing ---

    #[test]
    fn reject_tls_missing_cert() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:443"
[services.web.tls]
key_path = "/etc/key.pem"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("cert_path is missing"));
    }

    // --- DNS discovery validation ---

    #[test]
    fn reject_dns_discovery_without_hostname() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
discovery = "dns"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("dns_hostname"));
    }

    #[test]
    fn reject_dns_discovery_with_empty_hostname() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
discovery = "dns"
dns_hostname = ""
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("dns_hostname"));
    }

    #[test]
    fn reject_dns_discovery_invalid_refresh_interval() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
discovery = "dns"
dns_hostname = "backend.local"
dns_refresh_interval = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("dns_refresh_interval"));
    }

    #[test]
    fn reject_invalid_discovery_method() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
discovery = "consul"
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("unknown discovery"));
    }

    // --- Retry edge cases ---

    #[test]
    fn reject_retry_zero_attempts() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.retry]
attempts = 0
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("retry.attempts must be >= 1"));
    }

    #[test]
    fn reject_retry_invalid_initial_interval() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.retry]
attempts = 2
initial_interval = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("retry.initial_interval"));
    }

    #[test]
    fn reject_retry_invalid_max_interval() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.retry]
attempts = 2
max_interval = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("retry.max_interval"));
    }

    // --- Passive health check ---

    #[test]
    fn reject_passive_health_invalid_fail_timeout() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.passive_health]
fail_timeout = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("passive_health.fail_timeout"));
    }

    #[test]
    fn reject_passive_health_zero_max_fails() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.passive_health]
max_fails = 0
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("passive_health.max_fails must be >= 1")
        );
    }

    // --- Keepalive timeout ---

    #[test]
    fn reject_invalid_keepalive_timeout() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
keepalive_timeout = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid keepalive_timeout"));
    }

    // --- total_connection_timeout ---

    #[test]
    fn reject_invalid_total_connection_timeout() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
total_connection_timeout = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("total_connection_timeout"));
    }

    // --- tcp_keepalive ---

    #[test]
    fn reject_invalid_tcp_keepalive_idle() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.tcp_keepalive]
idle = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("tcp_keepalive.idle"));
    }

    #[test]
    fn reject_invalid_tcp_keepalive_interval() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.tcp_keepalive]
interval = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("tcp_keepalive.interval"));
    }

    // --- h2_ping_interval ---

    #[test]
    fn reject_invalid_h2_ping_interval() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
h2_ping_interval = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("h2_ping_interval"));
    }

    // --- response_buffer_size ---

    #[test]
    fn reject_invalid_response_buffer_size() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
response_buffer_size = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("response_buffer_size"));
    }

    // --- Circuit breaker ---

    #[test]
    fn reject_circuit_breaker_zero_failure_threshold() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.circuit_breaker]
failure_threshold = 0
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("circuit_breaker.failure_threshold must be >= 1")
        );
    }

    #[test]
    fn reject_circuit_breaker_zero_success_threshold() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.circuit_breaker]
success_threshold = 0
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("circuit_breaker.success_threshold must be >= 1")
        );
    }

    #[test]
    fn reject_circuit_breaker_invalid_open_duration() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.circuit_breaker]
open_duration = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("circuit_breaker.open_duration"));
    }

    #[test]
    fn reject_circuit_breaker_error_ratio_out_of_range() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.circuit_breaker]
error_ratio_threshold = 1.5
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("error_ratio_threshold must be between")
        );
    }

    #[test]
    fn reject_circuit_breaker_negative_error_ratio() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.circuit_breaker]
error_ratio_threshold = -0.1
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("error_ratio_threshold must be between")
        );
    }

    #[test]
    fn reject_circuit_breaker_zero_min_requests() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.circuit_breaker]
min_requests = 0
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("circuit_breaker.min_requests must be >= 1")
        );
    }

    #[test]
    fn reject_circuit_breaker_invalid_window() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.circuit_breaker]
window = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("circuit_breaker.window"));
    }

    // --- Sticky session ---

    #[test]
    fn reject_sticky_empty_cookie_name() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.sticky]
cookie_name = ""
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(
            err.to_string()
                .contains("sticky.cookie_name must not be empty")
        );
    }

    // --- Mirror config ---

    #[test]
    fn reject_mirror_unknown_upstream() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[services.web.routes.mirror]
upstream = "nonexistent"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("mirror upstream"));
    }

    #[test]
    fn reject_mirror_percent_over_100() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[services.web.routes.mirror]
upstream = "mirror-backend"
percent = 150
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.mirror-backend]
targets = ["127.0.0.1:3001"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("mirror.percent must be 0-100"));
    }

    // --- Cache invalid sub-fields ---

    #[test]
    fn reject_cache_invalid_max_file_size() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[services.web.routes.cache]
max_file_size = "bad"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("cache max_file_size"));
    }

    #[test]
    fn reject_cache_invalid_stale_while_revalidate() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[services.web.routes.cache]
stale_while_revalidate = "bad"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("cache stale_while_revalidate"));
    }

    #[test]
    fn reject_cache_invalid_stale_if_error() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[services.web.routes.cache]
stale_if_error = "bad"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("cache stale_if_error"));
    }

    // --- Health check unhealthy_interval ---

    #[test]
    fn reject_invalid_health_check_unhealthy_interval() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.health_check]
path = "/healthz"
unhealthy_interval = "bad"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("unhealthy_interval"));
    }

    // --- Invalid upstream_type ---

    #[test]
    fn reject_invalid_upstream_type() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
upstream_type = "magic"
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("invalid upstream_type"));
    }

    // --- Composite upstream requires services ---

    #[test]
    fn reject_composite_upstream_without_services() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
upstream_type = "weighted"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("requires at least one service"));
    }

    // --- Composite upstream service with zero weight ---

    #[test]
    fn reject_composite_upstream_zero_weight_service() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "canary"
[upstreams.v1]
targets = ["127.0.0.1:3001"]
[upstreams.canary]
upstream_type = "weighted"
services = [{ upstream = "v1", weight = 0 }]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("weight 0"));
    }

    // --- ConfigError display ---

    #[test]
    fn config_error_io_display() {
        let err = ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(err.to_string().contains("failed to read config file"));
    }

    #[test]
    fn config_error_unknown_upstream_display() {
        let err = ConfigError::UnknownUpstream("foo".to_string());
        assert!(err.to_string().contains("unknown upstream 'foo'"));
    }

    #[test]
    fn config_error_validation_multiple_display() {
        let err =
            ConfigError::ValidationMultiple(vec!["error one".to_string(), "error two".to_string()]);
        let msg = err.to_string();
        assert!(msg.contains("error one"));
        assert!(msg.contains("error two"));
        assert!(msg.contains("validation errors:"));
    }

    // --- load_from_str TOML parse error ---

    #[test]
    fn load_from_str_invalid_toml() {
        let err = load_from_str("{{{{not valid toml").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
        assert!(err.to_string().contains("failed to parse TOML"));
    }

    // --- Route name fallback in error messages ---

    #[test]
    fn unknown_upstream_error_uses_route_name() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
name = "my-route"
upstream = "nonexistent"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("my-route"));
    }

    #[test]
    fn unknown_upstream_error_uses_index_fallback() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "nonexistent"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("route[0]"));
    }

    // --- validate() Ok path ---

    #[test]
    fn validate_ok_for_valid_config() {
        let config = config_from_upstream("127.0.0.1:3000").unwrap();
        assert!(validate(&config).is_ok());
    }

    // --- Empty config (no services/upstreams) is valid ---

    #[test]
    fn empty_config_is_valid() {
        let toml = r"
[global]
";
        let config = load_from_str(toml).unwrap();
        assert!(config.services.is_empty());
        assert!(config.upstreams.is_empty());
    }

    // --- Failover upstream type ---

    #[test]
    fn failover_upstream_valid() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "ha"
[upstreams.primary]
targets = ["127.0.0.1:3001"]
[upstreams.secondary]
targets = ["127.0.0.1:3002"]
[upstreams.ha]
upstream_type = "failover"
services = [
  { upstream = "primary", weight = 1 },
  { upstream = "secondary", weight = 1 },
]
"#;
        load_from_str(toml).unwrap();
    }

    // --- Health check timeout equals interval ---

    #[test]
    fn reject_health_check_timeout_equals_interval() {
        let toml = r#"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
[upstreams.backend.health_check]
path = "/health"
interval = "5s"
timeout = "5s"
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("must be less than interval"));
    }

    // --- Valid global timeouts ---

    #[test]
    fn accept_valid_global_timeouts() {
        let toml = r#"
[global]
client_body_timeout = "30s"
client_write_timeout = "60s"
shutdown_timeout = "10s"
shutdown_drain_delay = "5s"
[services.web]
[[services.web.listeners]]
address = "0.0.0.0:80"
[[services.web.routes]]
upstream = "backend"
[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#;
        load_from_str(toml).unwrap();
    }
}
