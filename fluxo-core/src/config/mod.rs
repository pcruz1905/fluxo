//! Configuration system — TOML parsing, validation, defaults, and merging.

mod defaults;
mod types;

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

    /// Semantic validation failed.
    #[error("validation error: {0}")]
    Validation(String),

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
            load_balancing: "round_robin".to_string(),
            health_check: None,
            connect_timeout: defaults::connect_timeout(),
            read_timeout: defaults::read_timeout(),
            write_timeout: defaults::write_timeout(),
            retry: None,
            passive_health: None,
            sticky: None,
            circuit_breaker: None,
            keepalive_timeout: defaults::keepalive_timeout(),
            keepalive_pool_size: defaults::keepalive_pool_size(),
        },
    );

    let mut services = HashMap::new();
    services.insert(
        "default".to_string(),
        ServiceConfig {
            listeners: vec![ListenerConfig {
                address: "0.0.0.0:80".to_string(),
                offer_h2: false,
            }],
            tls: None,
            routes: vec![RouteConfig {
                name: Some("default".to_string()),
                match_host: vec![],
                match_path: vec![],
                match_method: vec![],
                match_header: Default::default(),
                upstream: "default".to_string(),
                max_request_body: None,
                plugins: Default::default(),
            }],
        },
    );

    let config = FluxoConfig {
        global: GlobalConfig::default(),
        services,
        upstreams,
    };
    validate(&config)?;
    Ok(config)
}

/// Validate cross-references and semantic constraints in the config.
pub fn validate(config: &FluxoConfig) -> Result<(), ConfigError> {
    // Validate admin address
    config
        .global
        .admin
        .parse::<std::net::SocketAddr>()
        .map_err(|e| {
            ConfigError::Validation(format!(
                "invalid admin address '{}': {}",
                config.global.admin, e
            ))
        })?;

    // Validate log_level
    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    if !valid_levels.contains(&config.global.log_level.as_str()) {
        return Err(ConfigError::Validation(format!(
            "invalid log_level '{}': must be one of {}",
            config.global.log_level,
            valid_levels.join(", ")
        )));
    }

    // Validate trusted_proxies are valid CIDRs
    for cidr in &config.global.trusted_proxies {
        cidr.parse::<ipnet::IpNet>().map_err(|e| {
            ConfigError::Validation(format!("invalid trusted_proxy CIDR '{}': {}", cidr, e))
        })?;
    }

    // Validate access_log_exclude patterns
    let valid_class_patterns = ["1xx", "2xx", "3xx", "4xx", "5xx"];
    for pattern in &config.global.access_log_exclude {
        if valid_class_patterns.contains(&pattern.as_str()) {
            continue;
        }
        // Try numeric range "200-299"
        if let Some((from, to)) = pattern.split_once('-') {
            match (from.parse::<u16>(), to.parse::<u16>()) {
                (Ok(f), Ok(t)) if f <= t && (100..=599).contains(&f) && (100..=599).contains(&t) => continue,
                _ => {}
            }
        }
        // Try exact status code
        if let Ok(code) = pattern.parse::<u16>() {
            if (100..=599).contains(&code) {
                continue;
            }
        }
        return Err(ConfigError::Validation(format!(
            "invalid access_log_exclude pattern '{}': must be a status code (200), class (2xx), or range (200-299)",
            pattern
        )));
    }

    // Every route's upstream must reference a key in config.upstreams
    for (service_name, service) in &config.services {
        for (i, route) in service.routes.iter().enumerate() {
            if !config.upstreams.contains_key(&route.upstream) {
                let fallback = format!("route[{}]", i);
                let route_desc = route.name.as_deref().unwrap_or(&fallback);
                return Err(ConfigError::UnknownUpstream(format!(
                    "'{}' in service '{}' route '{}'",
                    route.upstream, service_name, route_desc
                )));
            }

            // Validate max_request_body size string if set
            if let Some(size_str) = &route.max_request_body {
                parse_size(size_str).map_err(|_| {
                    ConfigError::Validation(format!(
                        "service '{}' route {}: invalid max_request_body '{}': \
                         expected format like '10mb', '1gb', '512kb'",
                        service_name, i, size_str
                    ))
                })?;
            }
        }

        // Validate listener addresses
        for listener in &service.listeners {
            if listener.address.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "empty listener address in service '{}'",
                    service_name
                )));
            }
            listener
                .address
                .parse::<std::net::SocketAddr>()
                .map_err(|e| {
                    ConfigError::Validation(format!(
                        "invalid listener address '{}' in service '{}': {}",
                        listener.address, service_name, e
                    ))
                })?;
        }

        // Validate plugin configuration per route
        for (i, route) in service.routes.iter().enumerate() {
            if let Err(e) =
                crate::plugins::config::compile_plugins(&route.plugins, &config.global.plugins)
            {
                return Err(ConfigError::Validation(format!(
                    "service '{}' route {}: {}",
                    service_name, i, e
                )));
            }
        }

        // Must have at least one listener
        if service.listeners.is_empty() {
            return Err(ConfigError::Validation(format!(
                "service '{}' has no listeners",
                service_name
            )));
        }
    }

    // Validate TLS configuration
    for (service_name, service) in &config.services {
        if let Some(tls) = &service.tls {
            if tls.acme {
                if tls.acme_email.is_none() {
                    return Err(ConfigError::Validation(format!(
                        "service '{}': acme = true requires acme_email to be set",
                        service_name
                    )));
                }
                if tls.cert_path.is_some() || tls.key_path.is_some() {
                    return Err(ConfigError::Validation(format!(
                        "service '{}': cannot use both acme and cert_path/key_path",
                        service_name
                    )));
                }
            }
            match (&tls.cert_path, &tls.key_path) {
                (Some(_), None) => {
                    return Err(ConfigError::Validation(format!(
                        "service '{}': cert_path is set but key_path is missing",
                        service_name
                    )));
                }
                (None, Some(_)) => {
                    return Err(ConfigError::Validation(format!(
                        "service '{}': key_path is set but cert_path is missing",
                        service_name
                    )));
                }
                _ => {}
            }
        }
    }

    // Validate upstream targets and timeouts
    for (name, upstream) in &config.upstreams {
        if upstream.discovery == "static" && upstream.targets.is_empty() {
            return Err(ConfigError::Validation(format!(
                "upstream '{}' has static discovery but no targets",
                name
            )));
        }

        // Validate each target address
        for target in &upstream.targets {
            target
                .address()
                .parse::<std::net::SocketAddr>()
                .map_err(|e| {
                    ConfigError::Validation(format!(
                        "upstream '{}': invalid target address '{}': {}",
                        name,
                        target.address(),
                        e
                    ))
                })?;
            if target.weight() == 0 {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': target '{}' has weight 0 (must be >= 1)",
                    name,
                    target.address()
                )));
            }
        }

        // Only "static" discovery supported currently
        if upstream.discovery != "static" {
            return Err(ConfigError::Validation(format!(
                "upstream '{}': discovery '{}' is not yet supported. Only 'static' is available.",
                name, upstream.discovery
            )));
        }

        // Validate load balancing strategy
        let valid_strategies = ["round_robin", "random", "fnv_hash", "consistent_hash"];
        if !valid_strategies.contains(&upstream.load_balancing.as_str()) {
            return Err(ConfigError::Validation(format!(
                "upstream '{}': unknown load_balancing '{}'. Valid: {}",
                name,
                upstream.load_balancing,
                valid_strategies.join(", ")
            )));
        }

        // Validate timeout strings
        for (field, value) in [
            ("connect_timeout", &upstream.connect_timeout),
            ("read_timeout", &upstream.read_timeout),
            ("write_timeout", &upstream.write_timeout),
        ] {
            parse_duration(value).map_err(|_| {
                ConfigError::Validation(format!(
                    "upstream '{}': invalid {} '{}': expected format like '5s', '500ms', '2m'",
                    name, field, value
                ))
            })?;
        }

        // Validate retry config
        if let Some(retry) = &upstream.retry {
            if retry.attempts == 0 {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': retry.attempts must be >= 1",
                    name
                )));
            }
            let valid_conditions = ["error", "timeout", "5xx"];
            for condition in &retry.on {
                if !valid_conditions.contains(&condition.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "upstream '{}': invalid retry condition '{}'. Valid: {}",
                        name,
                        condition,
                        valid_conditions.join(", ")
                    )));
                }
            }
        }

        // Validate passive health check config
        if let Some(ph) = &upstream.passive_health {
            parse_duration(&ph.fail_timeout).map_err(|_| {
                ConfigError::Validation(format!(
                    "upstream '{}': invalid passive_health.fail_timeout '{}'",
                    name, ph.fail_timeout
                ))
            })?;
            if ph.max_fails == 0 {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': passive_health.max_fails must be >= 1",
                    name
                )));
            }
        }

        // Validate keepalive timeout
        parse_duration(&upstream.keepalive_timeout).map_err(|_| {
            ConfigError::Validation(format!(
                "upstream '{}': invalid keepalive_timeout '{}': expected format like '60s', '30s'",
                name, upstream.keepalive_timeout
            ))
        })?;

        // Validate circuit breaker config
        if let Some(cb) = &upstream.circuit_breaker {
            if cb.failure_threshold == 0 {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': circuit_breaker.failure_threshold must be >= 1",
                    name
                )));
            }
            if cb.success_threshold == 0 {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': circuit_breaker.success_threshold must be >= 1",
                    name
                )));
            }
            parse_duration(&cb.open_duration).map_err(|_| {
                ConfigError::Validation(format!(
                    "upstream '{}': invalid circuit_breaker.open_duration '{}'",
                    name, cb.open_duration
                ))
            })?;
        }

        // Validate sticky session config
        if let Some(sticky) = &upstream.sticky {
            if sticky.cookie_name.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': sticky.cookie_name must not be empty",
                    name
                )));
            }
        }

        // Validate health check config
        if let Some(hc) = &upstream.health_check {
            if hc.path.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': health_check.path must not be empty",
                    name
                )));
            }
            if !hc.path.starts_with('/') {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': health_check.path must start with '/'",
                    name
                )));
            }
            let interval = parse_duration(&hc.interval).map_err(|_| {
                ConfigError::Validation(format!(
                    "upstream '{}': invalid health_check.interval '{}'",
                    name, hc.interval
                ))
            })?;
            let timeout = parse_duration(&hc.timeout).map_err(|_| {
                ConfigError::Validation(format!(
                    "upstream '{}': invalid health_check.timeout '{}'",
                    name, hc.timeout
                ))
            })?;
            if timeout >= interval {
                return Err(ConfigError::Validation(format!(
                    "upstream '{}': health_check.timeout ({}) must be less than interval ({})",
                    name, hc.timeout, hc.interval
                )));
            }
        }
    }

    Ok(())
}

/// Generate a default example configuration as a TOML string.
pub fn default_config_toml() -> String {
    r#"# Fluxo configuration file
# See https://github.com/fluxo-dev/fluxo for documentation.

[global]
# admin = "127.0.0.1:2019"
# threads = 0              # 0 = auto-detect CPU count
# log_level = "info"

[services.web]

  [[services.web.listeners]]
  address = "0.0.0.0:80"
  # offer_h2 = false

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
    let err = || ConfigError::Validation(format!("invalid size '{}': expected e.g. '10mb', '1gb', '512kb'", s));

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
        assert_eq!(config.upstreams["backend"].targets[0].address(), "127.0.0.1:3000");
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
        assert!(err.to_string().contains("cannot use both acme and cert_path"));
    }

    #[test]
    fn config_from_upstream_shorthand() {
        let config = config_from_upstream("127.0.0.1:3000").unwrap();
        assert_eq!(config.upstreams["default"].targets[0].address(), "127.0.0.1:3000");
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
}
