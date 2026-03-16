//! Configuration system — TOML parsing, validation, defaults, and merging.

mod defaults;
mod types;

pub use types::*;

use std::path::Path;

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

    // No config file found — return defaults
    Ok(FluxoConfig::default())
}

/// Create a minimal config for the `--upstream` CLI shorthand.
///
/// Generates a single service with a catch-all route pointing to the given upstream.
pub fn config_from_upstream(upstream: &str) -> FluxoConfig {
    use std::collections::HashMap;

    let mut upstreams = HashMap::new();
    upstreams.insert(
        "default".to_string(),
        UpstreamConfig {
            discovery: "static".to_string(),
            targets: vec![upstream.to_string()],
            load_balancing: "round_robin".to_string(),
            health_check: None,
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
                upstream: "default".to_string(),
            }],
        },
    );

    FluxoConfig {
        global: GlobalConfig::default(),
        services,
        upstreams,
    }
}

/// Validate cross-references and semantic constraints in the config.
pub fn validate(config: &FluxoConfig) -> Result<(), ConfigError> {
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
        }

        // Validate listeners have parseable addresses
        for listener in &service.listeners {
            if listener.address.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "empty listener address in service '{}'",
                    service_name
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

    // Validate TLS: if cert_path is set, key_path must also be set
    for (service_name, service) in &config.services {
        if let Some(tls) = &service.tls {
            if tls.acme {
                return Err(ConfigError::Validation(
                    "ACME is not yet supported in v0.1. Use cert_path/key_path for manual TLS."
                        .to_string(),
                ));
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

    // Validate upstream targets are non-empty for static discovery
    for (name, upstream) in &config.upstreams {
        if upstream.discovery == "static" && upstream.targets.is_empty() {
            return Err(ConfigError::Validation(format!(
                "upstream '{}' has static discovery but no targets",
                name
            )));
        }

        // Only "static" discovery is supported in v0.1
        if upstream.discovery != "static" {
            return Err(ConfigError::Validation(format!(
                "upstream '{}': discovery '{}' is not yet supported. Only 'static' is available in v0.1.",
                name, upstream.discovery
            )));
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
  upstream = "backend"

[upstreams.backend]
discovery = "static"
targets = ["127.0.0.1:3000"]
load_balancing = "round_robin"
# [upstreams.backend.health_check]
# path = "/healthz"
# interval = "10s"
"#
    .to_string()
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
        assert_eq!(
            config.upstreams["backend"].targets,
            vec!["127.0.0.1:3000"]
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
    fn reject_acme_in_v01() {
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
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("ACME is not yet supported"));
    }

    #[test]
    fn config_from_upstream_shorthand() {
        let config = config_from_upstream("localhost:3000");
        assert_eq!(config.upstreams["default"].targets, vec!["localhost:3000"]);
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
    fn default_config_has_correct_defaults() {
        let config = FluxoConfig::default();
        assert_eq!(config.global.admin, "127.0.0.1:2019");
        assert_eq!(config.global.log_level, "info");
        assert_eq!(config.global.threads, 0);
    }
}
