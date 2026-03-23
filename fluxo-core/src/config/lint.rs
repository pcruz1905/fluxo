//! Config linter — produces warnings for suspicious but valid configurations.
//!
//! Unlike `validate()` which produces hard errors, `lint()` produces warnings
//! for configurations that are technically valid but likely problematic in production.

use super::FluxoConfig;

/// Lint severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintLevel {
    /// Potential security or reliability issue.
    Warn,
    /// Informational suggestion.
    Info,
}

impl std::fmt::Display for LintLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Warn => write!(f, "WARN"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

/// A single lint warning.
#[derive(Debug, Clone)]
pub struct LintWarning {
    pub level: LintLevel,
    pub message: String,
}

impl std::fmt::Display for LintWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.level, self.message)
    }
}

/// Run all lint checks on the given config. Returns a list of warnings.
pub fn lint(config: &FluxoConfig) -> Vec<LintWarning> {
    let mut warnings = Vec::new();

    check_unused_upstreams(config, &mut warnings);
    check_public_listeners_without_tls(config, &mut warnings);
    check_admin_security(config, &mut warnings);
    check_missing_health_checks(config, &mut warnings);
    check_large_timeouts(config, &mut warnings);
    check_empty_services(config, &mut warnings);
    check_catchall_routes(config, &mut warnings);
    check_duplicate_routes(config, &mut warnings);

    warnings
}

/// Upstream defined but never referenced by any route.
fn check_unused_upstreams(config: &FluxoConfig, warnings: &mut Vec<LintWarning>) {
    let mut referenced: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for service in config.services.values() {
        for route in &service.routes {
            referenced.insert(&route.upstream);
            if let Some(mirror) = &route.mirror {
                referenced.insert(&mirror.upstream);
            }
        }
    }

    // Also check composite upstream references
    for upstream in config.upstreams.values() {
        for svc_ref in &upstream.services {
            referenced.insert(&svc_ref.upstream);
        }
    }

    for name in config.upstreams.keys() {
        if !referenced.contains(name.as_str()) {
            warnings.push(LintWarning {
                level: LintLevel::Info,
                message: format!("upstream '{name}' is defined but never referenced by any route"),
            });
        }
    }
}

/// Public-facing listener (0.0.0.0) without TLS.
fn check_public_listeners_without_tls(config: &FluxoConfig, warnings: &mut Vec<LintWarning>) {
    for (name, service) in &config.services {
        let has_tls = service
            .tls
            .as_ref()
            .is_some_and(|t| t.acme || t.cert_path.is_some());
        if has_tls {
            continue;
        }

        for listener in &service.listeners {
            if listener.address.starts_with("0.0.0.0:") || listener.address.starts_with("[::]:") {
                warnings.push(LintWarning {
                    level: LintLevel::Warn,
                    message: format!(
                        "service '{name}' listener '{}' is public without TLS — traffic is unencrypted",
                        listener.address
                    ),
                });
            }
        }
    }
}

/// Admin API on 0.0.0.0 without auth token.
fn check_admin_security(config: &FluxoConfig, warnings: &mut Vec<LintWarning>) {
    let is_public = config.global.admin.starts_with("0.0.0.0:")
        || config.global.admin.starts_with("[::]:");

    if is_public && config.global.admin_auth_token.is_none() {
        warnings.push(LintWarning {
            level: LintLevel::Warn,
            message: format!(
                "admin API listens on '{}' without authentication — set admin_auth_token",
                config.global.admin
            ),
        });
    }
}

/// Upstream with multiple targets but no health check.
fn check_missing_health_checks(config: &FluxoConfig, warnings: &mut Vec<LintWarning>) {
    for (name, upstream) in &config.upstreams {
        if upstream.targets.len() > 1 && upstream.health_check.is_none() {
            warnings.push(LintWarning {
                level: LintLevel::Info,
                message: format!(
                    "upstream '{name}' has {} targets but no health_check configured",
                    upstream.targets.len()
                ),
            });
        }
    }
}

/// Any timeout > 5 minutes.
fn check_large_timeouts(config: &FluxoConfig, warnings: &mut Vec<LintWarning>) {
    let five_min = std::time::Duration::from_secs(300);

    for (name, upstream) in &config.upstreams {
        let timeouts = [
            ("connect_timeout", &upstream.connect_timeout),
            ("read_timeout", &upstream.read_timeout),
            ("write_timeout", &upstream.write_timeout),
        ];

        for (field, value) in &timeouts {
            if let Ok(d) = super::parse_duration(value) {
                if d > five_min {
                    warnings.push(LintWarning {
                        level: LintLevel::Warn,
                        message: format!(
                            "upstream '{name}': {field} is {value} (> 5m) — may cause connection pile-up under load"
                        ),
                    });
                }
            }
        }
    }
}

/// Service with no routes defined.
fn check_empty_services(config: &FluxoConfig, warnings: &mut Vec<LintWarning>) {
    for (name, service) in &config.services {
        if service.routes.is_empty() {
            warnings.push(LintWarning {
                level: LintLevel::Warn,
                message: format!(
                    "service '{name}' has no routes — all requests will return 502"
                ),
            });
        }
    }
}

/// Routes with no matchers (host, path, method, header) — matches everything.
fn check_catchall_routes(config: &FluxoConfig, warnings: &mut Vec<LintWarning>) {
    for (name, service) in &config.services {
        for (i, route) in service.routes.iter().enumerate() {
            let has_matchers = !route.match_host.is_empty()
                || !route.match_path.is_empty()
                || !route.match_method.is_empty()
                || !route.match_header.is_empty()
                || !route.match_query.is_empty()
                || !route.match_client_ip.is_empty()
                || !route.match_geoip.is_empty();

            if !has_matchers {
                let fallback = format!("route[{i}]");
                let route_desc = route.name.as_deref().unwrap_or(&fallback);
                // Only warn if it's not the last route (a catch-all at the end is intentional)
                if i < service.routes.len() - 1 {
                    warnings.push(LintWarning {
                        level: LintLevel::Warn,
                        message: format!(
                            "service '{name}' {route_desc}: catch-all route (no matchers) is not last — routes after it will never match"
                        ),
                    });
                } else {
                    warnings.push(LintWarning {
                        level: LintLevel::Info,
                        message: format!(
                            "service '{name}' {route_desc}: catch-all route (no matchers) — matches all requests"
                        ),
                    });
                }
            }
        }
    }
}

/// Duplicate route patterns (same host + path) in same service.
fn check_duplicate_routes(config: &FluxoConfig, warnings: &mut Vec<LintWarning>) {
    for (name, service) in &config.services {
        let mut seen: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for (i, route) in service.routes.iter().enumerate() {
            // Build a fingerprint from host + path matchers
            let mut hosts: Vec<&str> = route.match_host.iter().map(String::as_str).collect();
            hosts.sort_unstable();
            let mut paths: Vec<&str> = route.match_path.iter().map(String::as_str).collect();
            paths.sort_unstable();

            let fingerprint = format!("hosts={hosts:?} paths={paths:?}");

            if let Some(prev_idx) = seen.get(&fingerprint) {
                let fallback = format!("route[{i}]");
                let route_desc = route.name.as_deref().unwrap_or(&fallback);
                warnings.push(LintWarning {
                    level: LintLevel::Warn,
                    message: format!(
                        "service '{name}' {route_desc}: duplicate match pattern as route[{prev_idx}] — this route will never match"
                    ),
                });
            } else {
                seen.insert(fingerprint, i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::config::*;
    use std::collections::HashMap;

    fn minimal_config() -> FluxoConfig {
        FluxoConfig {
            global: GlobalConfig::default(),
            services: HashMap::new(),
            upstreams: HashMap::new(),
            l4: Default::default(),
        }
    }

    #[test]
    fn no_warnings_on_empty_config() {
        let config = minimal_config();
        let warnings = lint(&config);
        assert!(warnings.is_empty());
    }

    #[test]
    fn warns_unused_upstream() {
        let mut config = minimal_config();
        config.upstreams.insert(
            "orphan".to_string(),
            UpstreamConfig {
                targets: vec![TargetConfig::Simple("127.0.0.1:3000".to_string())],
                ..Default::default()
            },
        );

        let warnings = lint(&config);
        assert!(warnings.iter().any(|w| w.message.contains("orphan")
            && w.message.contains("never referenced")));
    }

    #[test]
    fn no_warning_for_used_upstream() {
        let mut config = minimal_config();
        config.upstreams.insert(
            "backend".to_string(),
            UpstreamConfig {
                targets: vec![TargetConfig::Simple("127.0.0.1:3000".to_string())],
                ..Default::default()
            },
        );
        config.services.insert(
            "web".to_string(),
            ServiceConfig {
                routes: vec![RouteConfig {
                    upstream: "backend".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let warnings = lint(&config);
        assert!(!warnings.iter().any(|w| w.message.contains("backend")
            && w.message.contains("never referenced")));
    }

    #[test]
    fn warns_public_listener_without_tls() {
        let mut config = minimal_config();
        config.services.insert(
            "web".to_string(),
            ServiceConfig {
                listeners: vec![ListenerConfig {
                    address: "0.0.0.0:80".to_string(),
                    offer_h2: false,
                    proxy_protocol: false,
                }],
                ..Default::default()
            },
        );

        let warnings = lint(&config);
        assert!(warnings
            .iter()
            .any(|w| w.message.contains("public without TLS")));
    }

    #[test]
    fn warns_admin_on_public_without_auth() {
        let mut config = minimal_config();
        config.global.admin = "0.0.0.0:2019".to_string();

        let warnings = lint(&config);
        assert!(warnings
            .iter()
            .any(|w| w.message.contains("admin API") && w.message.contains("without authentication")));
    }

    #[test]
    fn no_warning_admin_with_auth() {
        let mut config = minimal_config();
        config.global.admin = "0.0.0.0:2019".to_string();
        config.global.admin_auth_token = Some("secret".to_string());

        let warnings = lint(&config);
        assert!(!warnings
            .iter()
            .any(|w| w.message.contains("admin API")));
    }

    #[test]
    fn warns_missing_health_check_on_multi_target() {
        let mut config = minimal_config();
        config.upstreams.insert(
            "pool".to_string(),
            UpstreamConfig {
                targets: vec![
                    TargetConfig::Simple("10.0.0.1:80".to_string()),
                    TargetConfig::Simple("10.0.0.2:80".to_string()),
                ],
                ..Default::default()
            },
        );

        let warnings = lint(&config);
        assert!(warnings
            .iter()
            .any(|w| w.message.contains("pool") && w.message.contains("no health_check")));
    }

    #[test]
    fn warns_duplicate_routes() {
        let mut config = minimal_config();
        config.upstreams.insert(
            "backend".to_string(),
            UpstreamConfig::default(),
        );
        config.services.insert(
            "web".to_string(),
            ServiceConfig {
                routes: vec![
                    RouteConfig {
                        match_host: vec!["api.example.com".to_string()],
                        match_path: vec!["/api/*".to_string()],
                        upstream: "backend".to_string(),
                        ..Default::default()
                    },
                    RouteConfig {
                        match_host: vec!["api.example.com".to_string()],
                        match_path: vec!["/api/*".to_string()],
                        upstream: "backend".to_string(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );

        let warnings = lint(&config);
        assert!(warnings
            .iter()
            .any(|w| w.message.contains("duplicate match pattern")));
    }

    #[test]
    fn warns_empty_service() {
        let mut config = minimal_config();
        config.services.insert(
            "empty".to_string(),
            ServiceConfig::default(),
        );

        let warnings = lint(&config);
        assert!(warnings
            .iter()
            .any(|w| w.message.contains("empty") && w.message.contains("no routes")));
    }
}
