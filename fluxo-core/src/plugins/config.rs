//! Plugin configuration parsing — compiles TOML plugin config into `BuiltinPlugin` instances.

use std::collections::HashMap;

use super::BuiltinPlugin;

/// Error type for plugin configuration.
#[derive(Debug, thiserror::Error)]
pub enum PluginConfigError {
    #[error(
        "unknown plugin: '{0}' (valid: headers, rate_limit, cors, ip_restrict, security_headers, request_id, redirect, static_response, compression, basic_auth, strip_prefix, add_prefix, path_rewrite, concurrency_limit, bandwidth_limit, request_buffer, jwt_auth, key_auth, csrf, referer_restrict, ua_restrict, static_files, traffic_split)"
    )]
    UnknownPlugin(String),

    #[error("invalid config for plugin '{name}': {reason}")]
    InvalidConfig { name: String, reason: String },
}

/// Compile plugin instances from route-level and global-level config.
///
/// Route plugins override global plugins of the same name.
/// Returns plugins in execution-order (`ip_restrict` first, then request-phase, then response-phase).
#[allow(clippy::implicit_hasher)]
pub fn compile_plugins(
    route_plugins: &HashMap<String, serde_json::Value>,
    global_plugins: &HashMap<String, serde_json::Value>,
) -> Result<Vec<BuiltinPlugin>, PluginConfigError> {
    // Merge: start with global, overlay route (route wins on conflict)
    let mut merged = global_plugins.clone();
    for (name, config) in route_plugins {
        merged.insert(name.clone(), config.clone());
    }

    let mut plugins = Vec::new();

    // Build plugins in phase order
    let ordered_names = [
        "jwt_auth", // Auth first — reject unauthorized before doing any work
        "key_auth",
        "basic_auth",
        "csrf",
        "ip_restrict",
        "referer_restrict",
        "ua_restrict",
        "rate_limit",
        "concurrency_limit",
        "traffic_split", // Routing decisions before forwarding
        "redirect",
        "static_response",
        "static_files",
        "request_id",
        "strip_prefix", // Path manipulation before forwarding
        "add_prefix",
        "path_rewrite",
        "headers",
        "cors",
        "security_headers",
        "compression", // Compression last in request phase (captures Accept-Encoding)
        "bandwidth_limit",
        "request_buffer",
    ];

    for name in ordered_names {
        if let Some(config) = merged.remove(name) {
            let plugin = build_plugin(name, config)?;
            plugins.push(plugin);
        }
    }

    // Any remaining keys are unknown plugins
    if let Some(unknown) = merged.keys().next() {
        return Err(PluginConfigError::UnknownPlugin(unknown.clone()));
    }

    Ok(plugins)
}

/// Build a single plugin instance from its name and config value.
#[allow(clippy::too_many_lines)]
fn build_plugin(name: &str, config: serde_json::Value) -> Result<BuiltinPlugin, PluginConfigError> {
    match name {
        "headers" => {
            let cfg: super::headers::HeadersConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::Headers(super::headers::HeadersPlugin::new(
                cfg,
            )))
        }
        "rate_limit" => {
            let cfg: super::rate_limit::RateLimitConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::RateLimit(
                super::rate_limit::RateLimitPlugin::new(&cfg),
            ))
        }
        "cors" => {
            let cfg: super::cors::CorsConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            super::cors::CorsPlugin::validate(&cfg).map_err(|reason| {
                PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason,
                }
            })?;
            Ok(BuiltinPlugin::Cors(super::cors::CorsPlugin::new(cfg)))
        }
        "ip_restrict" => {
            let cfg: super::ip_restrict::IpRestrictConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            let plugin = super::ip_restrict::IpRestrictPlugin::try_new(&cfg).map_err(|reason| {
                PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason,
                }
            })?;
            Ok(BuiltinPlugin::IpRestrict(plugin))
        }
        "security_headers" => {
            let cfg: super::security_headers::SecurityHeadersConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::SecurityHeaders(
                super::security_headers::SecurityHeadersPlugin::new(cfg),
            ))
        }
        "request_id" => {
            let cfg: super::request_id::RequestIdConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::RequestId(
                super::request_id::RequestIdPlugin::new(cfg),
            ))
        }
        "redirect" => {
            let cfg: super::redirect::RedirectConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            if !super::redirect::RedirectPlugin::validate_status(cfg.status) {
                return Err(PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: format!(
                        "invalid redirect status {}: must be 301, 302, 307, or 308",
                        cfg.status
                    ),
                });
            }
            Ok(BuiltinPlugin::Redirect(
                super::redirect::RedirectPlugin::new(cfg),
            ))
        }
        "static_response" => {
            let cfg: super::static_response::StaticResponseConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::StaticResponse(
                super::static_response::StaticResponsePlugin::new(cfg),
            ))
        }
        "compression" => {
            let cfg: super::compression::CompressionConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::Compression(
                super::compression::CompressionPlugin::new(&cfg),
            ))
        }
        "basic_auth" => {
            let cfg: super::basic_auth::BasicAuthConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            if cfg.users.is_empty() {
                return Err(PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: "basic_auth.users must not be empty".to_string(),
                });
            }
            Ok(BuiltinPlugin::BasicAuth(
                super::basic_auth::BasicAuthPlugin::new(cfg),
            ))
        }
        "strip_prefix" => {
            let cfg: super::strip_prefix::StripPrefixConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            if cfg.prefixes.is_empty() {
                return Err(PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: "strip_prefix.prefixes must not be empty".to_string(),
                });
            }
            Ok(BuiltinPlugin::StripPrefix(
                super::strip_prefix::StripPrefixPlugin::new(cfg),
            ))
        }
        "add_prefix" => {
            let cfg: super::add_prefix::AddPrefixConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            if cfg.prefix.is_empty() {
                return Err(PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: "add_prefix.prefix must not be empty".to_string(),
                });
            }
            Ok(BuiltinPlugin::AddPrefix(
                super::add_prefix::AddPrefixPlugin::new(cfg),
            ))
        }
        "concurrency_limit" => {
            let cfg: super::concurrency_limit::ConcurrencyLimitConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::ConcurrencyLimit(
                super::concurrency_limit::ConcurrencyLimitPlugin::new(&cfg),
            ))
        }
        "bandwidth_limit" => {
            let cfg: super::bandwidth_limit::BandwidthLimitConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::BandwidthLimit(
                super::bandwidth_limit::BandwidthLimitPlugin::new(&cfg),
            ))
        }
        "path_rewrite" => {
            let cfg: super::path_rewrite::PathRewriteConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            let plugin =
                super::path_rewrite::PathRewritePlugin::try_new(cfg).map_err(|reason| {
                    PluginConfigError::InvalidConfig {
                        name: name.to_string(),
                        reason,
                    }
                })?;
            Ok(BuiltinPlugin::PathRewrite(plugin))
        }
        "request_buffer" => {
            let cfg: super::request_buffer::RequestBufferConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::RequestBuffer(
                super::request_buffer::RequestBufferPlugin::new(&cfg),
            ))
        }
        "jwt_auth" => {
            let cfg: super::jwt_auth::JwtAuthConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            let plugin = super::jwt_auth::JwtAuthPlugin::try_new(cfg).map_err(|reason| {
                PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason,
                }
            })?;
            Ok(BuiltinPlugin::JwtAuth(plugin))
        }
        "key_auth" => {
            let cfg: super::key_auth::KeyAuthConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            let plugin = super::key_auth::KeyAuthPlugin::try_new(cfg).map_err(|reason| {
                PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason,
                }
            })?;
            Ok(BuiltinPlugin::KeyAuth(plugin))
        }
        "csrf" => {
            let cfg: super::csrf::CsrfConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            let plugin = super::csrf::CsrfPlugin::try_new(cfg).map_err(|reason| {
                PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason,
                }
            })?;
            Ok(BuiltinPlugin::Csrf(plugin))
        }
        "referer_restrict" => {
            let cfg: super::referer_restrict::RefererRestrictConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::RefererRestrict(
                super::referer_restrict::RefererRestrictPlugin::new(cfg),
            ))
        }
        "ua_restrict" => {
            let cfg: super::ua_restrict::UaRestrictConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            let plugin = super::ua_restrict::UaRestrictPlugin::try_new(&cfg).map_err(|reason| {
                PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason,
                }
            })?;
            Ok(BuiltinPlugin::UaRestrict(plugin))
        }
        "static_files" => {
            let cfg: super::static_files::StaticFilesConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            let plugin =
                super::static_files::StaticFilesPlugin::try_new(cfg).map_err(|reason| {
                    PluginConfigError::InvalidConfig {
                        name: name.to_string(),
                        reason,
                    }
                })?;
            Ok(BuiltinPlugin::StaticFiles(plugin))
        }
        "traffic_split" => {
            let cfg: super::traffic_split::TrafficSplitConfig = serde_json::from_value(config)
                .map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::TrafficSplit(
                super::traffic_split::TrafficSplitPlugin::new(cfg),
            ))
        }
        _ => Err(PluginConfigError::UnknownPlugin(name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_empty_plugin_config() {
        let config: HashMap<String, serde_json::Value> = HashMap::new();
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert!(plugins.is_empty());
    }

    #[test]
    fn parse_headers_plugin_config() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "headers".to_string(),
            serde_json::json!({
                "response_set": { "X-Powered-By": "fluxo" }
            }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
    }

    #[test]
    fn unknown_plugin_name_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("nonexistent".to_string(), serde_json::json!({}));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn global_plugins_merged_with_route_plugins() {
        let mut global: HashMap<String, serde_json::Value> = HashMap::new();
        global.insert(
            "security_headers".to_string(),
            serde_json::json!({ "hsts_max_age": 31536000 }),
        );
        let mut route: HashMap<String, serde_json::Value> = HashMap::new();
        route.insert(
            "headers".to_string(),
            serde_json::json!({ "response_set": { "X-Foo": "bar" } }),
        );
        let plugins = compile_plugins(&route, &global).unwrap();
        assert_eq!(plugins.len(), 2);
    }

    #[test]
    fn invalid_cidr_in_ip_restrict_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "ip_restrict".to_string(),
            serde_json::json!({ "deny": ["not-a-cidr"] }),
        );
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid deny CIDR"));
    }

    #[test]
    fn invalid_redirect_status_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "redirect".to_string(),
            serde_json::json!({ "url": "/new", "status": 500 }),
        );
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid redirect status"));
    }

    #[test]
    fn cors_credentials_with_wildcard_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "cors".to_string(),
            serde_json::json!({ "allowed_origins": ["*"], "allow_credentials": true }),
        );
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("incompatible with wildcard"));
    }

    #[test]
    fn route_plugin_overrides_global() {
        let mut global: HashMap<String, serde_json::Value> = HashMap::new();
        global.insert(
            "headers".to_string(),
            serde_json::json!({ "response_set": { "X-Global": "yes" } }),
        );
        let mut route: HashMap<String, serde_json::Value> = HashMap::new();
        route.insert(
            "headers".to_string(),
            serde_json::json!({ "response_set": { "X-Route": "yes" } }),
        );
        let plugins = compile_plugins(&route, &global).unwrap();
        // Route overrides global — only 1 headers plugin, not 2
        assert_eq!(plugins.len(), 1);
    }

    // --- Build every plugin type (covers all build_plugin branches) ---

    #[test]
    fn build_rate_limit_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "rate_limit".to_string(),
            serde_json::json!({ "requests_per_second": 10, "burst": 20 }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::RateLimit(_)));
    }

    #[test]
    fn build_cors_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "cors".to_string(),
            serde_json::json!({ "allowed_origins": ["https://example.com"] }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::Cors(_)));
    }

    #[test]
    fn build_ip_restrict_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "ip_restrict".to_string(),
            serde_json::json!({ "deny": ["10.0.0.0/8"] }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::IpRestrict(_)));
    }

    #[test]
    fn build_security_headers_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "security_headers".to_string(),
            serde_json::json!({ "hsts_max_age": 31536000 }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::SecurityHeaders(_)));
    }

    #[test]
    fn build_request_id_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("request_id".to_string(), serde_json::json!({}));
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::RequestId(_)));
    }

    #[test]
    fn build_redirect_plugin_valid() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "redirect".to_string(),
            serde_json::json!({ "url": "https://example.com{path}", "status": 301 }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::Redirect(_)));
    }

    #[test]
    fn build_static_response_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "static_response".to_string(),
            serde_json::json!({ "status": 200, "body": "OK" }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::StaticResponse(_)));
    }

    #[test]
    fn build_compression_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "compression".to_string(),
            serde_json::json!({ "algorithms": ["gzip"] }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::Compression(_)));
    }

    #[test]
    fn build_basic_auth_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "basic_auth".to_string(),
            serde_json::json!({ "users": { "admin": "password" } }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::BasicAuth(_)));
    }

    #[test]
    fn build_basic_auth_empty_users_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("basic_auth".to_string(), serde_json::json!({ "users": {} }));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn build_strip_prefix_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "strip_prefix".to_string(),
            serde_json::json!({ "prefixes": ["/api"] }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::StripPrefix(_)));
    }

    #[test]
    fn build_strip_prefix_empty_prefixes_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "strip_prefix".to_string(),
            serde_json::json!({ "prefixes": [] }),
        );
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn build_add_prefix_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "add_prefix".to_string(),
            serde_json::json!({ "prefix": "/api/v2" }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::AddPrefix(_)));
    }

    #[test]
    fn build_add_prefix_empty_prefix_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "add_prefix".to_string(),
            serde_json::json!({ "prefix": "" }),
        );
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn build_concurrency_limit_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "concurrency_limit".to_string(),
            serde_json::json!({ "max_connections": 100 }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::ConcurrencyLimit(_)));
    }

    #[test]
    fn build_bandwidth_limit_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "bandwidth_limit".to_string(),
            serde_json::json!({ "bytes_per_second": 1048576 }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::BandwidthLimit(_)));
    }

    #[test]
    fn build_path_rewrite_plugin() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "path_rewrite".to_string(),
            serde_json::json!({ "pattern": "^/old/(.*)", "replacement": "/new/$1" }),
        );
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(matches!(plugins[0], BuiltinPlugin::PathRewrite(_)));
    }

    #[test]
    fn build_path_rewrite_invalid_regex_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "path_rewrite".to_string(),
            serde_json::json!({ "pattern": "[invalid", "replacement": "" }),
        );
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid regex"));
    }

    // --- Invalid JSON shapes for deserialization errors ---

    #[test]
    fn invalid_json_for_rate_limit_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("rate_limit".to_string(), serde_json::json!("not-an-object"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("rate_limit"));
    }

    #[test]
    fn invalid_json_for_security_headers_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("security_headers".to_string(), serde_json::json!("bad"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("security_headers"));
    }

    #[test]
    fn invalid_json_for_request_id_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("request_id".to_string(), serde_json::json!(42));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("request_id"));
    }

    #[test]
    fn invalid_json_for_redirect_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("redirect".to_string(), serde_json::json!("not-valid"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("redirect"));
    }

    #[test]
    fn invalid_json_for_static_response_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("static_response".to_string(), serde_json::json!("bad"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("static_response"));
    }

    #[test]
    fn invalid_json_for_compression_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("compression".to_string(), serde_json::json!("bad"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("compression"));
    }

    #[test]
    fn invalid_json_for_basic_auth_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("basic_auth".to_string(), serde_json::json!("bad"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("basic_auth"));
    }

    #[test]
    fn invalid_json_for_strip_prefix_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("strip_prefix".to_string(), serde_json::json!("bad"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("strip_prefix"));
    }

    #[test]
    fn invalid_json_for_add_prefix_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("add_prefix".to_string(), serde_json::json!(99));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("add_prefix"));
    }

    #[test]
    fn invalid_json_for_concurrency_limit_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("concurrency_limit".to_string(), serde_json::json!("bad"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("concurrency_limit"));
    }

    #[test]
    fn invalid_json_for_bandwidth_limit_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("bandwidth_limit".to_string(), serde_json::json!("bad"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("bandwidth_limit"));
    }

    #[test]
    fn invalid_json_for_ip_restrict_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("ip_restrict".to_string(), serde_json::json!("bad"));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ip_restrict"));
    }

    #[test]
    fn invalid_json_for_cors_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("cors".to_string(), serde_json::json!(42));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cors"));
    }

    #[test]
    fn invalid_json_for_path_rewrite_returns_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("path_rewrite".to_string(), serde_json::json!(42));
        let result = compile_plugins(&config, &HashMap::new());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("path_rewrite"));
    }

    // --- Plugin ordering ---

    #[test]
    fn plugins_compiled_in_phase_order() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        // Insert in non-phase order
        config.insert(
            "compression".to_string(),
            serde_json::json!({ "algorithms": ["gzip"] }),
        );
        config.insert(
            "headers".to_string(),
            serde_json::json!({ "response_set": { "X-Foo": "bar" } }),
        );
        config.insert("request_id".to_string(), serde_json::json!({}));
        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        assert_eq!(plugins.len(), 3);
        // Phase order: request_id, headers, compression
        assert!(matches!(plugins[0], BuiltinPlugin::RequestId(_)));
        assert!(matches!(plugins[1], BuiltinPlugin::Headers(_)));
        assert!(matches!(plugins[2], BuiltinPlugin::Compression(_)));
    }

    // --- Error message content ---

    #[test]
    fn unknown_plugin_error_message_contains_name() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("foobar_plugin".to_string(), serde_json::json!({}));
        let err = compile_plugins(&config, &HashMap::new()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("foobar_plugin"));
        assert!(msg.contains("unknown plugin"));
    }

    #[test]
    fn multiple_unknown_plugins_returns_first_error() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert("unknown_a".to_string(), serde_json::json!({}));
        config.insert("unknown_b".to_string(), serde_json::json!({}));
        let err = compile_plugins(&config, &HashMap::new()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown plugin"));
    }

    // --- All plugins at once ---

    #[test]
    fn compile_all_plugins_together() {
        let mut config: HashMap<String, serde_json::Value> = HashMap::new();
        config.insert(
            "headers".to_string(),
            serde_json::json!({ "response_set": { "X-Foo": "bar" } }),
        );
        config.insert(
            "rate_limit".to_string(),
            serde_json::json!({ "requests_per_second": 10, "burst": 20 }),
        );
        config.insert(
            "cors".to_string(),
            serde_json::json!({ "allowed_origins": ["https://example.com"] }),
        );
        config.insert(
            "ip_restrict".to_string(),
            serde_json::json!({ "deny": ["10.0.0.0/8"] }),
        );
        config.insert(
            "security_headers".to_string(),
            serde_json::json!({ "hsts_max_age": 31536000 }),
        );
        config.insert("request_id".to_string(), serde_json::json!({}));
        config.insert(
            "redirect".to_string(),
            serde_json::json!({ "url": "/new", "status": 302 }),
        );
        config.insert(
            "static_response".to_string(),
            serde_json::json!({ "status": 200 }),
        );
        config.insert(
            "compression".to_string(),
            serde_json::json!({ "algorithms": ["gzip"] }),
        );
        config.insert(
            "basic_auth".to_string(),
            serde_json::json!({ "users": { "admin": "pass" } }),
        );
        config.insert(
            "strip_prefix".to_string(),
            serde_json::json!({ "prefixes": ["/api"] }),
        );
        config.insert(
            "add_prefix".to_string(),
            serde_json::json!({ "prefix": "/v2" }),
        );
        config.insert(
            "path_rewrite".to_string(),
            serde_json::json!({ "pattern": "^/old", "replacement": "/new" }),
        );
        config.insert(
            "concurrency_limit".to_string(),
            serde_json::json!({ "max_connections": 50 }),
        );
        config.insert(
            "bandwidth_limit".to_string(),
            serde_json::json!({ "bytes_per_second": 1024 }),
        );

        let plugins = compile_plugins(&config, &HashMap::new()).unwrap();
        // All 15 known plugins should be compiled (14 ordered + redirect is in the list = 15 total)
        assert_eq!(plugins.len(), 15);
    }
}
