//! Plugin configuration parsing — compiles TOML plugin config into BuiltinPlugin instances.

use std::collections::HashMap;

use super::BuiltinPlugin;

/// Error type for plugin configuration.
#[derive(Debug, thiserror::Error)]
pub enum PluginConfigError {
    #[error(
        "unknown plugin: '{0}' (valid: headers, rate_limit, cors, ip_restrict, security_headers, request_id, redirect, static_response, compression, basic_auth, strip_prefix, add_prefix, path_rewrite)"
    )]
    UnknownPlugin(String),

    #[error("invalid config for plugin '{name}': {reason}")]
    InvalidConfig { name: String, reason: String },
}

/// Compile plugin instances from route-level and global-level config.
///
/// Route plugins override global plugins of the same name.
/// Returns plugins in execution-order (ip_restrict first, then request-phase, then response-phase).
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
        "basic_auth",    // Auth first — reject unauthorized before doing any work
        "ip_restrict",
        "rate_limit",
        "redirect",
        "static_response",
        "request_id",
        "strip_prefix",  // Path manipulation before forwarding
        "add_prefix",
        "path_rewrite",
        "headers",
        "cors",
        "security_headers",
        "compression",   // Compression last in request phase (captures Accept-Encoding)
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
                super::rate_limit::RateLimitPlugin::new(cfg),
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
            let plugin = super::ip_restrict::IpRestrictPlugin::try_new(cfg).map_err(|reason| {
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
            let cfg: super::compression::CompressionConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
                    name: name.to_string(),
                    reason: e.to_string(),
                })?;
            Ok(BuiltinPlugin::Compression(
                super::compression::CompressionPlugin::new(cfg),
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
            let cfg: super::strip_prefix::StripPrefixConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
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
        "path_rewrite" => {
            let cfg: super::path_rewrite::PathRewriteConfig =
                serde_json::from_value(config).map_err(|e| PluginConfigError::InvalidConfig {
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
        _ => Err(PluginConfigError::UnknownPlugin(name.to_string())),
    }
}

#[cfg(test)]
mod tests {
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
}
