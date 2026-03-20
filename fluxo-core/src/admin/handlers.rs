use std::path::Path;
use std::sync::Arc;

use pingora_cache::Storage;

use crate::observability::MetricsRegistry;
use crate::proxy::{FluxoProxy, FluxoState};

/// Helper to safely serialize JSON and ensure a valid response even on serialization panic/failure.
pub fn json_response<T: serde::Serialize>(status: u16, value: &T) -> (u16, String, &'static str) {
    match serde_json::to_string(value) {
        Ok(body) => (status, body, "application/json"),
        Err(e) => (
            500,
            format!(r#"{{"error": "serialization failed: {e}"}}"#),
            "application/json",
        ),
    }
}

/// Helper for pretty-printed JSON responses.
pub fn json_response_pretty<T: serde::Serialize>(
    status: u16,
    value: &T,
) -> (u16, String, &'static str) {
    match serde_json::to_string_pretty(value) {
        Ok(body) => (status, body, "application/json"),
        Err(e) => (
            500,
            format!(r#"{{"error": "pretty serialization failed: {e}"}}"#),
            "application/json",
        ),
    }
}

/// GET /health — process health info
///
/// Returns 503 when the server is draining (graceful shutdown in progress),
/// allowing load balancers to remove this instance before connections drain.
pub fn handle_health(proxy: &FluxoProxy) -> (u16, String, &'static str) {
    let is_draining = proxy
        .static_state
        .draining
        .load(std::sync::atomic::Ordering::Relaxed);

    if is_draining {
        let body = serde_json::json!({
            "status": "draining",
            "version": env!("CARGO_PKG_VERSION"),
        });
        return json_response_pretty(503, &body);
    }

    let state = proxy.state_snapshot();
    let service_count = state.config.services.len();
    let upstream_count = state.config.upstreams.len();

    let body = serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "services": service_count,
        "upstreams": upstream_count,
    });
    json_response_pretty(200, &body)
}

/// GET /metrics — Prometheus text exposition
pub fn handle_metrics(metrics: &MetricsRegistry) -> (u16, String, &'static str) {
    (
        200,
        metrics.encode(),
        "text/plain; version=0.0.4; charset=utf-8",
    )
}

/// GET /config — export running config as JSON
pub fn handle_config(proxy: &FluxoProxy) -> (u16, String, &'static str) {
    let state = proxy.state_snapshot();
    json_response_pretty(200, &state.config)
}

/// GET /upstreams — list all upstreams with their target counts and health check status
pub fn handle_upstreams(proxy: &FluxoProxy) -> (u16, String, &'static str) {
    let state = proxy.state_snapshot();
    let mut upstreams = serde_json::Map::new();

    for (name, upstream_config) in &state.config.upstreams {
        let targets: Vec<serde_json::Value> = upstream_config
            .targets
            .iter()
            .map(|t| {
                serde_json::json!({
                    "address": t.address(),
                    "weight": t.weight(),
                })
            })
            .collect();

        upstreams.insert(
            name.clone(),
            serde_json::json!({
                "targets": targets,
                "load_balancing": upstream_config.load_balancing,
                "connect_timeout": upstream_config.connect_timeout,
                "read_timeout": upstream_config.read_timeout,
                "write_timeout": upstream_config.write_timeout,
                "health_check": upstream_config.health_check.as_ref().map(|hc| serde_json::json!({
                    "path": hc.path,
                    "interval": hc.interval,
                })),
            }),
        );
    }
    json_response_pretty(200, &serde_json::Value::Object(upstreams))
}

/// POST /config — replace running config with JSON body
pub fn handle_post_config(proxy: &Arc<FluxoProxy>, body: &[u8]) -> (u16, String, &'static str) {
    let config: crate::config::FluxoConfig = match serde_json::from_slice(body) {
        Ok(c) => c,
        Err(e) => {
            return json_response(
                400,
                &serde_json::json!({"error": format!("invalid JSON: {e}")}),
            );
        }
    };

    if let Err(e) = crate::config::validate(&config) {
        return match &e {
            crate::config::ConfigError::ValidationMultiple(errors) => {
                json_response(400, &serde_json::json!({"errors": errors}))
            }
            _ => json_response(400, &serde_json::json!({"error": e.to_string()})),
        };
    }

    match FluxoState::try_from_config(config) {
        Ok(new_state) => {
            proxy.reload(new_state);
            json_response(200, &serde_json::json!({"status": "reloaded"}))
        }
        Err(e) => json_response(500, &serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /reload — re-read config file from disk and hot-reload
pub fn handle_reload(
    proxy: &Arc<FluxoProxy>,
    config_path: Option<&str>,
) -> (u16, String, &'static str) {
    let path = if let Some(p) = config_path {
        p.to_string()
    } else {
        // Try default paths
        let candidates = ["fluxo.toml", "/etc/fluxo/fluxo.toml"];
        match candidates.iter().find(|p| Path::new(p).exists()) {
            Some(p) => p.to_string(),
            None => {
                return json_response(404, &serde_json::json!({"error": "no config file found"}));
            }
        }
    };

    match crate::config::load_from_file(Path::new(&path)) {
        Ok(config) => match FluxoState::try_from_config(config) {
            Ok(new_state) => {
                proxy.reload(new_state);
                json_response(
                    200,
                    &serde_json::json!({"status": "reloaded", "path": path}),
                )
            }
            Err(e) => json_response(500, &serde_json::json!({"error": e.to_string()})),
        },
        Err(e) => json_response(500, &serde_json::json!({"error": e.to_string()})),
    }
}

/// POST /cache/purge — purge cached entries by key.
///
/// Accepts JSON body with fields to build the cache key:
/// ```json
/// { "host": "example.com", "path": "/api/users", "method": "GET" }
/// ```
/// - `host` (required): the Host header value
/// - `path` (required): the request path (include query string if the route caches it)
/// - `method` (optional, default "GET"): the HTTP method
///
/// Returns `{"purged": true}` if the entry was found and removed,
/// `{"purged": false}` if no matching entry existed.
pub async fn handle_cache_purge(body: &[u8]) -> (u16, String, &'static str) {
    let request: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                400,
                &serde_json::json!({"error": format!("invalid JSON: {e}")}),
            );
        }
    };

    let Some(host) = request.get("host").and_then(|v| v.as_str()) else {
        return json_response(
            400,
            &serde_json::json!({"error": "missing required field: host"}),
        );
    };

    let Some(path) = request.get("path").and_then(|v| v.as_str()) else {
        return json_response(
            400,
            &serde_json::json!({"error": "missing required field: path"}),
        );
    };

    let method = request
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET");

    // Build cache key matching the logic in cache_key_callback
    let primary = format!("{method}{host}{path}");
    let key = pingora_cache::CacheKey::new("", primary, "");
    let compact = key.to_compact();

    let storage = crate::proxy::global_cache_storage();
    let span = pingora_cache::trace::Span::inactive();
    let handle = span.handle();

    match storage
        .purge(&compact, pingora_cache::PurgeType::Invalidation, &handle)
        .await
    {
        Ok(purged) => json_response(200, &serde_json::json!({"purged": purged})),
        Err(e) => json_response(
            500,
            &serde_json::json!({"error": format!("purge failed: {e}")}),
        ),
    }
}

/// Fallback for unknown routes
pub fn handle_not_found() -> (u16, String, &'static str) {
    let body = serde_json::json!({
        "error": "not found",
        "endpoints": [
            "GET /health",
            "GET /metrics",
            "GET /config",
            "GET /upstreams",
            "POST /config",
            "POST /reload",
            "POST /cache/purge",
        ]
    });
    json_response(404, &body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn not_found_lists_endpoints() {
        let (status, body, content_type) = handle_not_found();
        assert_eq!(status, 404);
        assert!(body.contains("/health"));
        assert!(body.contains("/metrics"));
        assert!(body.contains("/config"));
        assert_eq!(content_type, "application/json");
    }

    #[test]
    fn metrics_endpoint_returns_prometheus_format() {
        let metrics = MetricsRegistry::new().unwrap();
        metrics.record_request("web", "api", "GET", 200, 0.05, 1024, 256);

        let (status, body, content_type) = handle_metrics(&metrics);
        assert_eq!(status, 200);
        assert_eq!(content_type, "text/plain; version=0.0.4; charset=utf-8");
        assert!(body.contains("fluxo_requests_total"));
        assert!(body.contains("fluxo_request_duration_seconds"));
        assert!(body.contains(r#"method="GET""#));
        assert!(body.contains(r#"status="200""#));
    }

    #[test]
    fn metrics_endpoint_histogram_has_correct_buckets() {
        let metrics = MetricsRegistry::new().unwrap();
        metrics.record_request("web", "api", "GET", 200, 0.042, 0, 0);

        let (_, body, _) = handle_metrics(&metrics);
        assert!(body.contains(r#"le="0.001""#));
        assert!(body.contains(r#"le="0.01""#));
        assert!(body.contains(r#"le="0.1""#));
        assert!(body.contains(r#"le="1""#));
        assert!(body.contains(r#"le="10""#));
    }

    #[tokio::test]
    async fn cache_purge_missing_host_returns_400() {
        let body = br#"{"path": "/foo"}"#;
        let (status, resp, _) = handle_cache_purge(body).await;
        assert_eq!(status, 400);
        assert!(resp.contains("missing required field: host"));
    }

    #[tokio::test]
    async fn cache_purge_missing_path_returns_400() {
        let body = br#"{"host": "example.com"}"#;
        let (status, resp, _) = handle_cache_purge(body).await;
        assert_eq!(status, 400);
        assert!(resp.contains("missing required field: path"));
    }

    #[tokio::test]
    async fn cache_purge_invalid_json_returns_400() {
        let body = b"not json";
        let (status, resp, _) = handle_cache_purge(body).await;
        assert_eq!(status, 400);
        assert!(resp.contains("invalid JSON"));
    }

    #[tokio::test]
    async fn cache_purge_nonexistent_key_returns_false() {
        let body = br#"{"host": "no-such-host.test", "path": "/nonexistent"}"#;
        let (status, resp, _) = handle_cache_purge(body).await;
        assert_eq!(status, 200);
        assert!(resp.contains(r#""purged":false"#));
    }
}
