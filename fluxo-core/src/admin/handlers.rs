use crate::observability::MetricsRegistry;
use crate::proxy::FluxoProxy;

/// GET /health — process health info
pub fn handle_health(proxy: &FluxoProxy) -> (u16, String, &'static str) {
    let state = proxy.state_snapshot();
    let service_count = state.config.services.len();
    let upstream_count = state.config.upstreams.len();

    let body = serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "services": service_count,
        "upstreams": upstream_count,
    });

    (
        200,
        serde_json::to_string_pretty(&body).unwrap(),
        "application/json",
    )
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
    let body = serde_json::to_string_pretty(&state.config)
        .unwrap_or_else(|e| format!(r#"{{"error": "{e}"}}"#));
    (200, body, "application/json")
}

/// Fallback for unknown routes
pub fn handle_not_found() -> (u16, String, &'static str) {
    let body = serde_json::json!({
        "error": "not found",
        "endpoints": ["/health", "/metrics", "/config"]
    });
    (
        404,
        serde_json::to_string(&body).unwrap(),
        "application/json",
    )
}

#[cfg(test)]
mod tests {
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
}
