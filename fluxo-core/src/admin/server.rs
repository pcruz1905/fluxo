use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info};

use crate::observability::MetricsRegistry;
use crate::proxy::FluxoProxy;

use super::handlers;

/// Admin API HTTP server.
///
/// Runs as a Pingora `BackgroundService`, listening on a configurable address
/// (default 127.0.0.1:2019). Serves health checks, Prometheus metrics,
/// config inspection, and hot-reload endpoints.
pub struct AdminService {
    pub address: SocketAddr,
    pub proxy: Arc<FluxoProxy>,
    pub metrics: Arc<MetricsRegistry>,
    /// Path to the config file on disk — used by `POST /reload`.
    pub config_path: Option<String>,
    /// Optional bearer token for admin API authentication.
    pub auth_token: Option<String>,
}

impl AdminService {
    /// Check bearer token auth. Returns an error response if auth fails, `None` if OK.
    fn check_auth(
        req: &Request<Incoming>,
        auth_token: Option<&str>,
    ) -> Option<Response<Full<Bytes>>> {
        let Some(expected) = auth_token else {
            return None; // No auth configured
        };

        // /health is always exempt (load balancers need unauthenticated access)
        if req.uri().path() == "/health" {
            return None;
        }

        let authorized = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| token == expected);

        if authorized {
            return None;
        }

        let body = r#"{"error": "unauthorized"}"#;
        Some(
            Response::builder()
                .status(401)
                .header("content-type", "application/json")
                .header("www-authenticate", "Bearer")
                .body(Full::new(Bytes::from(body)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        )
    }

    async fn handle_request(
        proxy: Arc<FluxoProxy>,
        metrics: Arc<MetricsRegistry>,
        config_path: Option<String>,
        auth_token: Option<String>,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
        // Auth check (exempt: /health)
        if let Some(resp) = Self::check_auth(&req, auth_token.as_deref()) {
            return Ok(resp);
        }

        let method = req.method().as_str().to_string();
        let path = req.uri().path().to_string();

        let (status, body, content_type) = match (method.as_str(), path.as_str()) {
            ("GET", "/health") => handlers::handle_health(&proxy),
            ("GET", "/metrics") => handlers::handle_metrics(&metrics),
            ("GET", "/config") => handlers::handle_config(&proxy),
            ("GET", "/upstreams") => handlers::handle_upstreams(&proxy),
            ("POST", "/config") => {
                // Collect the full request body
                let body_bytes = match req.into_body().collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        let err_body = match serde_json::to_string(&serde_json::json!({
                            "error": format!("failed to read body: {e}")
                        })) {
                            Ok(b) => b,
                            Err(se) => format!(r#"{{"error": "JSON error: {se}"}}"#),
                        };
                        return Ok(Response::builder()
                            .status(400)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(err_body)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
                    }
                };
                handlers::handle_post_config(&proxy, &body_bytes)
            }
            ("POST", "/reload") => handlers::handle_reload(&proxy, config_path.as_deref()),
            ("POST", "/cache/purge") => {
                let body_bytes = match req.into_body().collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        let err_body = match serde_json::to_string(&serde_json::json!({
                            "error": format!("failed to read body: {e}")
                        })) {
                            Ok(b) => b,
                            Err(se) => format!(r#"{{"error": "JSON error: {se}"}}"#),
                        };
                        return Ok(Response::builder()
                            .status(400)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(err_body)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
                    }
                };
                handlers::handle_cache_purge(&body_bytes).await
            }
            _ => handlers::handle_not_found(),
        };

        let response = Response::builder()
            .status(status)
            .header("content-type", content_type)
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));

        Ok(response)
    }
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for AdminService {
    async fn start(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let listener = match TcpListener::bind(self.address).await {
            Ok(l) => l,
            Err(e) => {
                error!(address = %self.address, error = %e, "failed to bind admin API");
                return;
            }
        };

        info!(address = %self.address, "admin API listening");

        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            let proxy = self.proxy.clone();
                            let metrics = self.metrics.clone();
                            let config_path = self.config_path.clone();
                            let auth_token = self.auth_token.clone();
                            let io = hyper_util::rt::TokioIo::new(stream);

                            connections.spawn(async move {
                                let svc = service_fn(move |req| {
                                    Self::handle_request(
                                        proxy.clone(),
                                        metrics.clone(),
                                        config_path.clone(),
                                        auth_token.clone(),
                                        req,
                                    )
                                });
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, svc)
                                    .await
                                {
                                    error!(error = %e, "admin API connection error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "admin API accept error");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    info!("admin API shutting down");
                    break;
                }
            }
        }

        connections.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    /// Mirror of the auth logic in `AdminService::check_auth`, extracted for
    /// unit-testability without needing to construct `Request<Incoming>`.
    ///
    /// Returns `true` when the request is authorized (i.e. `check_auth` would
    /// return `None`).
    fn is_authorized(path: &str, auth_header: Option<&str>, expected_token: Option<&str>) -> bool {
        let Some(expected) = expected_token else {
            return true;
        };

        if path == "/health" {
            return true;
        }

        auth_header
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|token| token == expected)
    }

    // ---- no auth configured ----

    #[test]
    fn no_auth_configured_always_passes() {
        assert!(is_authorized("/metrics", None, None));
        assert!(is_authorized("/config", None, None));
        assert!(is_authorized("/reload", None, None));
        assert!(is_authorized("/health", None, None));
    }

    // ---- /health exemption ----

    #[test]
    fn health_exempt_without_header() {
        assert!(is_authorized("/health", None, Some("secret")));
    }

    #[test]
    fn health_exempt_with_wrong_token() {
        assert!(is_authorized(
            "/health",
            Some("Bearer wrong"),
            Some("secret")
        ));
    }

    #[test]
    fn health_exempt_with_garbage_header() {
        assert!(is_authorized("/health", Some("garbage"), Some("secret")));
    }

    // ---- valid bearer token ----

    #[test]
    fn valid_bearer_token_passes() {
        assert!(is_authorized(
            "/metrics",
            Some("Bearer secret"),
            Some("secret"),
        ));
    }

    #[test]
    fn valid_bearer_token_different_path() {
        assert!(is_authorized(
            "/config",
            Some("Bearer my-token"),
            Some("my-token"),
        ));
    }

    // ---- invalid / missing token ----

    #[test]
    fn wrong_bearer_token_rejected() {
        assert!(!is_authorized(
            "/metrics",
            Some("Bearer wrong"),
            Some("secret"),
        ));
    }

    #[test]
    fn missing_auth_header_rejected() {
        assert!(!is_authorized("/metrics", None, Some("secret")));
    }

    #[test]
    fn non_bearer_scheme_rejected() {
        assert!(!is_authorized(
            "/metrics",
            Some("Basic dXNlcjpwYXNz"),
            Some("secret"),
        ));
    }

    #[test]
    fn empty_bearer_value_rejected() {
        assert!(!is_authorized("/metrics", Some("Bearer "), Some("secret")));
    }

    #[test]
    fn bearer_prefix_without_space_rejected() {
        assert!(!is_authorized(
            "/metrics",
            Some("Bearersecret"),
            Some("secret"),
        ));
    }

    // ---- all non-health paths require auth ----

    #[test]
    fn all_paths_require_auth_except_health() {
        let paths = [
            "/metrics",
            "/config",
            "/reload",
            "/cache/purge",
            "/upstreams",
        ];
        for path in &paths {
            assert!(
                !is_authorized(path, None, Some("token")),
                "path {path} should require auth when no header is provided",
            );
        }
    }

    // ---- edge cases ----

    #[test]
    fn token_with_whitespace_must_match_exactly() {
        assert!(is_authorized(
            "/metrics",
            Some("Bearer  spaces "),
            Some(" spaces "),
        ));
        assert!(!is_authorized(
            "/metrics",
            Some("Bearer spaces"),
            Some(" spaces "),
        ));
    }

    #[test]
    fn case_sensitive_token() {
        assert!(!is_authorized(
            "/metrics",
            Some("Bearer SECRET"),
            Some("secret"),
        ));
    }
}
