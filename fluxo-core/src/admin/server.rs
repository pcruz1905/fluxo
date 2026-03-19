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
/// Runs as a Pingora BackgroundService, listening on a configurable address
/// (default 127.0.0.1:2019). Serves health checks, Prometheus metrics,
/// config inspection, and hot-reload endpoints.
pub struct AdminService {
    pub address: SocketAddr,
    pub proxy: Arc<FluxoProxy>,
    pub metrics: Arc<MetricsRegistry>,
    /// Path to the config file on disk — used by `POST /reload`.
    pub config_path: Option<String>,
}

impl AdminService {
    async fn handle_request(
        proxy: Arc<FluxoProxy>,
        metrics: Arc<MetricsRegistry>,
        config_path: Option<String>,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
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
                            Err(se) => format!(r#"{{"error": "JSON error: {}"}}"#, se),
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
                            let io = hyper_util::rt::TokioIo::new(stream);

                            connections.spawn(async move {
                                let svc = service_fn(move |req| {
                                    Self::handle_request(
                                        proxy.clone(),
                                        metrics.clone(),
                                        config_path.clone(),
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
