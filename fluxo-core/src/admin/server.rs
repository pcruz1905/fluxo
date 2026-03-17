use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::observability::MetricsRegistry;
use crate::proxy::FluxoProxy;

use super::handlers;

/// Admin API HTTP server.
///
/// Runs as a Pingora BackgroundService, listening on a configurable address
/// (default 127.0.0.1:2019). Serves health checks, Prometheus metrics,
/// and configuration inspection endpoints.
pub struct AdminService {
    pub address: SocketAddr,
    pub proxy: Arc<FluxoProxy>,
    pub metrics: Arc<MetricsRegistry>,
}

impl AdminService {
    async fn handle_request(
        proxy: Arc<FluxoProxy>,
        metrics: Arc<MetricsRegistry>,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
        let (status, body, content_type) = match (req.method().as_str(), req.uri().path()) {
            ("GET", "/health") => handlers::handle_health(&proxy),
            ("GET", "/metrics") => handlers::handle_metrics(&metrics),
            ("GET", "/config") => handlers::handle_config(&proxy),
            _ => handlers::handle_not_found(),
        };

        let response = Response::builder()
            .status(status)
            .header("content-type", content_type)
            .body(Full::new(Bytes::from(body)))
            .unwrap();

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

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            let proxy = self.proxy.clone();
                            let metrics = self.metrics.clone();
                            let io = hyper_util::rt::TokioIo::new(stream);

                            tokio::spawn(async move {
                                let svc = service_fn(move |req| {
                                    Self::handle_request(
                                        proxy.clone(),
                                        metrics.clone(),
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
    }
}
