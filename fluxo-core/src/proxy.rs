//! The Pingora `ProxyHttp` implementation — the heart of Fluxo.
//!
//! `FluxoProxy` implements `ProxyHttp` and dispatches to the routing engine,
//! upstream manager, and plugin pipeline from within each callback.

use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Error;
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use tracing::{info, warn};

use crate::context::RequestContext;

/// The central proxy type that implements Pingora's `ProxyHttp` trait.
///
/// For v0.1, this is a minimal implementation that proxies all traffic
/// to a hardcoded upstream. Routing, config, and ArcSwap will be wired
/// in subsequent steps.
pub struct FluxoProxy {
    /// The upstream address to proxy to (temporary for v0.1 scaffold).
    upstream_addr: Arc<String>,
}

impl FluxoProxy {
    /// Create a new proxy that forwards all requests to the given upstream.
    pub fn new(upstream_addr: String) -> Self {
        Self {
            upstream_addr: Arc::new(upstream_addr),
        }
    }
}

#[async_trait]
impl ProxyHttp for FluxoProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        let peer = HttpPeer::new(
            self.upstream_addr.as_str(),
            false, // no TLS to upstream for now
            String::new(),
        );

        info!(
            request_id = %ctx.request_id,
            upstream = %self.upstream_addr,
            "routing request to upstream"
        );

        Ok(Box::new(peer))
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&Error>,
        ctx: &mut Self::CTX,
    ) {
        let duration = ctx.elapsed();
        let status = session
            .response_written()
            .map(|resp| resp.status.as_u16())
            .unwrap_or(0);

        match error {
            Some(e) => {
                warn!(
                    request_id = %ctx.request_id,
                    status,
                    duration_ms = duration.as_millis() as u64,
                    error = %e,
                    "request completed with error"
                );
            }
            None => {
                info!(
                    request_id = %ctx.request_id,
                    status,
                    duration_ms = duration.as_millis() as u64,
                    "request completed"
                );
            }
        }
    }
}
