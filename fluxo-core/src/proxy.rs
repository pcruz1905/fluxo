//! The Pingora `ProxyHttp` implementation — the heart of Fluxo.
//!
//! `FluxoProxy` implements `ProxyHttp` and dispatches to the routing engine,
//! upstream manager, and (future) plugin pipeline from within each callback.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_core::Error;
use pingora_proxy::{ProxyHttp, Session};
use tracing::{info, warn};

use crate::config::FluxoConfig;
use crate::context::{MatchedRoute, RequestContext, SelectedPeer};
use crate::error::FluxoError;
use crate::routing::RouteTable;
use crate::upstream::peer::UpstreamGroup;
use crate::upstream::UpstreamName;

/// The pre-computed, immutable state derived from a `FluxoConfig`.
///
/// Stored in `ArcSwap` and shared across all worker threads.
/// Every field is read-only after construction. On config reload,
/// a new `FluxoState` is built and atomically swapped in.
pub struct FluxoState {
    /// The raw config that produced this state (kept for Admin API export / debugging).
    pub config: FluxoConfig,
    /// Pre-built route table, ready for matching.
    pub router: RouteTable,
    /// Pre-built upstream groups, each holding a Pingora LoadBalancer.
    pub upstreams: HashMap<UpstreamName, UpstreamGroup>,
}

impl FluxoState {
    /// Build a new `FluxoState` from a validated config.
    ///
    /// This is the single validation + compilation boundary. It can fail if
    /// route patterns are invalid or upstream addresses can't be resolved.
    pub fn try_from_config(config: FluxoConfig) -> Result<Self, FluxoError> {
        let router = RouteTable::build(&config)?;
        let upstreams = build_upstream_groups(&config)?;
        Ok(Self {
            config,
            router,
            upstreams,
        })
    }
}

/// Build upstream groups from the config.
fn build_upstream_groups(
    config: &FluxoConfig,
) -> Result<HashMap<UpstreamName, UpstreamGroup>, FluxoError> {
    let mut groups = HashMap::new();

    for (name, upstream_config) in &config.upstreams {
        let upstream_name = UpstreamName::from(name.as_str());
        let group = UpstreamGroup::new(
            upstream_name.clone(),
            &upstream_config.targets,
            Default::default(), // TLS config — will be wired from config in Step 5
            Default::default(), // Timeouts — will be wired from config later
        )?;
        groups.insert(upstream_name, group);
    }

    Ok(groups)
}

/// The central proxy type that implements Pingora's `ProxyHttp` trait.
///
/// Holds an `ArcSwap<FluxoState>` for lock-free config reads on the hot path.
/// All Pingora service instances share the same `FluxoProxy` (it's cheap to clone).
#[derive(Clone)]
pub struct FluxoProxy {
    state: Arc<ArcSwap<FluxoState>>,
}

impl FluxoProxy {
    /// Create a new proxy from a pre-computed state.
    pub fn new(state: FluxoState) -> Self {
        Self {
            state: Arc::new(ArcSwap::from(Arc::new(state))),
        }
    }

    /// Atomically replace the running config with a new one.
    ///
    /// Used by future config reload / Admin API.
    pub fn reload(&self, new_state: FluxoState) {
        self.state.store(Arc::new(new_state));
    }
}

#[async_trait]
impl ProxyHttp for FluxoProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<Error>> {
        let state = self.state.load();

        // Extract request info for matching
        let req_header = session.req_header();
        let host = req_header
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok());
        let path = req_header.uri.path();
        let method = req_header.method.as_str();

        // Route matching
        match state.router.match_route(host, path, method) {
            Some(route) => {
                ctx.matched_route = Some(MatchedRoute {
                    index: route.index,
                    upstream: route.upstream.clone(),
                    name: route.name.clone(),
                });
                Ok(false) // continue to upstream_peer
            }
            None => {
                // No route matched — return 404
                let _ = session.respond_error(404).await;
                Ok(true) // short-circuit, handled
            }
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        let state = self.state.load();

        let route = ctx
            .matched_route
            .as_ref()
            .expect("upstream_peer called without matched route (request_filter bug)");

        let upstream_group = state.upstreams.get(&route.upstream).ok_or_else(|| {
            Error::explain(
                pingora_core::ErrorType::InternalError,
                format!("upstream '{}' not found in state", route.upstream),
            )
        })?;

        let peer = upstream_group.select_peer().map_err(|e| {
            Error::explain(
                pingora_core::ErrorType::ConnectError,
                format!("failed to select peer from '{}': {}", route.upstream, e),
            )
        })?;

        // Record which peer was selected (for logging)
        if let Some(addr) = peer.address().as_inet() {
            ctx.selected_peer = Some(SelectedPeer {
                address: *addr,
                tls: peer.is_tls(),
            });
        }

        info!(
            request_id = %ctx.request_id,
            route = route.name.as_deref().unwrap_or("unnamed"),
            upstream = %route.upstream,
            "routing request"
        );

        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        // Add X-Request-ID header
        let request_id = ctx.request_id.to_string();
        upstream_request
            .insert_header("X-Request-ID", &request_id)
            .map_err(|e| {
                Error::explain(
                    pingora_core::ErrorType::InternalError,
                    format!("failed to set X-Request-ID: {}", e),
                )
            })?;

        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        use pingora_core::ErrorType::*;

        let code = match e.etype() {
            HTTPStatus(code) => *code,
            ConnectTimedout | ConnectRefused | ConnectNoRoute | ConnectError => 502,
            ReadTimedout | WriteTimedout => 504,
            ConnectionClosed => 502,
            _ => 502,
        };

        warn!(
            request_id = %ctx.request_id,
            error_type = ?e.etype(),
            status = code,
            error = %e,
            "proxy error"
        );

        // Send a simple error response
        let _ = session.respond_error(code).await;

        pingora_proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
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
        let route_name = ctx
            .matched_route
            .as_ref()
            .and_then(|r| r.name.as_deref())
            .unwrap_or("-");

        match error {
            Some(e) => {
                warn!(
                    request_id = %ctx.request_id,
                    status,
                    route = route_name,
                    duration_ms = duration.as_millis() as u64,
                    error = %e,
                    "request completed with error"
                );
            }
            None => {
                info!(
                    request_id = %ctx.request_id,
                    status,
                    route = route_name,
                    duration_ms = duration.as_millis() as u64,
                    "request completed"
                );
            }
        }
    }
}
