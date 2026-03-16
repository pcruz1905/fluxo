//! Per-request context passed through all Pingora `ProxyHttp` callbacks.

use std::net::SocketAddr;
use std::time::Instant;

use crate::upstream::UpstreamName;

/// Per-request state created by `new_ctx()` and threaded through all callbacks.
pub struct RequestContext {
    /// When the request started processing.
    pub start_time: Instant,

    /// Unique request identifier for tracing/logging.
    pub request_id: RequestId,

    /// The route that matched this request (set during `request_filter`).
    pub matched_route: Option<MatchedRoute>,

    /// Which upstream peer was selected (set during `upstream_peer`).
    pub selected_peer: Option<SelectedPeer>,
}

/// A snapshot of the matched route, cheaply cloneable.
///
/// Stores an index into the route table (not the full config struct)
/// to avoid cloning large structs per-request.
#[derive(Clone, Debug)]
pub struct MatchedRoute {
    /// Index into the route table (for fast lookups back into `FluxoState`).
    pub index: usize,
    /// Name of the upstream group this route targets.
    pub upstream: UpstreamName,
    /// The route's display name (for logging).
    pub name: Option<String>,
}

/// Info about which upstream peer was actually selected.
#[derive(Debug)]
pub struct SelectedPeer {
    /// The address of the selected peer.
    pub address: SocketAddr,
    /// Whether TLS is used for the upstream connection.
    pub tls: bool,
}

/// A unique request identifier, generated fast via `fastrand`.
#[derive(Debug, Clone)]
pub struct RequestId(u64);

impl RequestId {
    /// Generate a new random request ID.
    pub fn generate() -> Self {
        Self(fastrand::u64(..))
    }

    /// Return the raw u64 value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl RequestContext {
    /// Create a new per-request context with a fresh request ID and start time.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            request_id: RequestId::generate(),
            matched_route: None,
            selected_peer: None,
        }
    }

    /// Return the elapsed duration since request start.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}
