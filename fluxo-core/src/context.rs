//! Per-request context passed through all Pingora `ProxyHttp` callbacks.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::upstream::UpstreamName;

/// Encoding algorithm for response body compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionEncoding {
    Gzip,
    Brotli,
    Zstd,
}

impl CompressionEncoding {
    /// The string used in `Content-Encoding` and `Accept-Encoding` headers.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        }
    }
}

/// A typed response from a plugin that short-circuits the request.
#[derive(Debug, Clone)]
pub enum PluginResponse {
    /// Send a redirect with Location header.
    Redirect { status: u16, location: String },
    /// Send a static response with optional body and content type.
    Static {
        status: u16,
        body: Option<String>,
        content_type: Option<String>,
    },
    /// Send a rate-limited response with Retry-After seconds.
    RateLimited { retry_after_secs: Option<u64> },
    /// Send a 401 Unauthorized with WWW-Authenticate: Basic realm="...".
    BasicAuthChallenge { realm: String },
    /// Send a simple error status (403, etc).
    Error { status: u16 },
}

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

    /// Plugin response to send when a plugin short-circuits (set by plugins).
    pub plugin_response: Option<PluginResponse>,

    // --- Wide event fields (populated throughout request lifecycle) ---
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub tls_version: Option<String>,
    pub http_version: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub upstream_connect_ms: Option<u64>,
    pub upstream_response_ms: Option<u64>,
    pub error_message: Option<String>,
    pub retry_count: u32,

    // --- Compression state ---
    /// The `Accept-Encoding` header value from the client request.
    /// Captured by the compression plugin's `on_request` phase.
    pub accept_encoding: Option<String>,
    /// The encoding chosen for this response (set by compression plugin's `on_response`).
    pub compression_encoding: Option<CompressionEncoding>,
    /// Buffer accumulating response body chunks for buffered compression.
    pub response_body_buffer: Vec<u8>,
}

/// A snapshot of the matched route, cheaply cloneable.
#[derive(Clone, Debug)]
pub struct MatchedRoute {
    /// Index into the route table (for fast lookups back into `FluxoState`).
    pub index: usize,
    /// Name of the upstream group this route targets.
    pub upstream: UpstreamName,
    /// The route's display name (for logging).
    pub name: Option<Arc<str>>,
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
    pub fn generate() -> Self {
        Self(fastrand::u64(..))
    }

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
            plugin_response: None,
            method: None,
            host: None,
            path: None,
            client_ip: None,
            user_agent: None,
            tls_version: None,
            http_version: None,
            bytes_sent: 0,
            bytes_received: 0,
            upstream_connect_ms: None,
            upstream_response_ms: None,
            error_message: None,
            retry_count: 0,
            accept_encoding: None,
            compression_encoding: None,
            response_body_buffer: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_event_fields_default_to_none() {
        let ctx = RequestContext::new();
        assert!(ctx.plugin_response.is_none());
        assert!(ctx.method.is_none());
        assert!(ctx.host.is_none());
        assert!(ctx.path.is_none());
        assert!(ctx.client_ip.is_none());
        assert!(ctx.user_agent.is_none());
        assert!(ctx.tls_version.is_none());
        assert!(ctx.http_version.is_none());
        assert_eq!(ctx.bytes_sent, 0);
        assert_eq!(ctx.bytes_received, 0);
        assert!(ctx.upstream_connect_ms.is_none());
        assert!(ctx.upstream_response_ms.is_none());
        assert!(ctx.error_message.is_none());
        assert_eq!(ctx.retry_count, 0);
        assert!(ctx.accept_encoding.is_none());
        assert!(ctx.compression_encoding.is_none());
        assert!(ctx.response_body_buffer.is_empty());
    }

    #[test]
    fn elapsed_returns_positive_duration() {
        let ctx = RequestContext::new();
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(ctx.elapsed().as_micros() > 0);
    }

    #[test]
    fn compression_encoding_as_str() {
        assert_eq!(CompressionEncoding::Gzip.as_str(), "gzip");
        assert_eq!(CompressionEncoding::Brotli.as_str(), "br");
        assert_eq!(CompressionEncoding::Zstd.as_str(), "zstd");
    }
}
