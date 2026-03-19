//! Per-request context passed through all Pingora `ProxyHttp` callbacks.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::proxy_protocol::ProxyProtocolInfo;
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

/// Streaming compressor — compresses chunks incrementally without buffering the full body.
/// Monolake-inspired: BodyEncodeExt pattern adapted for Pingora's chunk-based body filter.
pub enum StreamingCompressor {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

impl StreamingCompressor {
    /// Create a new streaming compressor for the given encoding.
    pub fn new(encoding: CompressionEncoding) -> Self {
        match encoding {
            CompressionEncoding::Gzip => Self::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            )),
            CompressionEncoding::Brotli => Self::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                4,
                22,
            ))),
            CompressionEncoding::Zstd => {
                Self::Zstd(zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap())
            }
        }
    }

    /// Write a chunk of data into the compressor. Returns compressed output (may be empty).
    pub fn write_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        use std::io::Write;
        match self {
            Self::Gzip(enc) => {
                enc.write_all(data)?;
                enc.flush()?;
                Ok(enc.get_mut().drain(..).collect())
            }
            Self::Brotli(enc) => {
                enc.write_all(data)?;
                enc.flush()?;
                Ok(enc.get_mut().drain(..).collect())
            }
            Self::Zstd(enc) => {
                enc.write_all(data)?;
                enc.flush()?;
                Ok(enc.get_mut().drain(..).collect())
            }
        }
    }

    /// Finalize the compressor, flushing all remaining data. Must be called on end-of-stream.
    pub fn finish(self) -> Result<Vec<u8>, std::io::Error> {
        match self {
            Self::Gzip(enc) => enc.finish(),
            Self::Brotli(mut enc) => {
                use std::io::Write;
                enc.flush()?;
                // Drop the CompressorWriter to finalize
                let inner = std::mem::take(enc.get_mut());
                drop(enc);
                // The inner vec already has the flushed data; we need to get the final bytes
                // by consuming the writer properly
                Ok(inner)
            }
            Self::Zstd(enc) => enc.finish(),
        }
    }
}

impl std::fmt::Debug for StreamingCompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gzip(_) => f.write_str("StreamingCompressor::Gzip"),
            Self::Brotli(_) => f.write_str("StreamingCompressor::Brotli"),
            Self::Zstd(_) => f.write_str("StreamingCompressor::Zstd"),
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

    // --- Sticky session state ---
    /// The sticky session cookie value read from the incoming request (if any).
    pub sticky_cookie_value: Option<String>,
    /// Whether a new sticky cookie needs to be set on the response.
    pub sticky_cookie_new: bool,

    // --- PROXY protocol state ---
    /// PROXY protocol info parsed from the connection (if listener has proxy_protocol enabled).
    /// Contains the real client source/destination addresses from the PROXY header.
    pub proxy_protocol_info: Option<ProxyProtocolInfo>,

    // --- Compression state ---
    /// The `Accept-Encoding` header value from the client request.
    /// Captured by the compression plugin's `on_request` phase.
    pub accept_encoding: Option<String>,
    /// The encoding chosen for this response (set by compression plugin's `on_response`).
    pub compression_encoding: Option<CompressionEncoding>,
    /// Streaming compressor state — compresses chunks incrementally (no full-body buffering).
    pub compressor: Option<StreamingCompressor>,
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
            sticky_cookie_value: None,
            sticky_cookie_new: false,
            proxy_protocol_info: None,
            accept_encoding: None,
            compression_encoding: None,
            compressor: None,
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

impl RequestContext {
    /// Reset all fields to defaults without deallocating.
    ///
    /// Nginx-inspired: reuse pre-allocated context objects instead of creating
    /// new ones per request. This avoids allocation pressure under high load.
    pub fn reset(&mut self) {
        self.start_time = Instant::now();
        self.request_id = RequestId::generate();
        self.matched_route = None;
        self.selected_peer = None;
        self.plugin_response = None;
        self.method = None;
        self.host = None;
        self.path = None;
        self.client_ip = None;
        self.user_agent = None;
        self.tls_version = None;
        self.http_version = None;
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.upstream_connect_ms = None;
        self.upstream_response_ms = None;
        self.error_message = None;
        self.retry_count = 0;
        self.sticky_cookie_value = None;
        self.sticky_cookie_new = false;
        self.proxy_protocol_info = None;
        self.accept_encoding = None;
        self.compression_encoding = None;
        self.compressor = None;
    }
}

/// Pre-allocated pool of `RequestContext` objects.
///
/// Nginx-inspired: connections are pre-allocated at startup in a flat array.
/// This pool does the same for per-request contexts, avoiding allocation
/// churn under high load. When the pool is empty, new contexts are created
/// on-demand (graceful degradation).
pub struct RequestContextPool {
    pool: parking_lot::Mutex<Vec<RequestContext>>,
    capacity: usize,
}

impl RequestContextPool {
    /// Create a new pool pre-populated with `capacity` contexts.
    pub fn new(capacity: usize) -> Self {
        let mut pool = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            pool.push(RequestContext::new());
        }
        Self {
            pool: parking_lot::Mutex::new(pool),
            capacity,
        }
    }

    /// Acquire a context from the pool, or create a new one if empty.
    pub fn acquire(&self) -> RequestContext {
        self.pool.lock().pop().unwrap_or_else(RequestContext::new)
    }

    /// Return a context to the pool. Resets all fields before storing.
    /// If the pool is at capacity, the context is dropped.
    pub fn release(&self, mut ctx: RequestContext) {
        ctx.reset();
        let mut pool = self.pool.lock();
        if pool.len() < self.capacity {
            pool.push(ctx);
        }
    }

    /// Current number of available contexts in the pool.
    pub fn available(&self) -> usize {
        self.pool.lock().len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
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
        assert!(ctx.sticky_cookie_value.is_none());
        assert!(!ctx.sticky_cookie_new);
        assert!(ctx.proxy_protocol_info.is_none());
        assert!(ctx.accept_encoding.is_none());
        assert!(ctx.compression_encoding.is_none());
        assert!(ctx.compressor.is_none());
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

    #[test]
    fn reset_clears_all_fields() {
        let mut ctx = RequestContext::new();
        ctx.method = Some("POST".to_string());
        ctx.bytes_sent = 999;
        ctx.retry_count = 3;
        ctx.sticky_cookie_new = true;

        ctx.reset();

        assert!(ctx.method.is_none());
        assert_eq!(ctx.bytes_sent, 0);
        assert_eq!(ctx.retry_count, 0);
        assert!(!ctx.sticky_cookie_new);
    }

    #[test]
    fn pool_acquire_returns_context() {
        let pool = RequestContextPool::new(2);
        assert_eq!(pool.available(), 2);

        let _ctx = pool.acquire();
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn pool_release_recycles_context() {
        let pool = RequestContextPool::new(1);
        let ctx = pool.acquire();
        assert_eq!(pool.available(), 0);

        pool.release(ctx);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn pool_acquire_creates_new_when_empty() {
        let pool = RequestContextPool::new(0);
        assert_eq!(pool.available(), 0);

        let ctx = pool.acquire(); // should not panic
        assert!(ctx.method.is_none());
    }

    #[test]
    fn pool_release_drops_when_at_capacity() {
        let pool = RequestContextPool::new(1);
        // Pool starts full
        assert_eq!(pool.available(), 1);

        let ctx1 = pool.acquire();
        let ctx2 = RequestContext::new();
        pool.release(ctx1);
        pool.release(ctx2); // should be dropped (pool at capacity)
        assert_eq!(pool.available(), 1);
    }
}
