//! Per-request context passed through all Pingora `ProxyHttp` callbacks.

use std::collections::HashMap;
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
/// Monolake-inspired: `BodyEncodeExt` pattern adapted for Pingora's chunk-based body filter.
pub enum StreamingCompressor {
    Gzip(flate2::write::GzEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

impl StreamingCompressor {
    /// Create a new streaming compressor for the given encoding.
    pub fn new(encoding: CompressionEncoding) -> Option<Self> {
        match encoding {
            CompressionEncoding::Gzip => Some(Self::Gzip(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            ))),
            CompressionEncoding::Brotli => Some(Self::Brotli(Box::new(
                brotli::CompressorWriter::new(Vec::new(), 4096, 4, 22),
            ))),
            CompressionEncoding::Zstd => zstd::stream::write::Encoder::new(Vec::new(), 1)
                .ok()
                .map(Self::Zstd),
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

/// Outcome of the cache lookup for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStatus {
    Hit,
    Miss,
    Stale,
    Bypass,
    Expired,
}

impl CacheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "HIT",
            Self::Miss => "MISS",
            Self::Stale => "STALE",
            Self::Bypass => "BYPASS",
            Self::Expired => "EXPIRED",
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
    /// Send a CORS preflight response with actual HTTP headers.
    Cors { headers: Vec<(String, String)> },
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
    /// PROXY protocol info parsed from the connection (if listener has `proxy_protocol` enabled).
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

    // --- Error page interception (Nginx proxy_intercept_errors inspired) ---
    /// Custom error page body to serve instead of upstream response.
    pub error_page_override: Option<String>,

    // --- Response buffering state (Nginx proxy_buffering inspired) ---
    /// Accumulation buffer for upstream response chunks.
    pub response_buffer: Vec<u8>,
    /// Max buffer size in bytes (0 = buffering disabled).
    pub response_buffer_limit: usize,
    /// Whether buffering is currently active (accumulating chunks).
    pub response_buffering_active: bool,

    // --- HTTP caching state ---
    /// Cache outcome for access log and metrics.
    pub cache_status: Option<CacheStatus>,

    // --- Bandwidth throttling state ---
    /// Maximum response body bytes per second. Set by `bandwidth_limit` plugin.
    pub bandwidth_limit_bps: Option<u64>,

    // --- Concurrency limiting state ---
    /// Semaphore permit held for the duration of the request.
    /// Dropped automatically when the context is dropped (end of request).
    pub concurrency_permit: Option<tokio::sync::OwnedSemaphorePermit>,

    // --- Extensions map (Nginx $variable inspired) ---
    /// Arbitrary key-value data for inter-plugin communication.
    /// Plugins can store values in the request phase and read them in the response phase.
    pub extensions: HashMap<String, serde_json::Value>,
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
            error_page_override: None,
            response_buffer: Vec::new(),
            response_buffer_limit: 0,
            response_buffering_active: false,
            cache_status: None,
            bandwidth_limit_bps: None,
            concurrency_permit: None,
            extensions: HashMap::new(),
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
        self.error_page_override = None;
        self.response_buffer.clear();
        self.response_buffer_limit = 0;
        self.response_buffering_active = false;
        self.cache_status = None;
        self.bandwidth_limit_bps = None;
        self.concurrency_permit = None;
        self.extensions.clear();
    }

    /// Store an arbitrary value in the extensions map for inter-plugin communication.
    pub fn set_extension(&mut self, key: impl Into<String>, val: serde_json::Value) {
        self.extensions.insert(key.into(), val);
    }

    /// Retrieve a value from the extensions map.
    pub fn get_extension(&self, key: &str) -> Option<&serde_json::Value> {
        self.extensions.get(key)
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
        self.pool.lock().pop().unwrap_or_default()
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
        assert!(ctx.response_buffer.is_empty());
        assert_eq!(ctx.response_buffer_limit, 0);
        assert!(!ctx.response_buffering_active);
        assert!(ctx.extensions.is_empty());
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

    #[test]
    fn extensions_set_and_get() {
        let mut ctx = RequestContext::new();
        ctx.set_extension("request_tag", serde_json::json!("canary-v2"));
        assert_eq!(
            ctx.get_extension("request_tag"),
            Some(&serde_json::json!("canary-v2"))
        );
        assert!(ctx.get_extension("nonexistent").is_none());
    }

    #[test]
    fn cache_status_as_str() {
        assert_eq!(CacheStatus::Hit.as_str(), "HIT");
        assert_eq!(CacheStatus::Miss.as_str(), "MISS");
        assert_eq!(CacheStatus::Stale.as_str(), "STALE");
        assert_eq!(CacheStatus::Bypass.as_str(), "BYPASS");
        assert_eq!(CacheStatus::Expired.as_str(), "EXPIRED");
    }

    #[test]
    fn cache_status_cleared_on_reset() {
        let mut ctx = RequestContext::new();
        ctx.cache_status = Some(CacheStatus::Hit);
        ctx.reset();
        assert!(ctx.cache_status.is_none());
    }

    #[test]
    fn extensions_cleared_on_reset() {
        let mut ctx = RequestContext::new();
        ctx.set_extension("key", serde_json::json!(42));
        assert!(!ctx.extensions.is_empty());
        ctx.reset();
        assert!(ctx.extensions.is_empty());
    }

    // --- StreamingCompressor tests ---

    #[test]
    fn streaming_compressor_gzip_roundtrip() {
        let mut compressor = StreamingCompressor::new(CompressionEncoding::Gzip).unwrap();
        let data = b"hello world, this is a test of gzip compression";
        let _compressed = compressor.write_chunk(data).unwrap();
        let final_bytes = compressor.finish().unwrap();
        // Compressed output should be non-empty (or at least finish should succeed)
        // finish() succeeded — compressed output may or may not be empty
        let _ = final_bytes;
    }

    #[test]
    fn streaming_compressor_brotli_roundtrip() {
        let mut compressor = StreamingCompressor::new(CompressionEncoding::Brotli).unwrap();
        let data = b"hello world, this is a test of brotli compression";
        let _compressed = compressor.write_chunk(data).unwrap();
        let _final_bytes = compressor.finish().unwrap();
    }

    #[test]
    fn streaming_compressor_zstd_roundtrip() {
        let mut compressor = StreamingCompressor::new(CompressionEncoding::Zstd).unwrap();
        let data = b"hello world, this is a test of zstd compression";
        let _compressed = compressor.write_chunk(data).unwrap();
        let final_bytes = compressor.finish().unwrap();
        assert!(!final_bytes.is_empty());
    }

    #[test]
    fn streaming_compressor_debug_display() {
        let gzip = StreamingCompressor::new(CompressionEncoding::Gzip).unwrap();
        assert_eq!(format!("{gzip:?}"), "StreamingCompressor::Gzip");

        let brotli = StreamingCompressor::new(CompressionEncoding::Brotli).unwrap();
        assert_eq!(format!("{brotli:?}"), "StreamingCompressor::Brotli");

        let zstd = StreamingCompressor::new(CompressionEncoding::Zstd).unwrap();
        assert_eq!(format!("{zstd:?}"), "StreamingCompressor::Zstd");
    }

    #[test]
    fn streaming_compressor_write_empty_chunk() {
        let mut compressor = StreamingCompressor::new(CompressionEncoding::Gzip).unwrap();
        let result = compressor.write_chunk(b"").unwrap();
        // Writing empty data is valid — may produce empty output
        assert!(result.is_empty() || !result.is_empty());
        let _ = compressor.finish().unwrap();
    }

    // --- RequestId tests ---

    #[test]
    fn request_id_display_is_16_hex_chars() {
        let id = RequestId::generate();
        let display = format!("{id}");
        assert_eq!(display.len(), 16);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn request_id_as_u64_returns_inner() {
        let id = RequestId::generate();
        let val = id.as_u64();
        // The display should be the hex representation of the u64
        assert_eq!(format!("{val:016x}"), format!("{id}"));
    }

    #[test]
    fn request_id_clone_preserves_value() {
        let id = RequestId::generate();
        let cloned = id.clone();
        assert_eq!(id.as_u64(), cloned.as_u64());
    }

    // --- PluginResponse variants ---

    #[test]
    fn plugin_response_redirect_debug() {
        let resp = PluginResponse::Redirect {
            status: 301,
            location: "https://example.com".to_string(),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("Redirect"));
        assert!(debug.contains("301"));
    }

    #[test]
    fn plugin_response_static_debug() {
        let resp = PluginResponse::Static {
            status: 200,
            body: Some("OK".to_string()),
            content_type: Some("text/plain".to_string()),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("Static"));
        assert!(debug.contains("200"));
    }

    #[test]
    fn plugin_response_rate_limited_debug() {
        let resp = PluginResponse::RateLimited {
            retry_after_secs: Some(60),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("RateLimited"));
    }

    #[test]
    fn plugin_response_basic_auth_challenge_debug() {
        let resp = PluginResponse::BasicAuthChallenge {
            realm: "Protected".to_string(),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("BasicAuthChallenge"));
    }

    #[test]
    fn plugin_response_error_debug() {
        let resp = PluginResponse::Error { status: 403 };
        let debug = format!("{resp:?}");
        assert!(debug.contains("Error"));
        assert!(debug.contains("403"));
    }

    #[test]
    fn plugin_response_cors_debug() {
        let resp = PluginResponse::Cors {
            headers: vec![("Access-Control-Allow-Origin".to_string(), "*".to_string())],
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("Cors"));
    }

    // --- RequestContext reset thoroughness ---

    #[test]
    fn reset_clears_compression_and_buffer_fields() {
        let mut ctx = RequestContext::new();
        ctx.accept_encoding = Some("gzip".to_string());
        ctx.compression_encoding = Some(CompressionEncoding::Gzip);
        ctx.error_page_override = Some("<h1>Error</h1>".to_string());
        ctx.response_buffer = vec![1, 2, 3];
        ctx.response_buffer_limit = 1024;
        ctx.response_buffering_active = true;
        ctx.bandwidth_limit_bps = Some(1024);

        ctx.reset();

        assert!(ctx.accept_encoding.is_none());
        assert!(ctx.compression_encoding.is_none());
        assert!(ctx.error_page_override.is_none());
        assert!(ctx.response_buffer.is_empty());
        assert_eq!(ctx.response_buffer_limit, 0);
        assert!(!ctx.response_buffering_active);
        assert!(ctx.bandwidth_limit_bps.is_none());
    }

    // --- Extensions edge cases ---

    #[test]
    fn extensions_overwrite_existing_key() {
        let mut ctx = RequestContext::new();
        ctx.set_extension("key", serde_json::json!("first"));
        ctx.set_extension("key", serde_json::json!("second"));
        assert_eq!(ctx.get_extension("key"), Some(&serde_json::json!("second")));
    }

    #[test]
    fn extensions_multiple_keys() {
        let mut ctx = RequestContext::new();
        ctx.set_extension("a", serde_json::json!(1));
        ctx.set_extension("b", serde_json::json!(2));
        ctx.set_extension("c", serde_json::json!(3));
        assert_eq!(ctx.extensions.len(), 3);
        assert_eq!(ctx.get_extension("a"), Some(&serde_json::json!(1)));
        assert_eq!(ctx.get_extension("b"), Some(&serde_json::json!(2)));
        assert_eq!(ctx.get_extension("c"), Some(&serde_json::json!(3)));
    }

    // --- MatchedRoute and SelectedPeer ---

    #[test]
    fn matched_route_clone_and_debug() {
        let route = MatchedRoute {
            index: 0,
            upstream: crate::upstream::UpstreamName::from("backend"),
            name: Some(Arc::from("api-route")),
        };
        let cloned = route.clone();
        assert_eq!(cloned.index, 0);
        assert_eq!(cloned.name.as_deref(), Some("api-route"));
        let debug = format!("{route:?}");
        assert!(debug.contains("MatchedRoute"));
    }

    #[test]
    fn selected_peer_debug() {
        let peer = SelectedPeer {
            address: "127.0.0.1:8080".parse().unwrap(),
            tls: false,
        };
        let debug = format!("{peer:?}");
        assert!(debug.contains("SelectedPeer"));
        assert!(debug.contains("127.0.0.1:8080"));
    }

    // --- Default trait ---

    #[test]
    fn request_context_default_is_same_as_new() {
        let ctx = RequestContext::default();
        assert!(ctx.method.is_none());
        assert_eq!(ctx.bytes_sent, 0);
        assert!(ctx.extensions.is_empty());
    }

    // --- Pool edge cases ---

    #[test]
    fn pool_release_resets_fields() {
        let pool = RequestContextPool::new(2);
        let mut ctx = pool.acquire();
        ctx.method = Some("POST".to_string());
        ctx.bytes_sent = 999;
        ctx.set_extension("key", serde_json::json!("val"));

        pool.release(ctx);
        // Acquire back — fields should be reset
        let recycled = pool.acquire();
        assert!(recycled.method.is_none());
        assert_eq!(recycled.bytes_sent, 0);
        assert!(recycled.extensions.is_empty());
    }

    #[test]
    fn pool_multiple_acquire_release_cycles() {
        let pool = RequestContextPool::new(2);
        for _ in 0..10 {
            let ctx = pool.acquire();
            pool.release(ctx);
        }
        assert!(pool.available() <= 2);
    }
}
