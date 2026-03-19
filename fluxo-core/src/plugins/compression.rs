//! Compression plugin — gzip, brotli, and zstd response body compression.
//!
//! Equivalent to nginx's `gzip on` / `brotli on` / `zstd on` directives.
//!
//! **How it works:**
//! 1. `on_request`: captures `Accept-Encoding` from the client request.
//! 2. `on_response`: picks the best encoding, sets `Content-Encoding`, removes `Content-Length`.
//! 3. `proxy.rs` `response_body_filter`: buffers body chunks and compresses on end-of-stream.

use serde::{Deserialize, Serialize};

use crate::context::{CompressionEncoding, RequestContext};
use crate::plugins::PluginAction;

/// Configuration for the compression plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Compression algorithms in priority order.
    /// Valid values: `"zstd"`, `"br"`, `"gzip"`.
    /// Default: `["zstd", "br", "gzip"]`.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,

    /// Minimum response body size to compress (bytes).
    /// Responses smaller than this are sent uncompressed.
    /// Default: 256.
    #[serde(default = "default_min_size")]
    pub min_size: u64,
}

fn default_algorithms() -> Vec<String> {
    vec!["zstd".to_string(), "br".to_string(), "gzip".to_string()]
}

fn default_min_size() -> u64 {
    256
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithms: default_algorithms(),
            min_size: default_min_size(),
        }
    }
}

/// The compression plugin — selects encoding per request and signals the proxy
/// to compress the buffered response body.
#[derive(Debug)]
pub struct CompressionPlugin {
    /// Algorithms in priority order.
    algorithms: Vec<CompressionEncoding>,
    /// Minimum byte size to trigger compression.
    min_size: u64,
}

impl CompressionPlugin {
    pub fn new(config: CompressionConfig) -> Self {
        let algorithms = config
            .algorithms
            .iter()
            .filter_map(|s| match s.as_str() {
                "gzip" => Some(CompressionEncoding::Gzip),
                "br" | "brotli" => Some(CompressionEncoding::Brotli),
                "zstd" => Some(CompressionEncoding::Zstd),
                _ => None,
            })
            .collect();
        Self {
            algorithms,
            min_size: config.min_size,
        }
    }

    /// Capture `Accept-Encoding` from the client request.
    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        ctx.accept_encoding = req
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase());
        PluginAction::Continue
    }

    /// Pick the best encoding and update response headers.
    ///
    /// Called in the response phase. Sets `ctx.compression_encoding` which
    /// signals `response_body_filter` in proxy.rs to buffer and compress.
    pub fn on_response(&self, resp: &mut pingora_http::ResponseHeader, ctx: &mut RequestContext) {
        // Don't re-encode already-encoded responses
        if resp.headers.get("content-encoding").is_some() {
            return;
        }

        // Need client's Accept-Encoding preference
        let accept = match &ctx.accept_encoding {
            Some(a) => a.as_str(),
            None => return,
        };

        // Don't compress binary/already-compressed content types
        let content_type = resp
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if should_skip_compression(content_type) {
            return;
        }

        // Pick first algorithm the client accepts
        let encoding = match self
            .algorithms
            .iter()
            .find(|enc| accept.contains(enc.as_str()))
        {
            Some(e) => *e,
            None => return,
        };

        // Check content-length if available — skip tiny responses
        if let Some(cl) = resp
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            if cl < self.min_size {
                return;
            }
        }

        ctx.compression_encoding = Some(encoding);
        let _ = resp.insert_header("content-encoding", encoding.as_str());
        resp.remove_header("content-length");
    }
}

/// Returns true for content types that should not be compressed
/// (already compressed or binary formats where compression yields no benefit).
fn should_skip_compression(content_type: &str) -> bool {
    let skip_prefixes = [
        "image/",
        "video/",
        "audio/",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/x-brotli",
        "application/zstd",
        "application/octet-stream",
        "application/pdf",
    ];
    skip_prefixes
        .iter()
        .any(|prefix| content_type.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_plugin(algorithms: &[&str]) -> CompressionPlugin {
        CompressionPlugin::new(CompressionConfig {
            algorithms: algorithms.iter().map(|s| s.to_string()).collect(),
            min_size: 0, // no minimum for tests
        })
    }

    fn make_ctx_with_accept(accept: &str) -> RequestContext {
        let mut ctx = RequestContext::new();
        ctx.accept_encoding = Some(accept.to_lowercase());
        ctx
    }

    #[test]
    fn picks_gzip_when_accepted() {
        let plugin = make_plugin(&["gzip"]);
        let mut ctx = make_ctx_with_accept("gzip, deflate");
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/html").unwrap();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(ctx.compression_encoding, Some(CompressionEncoding::Gzip));
        assert!(resp.headers.get("content-encoding").is_some());
    }

    #[test]
    fn picks_brotli_over_gzip_by_priority() {
        let plugin = make_plugin(&["br", "gzip"]);
        let mut ctx = make_ctx_with_accept("gzip, br");
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/html").unwrap();
        plugin.on_response(&mut resp, &mut ctx);
        // br has higher priority — should win
        assert_eq!(ctx.compression_encoding, Some(CompressionEncoding::Brotli));
    }

    #[test]
    fn skips_already_encoded_response() {
        let plugin = make_plugin(&["gzip"]);
        let mut ctx = make_ctx_with_accept("gzip");
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-encoding", "gzip").unwrap();
        plugin.on_response(&mut resp, &mut ctx);
        // Already encoded — should not set compression_encoding
        assert_eq!(ctx.compression_encoding, None);
    }

    #[test]
    fn skips_when_no_accept_encoding() {
        let plugin = make_plugin(&["gzip"]);
        let mut ctx = RequestContext::new(); // no accept_encoding set
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/html").unwrap();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(ctx.compression_encoding, None);
    }

    #[test]
    fn skips_image_content_type() {
        let plugin = make_plugin(&["gzip"]);
        let mut ctx = make_ctx_with_accept("gzip");
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "image/png").unwrap();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(ctx.compression_encoding, None);
    }

    #[test]
    fn skips_when_client_does_not_accept_configured_algorithms() {
        let plugin = make_plugin(&["zstd"]);
        let mut ctx = make_ctx_with_accept("gzip, br"); // no zstd
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/plain").unwrap();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(ctx.compression_encoding, None);
    }

    #[test]
    fn removes_content_length_on_compression() {
        let plugin = make_plugin(&["gzip"]);
        let mut ctx = make_ctx_with_accept("gzip");
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/html").unwrap();
        resp.insert_header("content-length", "1000").unwrap();
        plugin.on_response(&mut resp, &mut ctx);
        // Content-Length must be removed (compressed size is different)
        assert!(resp.headers.get("content-length").is_none());
    }
}
