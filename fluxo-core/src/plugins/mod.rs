//! Built-in plugin system.
//!
//! Plugins are middleware that run at specific phases of the request lifecycle.
//! Each route compiles its configured plugins into a `PluginPipeline` at config
//! load time. During request processing, proxy.rs calls the pipeline at each phase.
//!
//! Body filters (Nginx-inspired) handle streaming response body transformations
//! separately from the header-level plugin pipeline.

pub mod body_filter;

pub mod add_prefix;
pub mod basic_auth;
pub mod compression;
pub mod concurrency_limit;
pub mod config;
pub mod cors;
pub mod headers;
pub mod ip_restrict;
pub mod path_rewrite;
pub mod pipeline;
pub mod rate_limit;
pub mod redirect;
pub mod request_id;
pub mod security_headers;
pub mod static_response;
pub mod strip_prefix;

pub use pipeline::PluginPipeline;

/// Result of a plugin phase execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginAction {
    /// Continue to the next plugin / phase.
    Continue,
    /// Short-circuit: the plugin has written a response directly.
    /// Contains the HTTP status code for logging purposes.
    Handled(u16),
}

/// The unified plugin enum. Enum dispatch avoids trait object overhead.
#[derive(Debug)]
pub enum BuiltinPlugin {
    Headers(headers::HeadersPlugin),
    RateLimit(rate_limit::RateLimitPlugin),
    Cors(cors::CorsPlugin),
    IpRestrict(ip_restrict::IpRestrictPlugin),
    SecurityHeaders(security_headers::SecurityHeadersPlugin),
    RequestId(request_id::RequestIdPlugin),
    Redirect(redirect::RedirectPlugin),
    StaticResponse(static_response::StaticResponsePlugin),
    Compression(compression::CompressionPlugin),
    BasicAuth(basic_auth::BasicAuthPlugin),
    StripPrefix(strip_prefix::StripPrefixPlugin),
    AddPrefix(add_prefix::AddPrefixPlugin),
    PathRewrite(path_rewrite::PathRewritePlugin),
    ConcurrencyLimit(concurrency_limit::ConcurrencyLimitPlugin),
}

impl BuiltinPlugin {
    /// Run the request phase. Returns Handled(status) to short-circuit.
    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> PluginAction {
        match self {
            Self::IpRestrict(p) => p.on_request(req, ctx),
            Self::RateLimit(p) => p.on_request(req, ctx),
            Self::Redirect(p) => p.on_request(req, ctx),
            Self::StaticResponse(p) => p.on_request(req, ctx),
            Self::Cors(p) => p.on_request(req, ctx),
            Self::Compression(p) => p.on_request(req, ctx),
            Self::BasicAuth(p) => p.on_request(req, ctx),
            Self::ConcurrencyLimit(p) => p.on_request(req, ctx),
            _ => PluginAction::Continue,
        }
    }

    /// Run the upstream request phase. Mutate headers before forwarding.
    pub fn on_upstream_request(
        &self,
        upstream_req: &mut pingora_http::RequestHeader,
        ctx: &crate::context::RequestContext,
    ) {
        match self {
            Self::RequestId(p) => p.on_upstream_request(upstream_req, ctx),
            Self::Headers(p) => p.on_upstream_request(upstream_req, ctx),
            Self::StripPrefix(p) => p.on_upstream_request(upstream_req, ctx),
            Self::AddPrefix(p) => p.on_upstream_request(upstream_req, ctx),
            Self::PathRewrite(p) => p.on_upstream_request(upstream_req, ctx),
            _ => {}
        }
    }

    /// Run the response phase. Mutate response headers.
    pub fn on_response(
        &self,
        resp: &mut pingora_http::ResponseHeader,
        ctx: &mut crate::context::RequestContext,
    ) {
        match self {
            Self::Headers(p) => p.on_response(resp, ctx),
            Self::Cors(p) => p.on_response(resp, ctx),
            Self::SecurityHeaders(p) => p.on_response(resp, ctx),
            Self::Compression(p) => p.on_response(resp, ctx),
            _ => {}
        }
    }
}
