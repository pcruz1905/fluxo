//! Built-in plugin system.
//!
//! Plugins are middleware that run at specific phases of the request lifecycle.
//! Each route compiles its configured plugins into a `PluginPipeline` at config
//! load time. During request processing, proxy.rs calls the pipeline at each phase.

pub mod config;
pub mod cors;
pub mod headers;
pub mod ip_restrict;
pub mod pipeline;
pub mod rate_limit;
pub mod redirect;
pub mod request_id;
pub mod security_headers;
pub mod static_response;

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
}
