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
pub mod bandwidth_limit;
pub mod basic_auth;
pub mod compression;
pub mod concurrency_limit;
pub mod config;
pub mod cors;
pub mod csrf;
pub mod digest_auth;
pub mod forward_auth;
pub mod headers;
pub mod ip_restrict;
pub mod jwt_auth;
pub mod key_auth;
pub mod ldap_auth;
pub mod oauth2;
pub mod path_rewrite;
pub mod pipeline;
pub mod rate_limit;
pub mod redirect;
pub mod referer_restrict;
pub mod request_buffer;
pub mod request_id;
pub mod security_headers;
pub mod static_files;
pub mod static_response;
pub mod strip_prefix;
pub mod sub_filter;
pub mod traffic_split;
pub mod ua_restrict;

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
    BandwidthLimit(bandwidth_limit::BandwidthLimitPlugin),
    StripPrefix(strip_prefix::StripPrefixPlugin),
    AddPrefix(add_prefix::AddPrefixPlugin),
    PathRewrite(path_rewrite::PathRewritePlugin),
    ConcurrencyLimit(concurrency_limit::ConcurrencyLimitPlugin),
    RequestBuffer(request_buffer::RequestBufferPlugin),
    JwtAuth(jwt_auth::JwtAuthPlugin),
    KeyAuth(key_auth::KeyAuthPlugin),
    Csrf(csrf::CsrfPlugin),
    RefererRestrict(referer_restrict::RefererRestrictPlugin),
    UaRestrict(ua_restrict::UaRestrictPlugin),
    StaticFiles(static_files::StaticFilesPlugin),
    TrafficSplit(traffic_split::TrafficSplitPlugin),
    OAuth2(oauth2::OAuth2Plugin),
    ForwardAuth(forward_auth::ForwardAuthPlugin),
    DigestAuth(digest_auth::DigestAuthPlugin),
    LdapAuth(ldap_auth::LdapAuthPlugin),
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
            Self::BandwidthLimit(p) => p.on_request(req, ctx),
            Self::RequestBuffer(p) => p.on_request(req, ctx),
            Self::JwtAuth(p) => p.on_request(req, ctx),
            Self::KeyAuth(p) => p.on_request(req, ctx),
            Self::Csrf(p) => p.on_request(req, ctx),
            Self::RefererRestrict(p) => p.on_request(req, ctx),
            Self::UaRestrict(p) => p.on_request(req, ctx),
            Self::StaticFiles(p) => p.on_request(req, ctx),
            Self::TrafficSplit(p) => p.on_request(req, ctx),
            Self::OAuth2(p) => p.on_request(req, ctx),
            Self::ForwardAuth(p) => p.on_request(req, ctx),
            Self::DigestAuth(p) => p.on_request(req, ctx),
            Self::LdapAuth(p) => p.on_request(req, ctx),
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
            Self::KeyAuth(p) => p.on_upstream_request(upstream_req, ctx),
            Self::OAuth2(p) => p.on_upstream_request(upstream_req, ctx),
            Self::ForwardAuth(p) => p.on_upstream_request(upstream_req, ctx),
            Self::LdapAuth(p) => p.on_upstream_request(upstream_req, ctx),
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
            Self::Csrf(p) => p.on_response(resp, ctx),
            Self::TrafficSplit(p) => p.on_response(resp, ctx),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // --- on_request dispatch tests ---

    #[test]
    fn headers_on_request_returns_continue() {
        let plugin = BuiltinPlugin::Headers(headers::HeadersPlugin::new(Default::default()));
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        // Headers has no on_request branch — falls through to Continue
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn redirect_on_request_returns_handled() {
        let cfg = redirect::RedirectConfig {
            url: "/new".to_string(),
            status: 302,
        };
        let plugin = BuiltinPlugin::Redirect(redirect::RedirectPlugin::new(cfg));
        let req = pingora_http::RequestHeader::build("GET", b"/old", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(302)
        );
    }

    #[test]
    fn static_response_on_request_returns_handled() {
        let cfg = static_response::StaticResponseConfig {
            status: 200,
            body: Some("OK".to_string()),
            content_type: None,
        };
        let plugin = BuiltinPlugin::StaticResponse(static_response::StaticResponsePlugin::new(cfg));
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(200)
        );
    }

    #[test]
    fn bandwidth_limit_on_request_sets_bps() {
        let cfg = bandwidth_limit::BandwidthLimitConfig {
            bytes_per_second: 512,
        };
        let plugin =
            BuiltinPlugin::BandwidthLimit(bandwidth_limit::BandwidthLimitPlugin::new(&cfg));
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
        assert_eq!(ctx.bandwidth_limit_bps, Some(512));
    }

    #[test]
    fn compression_on_request_captures_accept_encoding() {
        let cfg = compression::CompressionConfig::default();
        let plugin = BuiltinPlugin::Compression(compression::CompressionPlugin::new(&cfg));
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("accept-encoding", "gzip, br").unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
        assert!(ctx.accept_encoding.is_some());
    }

    // --- on_upstream_request dispatch tests ---

    #[test]
    fn request_id_on_upstream_request_injects_header() {
        let plugin = BuiltinPlugin::RequestId(request_id::RequestIdPlugin::default());
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert!(req.headers.get("X-Request-ID").is_some());
    }

    #[test]
    fn headers_on_upstream_request_sets_header() {
        let cfg = headers::HeadersConfig {
            request_set: std::iter::once(("X-Proxy".to_string(), "fluxo".to_string())).collect(),
            ..Default::default()
        };
        let plugin = BuiltinPlugin::Headers(headers::HeadersPlugin::new(cfg));
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(
            req.headers.get("X-Proxy").unwrap().to_str().unwrap(),
            "fluxo"
        );
    }

    #[test]
    fn strip_prefix_on_upstream_request_modifies_path() {
        let cfg = strip_prefix::StripPrefixConfig {
            prefixes: vec!["/api".to_string()],
            forward_prefix: false,
        };
        let plugin = BuiltinPlugin::StripPrefix(strip_prefix::StripPrefixPlugin::new(cfg));
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/users", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/users");
    }

    #[test]
    fn add_prefix_on_upstream_request_prepends() {
        let cfg = add_prefix::AddPrefixConfig {
            prefix: "/v2".to_string(),
        };
        let plugin = BuiltinPlugin::AddPrefix(add_prefix::AddPrefixPlugin::new(cfg));
        let mut req = pingora_http::RequestHeader::build("GET", b"/users", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/v2/users");
    }

    #[test]
    fn path_rewrite_on_upstream_request_rewrites() {
        let cfg = path_rewrite::PathRewriteConfig {
            pattern: "^/old".to_string(),
            replacement: "/new".to_string(),
        };
        let plugin =
            BuiltinPlugin::PathRewrite(path_rewrite::PathRewritePlugin::try_new(cfg).unwrap());
        let mut req = pingora_http::RequestHeader::build("GET", b"/old/page", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/new/page");
    }

    #[test]
    fn non_upstream_plugin_on_upstream_request_is_noop() {
        // Plugins that don't participate in upstream_request phase should be no-ops
        let cfg = compression::CompressionConfig::default();
        let plugin = BuiltinPlugin::Compression(compression::CompressionPlugin::new(&cfg));
        let mut req = pingora_http::RequestHeader::build("GET", b"/test", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/test"); // unchanged
    }

    // --- on_response dispatch tests ---

    #[test]
    fn headers_on_response_sets_header() {
        let cfg = headers::HeadersConfig {
            response_set: std::iter::once(("X-Powered-By".to_string(), "fluxo".to_string()))
                .collect(),
            ..Default::default()
        };
        let plugin = BuiltinPlugin::Headers(headers::HeadersPlugin::new(cfg));
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(
            resp.headers.get("X-Powered-By").unwrap().to_str().unwrap(),
            "fluxo"
        );
    }

    #[test]
    fn security_headers_on_response_sets_hsts() {
        let cfg = security_headers::SecurityHeadersConfig {
            hsts_max_age: Some(86400),
            ..Default::default()
        };
        let plugin =
            BuiltinPlugin::SecurityHeaders(security_headers::SecurityHeadersPlugin::new(cfg));
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        assert!(resp.headers.get("Strict-Transport-Security").is_some());
    }

    #[test]
    fn non_response_plugin_on_response_is_noop() {
        // Plugins that don't participate in response phase should be no-ops
        let plugin = BuiltinPlugin::RequestId(request_id::RequestIdPlugin::default());
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        let header_count_before = resp.headers.len();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(resp.headers.len(), header_count_before); // unchanged
    }
}
