//! Plugin pipeline — an ordered list of plugins compiled per-route.

use super::BuiltinPlugin;

/// An ordered list of plugins to execute at each request phase.
#[derive(Debug)]
pub struct PluginPipeline {
    plugins: Vec<BuiltinPlugin>,
}

impl PluginPipeline {
    /// Create a new pipeline from a list of plugins.
    pub fn new(plugins: Vec<BuiltinPlugin>) -> Self {
        Self { plugins }
    }

    /// Create an empty pipeline (no-op at all phases).
    pub fn empty() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Number of plugins in the pipeline.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the pipeline is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Execute all request-phase plugins. Returns Handled if any short-circuited.
    pub fn run_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        for plugin in &self.plugins {
            match plugin.on_request(req, ctx) {
                super::PluginAction::Continue => {}
                action @ super::PluginAction::Handled(_) => return action,
            }
        }
        super::PluginAction::Continue
    }

    /// Execute all upstream-request-phase plugins.
    pub fn run_upstream_request(
        &self,
        upstream_req: &mut pingora_http::RequestHeader,
        ctx: &crate::context::RequestContext,
    ) {
        for plugin in &self.plugins {
            plugin.on_upstream_request(upstream_req, ctx);
        }
    }

    /// Execute all response-phase plugins.
    pub fn run_response(
        &self,
        resp: &mut pingora_http::ResponseHeader,
        ctx: &mut crate::context::RequestContext,
    ) {
        for plugin in &self.plugins {
            plugin.on_response(resp, ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn empty_pipeline_returns_continue_on_all_phases() {
        let pipeline = PluginPipeline::empty();
        assert_eq!(pipeline.len(), 0);
    }

    #[test]
    fn pipeline_from_single_plugin() {
        let plugin = BuiltinPlugin::RequestId(super::super::request_id::RequestIdPlugin::default());
        let pipeline = PluginPipeline::new(vec![plugin]);
        assert_eq!(pipeline.len(), 1);
    }

    #[test]
    fn empty_pipeline_is_empty() {
        let pipeline = PluginPipeline::empty();
        assert!(pipeline.is_empty());
    }

    #[test]
    fn non_empty_pipeline_is_not_empty() {
        let plugin = BuiltinPlugin::RequestId(super::super::request_id::RequestIdPlugin::default());
        let pipeline = PluginPipeline::new(vec![plugin]);
        assert!(!pipeline.is_empty());
    }

    #[test]
    fn pipeline_len_with_multiple_plugins() {
        let plugins = vec![
            BuiltinPlugin::RequestId(super::super::request_id::RequestIdPlugin::default()),
            BuiltinPlugin::Headers(super::super::headers::HeadersPlugin::new(Default::default())),
            BuiltinPlugin::SecurityHeaders(
                super::super::security_headers::SecurityHeadersPlugin::new(Default::default()),
            ),
        ];
        let pipeline = PluginPipeline::new(plugins);
        assert_eq!(pipeline.len(), 3);
    }

    #[test]
    fn run_request_empty_pipeline_returns_continue() {
        let pipeline = PluginPipeline::empty();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(pipeline.run_request(&req, &mut ctx), super::super::PluginAction::Continue);
    }

    #[test]
    fn run_request_with_continue_plugins_returns_continue() {
        // Headers plugin does not participate in request phase, returns Continue
        let plugins = vec![
            BuiltinPlugin::Headers(super::super::headers::HeadersPlugin::new(Default::default())),
            BuiltinPlugin::SecurityHeaders(
                super::super::security_headers::SecurityHeadersPlugin::new(Default::default()),
            ),
        ];
        let pipeline = PluginPipeline::new(plugins);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(pipeline.run_request(&req, &mut ctx), super::super::PluginAction::Continue);
    }

    #[test]
    fn run_request_short_circuits_on_handled() {
        // Redirect plugin returns Handled(302)
        let redirect_cfg = super::super::redirect::RedirectConfig {
            url: "/new".to_string(),
            status: 302,
        };
        let plugins = vec![
            BuiltinPlugin::Redirect(super::super::redirect::RedirectPlugin::new(redirect_cfg)),
            // This plugin should never be reached
            BuiltinPlugin::Headers(super::super::headers::HeadersPlugin::new(Default::default())),
        ];
        let pipeline = PluginPipeline::new(plugins);
        let req = pingora_http::RequestHeader::build("GET", b"/old", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(
            pipeline.run_request(&req, &mut ctx),
            super::super::PluginAction::Handled(302)
        );
    }

    #[test]
    fn run_request_static_response_short_circuits() {
        let static_cfg = super::super::static_response::StaticResponseConfig {
            status: 503,
            body: Some("maintenance".to_string()),
            content_type: None,
        };
        let plugins = vec![
            BuiltinPlugin::StaticResponse(
                super::super::static_response::StaticResponsePlugin::new(static_cfg),
            ),
        ];
        let pipeline = PluginPipeline::new(plugins);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(
            pipeline.run_request(&req, &mut ctx),
            super::super::PluginAction::Handled(503)
        );
    }

    #[test]
    fn run_request_continue_then_handled() {
        // First plugin (Headers) returns Continue, second (Redirect) returns Handled
        let redirect_cfg = super::super::redirect::RedirectConfig {
            url: "/dest".to_string(),
            status: 301,
        };
        let plugins = vec![
            BuiltinPlugin::Headers(super::super::headers::HeadersPlugin::new(Default::default())),
            BuiltinPlugin::Redirect(super::super::redirect::RedirectPlugin::new(redirect_cfg)),
        ];
        let pipeline = PluginPipeline::new(plugins);
        let req = pingora_http::RequestHeader::build("GET", b"/src", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(
            pipeline.run_request(&req, &mut ctx),
            super::super::PluginAction::Handled(301)
        );
    }

    #[test]
    fn run_upstream_request_empty_pipeline_is_noop() {
        let pipeline = PluginPipeline::empty();
        let mut req = pingora_http::RequestHeader::build("GET", b"/test", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        pipeline.run_upstream_request(&mut req, &ctx);
        // Path unchanged
        assert_eq!(req.uri.path(), "/test");
    }

    #[test]
    fn run_upstream_request_applies_plugins_in_order() {
        let strip_cfg = super::super::strip_prefix::StripPrefixConfig {
            prefixes: vec!["/api".to_string()],
            forward_prefix: false,
        };
        let add_cfg = super::super::add_prefix::AddPrefixConfig {
            prefix: "/v2".to_string(),
        };
        // Strip /api first, then add /v2
        let plugins = vec![
            BuiltinPlugin::StripPrefix(super::super::strip_prefix::StripPrefixPlugin::new(strip_cfg)),
            BuiltinPlugin::AddPrefix(super::super::add_prefix::AddPrefixPlugin::new(add_cfg)),
        ];
        let pipeline = PluginPipeline::new(plugins);
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/users", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        pipeline.run_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/v2/users");
    }

    #[test]
    fn run_upstream_request_request_id_injects_header() {
        let plugins = vec![
            BuiltinPlugin::RequestId(super::super::request_id::RequestIdPlugin::default()),
        ];
        let pipeline = PluginPipeline::new(plugins);
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        pipeline.run_upstream_request(&mut req, &ctx);
        assert!(req.headers.get("X-Request-ID").is_some());
    }

    #[test]
    fn run_response_empty_pipeline_is_noop() {
        let pipeline = PluginPipeline::empty();
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        let header_count_before = resp.headers.len();
        pipeline.run_response(&mut resp, &mut ctx);
        assert_eq!(resp.headers.len(), header_count_before);
    }

    #[test]
    fn run_response_applies_plugins() {
        let headers_cfg = super::super::headers::HeadersConfig {
            response_set: std::iter::once(("X-Powered-By".to_string(), "fluxo".to_string()))
                .collect(),
            ..Default::default()
        };
        let sec_cfg = super::super::security_headers::SecurityHeadersConfig {
            hsts_max_age: Some(31536000),
            ..Default::default()
        };
        let plugins = vec![
            BuiltinPlugin::Headers(super::super::headers::HeadersPlugin::new(headers_cfg)),
            BuiltinPlugin::SecurityHeaders(
                super::super::security_headers::SecurityHeadersPlugin::new(sec_cfg),
            ),
        ];
        let pipeline = PluginPipeline::new(plugins);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        pipeline.run_response(&mut resp, &mut ctx);
        assert_eq!(
            resp.headers.get("X-Powered-By").unwrap().to_str().unwrap(),
            "fluxo"
        );
        assert!(resp.headers.get("Strict-Transport-Security").is_some());
    }

    #[test]
    fn new_from_empty_vec_is_empty() {
        let pipeline = PluginPipeline::new(vec![]);
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.len(), 0);
    }
}
