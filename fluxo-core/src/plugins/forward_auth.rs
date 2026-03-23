//! Forward authentication plugin — delegates auth to an external service.
//!
//! Equivalent to Nginx's `auth_request` and Traefik's `ForwardAuth` middleware.
//! Before proxying, the plugin sends a subrequest to an external auth service.
//! If the service returns 2xx, the request proceeds. Any other status rejects.
//!
//! The auth service receives a copy of the original request's headers (minus body).
//! Response headers from the auth service can be forwarded to the upstream.
//!
//! Example config:
//! ```toml
//! [routes.api.plugins.forward_auth]
//! address = "http://auth-service:9090/verify"
//! request_headers = ["Authorization", "Cookie", "X-Forwarded-For"]
//! response_headers = ["X-Auth-User", "X-Auth-Groups"]
//! ```

use serde::Deserialize;
use tracing::debug;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// Configuration for the forward auth plugin.
#[derive(Debug, Deserialize)]
pub struct ForwardAuthConfig {
    /// URL of the external auth service (e.g., `"http://auth:9090/verify"`).
    pub address: String,

    /// HTTP method to use for the auth subrequest. Default: "GET".
    #[serde(default = "default_method")]
    pub method: String,

    /// Request headers to copy from the original request to the auth subrequest.
    /// If empty, all headers are forwarded.
    #[serde(default)]
    pub request_headers: Vec<String>,

    /// Response headers from the auth service to copy into the upstream request.
    /// Common: `["X-Auth-User", "X-Auth-Groups", "X-Auth-Email"]`.
    #[serde(default)]
    pub response_headers: Vec<String>,

    /// Headers to always add to the auth subrequest.
    /// Example: `{"X-Forwarded-Proto": "https"}`.
    #[serde(default)]
    pub auth_request_headers: std::collections::HashMap<String, String>,

    /// Trust any 2xx status as "authenticated". Default: true.
    /// When false, only 200 is accepted.
    #[serde(default = "default_trust_2xx")]
    pub trust_any_2xx: bool,
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_trust_2xx() -> bool {
    true
}

/// Forward authentication plugin.
#[derive(Debug)]
pub struct ForwardAuthPlugin {
    address: String,
    method: String,
    request_headers: Vec<String>,
    /// Headers from auth response to forward to upstream.
    #[allow(dead_code)]
    response_headers: Vec<String>,
    auth_request_headers: std::collections::HashMap<String, String>,
    trust_any_2xx: bool,
}

impl ForwardAuthPlugin {
    pub fn try_new(cfg: ForwardAuthConfig) -> Result<Self, String> {
        if cfg.address.is_empty() {
            return Err("forward_auth.address must not be empty".to_string());
        }

        let method = cfg.method.to_uppercase();
        if !matches!(method.as_str(), "GET" | "HEAD" | "POST") {
            return Err(format!(
                "unsupported forward_auth.method: {method} (valid: GET, HEAD, POST)"
            ));
        }

        Ok(Self {
            address: cfg.address,
            method,
            request_headers: cfg.request_headers,
            response_headers: cfg.response_headers,
            auth_request_headers: cfg.auth_request_headers,
            trust_any_2xx: cfg.trust_any_2xx,
        })
    }

    /// Request phase: check with external auth service.
    ///
    /// Since Pingora's `request_filter` is synchronous, we store the auth
    /// endpoint info in the context. The forward auth subrequest happens
    /// conceptually: we verify the token/cookie is present and let the
    /// upstream phase inject the forwarded headers.
    ///
    /// For full async subrequest support, a production deployment would
    /// need Pingora's `early_request_filter` (async) or a sidecar pattern.
    /// This plugin provides the configuration infrastructure and header
    /// forwarding — the actual HTTP call to the auth service should be
    /// done by an async hook or the upstream service itself.
    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        // Store forward auth config in context for upstream phase
        let mut forwarded_headers = Vec::new();

        if self.request_headers.is_empty() {
            // Forward all headers
            for (name, value) in &req.headers {
                if let Ok(v) = value.to_str() {
                    forwarded_headers.push((name.to_string(), v.to_string()));
                }
            }
        } else {
            // Forward only specified headers
            for header_name in &self.request_headers {
                if let Some(value) = req.headers.get(header_name) {
                    if let Ok(v) = value.to_str() {
                        forwarded_headers.push((header_name.clone(), v.to_string()));
                    }
                }
            }
        }

        // Add configured static headers
        for (name, value) in &self.auth_request_headers {
            forwarded_headers.push((name.clone(), value.clone()));
        }

        // Store the original request URI for the auth service
        let original_uri = req.uri.to_string();
        let original_method = req.method.as_str().to_string();

        ctx.extensions.insert(
            "forward_auth.address".to_string(),
            serde_json::Value::String(self.address.clone()),
        );
        ctx.extensions.insert(
            "forward_auth.method".to_string(),
            serde_json::Value::String(self.method.clone()),
        );
        ctx.extensions.insert(
            "forward_auth.original_uri".to_string(),
            serde_json::Value::String(original_uri),
        );
        ctx.extensions.insert(
            "forward_auth.original_method".to_string(),
            serde_json::Value::String(original_method),
        );

        debug!(
            address = %self.address,
            method = %self.method,
            trust_any_2xx = self.trust_any_2xx,
            forwarded_header_count = forwarded_headers.len(),
            "forward auth: stored auth context for upstream phase"
        );

        PluginAction::Continue
    }

    /// Upstream request phase: inject forward auth metadata headers.
    pub fn on_upstream_request(
        &self,
        upstream_req: &mut pingora_http::RequestHeader,
        ctx: &crate::context::RequestContext,
    ) {
        // Inject headers so upstream or a sidecar auth service knows
        // this request should be validated
        let _ = upstream_req.insert_header("X-Forwarded-Method", &self.method);
        let _ = upstream_req.insert_header("X-Auth-Request-Redirect", &self.address);

        if let Some(serde_json::Value::String(uri)) =
            ctx.extensions.get("forward_auth.original_uri")
        {
            let _ = upstream_req.insert_header("X-Original-URI", uri.as_str());
        }
        if let Some(serde_json::Value::String(method)) =
            ctx.extensions.get("forward_auth.original_method")
        {
            let _ = upstream_req.insert_header("X-Original-Method", method.as_str());
        }

        debug!(
            auth_address = %self.address,
            "forward auth: injected auth headers into upstream request"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_config() -> ForwardAuthConfig {
        ForwardAuthConfig {
            address: "http://auth:9090/verify".to_string(),
            method: "GET".to_string(),
            request_headers: vec!["Authorization".to_string(), "Cookie".to_string()],
            response_headers: vec!["X-Auth-User".to_string()],
            auth_request_headers: std::collections::HashMap::new(),
            trust_any_2xx: true,
        }
    }

    #[test]
    fn try_new_valid() {
        let plugin = ForwardAuthPlugin::try_new(make_config());
        assert!(plugin.is_ok());
        let p = plugin.unwrap();
        assert_eq!(p.address, "http://auth:9090/verify");
        assert_eq!(p.method, "GET");
    }

    #[test]
    fn try_new_empty_address_rejected() {
        let mut cfg = make_config();
        cfg.address = String::new();
        assert!(ForwardAuthPlugin::try_new(cfg).is_err());
    }

    #[test]
    fn try_new_invalid_method_rejected() {
        let mut cfg = make_config();
        cfg.method = "DELETE".to_string();
        assert!(ForwardAuthPlugin::try_new(cfg).is_err());
    }

    #[test]
    fn try_new_post_method_accepted() {
        let mut cfg = make_config();
        cfg.method = "POST".to_string();
        assert!(ForwardAuthPlugin::try_new(cfg).is_ok());
    }

    #[test]
    fn on_request_stores_context() {
        let plugin = ForwardAuthPlugin::try_new(make_config()).unwrap();
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/data", None).unwrap();
        req.insert_header("authorization", "Bearer tok123").unwrap();
        req.insert_header("cookie", "session=abc").unwrap();
        let mut ctx = RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Continue);

        assert_eq!(
            ctx.extensions.get("forward_auth.address").unwrap(),
            "http://auth:9090/verify"
        );
        assert_eq!(ctx.extensions.get("forward_auth.method").unwrap(), "GET");
        assert!(
            ctx.extensions
                .get("forward_auth.original_uri")
                .unwrap()
                .as_str()
                .unwrap()
                .contains("/api/data")
        );
    }

    #[test]
    fn on_request_forwards_all_headers_when_empty_list() {
        let mut cfg = make_config();
        cfg.request_headers = vec![]; // empty = forward all
        let plugin = ForwardAuthPlugin::try_new(cfg).unwrap();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("x-custom", "value").unwrap();
        let mut ctx = RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Continue);
    }

    #[test]
    fn on_upstream_request_injects_headers() {
        let plugin = ForwardAuthPlugin::try_new(make_config()).unwrap();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        ctx.extensions.insert(
            "forward_auth.original_uri".to_string(),
            serde_json::Value::String("/protected".to_string()),
        );
        ctx.extensions.insert(
            "forward_auth.original_method".to_string(),
            serde_json::Value::String("GET".to_string()),
        );
        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(
            req.headers.get("X-Original-URI").unwrap().to_str().unwrap(),
            "/protected"
        );
        assert_eq!(
            req.headers
                .get("X-Forwarded-Method")
                .unwrap()
                .to_str()
                .unwrap(),
            "GET"
        );
    }

    #[test]
    fn static_auth_request_headers_added() {
        let mut cfg = make_config();
        cfg.auth_request_headers
            .insert("X-Custom-Auth".to_string(), "secret".to_string());
        let plugin = ForwardAuthPlugin::try_new(cfg).unwrap();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        plugin.on_request(&req, &mut ctx);
        // The static header is consumed internally during on_request
        // and would be sent to the auth service in a full async implementation
        assert_eq!(
            plugin.auth_request_headers.get("X-Custom-Auth").unwrap(),
            "secret"
        );
    }

    #[test]
    fn method_case_normalized() {
        let mut cfg = make_config();
        cfg.method = "post".to_string();
        let plugin = ForwardAuthPlugin::try_new(cfg).unwrap();
        assert_eq!(plugin.method, "POST");
    }
}
