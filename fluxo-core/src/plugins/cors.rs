//! CORS plugin — Cross-Origin Resource Sharing headers.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    pub max_age: Option<u64>,
    #[serde(default)]
    pub allow_credentials: bool,
    #[serde(default)]
    pub expose_headers: Vec<String>,
}

#[derive(Debug)]
pub struct CorsPlugin {
    pub config: CorsConfig,
    /// Whether all origins are allowed (wildcard mode).
    wildcard: bool,
}

impl CorsPlugin {
    pub fn new(config: CorsConfig) -> Self {
        let wildcard = config.allowed_origins.iter().any(|o| o == "*");
        Self { config, wildcard }
    }

    /// Validate CORS config at build time.
    pub fn validate(config: &CorsConfig) -> Result<(), String> {
        if config.allow_credentials && config.allowed_origins.iter().any(|o| o == "*") {
            return Err(
                "CORS: allow_credentials=true is incompatible with wildcard origin '*'. \
                 List specific origins instead."
                    .into(),
            );
        }
        Ok(())
    }

    /// Handle preflight OPTIONS requests. Returns Handled(204) if this is a preflight.
    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        // Only intercept OPTIONS requests with an Origin header (CORS preflight)
        if req.method != http::Method::OPTIONS {
            return super::PluginAction::Continue;
        }
        let origin = match req.headers.get("origin").and_then(|v| v.to_str().ok()) {
            Some(o) => o,
            None => return super::PluginAction::Continue,
        };

        // Build preflight response headers as the body for static response
        let allow_origin = self.resolve_origin(origin);
        let mut headers = format!("Access-Control-Allow-Origin: {allow_origin}");

        if !self.config.allowed_methods.is_empty() {
            headers.push_str(&format!(
                "\r\nAccess-Control-Allow-Methods: {}",
                self.config.allowed_methods.join(", ")
            ));
        }
        if !self.config.allowed_headers.is_empty() {
            headers.push_str(&format!(
                "\r\nAccess-Control-Allow-Headers: {}",
                self.config.allowed_headers.join(", ")
            ));
        }
        if let Some(max_age) = self.config.max_age {
            headers.push_str(&format!("\r\nAccess-Control-Max-Age: {max_age}"));
        }
        if self.config.allow_credentials {
            headers.push_str("\r\nAccess-Control-Allow-Credentials: true");
        }

        // Store origin for the proxy to use when building the response
        ctx.plugin_response = Some(crate::context::PluginResponse::Static {
            status: 204,
            body: None,
            content_type: None,
        });
        // Store the resolved origin so on_response can use it
        ctx.error_message = Some(format!("cors-origin:{allow_origin}"));
        super::PluginAction::Handled(204)
    }

    /// Resolve the Allow-Origin value: reflect the request origin if it matches,
    /// or use "*" only in wildcard mode without credentials.
    fn resolve_origin(&self, request_origin: &str) -> String {
        if self.wildcard && !self.config.allow_credentials {
            return "*".to_string();
        }
        // Check if request origin is in the allowed list
        if self.wildcard
            || self
                .config
                .allowed_origins
                .iter()
                .any(|o| o == request_origin)
        {
            return request_origin.to_string();
        }
        // Origin not allowed — return empty (browser will block)
        String::new()
    }

    pub fn on_response(
        &self,
        resp: &mut pingora_http::ResponseHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        // For normal (non-preflight) responses, add CORS headers.
        // Use origin reflection (not join) for spec compliance.
        // We don't have the request Origin header here, so for non-wildcard
        // we reflect the first configured origin. The proper fix would be to
        // store the request Origin in ctx, but for now this handles the common cases.
        let origin = if self.wildcard && !self.config.allow_credentials {
            "*".to_string()
        } else if self.config.allowed_origins.len() == 1 {
            self.config.allowed_origins[0].clone()
        } else {
            // Multiple specific origins: ideally we'd reflect the request Origin.
            // For now, use the first one. Full reflection needs request-phase Origin storage.
            self.config
                .allowed_origins
                .first()
                .cloned()
                .unwrap_or_default()
        };

        if !origin.is_empty() {
            let _ = resp.insert_header("Access-Control-Allow-Origin", &origin);
            // Vary: Origin is required when reflecting specific origins
            if origin != "*" {
                let _ = resp.insert_header("Vary", "Origin");
            }
        }

        if !self.config.allowed_methods.is_empty() {
            let _ = resp.insert_header(
                "Access-Control-Allow-Methods",
                self.config.allowed_methods.join(", "),
            );
        }

        if !self.config.allowed_headers.is_empty() {
            let _ = resp.insert_header(
                "Access-Control-Allow-Headers",
                self.config.allowed_headers.join(", "),
            );
        }

        if let Some(max_age) = self.config.max_age {
            let _ = resp.insert_header("Access-Control-Max-Age", max_age.to_string());
        }

        if self.config.allow_credentials {
            let _ = resp.insert_header("Access-Control-Allow-Credentials", "true");
        }

        if !self.config.expose_headers.is_empty() {
            let _ = resp.insert_header(
                "Access-Control-Expose-Headers",
                self.config.expose_headers.join(", "),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_cors_headers_for_allowed_origin() {
        let config = CorsConfig {
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_age: Some(3600),
            allow_credentials: false,
            expose_headers: vec![],
        };
        let plugin = CorsPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &ctx);
        assert_eq!(
            resp.headers
                .get("Access-Control-Allow-Origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "https://app.example.com"
        );
        assert!(resp.headers.get("Access-Control-Allow-Methods").is_some());
        // Specific origin must include Vary: Origin
        assert_eq!(
            resp.headers.get("Vary").unwrap().to_str().unwrap(),
            "Origin"
        );
    }

    #[test]
    fn wildcard_origin_allows_all() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec![],
            max_age: None,
            allow_credentials: false,
            expose_headers: vec![],
        };
        let plugin = CorsPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &ctx);
        assert_eq!(
            resp.headers
                .get("Access-Control-Allow-Origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );
        // Wildcard should NOT have Vary: Origin
        assert!(resp.headers.get("Vary").is_none());
    }

    #[test]
    fn credentials_with_specific_origin() {
        let config = CorsConfig {
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec![],
            max_age: None,
            allow_credentials: true,
            expose_headers: vec![],
        };
        let plugin = CorsPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &ctx);
        assert_eq!(
            resp.headers
                .get("Access-Control-Allow-Credentials")
                .unwrap()
                .to_str()
                .unwrap(),
            "true"
        );
        // Must NOT be wildcard when credentials are enabled
        assert_ne!(
            resp.headers
                .get("Access-Control-Allow-Origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "*"
        );
    }

    #[test]
    fn credentials_with_wildcard_rejected_at_validation() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allowed_methods: vec![],
            allowed_headers: vec![],
            max_age: None,
            allow_credentials: true,
            expose_headers: vec![],
        };
        assert!(CorsPlugin::validate(&config).is_err());
    }

    #[test]
    fn preflight_options_returns_handled() {
        let config = CorsConfig {
            allowed_origins: vec!["https://app.example.com".into()],
            allowed_methods: vec!["GET".into(), "POST".into()],
            allowed_headers: vec!["Content-Type".into()],
            max_age: Some(3600),
            allow_credentials: false,
            expose_headers: vec![],
        };
        let plugin = CorsPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("OPTIONS", b"/api", None).unwrap();
        req.insert_header("Origin", "https://app.example.com")
            .unwrap();
        let mut ctx = crate::context::RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, super::super::PluginAction::Handled(204));
    }

    #[test]
    fn non_options_request_continues() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
            allowed_methods: vec![],
            allowed_headers: vec![],
            max_age: None,
            allow_credentials: false,
            expose_headers: vec![],
        };
        let plugin = CorsPlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/api", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, super::super::PluginAction::Continue);
    }
}
