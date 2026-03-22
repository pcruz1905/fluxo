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
    /// For all requests with an Origin header, stores the origin in ctx for use in `on_response`.
    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        // Capture the request Origin into ctx for ALL requests (needed by on_response).
        if let Some(origin) = req.headers.get("origin").and_then(|v| v.to_str().ok()) {
            ctx.set_extension(
                "cors_request_origin",
                serde_json::Value::String(origin.to_string()),
            );
        }

        // Only intercept OPTIONS requests with an Origin header (CORS preflight)
        if req.method != http::Method::OPTIONS {
            return super::PluginAction::Continue;
        }
        let Some(origin) = req.headers.get("origin").and_then(|v| v.to_str().ok()) else {
            return super::PluginAction::Continue;
        };

        let allow_origin = self.resolve_origin(origin);

        // Build CORS headers as key-value pairs for the response
        let mut cors_headers: Vec<(String, String)> = Vec::new();
        cors_headers.push(("Access-Control-Allow-Origin".into(), allow_origin.clone()));

        if !self.config.allowed_methods.is_empty() {
            cors_headers.push((
                "Access-Control-Allow-Methods".into(),
                self.config.allowed_methods.join(", "),
            ));
        }
        if !self.config.allowed_headers.is_empty() {
            cors_headers.push((
                "Access-Control-Allow-Headers".into(),
                self.config.allowed_headers.join(", "),
            ));
        }
        if let Some(max_age) = self.config.max_age {
            cors_headers.push(("Access-Control-Max-Age".into(), max_age.to_string()));
        }
        if self.config.allow_credentials {
            cors_headers.push(("Access-Control-Allow-Credentials".into(), "true".into()));
        }
        // Vary: Origin when reflecting specific origins
        if allow_origin != "*" {
            cors_headers.push(("Vary".into(), "Origin".into()));
        }

        ctx.plugin_response = Some(crate::context::PluginResponse::Cors {
            headers: cors_headers,
        });
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
        ctx: &mut crate::context::RequestContext,
    ) {
        // For normal (non-preflight) responses, add CORS headers.
        // The request Origin was stored in ctx.extensions during on_request,
        // so we can properly reflect the correct origin per the CORS spec.
        let stored_origin = ctx
            .extensions
            .get("cors_request_origin")
            .and_then(|v| v.as_str());

        let origin = if self.wildcard && !self.config.allow_credentials {
            "*".to_string()
        } else if let Some(request_origin) = stored_origin {
            // Use the stored request Origin for proper reflection via resolve_origin.
            self.resolve_origin(request_origin)
        } else if self.config.allowed_origins.len() == 1 {
            // Fallback: no stored origin but only one configured, use it directly.
            self.config.allowed_origins[0].clone()
        } else {
            // Fallback: no stored origin and multiple configured origins.
            // Without knowing the request Origin we can't reflect correctly.
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
    #![allow(clippy::unwrap_used)]
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
        let mut ctx = crate::context::RequestContext::new();
        // Simulate on_request storing the Origin header
        ctx.set_extension(
            "cors_request_origin",
            serde_json::Value::String("https://app.example.com".into()),
        );
        plugin.on_response(&mut resp, &mut ctx);
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
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
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
        let mut ctx = crate::context::RequestContext::new();
        // Simulate on_request storing the Origin header
        ctx.set_extension(
            "cors_request_origin",
            serde_json::Value::String("https://app.example.com".into()),
        );
        plugin.on_response(&mut resp, &mut ctx);
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
        let mut req = pingora_http::RequestHeader::build("GET", b"/api", None).unwrap();
        req.insert_header("Origin", "https://app.example.com")
            .unwrap();
        let mut ctx = crate::context::RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, super::super::PluginAction::Continue);
        // Origin should still be stored in ctx for use in on_response
        assert_eq!(
            ctx.extensions
                .get("cors_request_origin")
                .and_then(|v| v.as_str()),
            Some("https://app.example.com")
        );
    }

    #[test]
    fn multi_origin_reflects_request_origin() {
        let config = CorsConfig {
            allowed_origins: vec![
                "https://a.example.com".into(),
                "https://b.example.com".into(),
            ],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec![],
            max_age: None,
            allow_credentials: false,
            expose_headers: vec![],
        };
        let plugin = CorsPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        // Simulate on_request storing Origin: https://b.example.com
        ctx.set_extension(
            "cors_request_origin",
            serde_json::Value::String("https://b.example.com".into()),
        );
        plugin.on_response(&mut resp, &mut ctx);
        // Must reflect the actual request origin, not the first configured one
        assert_eq!(
            resp.headers
                .get("Access-Control-Allow-Origin")
                .unwrap()
                .to_str()
                .unwrap(),
            "https://b.example.com"
        );
        // Specific origin must include Vary: Origin
        assert_eq!(
            resp.headers.get("Vary").unwrap().to_str().unwrap(),
            "Origin"
        );
    }
}
