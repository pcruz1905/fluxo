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
}

impl CorsPlugin {
    pub fn new(config: CorsConfig) -> Self {
        Self { config }
    }

    pub fn on_response(
        &self,
        resp: &mut pingora_http::ResponseHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        // Allow-Origin
        let origin = if self.config.allowed_origins.iter().any(|o| o == "*") {
            "*".to_string()
        } else {
            self.config.allowed_origins.join(", ")
        };
        let _ = resp.insert_header("Access-Control-Allow-Origin", &origin);

        // Allow-Methods
        if !self.config.allowed_methods.is_empty() {
            let _ = resp.insert_header(
                "Access-Control-Allow-Methods",
                self.config.allowed_methods.join(", "),
            );
        }

        // Allow-Headers
        if !self.config.allowed_headers.is_empty() {
            let _ = resp.insert_header(
                "Access-Control-Allow-Headers",
                self.config.allowed_headers.join(", "),
            );
        }

        // Max-Age
        if let Some(max_age) = self.config.max_age {
            let _ = resp.insert_header("Access-Control-Max-Age", max_age.to_string());
        }

        // Credentials
        if self.config.allow_credentials {
            let _ = resp.insert_header("Access-Control-Allow-Credentials", "true");
        }

        // Expose-Headers
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
        assert!(resp.headers.get("Access-Control-Allow-Methods").is_some());
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
    }

    #[test]
    fn credentials_flag_sets_header() {
        let config = CorsConfig {
            allowed_origins: vec!["*".into()],
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
    }
}
