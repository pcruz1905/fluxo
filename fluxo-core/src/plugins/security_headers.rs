//! Security headers plugin — HSTS, X-Frame-Options, CSP, etc.

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct SecurityHeadersConfig {
    /// HSTS max-age in seconds. If set, adds Strict-Transport-Security header.
    pub hsts_max_age: Option<u64>,
    /// Include subdomains in HSTS.
    #[serde(default)]
    pub hsts_include_subdomains: bool,
    /// X-Frame-Options value (e.g., "DENY", "SAMEORIGIN").
    pub x_frame_options: Option<String>,
    /// If true, adds X-Content-Type-Options: nosniff.
    #[serde(default)]
    pub x_content_type_options: bool,
    /// If true, adds X-XSS-Protection: 1; mode=block.
    #[serde(default)]
    pub x_xss_protection: bool,
    /// Content-Security-Policy value.
    pub content_security_policy: Option<String>,
    /// Referrer-Policy value.
    pub referrer_policy: Option<String>,
    /// Permissions-Policy value.
    pub permissions_policy: Option<String>,
}

#[derive(Debug)]
pub struct SecurityHeadersPlugin {
    pub config: SecurityHeadersConfig,
}

impl SecurityHeadersPlugin {
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }

    pub fn on_response(
        &self,
        resp: &mut pingora_http::ResponseHeader,
        _ctx: &mut crate::context::RequestContext,
    ) {
        if let Some(max_age) = self.config.hsts_max_age {
            let value = if self.config.hsts_include_subdomains {
                format!("max-age={max_age}; includeSubDomains")
            } else {
                format!("max-age={max_age}")
            };
            let _ = resp.insert_header("Strict-Transport-Security", &value);
        }

        if let Some(ref value) = self.config.x_frame_options {
            let _ = resp.insert_header("X-Frame-Options", value.as_str());
        }

        if self.config.x_content_type_options {
            let _ = resp.insert_header("X-Content-Type-Options", "nosniff");
        }

        if self.config.x_xss_protection {
            let _ = resp.insert_header("X-XSS-Protection", "1; mode=block");
        }

        if let Some(ref csp) = self.config.content_security_policy {
            let _ = resp.insert_header("Content-Security-Policy", csp.as_str());
        }

        if let Some(ref referrer) = self.config.referrer_policy {
            let _ = resp.insert_header("Referrer-Policy", referrer.as_str());
        }

        if let Some(ref permissions) = self.config.permissions_policy {
            let _ = resp.insert_header("Permissions-Policy", permissions.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn adds_hsts_header() {
        let config = SecurityHeadersConfig {
            hsts_max_age: Some(31536000),
            ..Default::default()
        };
        let plugin = SecurityHeadersPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        let hsts = resp
            .headers
            .get("Strict-Transport-Security")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(hsts.contains("max-age=31536000"));
    }

    #[test]
    fn adds_x_frame_options() {
        let config = SecurityHeadersConfig {
            x_frame_options: Some("DENY".into()),
            ..Default::default()
        };
        let plugin = SecurityHeadersPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(
            resp.headers
                .get("X-Frame-Options")
                .unwrap()
                .to_str()
                .unwrap(),
            "DENY"
        );
    }

    #[test]
    fn adds_content_type_options() {
        let config = SecurityHeadersConfig {
            x_content_type_options: true,
            ..Default::default()
        };
        let plugin = SecurityHeadersPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        assert_eq!(
            resp.headers
                .get("X-Content-Type-Options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn default_config_adds_nothing() {
        let config = SecurityHeadersConfig::default();
        let plugin = SecurityHeadersPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        assert!(resp.headers.get("Strict-Transport-Security").is_none());
    }
}
