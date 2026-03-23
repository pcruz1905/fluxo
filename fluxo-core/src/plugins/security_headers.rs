//! Security headers plugin — HSTS, X-Frame-Options, CSP, etc.

use serde::Deserialize;

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Deserialize)]
pub struct SecurityHeadersConfig {
    /// HSTS max-age in seconds. If set, adds Strict-Transport-Security header.
    pub hsts_max_age: Option<u64>,
    /// Include subdomains in HSTS.
    #[serde(default)]
    pub hsts_include_subdomains: bool,
    /// Add preload flag to HSTS header.
    #[serde(default)]
    pub hsts_preload: bool,
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
    /// `Expect-CT` max-age in seconds. If set, adds `Expect-CT` header.
    /// Informs browsers to enforce Certificate Transparency.
    pub expect_ct_max_age: Option<u64>,
    /// Add "enforce" directive to `Expect-CT`. Default: false.
    #[serde(default)]
    pub expect_ct_enforce: bool,
    /// Report URI for `Expect-CT` failures.
    pub expect_ct_report_uri: Option<String>,
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
            let mut value = format!("max-age={max_age}");
            if self.config.hsts_include_subdomains {
                value.push_str("; includeSubDomains");
            }
            if self.config.hsts_preload {
                value.push_str("; preload");
            }
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

        if let Some(max_age) = self.config.expect_ct_max_age {
            let value = crate::tls::ct::expect_ct_header(
                max_age,
                self.config.expect_ct_enforce,
                self.config.expect_ct_report_uri.as_deref(),
            );
            let _ = resp.insert_header("Expect-CT", &value);
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
    fn hsts_preload_flag_added() {
        let config = SecurityHeadersConfig {
            hsts_max_age: Some(31536000),
            hsts_include_subdomains: true,
            hsts_preload: true,
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
        assert!(hsts.contains("includeSubDomains"));
        assert!(hsts.contains("preload"));
    }

    #[test]
    fn adds_expect_ct_header() {
        let config = SecurityHeadersConfig {
            expect_ct_max_age: Some(86400),
            expect_ct_enforce: true,
            expect_ct_report_uri: Some("https://example.com/ct-report".to_string()),
            ..Default::default()
        };
        let plugin = SecurityHeadersPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        let ct = resp.headers.get("Expect-CT").unwrap().to_str().unwrap();
        assert!(ct.contains("max-age=86400"));
        assert!(ct.contains("enforce"));
        assert!(ct.contains("report-uri"));
    }

    #[test]
    fn expect_ct_basic() {
        let config = SecurityHeadersConfig {
            expect_ct_max_age: Some(3600),
            ..Default::default()
        };
        let plugin = SecurityHeadersPlugin::new(config);
        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_response(&mut resp, &mut ctx);
        let ct = resp.headers.get("Expect-CT").unwrap().to_str().unwrap();
        assert_eq!(ct, "max-age=3600");
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
