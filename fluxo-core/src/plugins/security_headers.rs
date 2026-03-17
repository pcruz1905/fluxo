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
        _resp: &mut pingora_http::ResponseHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        // TODO: implement in Task 6
    }
}
