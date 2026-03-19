//! Request ID plugin — inject unique request ID into upstream requests.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RequestIdConfig {
    /// Header name to inject (default: "X-Request-ID").
    #[serde(default = "default_header")]
    pub header: String,
}

fn default_header() -> String {
    "X-Request-ID".into()
}

impl Default for RequestIdConfig {
    fn default() -> Self {
        Self {
            header: default_header(),
        }
    }
}

#[derive(Debug)]
pub struct RequestIdPlugin {
    pub config: RequestIdConfig,
}

impl Default for RequestIdPlugin {
    fn default() -> Self {
        Self::new(RequestIdConfig::default())
    }
}

impl RequestIdPlugin {
    pub fn new(config: RequestIdConfig) -> Self {
        Self { config }
    }

    pub fn on_upstream_request(
        &self,
        req: &mut pingora_http::RequestHeader,
        ctx: &crate::context::RequestContext,
    ) {
        let _ = req.insert_header(self.config.header.clone(), ctx.request_id.to_string());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn injects_request_id_with_default_header() {
        let config = RequestIdConfig::default();
        let plugin = RequestIdPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        let value = req.headers.get("X-Request-ID").unwrap().to_str().unwrap();
        assert_eq!(value, ctx.request_id.to_string());
    }

    #[test]
    fn uses_custom_header_name() {
        let config = RequestIdConfig {
            header: "X-Trace-ID".into(),
        };
        let plugin = RequestIdPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let ctx = crate::context::RequestContext::new();
        plugin.on_upstream_request(&mut req, &ctx);
        assert!(req.headers.get("X-Trace-ID").is_some());
        assert!(req.headers.get("X-Request-ID").is_none());
    }
}
