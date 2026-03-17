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
        _req: &mut pingora_http::RequestHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        // TODO: implement in Task 8
    }
}
