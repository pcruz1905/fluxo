//! Static response plugin — fixed responses for health checks, maintenance pages.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct StaticResponseConfig {
    /// HTTP status code to return.
    pub status: u16,
    /// Response body.
    pub body: Option<String>,
    /// Content-Type header value.
    pub content_type: Option<String>,
}

#[derive(Debug)]
pub struct StaticResponsePlugin {
    pub config: StaticResponseConfig,
}

impl StaticResponsePlugin {
    pub fn new(config: StaticResponseConfig) -> Self {
        Self { config }
    }
}
