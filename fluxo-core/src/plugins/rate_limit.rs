//! Rate limiting plugin — token bucket per route/IP.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per second.
    pub requests_per_second: u32,
    /// Burst capacity (max requests allowed in a burst).
    pub burst: u32,
}

#[derive(Debug)]
pub struct RateLimitPlugin {
    pub config: RateLimitConfig,
}

impl RateLimitPlugin {
    pub fn new(config: RateLimitConfig) -> Self {
        Self { config }
    }

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        _ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        super::PluginAction::Continue // TODO: implement in Task 11
    }
}
