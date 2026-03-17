//! Rate limiting plugin — token bucket per route/IP.

use std::num::NonZeroU32;
use std::sync::Arc;

use dashmap::DashMap;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::InMemoryState};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per second.
    pub requests_per_second: u32,
    /// Burst capacity (max requests allowed in a burst).
    pub burst: u32,
}

type Limiter = RateLimiter<governor::state::NotKeyed, InMemoryState, DefaultClock>;

pub struct RateLimitPlugin {
    /// Per-IP rate limiters.
    limiters: Arc<DashMap<String, Arc<Limiter>>>,
    quota: Quota,
}

impl std::fmt::Debug for RateLimitPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitPlugin")
            .field("quota", &self.quota)
            .finish()
    }
}

impl RateLimitPlugin {
    pub fn new(config: RateLimitConfig) -> Self {
        let burst = NonZeroU32::new(config.burst.max(1)).unwrap();
        let rps = NonZeroU32::new(config.requests_per_second.max(1)).unwrap();
        let quota = Quota::per_second(rps).allow_burst(burst);
        Self {
            limiters: Arc::new(DashMap::new()),
            quota,
        }
    }

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        let key = ctx.client_ip.as_deref().unwrap_or("unknown").to_string();

        let limiter = self
            .limiters
            .entry(key)
            .or_insert_with(|| Arc::new(RateLimiter::direct(self.quota)))
            .clone();

        match limiter.check() {
            Ok(_) => super::PluginAction::Continue,
            Err(_) => super::PluginAction::Handled(429),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_within_limit() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst: 10,
        };
        let plugin = RateLimitPlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        ctx.client_ip = Some("10.0.0.1".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Continue
        );
    }

    #[test]
    fn blocks_when_burst_exceeded() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst: 1,
        };
        let plugin = RateLimitPlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        // First request should pass
        let mut ctx = crate::context::RequestContext::new();
        ctx.client_ip = Some("10.0.0.1".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Continue
        );

        // Second request should be rate limited
        let mut ctx2 = crate::context::RequestContext::new();
        ctx2.client_ip = Some("10.0.0.1".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx2),
            super::super::PluginAction::Handled(429)
        );
    }

    #[test]
    fn different_ips_have_separate_limits() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst: 1,
        };
        let plugin = RateLimitPlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        // IP A uses its quota
        let mut ctx1 = crate::context::RequestContext::new();
        ctx1.client_ip = Some("10.0.0.1".into());
        plugin.on_request(&req, &mut ctx1);

        // IP B should still have its own quota
        let mut ctx2 = crate::context::RequestContext::new();
        ctx2.client_ip = Some("10.0.0.2".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx2),
            super::super::PluginAction::Continue
        );
    }

    #[test]
    fn no_client_ip_uses_fallback_key() {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst: 1,
        };
        let plugin = RateLimitPlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Continue
        );
    }
}
