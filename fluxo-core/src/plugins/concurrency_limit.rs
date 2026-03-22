//! Concurrency (in-flight) request limiting plugin.
//!
//! Limits the number of concurrent in-flight requests per client IP.
//! Uses a bounded cache of semaphore permits per IP, similar to `rate_limit`.
//! Returns 503 Service Unavailable when the concurrency limit is exceeded.

use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use serde::Deserialize;
use tokio::sync::Semaphore;

#[derive(Debug, Deserialize)]
pub struct ConcurrencyLimitConfig {
    /// Maximum concurrent in-flight requests per client IP.
    pub max_connections: u32,
    /// Maximum number of unique keys (IPs) to track. Default: `10_000`.
    #[serde(default = "default_max_keys")]
    pub max_keys: u64,
}

fn default_max_keys() -> u64 {
    10_000
}

pub struct ConcurrencyLimitPlugin {
    /// Per-IP semaphores with TTL eviction and bounded size.
    semaphores: Cache<String, Arc<Semaphore>>,
    max_connections: u32,
}

impl std::fmt::Debug for ConcurrencyLimitPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrencyLimitPlugin")
            .field("max_connections", &self.max_connections)
            .finish_non_exhaustive()
    }
}

impl ConcurrencyLimitPlugin {
    pub fn new(config: &ConcurrencyLimitConfig) -> Self {
        let max = config.max_connections.max(1);
        let semaphores = Cache::builder()
            .max_capacity(config.max_keys)
            .time_to_idle(Duration::from_secs(300))
            .build();
        Self {
            semaphores,
            max_connections: max,
        }
    }

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        let key = ctx.client_ip.as_deref().unwrap_or("unknown").to_string();
        let max = self.max_connections;
        let sem = self
            .semaphores
            .get_with(key, || Arc::new(Semaphore::new(max as usize)));

        if let Ok(permit) = sem.try_acquire_owned() {
            // Permit is held for the request's lifetime.
            // Dropped when the context is dropped (end of request).
            ctx.concurrency_permit = Some(permit);
            super::PluginAction::Continue
        } else {
            ctx.plugin_response =
                Some(crate::context::PluginResponse::Error { status: 503 });
            super::PluginAction::Handled(503)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn allows_requests_within_limit() {
        let config = ConcurrencyLimitConfig {
            max_connections: 2,
            max_keys: 100,
        };
        let plugin = ConcurrencyLimitPlugin::new(&config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        let mut ctx = crate::context::RequestContext::new();
        ctx.client_ip = Some("10.0.0.1".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Continue
        );
    }

    #[test]
    fn blocks_when_limit_exceeded() {
        let config = ConcurrencyLimitConfig {
            max_connections: 1,
            max_keys: 100,
        };
        let plugin = ConcurrencyLimitPlugin::new(&config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        // First request — should pass and hold permit
        let mut ctx1 = crate::context::RequestContext::new();
        ctx1.client_ip = Some("10.0.0.1".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx1),
            super::super::PluginAction::Continue
        );

        // Second request from same IP — should be rejected (permit still held by ctx1)
        let mut ctx2 = crate::context::RequestContext::new();
        ctx2.client_ip = Some("10.0.0.1".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx2),
            super::super::PluginAction::Handled(503)
        );
    }

    #[test]
    fn different_ips_have_separate_limits() {
        let config = ConcurrencyLimitConfig {
            max_connections: 1,
            max_keys: 100,
        };
        let plugin = ConcurrencyLimitPlugin::new(&config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        // IP A uses its slot
        let mut ctx1 = crate::context::RequestContext::new();
        ctx1.client_ip = Some("10.0.0.1".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx1),
            super::super::PluginAction::Continue
        );

        // IP B should have its own limit
        let mut ctx2 = crate::context::RequestContext::new();
        ctx2.client_ip = Some("10.0.0.2".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx2),
            super::super::PluginAction::Continue
        );
    }

    #[test]
    fn permit_released_on_drop() {
        let config = ConcurrencyLimitConfig {
            max_connections: 1,
            max_keys: 100,
        };
        let plugin = ConcurrencyLimitPlugin::new(&config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();

        {
            let mut ctx = crate::context::RequestContext::new();
            ctx.client_ip = Some("10.0.0.1".into());
            assert_eq!(
                plugin.on_request(&req, &mut ctx),
                super::super::PluginAction::Continue
            );
            // ctx dropped here, releasing permit
        }

        // Should be allowed again
        let mut ctx2 = crate::context::RequestContext::new();
        ctx2.client_ip = Some("10.0.0.1".into());
        assert_eq!(
            plugin.on_request(&req, &mut ctx2),
            super::super::PluginAction::Continue
        );
    }
}
