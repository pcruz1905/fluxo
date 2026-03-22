//! Bandwidth throttling plugin — limits response body transfer rate.
//!
//! Sets a per-request byte rate limit. The proxy's body filter uses this
//! to pace response chunk delivery. Nginx equivalent: `limit_rate`.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct BandwidthLimitConfig {
    /// Maximum bytes per second for response body delivery.
    /// Example: `1048576` for 1 MB/s. Supports human-readable: parsed as raw number.
    pub bytes_per_second: u64,
}

#[derive(Debug)]
pub struct BandwidthLimitPlugin {
    bytes_per_second: u64,
}

impl BandwidthLimitPlugin {
    pub fn new(config: &BandwidthLimitConfig) -> Self {
        Self {
            bytes_per_second: config.bytes_per_second.max(1),
        }
    }

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        ctx.bandwidth_limit_bps = Some(self.bytes_per_second);
        super::PluginAction::Continue
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn sets_bandwidth_limit_on_context() {
        let config = BandwidthLimitConfig {
            bytes_per_second: 1024,
        };
        let plugin = BandwidthLimitPlugin::new(&config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert!(ctx.bandwidth_limit_bps.is_none());
        plugin.on_request(&req, &mut ctx);
        assert_eq!(ctx.bandwidth_limit_bps, Some(1024));
    }

    #[test]
    fn minimum_one_byte_per_second() {
        let config = BandwidthLimitConfig {
            bytes_per_second: 0,
        };
        let plugin = BandwidthLimitPlugin::new(&config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        plugin.on_request(&req, &mut ctx);
        assert_eq!(ctx.bandwidth_limit_bps, Some(1));
    }
}
