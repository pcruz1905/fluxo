//! Request buffering plugin — buffer request bodies before forwarding.
//!
//! Enables retries with the original request body by buffering it in memory.
//! Traefik equivalent: `Buffering` middleware.
//! Nginx equivalent: `proxy_request_buffering`.

use serde::Deserialize;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// Configuration for request buffering.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestBufferConfig {
    /// Maximum request body size to buffer in bytes.
    /// Requests exceeding this are rejected with 413.
    /// Default: 1048576 (1 MB). Set to 0 for unlimited.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,

    /// Memory threshold — bodies larger than this spill context info only.
    /// The actual buffering is advisory (sets context flag for retry logic).
    /// Default: 1048576 (1 MB).
    #[serde(default = "default_mem_bytes")]
    pub mem_body_bytes: u64,
}

fn default_max_body_bytes() -> u64 {
    1_048_576
}

fn default_mem_bytes() -> u64 {
    1_048_576
}

/// Request buffering plugin.
#[derive(Debug)]
pub struct RequestBufferPlugin {
    max_body_bytes: u64,
}

impl RequestBufferPlugin {
    pub fn new(config: &RequestBufferConfig) -> Self {
        Self {
            max_body_bytes: config.max_body_bytes,
        }
    }

    /// On request phase — set buffering flag in context.
    /// The actual body buffering is handled by Pingora's request body reading.
    /// This plugin sets the max body size limit which is enforced during proxying.
    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        // Store the buffering limit in context for enforcement during body read
        ctx.request_buffer_max_bytes = Some(self.max_body_bytes);
        PluginAction::Continue
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn sets_buffer_limit_in_context() {
        let cfg = RequestBufferConfig {
            max_body_bytes: 2048,
            mem_body_bytes: 1024,
        };
        let plugin = RequestBufferPlugin::new(&cfg);
        let req = pingora_http::RequestHeader::build("POST", b"/upload", None).unwrap();
        let mut ctx = RequestContext::new();
        assert!(ctx.request_buffer_max_bytes.is_none());
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Continue);
        assert_eq!(ctx.request_buffer_max_bytes, Some(2048));
    }

    #[test]
    fn zero_means_unlimited() {
        let cfg = RequestBufferConfig {
            max_body_bytes: 0,
            mem_body_bytes: 0,
        };
        let plugin = RequestBufferPlugin::new(&cfg);
        let req = pingora_http::RequestHeader::build("POST", b"/upload", None).unwrap();
        let mut ctx = RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Continue);
        assert_eq!(ctx.request_buffer_max_bytes, Some(0));
    }

    #[test]
    fn default_config_values() {
        let cfg: RequestBufferConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.max_body_bytes, 1_048_576);
        assert_eq!(cfg.mem_body_bytes, 1_048_576);
    }
}
