//! IP restriction plugin — CIDR-based allow/deny lists.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct IpRestrictConfig {
    /// CIDR ranges to deny (checked first).
    #[serde(default)]
    pub deny: Vec<String>,
    /// CIDR ranges to allow (if non-empty, all others are denied).
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug)]
pub struct IpRestrictPlugin {
    pub config: IpRestrictConfig,
}

impl IpRestrictPlugin {
    pub fn new(config: IpRestrictConfig) -> Self {
        Self { config }
    }

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        _ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        super::PluginAction::Continue // TODO: implement in Task 7
    }
}
