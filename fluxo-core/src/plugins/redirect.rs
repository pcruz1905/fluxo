//! Redirect plugin — HTTP->HTTPS and path redirects.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RedirectConfig {
    /// Redirect URL. Supports `{path}` and `{host}` placeholders.
    pub url: String,
    /// HTTP status code (301, 302, 307, 308). Default: 301.
    #[serde(default = "default_status")]
    pub status: u16,
}

fn default_status() -> u16 {
    301
}

#[derive(Debug)]
pub struct RedirectPlugin {
    pub config: RedirectConfig,
}

impl RedirectPlugin {
    pub fn new(config: RedirectConfig) -> Self {
        Self { config }
    }

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        _ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        super::PluginAction::Continue // TODO: implement in Task 9
    }
}
