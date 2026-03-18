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

    /// Validate the redirect status code during config compilation.
    pub fn validate_status(status: u16) -> bool {
        matches!(status, 301 | 302 | 307 | 308)
    }

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        let url = self
            .config
            .url
            .replace("{path}", ctx.path.as_deref().unwrap_or("/"))
            .replace("{host}", ctx.host.as_deref().unwrap_or(""));

        ctx.plugin_response = Some(crate::context::PluginResponse::Redirect {
            status: self.config.status,
            location: url,
        });
        super::PluginAction::Handled(self.config.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_redirect_returns_handled_301() {
        let config = RedirectConfig {
            url: "https://new.example.com{path}".into(),
            status: 301,
        };
        let plugin = RedirectPlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/old", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        ctx.path = Some("/old".into());
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, super::super::PluginAction::Handled(301));
        match &ctx.plugin_response {
            Some(crate::context::PluginResponse::Redirect { location, .. }) => {
                assert_eq!(location, "https://new.example.com/old");
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[test]
    fn temporary_redirect_returns_handled_302() {
        let config = RedirectConfig {
            url: "/new-path".into(),
            status: 302,
        };
        let plugin = RedirectPlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/old", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        ctx.path = Some("/old".into());
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, super::super::PluginAction::Handled(302));
    }

    #[test]
    fn validates_redirect_status_codes() {
        assert!(RedirectPlugin::validate_status(301));
        assert!(RedirectPlugin::validate_status(302));
        assert!(RedirectPlugin::validate_status(307));
        assert!(RedirectPlugin::validate_status(308));
        assert!(!RedirectPlugin::validate_status(200));
        assert!(!RedirectPlugin::validate_status(500));
    }
}
