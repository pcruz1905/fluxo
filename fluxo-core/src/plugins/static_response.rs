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

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        let mut info = format!("static:{}", self.config.status);
        if let Some(ref ct) = self.config.content_type {
            info.push_str(&format!("|ct:{ct}"));
        }
        if let Some(ref body) = self.config.body {
            info.push_str(&format!("|body:{body}"));
        }
        ctx.error_message = Some(info);
        super::PluginAction::Handled(self.config.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_configured_status() {
        let config = StaticResponseConfig {
            status: 200,
            body: Some("OK".into()),
            content_type: None,
        };
        let plugin = StaticResponsePlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/health", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Handled(200)
        );
    }

    #[test]
    fn maintenance_mode_returns_503() {
        let config = StaticResponseConfig {
            status: 503,
            body: Some("Service temporarily unavailable".into()),
            content_type: Some("text/plain".into()),
        };
        let plugin = StaticResponsePlugin::new(config);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Handled(503)
        );
    }
}
