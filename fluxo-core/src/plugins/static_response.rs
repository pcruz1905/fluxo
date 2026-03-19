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
        ctx.plugin_response = Some(crate::context::PluginResponse::Static {
            status: self.config.status,
            body: self.config.body.clone(),
            content_type: self.config.content_type.clone(),
        });
        super::PluginAction::Handled(self.config.status)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
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
        match &ctx.plugin_response {
            Some(crate::context::PluginResponse::Static { body, .. }) => {
                assert_eq!(body.as_deref(), Some("OK"));
            }
            other => panic!("expected Static, got {other:?}"),
        }
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
        match &ctx.plugin_response {
            Some(crate::context::PluginResponse::Static {
                status,
                body,
                content_type,
            }) => {
                assert_eq!(*status, 503);
                assert_eq!(body.as_deref(), Some("Service temporarily unavailable"));
                assert_eq!(content_type.as_deref(), Some("text/plain"));
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }
}
