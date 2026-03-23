//! User-Agent restriction plugin — allow/deny requests based on User-Agent header.

use regex::Regex;
use serde::Deserialize;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// User-Agent restriction configuration.
#[derive(Debug, Deserialize)]
pub struct UaRestrictConfig {
    /// Allowed User-Agent regex patterns. Empty = no allow filter.
    #[serde(default)]
    pub allow: Vec<String>,

    /// Denied User-Agent regex patterns.
    #[serde(default)]
    pub deny: Vec<String>,

    /// Whether to allow requests with no User-Agent header. Default: true.
    #[serde(default = "default_allow_empty")]
    pub allow_empty: bool,
}

fn default_allow_empty() -> bool {
    true
}

/// User-Agent restriction plugin.
#[derive(Debug)]
pub struct UaRestrictPlugin {
    allow: Vec<Regex>,
    deny: Vec<Regex>,
    allow_empty: bool,
}

impl UaRestrictPlugin {
    pub fn try_new(cfg: &UaRestrictConfig) -> Result<Self, String> {
        let allow = cfg
            .allow
            .iter()
            .map(|p| Regex::new(p).map_err(|e| format!("invalid allow regex '{p}': {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let deny = cfg
            .deny
            .iter()
            .map(|p| Regex::new(p).map_err(|e| format!("invalid deny regex '{p}': {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            allow,
            deny,
            allow_empty: cfg.allow_empty,
        })
    }

    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let ua = req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if ua.is_empty() {
            if self.allow_empty {
                return PluginAction::Continue;
            }
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return PluginAction::Handled(403);
        }

        // Check deny list first
        if self.deny.iter().any(|r| r.is_match(ua)) {
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return PluginAction::Handled(403);
        }

        // Check allow list (if non-empty, acts as whitelist)
        if !self.allow.is_empty() && !self.allow.iter().any(|r| r.is_match(ua)) {
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return PluginAction::Handled(403);
        }

        PluginAction::Continue
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn allow_matching_ua() {
        let plugin = UaRestrictPlugin::try_new(&UaRestrictConfig {
            allow: vec!["^Mozilla".to_string()],
            deny: vec![],
            allow_empty: true,
        })
        .unwrap();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("user-agent", "Mozilla/5.0").unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn deny_matching_ua() {
        let plugin = UaRestrictPlugin::try_new(&UaRestrictConfig {
            allow: vec![],
            deny: vec!["(?i)bot".to_string()],
            allow_empty: true,
        })
        .unwrap();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("user-agent", "Googlebot/2.1").unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Handled(403));
    }

    #[test]
    fn empty_ua_allowed_by_default() {
        let plugin = UaRestrictPlugin::try_new(&UaRestrictConfig {
            allow: vec![],
            deny: vec!["bot".to_string()],
            allow_empty: true,
        })
        .unwrap();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn invalid_regex_returns_error() {
        let result = UaRestrictPlugin::try_new(&UaRestrictConfig {
            allow: vec!["[invalid".to_string()],
            deny: vec![],
            allow_empty: true,
        });
        assert!(result.is_err());
    }
}
