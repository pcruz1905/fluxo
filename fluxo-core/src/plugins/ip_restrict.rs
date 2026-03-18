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
    deny: Vec<ipnet::IpNet>,
    allow: Vec<ipnet::IpNet>,
}

impl IpRestrictPlugin {
    /// Create a new IP restrict plugin. Returns Err if any CIDR fails to parse.
    pub fn try_new(config: IpRestrictConfig) -> Result<Self, String> {
        let mut deny = Vec::with_capacity(config.deny.len());
        for s in &config.deny {
            deny.push(
                s.parse::<ipnet::IpNet>()
                    .map_err(|e| format!("invalid deny CIDR '{s}': {e}"))?,
            );
        }
        let mut allow = Vec::with_capacity(config.allow.len());
        for s in &config.allow {
            allow.push(
                s.parse::<ipnet::IpNet>()
                    .map_err(|e| format!("invalid allow CIDR '{s}': {e}"))?,
            );
        }
        Ok(Self { deny, allow })
    }

    pub fn on_request(
        &self,
        _req: &pingora_http::RequestHeader,
        ctx: &mut crate::context::RequestContext,
    ) -> super::PluginAction {
        let ip = match ctx
            .client_ip
            .as_deref()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        {
            Some(ip) => ip,
            None => {
                if !self.allow.is_empty() {
                    ctx.plugin_response =
                        Some(crate::context::PluginResponse::Error { status: 403 });
                    return super::PluginAction::Handled(403);
                }
                return super::PluginAction::Continue;
            }
        };

        // Check deny list first
        if self.deny.iter().any(|net| net.contains(&ip)) {
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return super::PluginAction::Handled(403);
        }

        // If allow list is present, only matching IPs pass
        if !self.allow.is_empty() && !self.allow.iter().any(|net| net.contains(&ip)) {
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return super::PluginAction::Handled(403);
        }

        super::PluginAction::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_list_blocks_matching_ip() {
        let config = IpRestrictConfig {
            deny: vec!["192.168.1.0/24".into()],
            allow: vec![],
        };
        let plugin = IpRestrictPlugin::try_new(config).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        ctx.client_ip = Some("192.168.1.50".into());
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Handled(403)
        );
    }

    #[test]
    fn deny_list_allows_non_matching_ip() {
        let config = IpRestrictConfig {
            deny: vec!["192.168.1.0/24".into()],
            allow: vec![],
        };
        let plugin = IpRestrictPlugin::try_new(config).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        ctx.client_ip = Some("10.0.0.1".into());
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Continue
        );
    }

    #[test]
    fn allow_list_blocks_non_matching_ip() {
        let config = IpRestrictConfig {
            deny: vec![],
            allow: vec!["10.0.0.0/8".into()],
        };
        let plugin = IpRestrictPlugin::try_new(config).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        ctx.client_ip = Some("192.168.1.1".into());
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Handled(403)
        );
    }

    #[test]
    fn allow_list_permits_matching_ip() {
        let config = IpRestrictConfig {
            deny: vec![],
            allow: vec!["10.0.0.0/8".into()],
        };
        let plugin = IpRestrictPlugin::try_new(config).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        ctx.client_ip = Some("10.1.2.3".into());
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Continue
        );
    }

    #[test]
    fn missing_client_ip_is_denied_when_allow_list_present() {
        let config = IpRestrictConfig {
            deny: vec![],
            allow: vec!["10.0.0.0/8".into()],
        };
        let plugin = IpRestrictPlugin::try_new(config).unwrap();
        let mut ctx = crate::context::RequestContext::new();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            super::super::PluginAction::Handled(403)
        );
    }

    #[test]
    fn invalid_cidr_returns_error() {
        let config = IpRestrictConfig {
            deny: vec!["not-a-cidr".into()],
            allow: vec![],
        };
        let result = IpRestrictPlugin::try_new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid deny CIDR"));
    }
}
