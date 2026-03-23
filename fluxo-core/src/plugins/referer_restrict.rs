//! Referer restriction plugin — allow/deny requests based on the Referer header domain.

use serde::Deserialize;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// Referer restriction configuration.
#[derive(Debug, Deserialize)]
pub struct RefererRestrictConfig {
    /// Allowed referer domains. Wildcard prefix supported: "*.example.com".
    /// Empty = no allow list (all referers pass unless denied).
    #[serde(default)]
    pub allow: Vec<String>,

    /// Denied referer domains. Wildcard prefix supported: "*.example.com".
    #[serde(default)]
    pub deny: Vec<String>,

    /// Whether to allow requests with no Referer header. Default: true.
    #[serde(default = "default_allow_empty")]
    pub allow_empty: bool,
}

fn default_allow_empty() -> bool {
    true
}

/// Referer restriction plugin.
#[derive(Debug)]
pub struct RefererRestrictPlugin {
    allow: Vec<RefererPattern>,
    deny: Vec<RefererPattern>,
    allow_empty: bool,
}

#[derive(Debug)]
enum RefererPattern {
    Exact(String),
    WildcardSuffix(String), // *.example.com → matches any subdomain
}

impl RefererPattern {
    fn parse(pattern: &str) -> Self {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            Self::WildcardSuffix(suffix.to_lowercase())
        } else {
            Self::Exact(pattern.to_lowercase())
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        match self {
            Self::Exact(pattern) => domain == *pattern,
            Self::WildcardSuffix(suffix) => {
                domain.ends_with(suffix)
                    && domain.len() > suffix.len()
                    && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            }
        }
    }
}

impl RefererRestrictPlugin {
    pub fn new(cfg: RefererRestrictConfig) -> Self {
        Self {
            allow: cfg.allow.iter().map(|p| RefererPattern::parse(p)).collect(),
            deny: cfg.deny.iter().map(|p| RefererPattern::parse(p)).collect(),
            allow_empty: cfg.allow_empty,
        }
    }

    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let referer = req.headers.get("referer").and_then(|v| v.to_str().ok());

        let domain = match referer {
            None | Some("") => {
                if self.allow_empty {
                    return PluginAction::Continue;
                }
                ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
                return PluginAction::Handled(403);
            }
            Some(referer_url) => extract_domain(referer_url),
        };

        let Some(domain) = domain else {
            if self.allow_empty {
                return PluginAction::Continue;
            }
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return PluginAction::Handled(403);
        };

        // Check deny list first
        if self.deny.iter().any(|p| p.matches(&domain)) {
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return PluginAction::Handled(403);
        }

        // Check allow list (if non-empty, acts as whitelist)
        if !self.allow.is_empty() && !self.allow.iter().any(|p| p.matches(&domain)) {
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
            return PluginAction::Handled(403);
        }

        PluginAction::Continue
    }
}

/// Extract the domain from a URL string (e.g., "<https://example.com/path>" → "example.com").
fn extract_domain(url: &str) -> Option<String> {
    // Strip scheme
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Take everything before the first '/' or ':'
    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn exact_match_allows() {
        let plugin = RefererRestrictPlugin::new(RefererRestrictConfig {
            allow: vec!["example.com".to_string()],
            deny: vec![],
            allow_empty: true,
        });
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("referer", "https://example.com/page")
            .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn wildcard_match_allows() {
        let plugin = RefererRestrictPlugin::new(RefererRestrictConfig {
            allow: vec!["*.example.com".to_string()],
            deny: vec![],
            allow_empty: true,
        });
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("referer", "https://sub.example.com/page")
            .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn deny_list_blocks() {
        let plugin = RefererRestrictPlugin::new(RefererRestrictConfig {
            allow: vec![],
            deny: vec!["evil.com".to_string()],
            allow_empty: true,
        });
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("referer", "https://evil.com/attack")
            .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn empty_referer_allowed_by_default() {
        let plugin = RefererRestrictPlugin::new(RefererRestrictConfig {
            allow: vec!["example.com".to_string()],
            deny: vec![],
            allow_empty: true,
        });
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn empty_referer_blocked_when_configured() {
        let plugin = RefererRestrictPlugin::new(RefererRestrictConfig {
            allow: vec!["example.com".to_string()],
            deny: vec![],
            allow_empty: false,
        });
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn extract_domain_https() {
        assert_eq!(
            extract_domain("https://example.com/page"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn extract_domain_with_port() {
        assert_eq!(
            extract_domain("http://example.com:8080/page"),
            Some("example.com".to_string())
        );
    }
}
