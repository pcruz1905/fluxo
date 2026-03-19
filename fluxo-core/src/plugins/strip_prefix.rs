//! Strip prefix plugin — remove path prefix before forwarding to upstream.
//!
//! Equivalent to Traefik's `StripPrefix` middleware and nginx's rewrite.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct StripPrefixConfig {
    /// Prefixes to strip (first match wins).
    pub prefixes: Vec<String>,
    /// Whether to add X-Forwarded-Prefix header. Default: true.
    #[serde(default = "default_forward_prefix")]
    pub forward_prefix: bool,
}

fn default_forward_prefix() -> bool {
    true
}

#[derive(Debug)]
pub struct StripPrefixPlugin {
    pub config: StripPrefixConfig,
}

impl StripPrefixPlugin {
    pub fn new(config: StripPrefixConfig) -> Self {
        Self { config }
    }

    pub fn on_upstream_request(
        &self,
        req: &mut pingora_http::RequestHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        let path = req.uri.path().to_string();

        for prefix in &self.config.prefixes {
            if let Some(stripped) = path.strip_prefix(prefix.as_str()) {
                // Boundary check: prefix must end at a path segment boundary.
                // "/stat" should NOT strip from "/status" — only from "/stat" or "/stat/..."
                if !stripped.is_empty() && !stripped.starts_with('/') {
                    continue;
                }

                let new_path = if stripped.is_empty() {
                    "/".to_string()
                } else {
                    stripped.to_string()
                };

                if self.config.forward_prefix {
                    let _ = req.insert_header("X-Forwarded-Prefix", prefix.as_str());
                }

                let new_uri = if let Some(query) = req.uri.query() {
                    format!("{new_path}?{query}")
                } else {
                    new_path
                };

                if let Ok(uri) = new_uri.parse() {
                    req.set_uri(uri);
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::context::RequestContext;

    #[test]
    fn strip_prefix_from_path() {
        let config = StripPrefixConfig {
            prefixes: vec!["/api/v1".to_string()],
            forward_prefix: true,
        };
        let plugin = StripPrefixPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/v1/users", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/users");
        assert_eq!(
            req.headers
                .get("X-Forwarded-Prefix")
                .unwrap()
                .to_str()
                .unwrap(),
            "/api/v1"
        );
    }

    #[test]
    fn strip_prefix_root_path() {
        let config = StripPrefixConfig {
            prefixes: vec!["/api".to_string()],
            forward_prefix: false,
        };
        let plugin = StripPrefixPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/api", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/");
        assert!(req.headers.get("X-Forwarded-Prefix").is_none());
    }

    #[test]
    fn strip_prefix_first_match_wins() {
        let config = StripPrefixConfig {
            prefixes: vec!["/api/v1".to_string(), "/api".to_string()],
            forward_prefix: true,
        };
        let plugin = StripPrefixPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/v1/items", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/items");
    }

    #[test]
    fn strip_prefix_respects_path_boundary() {
        // "/stat" should NOT strip from "/status" (Traefik behavior)
        let config = StripPrefixConfig {
            prefixes: vec!["/stat".to_string()],
            forward_prefix: true,
        };
        let plugin = StripPrefixPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/status", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/status"); // unchanged — not a boundary match
    }

    #[test]
    fn strip_prefix_matches_at_boundary() {
        // "/stat" SHOULD strip from "/stat/us" (boundary at "/")
        let config = StripPrefixConfig {
            prefixes: vec!["/stat".to_string()],
            forward_prefix: false,
        };
        let plugin = StripPrefixPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/stat/us", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/us");
    }

    #[test]
    fn no_matching_prefix_leaves_path_unchanged() {
        let config = StripPrefixConfig {
            prefixes: vec!["/admin".to_string()],
            forward_prefix: true,
        };
        let plugin = StripPrefixPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/users", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/api/users");
    }
}
