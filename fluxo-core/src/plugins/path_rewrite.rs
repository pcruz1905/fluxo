//! Path rewrite plugin — regex-based URL rewriting before forwarding to upstream.
//!
//! Equivalent to nginx's `rewrite` directive and Traefik's `ReplacePathRegex`.

use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PathRewriteConfig {
    /// Regex pattern to match against the request path.
    pub pattern: String,
    /// Replacement string. Supports capture group references like `$1`, `$2`.
    pub replacement: String,
}

#[derive(Debug)]
pub struct PathRewritePlugin {
    regex: Regex,
    replacement: String,
}

impl PathRewritePlugin {
    pub fn try_new(config: PathRewriteConfig) -> Result<Self, String> {
        let regex = Regex::new(&config.pattern)
            .map_err(|e| format!("invalid regex '{}': {}", config.pattern, e))?;
        Ok(Self {
            regex,
            replacement: config.replacement,
        })
    }

    pub fn on_upstream_request(
        &self,
        req: &mut pingora_http::RequestHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        let path = req.uri.path().to_string();
        let new_path = self.regex.replace(&path, &self.replacement);

        if new_path != path {
            // Preserve original path in X-Replaced-Path header (Traefik convention)
            let _ = req.insert_header("X-Replaced-Path", &path);

            let new_uri = req.uri.query().map_or_else(
                || new_path.to_string(),
                |query| format!("{new_path}?{query}"),
            );

            if let Ok(uri) = new_uri.parse() {
                req.set_uri(uri);
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
    fn rewrite_path_with_capture_groups() {
        let config = PathRewriteConfig {
            pattern: r"^/api/v1/(.*)".to_string(),
            replacement: "/v2/$1".to_string(),
        };
        let plugin = PathRewritePlugin::try_new(config).unwrap();
        let mut req =
            pingora_http::RequestHeader::build("GET", b"/api/v1/users/123", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/v2/users/123");
    }

    #[test]
    fn rewrite_path_simple_replacement() {
        let config = PathRewriteConfig {
            pattern: r"^/old-path".to_string(),
            replacement: "/new-path".to_string(),
        };
        let plugin = PathRewritePlugin::try_new(config).unwrap();
        let mut req =
            pingora_http::RequestHeader::build("GET", b"/old-path/resource", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/new-path/resource");
    }

    #[test]
    fn no_match_leaves_path_unchanged() {
        let config = PathRewriteConfig {
            pattern: r"^/admin/(.*)".to_string(),
            replacement: "/internal/$1".to_string(),
        };
        let plugin = PathRewritePlugin::try_new(config).unwrap();
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/users", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/api/users");
    }

    #[test]
    fn invalid_regex_returns_error() {
        let config = PathRewriteConfig {
            pattern: r"[invalid".to_string(),
            replacement: "".to_string(),
        };
        assert!(PathRewritePlugin::try_new(config).is_err());
    }

    #[test]
    fn rewrite_sets_x_replaced_path_header() {
        let config = PathRewriteConfig {
            pattern: r"^/api/v1/(.*)".to_string(),
            replacement: "/v2/$1".to_string(),
        };
        let plugin = PathRewritePlugin::try_new(config).unwrap();
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/v1/users", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/v2/users");
        assert_eq!(
            req.headers
                .get("X-Replaced-Path")
                .unwrap()
                .to_str()
                .unwrap(),
            "/api/v1/users"
        );
    }

    #[test]
    fn no_match_does_not_set_x_replaced_path() {
        let config = PathRewriteConfig {
            pattern: r"^/admin/(.*)".to_string(),
            replacement: "/internal/$1".to_string(),
        };
        let plugin = PathRewritePlugin::try_new(config).unwrap();
        let mut req = pingora_http::RequestHeader::build("GET", b"/api/users", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert!(req.headers.get("X-Replaced-Path").is_none());
    }

    #[test]
    fn rewrite_preserves_query_string() {
        let config = PathRewriteConfig {
            pattern: r"^/old".to_string(),
            replacement: "/new".to_string(),
        };
        let plugin = PathRewritePlugin::try_new(config).unwrap();
        let mut req =
            pingora_http::RequestHeader::build("GET", b"/old/page?key=value", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/new/page");
        assert_eq!(req.uri.query(), Some("key=value"));
    }
}
