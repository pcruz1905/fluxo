//! Add prefix plugin — prepend a path prefix before forwarding to upstream.
//!
//! Equivalent to Traefik's AddPrefix middleware.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AddPrefixConfig {
    /// The prefix to prepend to every request path.
    pub prefix: String,
}

#[derive(Debug)]
pub struct AddPrefixPlugin {
    pub config: AddPrefixConfig,
}

impl AddPrefixPlugin {
    pub fn new(config: AddPrefixConfig) -> Self {
        Self { config }
    }

    pub fn on_upstream_request(
        &self,
        req: &mut pingora_http::RequestHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        let path = req.uri.path();
        let new_path = format!("{}{}", self.config.prefix, path);

        let new_uri = if let Some(query) = req.uri.query() {
            format!("{new_path}?{query}")
        } else {
            new_path
        };

        if let Ok(uri) = new_uri.parse() {
            req.set_uri(uri);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::context::RequestContext;

    #[test]
    fn add_prefix_to_path() {
        let config = AddPrefixConfig {
            prefix: "/api/v2".to_string(),
        };
        let plugin = AddPrefixPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/users", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/api/v2/users");
    }

    #[test]
    fn add_prefix_to_root() {
        let config = AddPrefixConfig {
            prefix: "/internal".to_string(),
        };
        let plugin = AddPrefixPlugin::new(config);
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let ctx = RequestContext::new();

        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(req.uri.path(), "/internal/");
    }
}
