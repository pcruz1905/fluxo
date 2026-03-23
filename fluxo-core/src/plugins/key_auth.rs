//! API key authentication plugin — validates API keys from header or query parameter.

use serde::Deserialize;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// API key authentication configuration.
#[derive(Debug, Deserialize)]
pub struct KeyAuthConfig {
    /// Valid API keys.
    pub keys: Vec<String>,

    /// Where to look for the key. Default: "header".
    /// Valid: "header", "query".
    #[serde(default = "default_key_source")]
    pub key_source: String,

    /// Header name when `key_source = "header"`. Default: "X-API-Key".
    #[serde(default = "default_header_name")]
    pub header_name: String,

    /// Query parameter name when `key_source = "query"`. Default: "`api_key`".
    #[serde(default = "default_query_param")]
    pub query_param: String,

    /// Remove the key from the request before forwarding to upstream. Default: false.
    #[serde(default)]
    pub hide_credentials: bool,
}

fn default_key_source() -> String {
    "header".to_string()
}
fn default_header_name() -> String {
    "X-API-Key".to_string()
}
fn default_query_param() -> String {
    "api_key".to_string()
}

/// API key authentication plugin.
#[derive(Debug)]
pub struct KeyAuthPlugin {
    keys: std::collections::HashSet<String>,
    key_source: KeySource,
    header_name: String,
    query_param: String,
    hide_credentials: bool,
}

#[derive(Debug, Clone, Copy)]
enum KeySource {
    Header,
    Query,
}

impl KeyAuthPlugin {
    pub fn try_new(cfg: KeyAuthConfig) -> Result<Self, String> {
        if cfg.keys.is_empty() {
            return Err("key_auth.keys must not be empty".to_string());
        }
        let key_source = match cfg.key_source.as_str() {
            "header" => KeySource::Header,
            "query" => KeySource::Query,
            other => {
                return Err(format!(
                    "unsupported key_source: {other} (valid: header, query)"
                ));
            }
        };
        Ok(Self {
            keys: cfg.keys.into_iter().collect(),
            key_source,
            header_name: cfg.header_name,
            query_param: cfg.query_param,
            hide_credentials: cfg.hide_credentials,
        })
    }

    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let Some(key) = self.extract_key(req) else {
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 401 });
            return PluginAction::Handled(401);
        };

        if self.keys.contains(&key) {
            PluginAction::Continue
        } else {
            ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 401 });
            PluginAction::Handled(401)
        }
    }

    pub fn on_upstream_request(
        &self,
        upstream_req: &mut pingora_http::RequestHeader,
        _ctx: &crate::context::RequestContext,
    ) {
        if !self.hide_credentials {
            return;
        }
        match self.key_source {
            KeySource::Header => {
                upstream_req.remove_header(&self.header_name);
            }
            KeySource::Query => {
                // Strip the API key query parameter from the URI
                let uri = &upstream_req.uri;
                if let Some(query) = uri.query() {
                    let filtered: Vec<&str> = query
                        .split('&')
                        .filter(|pair| {
                            pair.split_once('=')
                                .is_none_or(|(k, _)| k != self.query_param)
                        })
                        .collect();
                    let new_query = if filtered.is_empty() {
                        String::new()
                    } else {
                        format!("?{}", filtered.join("&"))
                    };
                    let path = uri.path();
                    let new_uri = format!("{path}{new_query}");
                    if let Ok(uri) = new_uri.parse() {
                        upstream_req.set_uri(uri);
                    }
                }
            }
        }
    }

    fn extract_key(&self, req: &pingora_http::RequestHeader) -> Option<String> {
        match self.key_source {
            KeySource::Header => req
                .headers
                .get(&self.header_name)
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            KeySource::Query => {
                let query = req.uri.query()?;
                for pair in query.split('&') {
                    if let Some((key, value)) = pair.split_once('=') {
                        if key == self.query_param {
                            return Some(
                                percent_encoding::percent_decode_str(value)
                                    .decode_utf8_lossy()
                                    .into_owned(),
                            );
                        }
                    }
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_plugin() -> KeyAuthPlugin {
        KeyAuthPlugin::try_new(KeyAuthConfig {
            keys: vec!["valid-key-123".to_string()],
            key_source: "header".to_string(),
            header_name: "X-API-Key".to_string(),
            query_param: "api_key".to_string(),
            hide_credentials: false,
        })
        .unwrap()
    }

    #[test]
    fn empty_keys_rejected() {
        let result = KeyAuthPlugin::try_new(KeyAuthConfig {
            keys: vec![],
            key_source: "header".to_string(),
            header_name: "X-API-Key".to_string(),
            query_param: "api_key".to_string(),
            hide_credentials: false,
        });
        assert!(result.is_err());
    }

    #[test]
    fn missing_key_returns_401() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(401)
        );
    }

    #[test]
    fn valid_key_passes() {
        let plugin = make_plugin();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-API-Key", "valid-key-123").unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn invalid_key_returns_401() {
        let plugin = make_plugin();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-API-Key", "wrong-key").unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(401)
        );
    }
}
