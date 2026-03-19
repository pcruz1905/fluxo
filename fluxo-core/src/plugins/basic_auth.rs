//! Basic authentication plugin.
//!
//! Implements HTTP Basic Auth (RFC 7617) — equivalent to nginx's `auth_basic` directive.
//!
//! Passwords can be stored as plain text (dev only) or SHA-256 hashed with a `{SHA256}` prefix.
//!
//! Example config:
//! ```toml
//! [routes.admin.plugins.basic_auth]
//! realm = "Admin Panel"
//! [routes.admin.plugins.basic_auth.users]
//! "admin" = "{SHA256}8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
//! "dev"   = "plaintext-pass"   # plain text only for development
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::context::{PluginResponse, RequestContext};
use crate::plugins::PluginAction;

/// Configuration for the basic auth plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    /// Map of `username → password`.
    ///
    /// Passwords can be:
    /// - Plain text: `"mypassword"` (development only — no protection against timing attacks)
    /// - SHA-256 hex: `"{SHA256}abcdef..."`
    pub users: HashMap<String, String>,

    /// WWW-Authenticate realm name shown in browser credential prompts.
    #[serde(default = "default_realm")]
    pub realm: String,
}

fn default_realm() -> String {
    "Protected".to_string()
}

/// The basic auth plugin.
#[derive(Debug)]
pub struct BasicAuthPlugin {
    users: HashMap<String, String>,
    realm: String,
}

impl BasicAuthPlugin {
    pub fn new(config: BasicAuthConfig) -> Self {
        Self {
            users: config.users,
            realm: config.realm,
        }
    }

    /// Check the incoming request for valid Basic credentials.
    ///
    /// Returns `Handled(401)` with a `BasicAuthChallenge` plugin response if
    /// the request is missing or has invalid credentials.
    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let authorized = req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|b64| {
                base64::engine::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    b64.trim(),
                )
                .ok()
            })
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .is_some_and(|creds| {
                // Split on first ':' — passwords may contain colons
                let colon = creds.find(':').unwrap_or(creds.len());
                let username = &creds[..colon];
                let password = if colon < creds.len() {
                    &creds[colon + 1..]
                } else {
                    ""
                };
                self.check_credentials(username, password)
            });

        if authorized {
            PluginAction::Continue
        } else {
            ctx.plugin_response = Some(PluginResponse::BasicAuthChallenge {
                realm: self.realm.clone(),
            });
            PluginAction::Handled(401)
        }
    }

    /// Verify username and password against the configured users map.
    fn check_credentials(&self, username: &str, password: &str) -> bool {
        self.users.get(username).is_some_and(|stored| {
            stored.strip_prefix("{SHA256}").map_or_else(
                || {
                    // Plain text comparison (constant-time)
                    constant_time_eq(password.as_bytes(), stored.as_bytes())
                },
                |hex_hash| {
                    // SHA-256 comparison
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(password.as_bytes());
                    let result = format!("{:x}", hasher.finalize());
                    constant_time_eq(result.as_bytes(), hex_hash.as_bytes())
                },
            )
        })
    }
}

/// Constant-time byte comparison to prevent timing-based credential enumeration.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use sha2::{Digest, Sha256};

    fn sha256_hex(s: &str) -> String {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        format!("{:x}", h.finalize())
    }

    fn make_plugin_plain(users: &[(&str, &str)]) -> BasicAuthPlugin {
        BasicAuthPlugin::new(BasicAuthConfig {
            users: users
                .iter()
                .map(|(u, p)| (u.to_string(), p.to_string()))
                .collect(),
            realm: "Test".to_string(),
        })
    }

    fn make_plugin_hashed(username: &str, password: &str) -> BasicAuthPlugin {
        let hash = format!("{{SHA256}}{}", sha256_hex(password));
        BasicAuthPlugin::new(BasicAuthConfig {
            users: std::iter::once((username.to_string(), hash)).collect(),
            realm: "Test".to_string(),
        })
    }

    fn make_request_with_basic_auth(username: &str, password: &str) -> pingora_http::RequestHeader {
        use base64::Engine as _;
        let creds =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Authorization", format!("Basic {creds}"))
            .unwrap();
        req
    }

    #[test]
    fn valid_plain_text_credentials() {
        let plugin = make_plugin_plain(&[("alice", "secret")]);
        let req = make_request_with_basic_auth("alice", "secret");
        let mut ctx = RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Continue);
    }

    #[test]
    fn invalid_password() {
        let plugin = make_plugin_plain(&[("alice", "secret")]);
        let req = make_request_with_basic_auth("alice", "wrong");
        let mut ctx = RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Handled(401));
        assert!(matches!(
            ctx.plugin_response,
            Some(PluginResponse::BasicAuthChallenge { .. })
        ));
    }

    #[test]
    fn unknown_username() {
        let plugin = make_plugin_plain(&[("alice", "secret")]);
        let req = make_request_with_basic_auth("bob", "anything");
        let mut ctx = RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Handled(401));
    }

    #[test]
    fn missing_auth_header() {
        let plugin = make_plugin_plain(&[("alice", "secret")]);
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Handled(401));
    }

    #[test]
    fn sha256_hashed_valid_credentials() {
        let plugin = make_plugin_hashed("admin", "supersecret");
        let req = make_request_with_basic_auth("admin", "supersecret");
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn sha256_hashed_wrong_password() {
        let plugin = make_plugin_hashed("admin", "supersecret");
        let req = make_request_with_basic_auth("admin", "wrong");
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(401)
        );
    }

    #[test]
    fn password_with_colon() {
        // Passwords containing ':' must still work — we only split on the first colon
        let plugin = make_plugin_plain(&[("user", "pass:word:extra")]);
        let req = make_request_with_basic_auth("user", "pass:word:extra");
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn realm_included_in_challenge() {
        let plugin = BasicAuthPlugin::new(BasicAuthConfig {
            users: Default::default(),
            realm: "My App".to_string(),
        });
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        plugin.on_request(&req, &mut ctx);
        match &ctx.plugin_response {
            Some(PluginResponse::BasicAuthChallenge { realm }) => {
                assert_eq!(realm, "My App");
            }
            _ => panic!("expected BasicAuthChallenge"),
        }
    }
}
