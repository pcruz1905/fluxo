//! Digest authentication plugin (RFC 7616 / RFC 2617).
//!
//! Implements HTTP Digest Auth — the challenge-response alternative to Basic Auth.
//! The server sends a nonce; the client hashes `username:realm:password` with the
//! nonce and sends it back, avoiding plaintext password transmission.
//!
//! Example config:
//! ```toml
//! [routes.admin.plugins.digest_auth]
//! realm = "Admin Panel"
//! algorithm = "SHA-256"
//! [routes.admin.plugins.digest_auth.users]
//! "admin" = "supersecret"
//! ```

use std::collections::HashMap;

use md5::Md5;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::context::{PluginResponse, RequestContext};
use crate::plugins::PluginAction;

/// Configuration for the digest auth plugin.
#[derive(Debug, Deserialize)]
pub struct DigestAuthConfig {
    /// Map of `username → password`.
    pub users: HashMap<String, String>,

    /// Realm name shown in the digest challenge.
    #[serde(default = "default_realm")]
    pub realm: String,

    /// Hash algorithm: "MD5" or "SHA-256" (default).
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

fn default_realm() -> String {
    "Protected".to_string()
}

fn default_algorithm() -> String {
    "SHA-256".to_string()
}

#[derive(Debug, Clone, Copy)]
enum DigestAlgorithm {
    Md5,
    Sha256,
}

/// Digest authentication plugin.
#[derive(Debug)]
pub struct DigestAuthPlugin {
    users: HashMap<String, String>,
    realm: String,
    algorithm: DigestAlgorithm,
    algorithm_name: String,
}

impl DigestAuthPlugin {
    pub fn try_new(cfg: DigestAuthConfig) -> Result<Self, String> {
        let algorithm = match cfg.algorithm.to_uppercase().as_str() {
            "MD5" => DigestAlgorithm::Md5,
            "SHA-256" | "SHA256" => DigestAlgorithm::Sha256,
            other => {
                return Err(format!(
                    "unsupported digest algorithm: {other} (valid: MD5, SHA-256)"
                ));
            }
        };

        if cfg.users.is_empty() {
            return Err("digest_auth.users must not be empty".to_string());
        }

        let algorithm_name = match algorithm {
            DigestAlgorithm::Md5 => "MD5".to_string(),
            DigestAlgorithm::Sha256 => "SHA-256".to_string(),
        };

        Ok(Self {
            users: cfg.users,
            realm: cfg.realm,
            algorithm,
            algorithm_name,
        })
    }

    /// Request phase: validate digest credentials or issue a challenge.
    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let Some(auth_header) = req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        else {
            return self.send_challenge(ctx);
        };

        let Some(digest_params) = auth_header.strip_prefix("Digest ") else {
            return self.send_challenge(ctx);
        };

        // Parse digest parameters
        let params = parse_digest_params(digest_params);

        let Some(username) = params.get("username") else {
            return self.send_challenge(ctx);
        };
        let Some(password) = self.users.get(username.as_str()) else {
            return self.send_challenge(ctx);
        };
        let Some(nonce) = params.get("nonce") else {
            return self.send_challenge(ctx);
        };
        let Some(response) = params.get("response") else {
            return self.send_challenge(ctx);
        };

        let uri = params
            .get("uri")
            .map_or_else(|| req.uri.path(), String::as_str);
        let nc = params.get("nc").map_or("00000001", String::as_str);
        let cnonce = params.get("cnonce").map_or("", String::as_str);
        let qop = params.get("qop").map_or("auth", String::as_str);

        // Compute expected response hash
        let ha1 = self.hash(&format!(
            "{username}:{realm}:{password}",
            realm = self.realm
        ));
        let ha2 = self.hash(&format!("{method}:{uri}", method = req.method.as_str()));

        let expected = if qop == "auth" || qop == "auth-int" {
            self.hash(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"))
        } else {
            self.hash(&format!("{ha1}:{nonce}:{ha2}"))
        };

        if constant_time_eq(response.as_bytes(), expected.as_bytes()) {
            PluginAction::Continue
        } else {
            self.send_challenge(ctx)
        }
    }

    fn send_challenge(&self, ctx: &mut RequestContext) -> PluginAction {
        // Generate a nonce (timestamp-based for simplicity)
        let nonce = generate_nonce();

        let challenge = format!(
            "Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm={algo}, qop=\"auth\"",
            realm = self.realm,
            algo = self.algorithm_name,
        );

        ctx.plugin_response = Some(PluginResponse::Static {
            status: 401,
            body: Some("Unauthorized".to_string()),
            content_type: Some("text/plain".to_string()),
        });

        // Store the WWW-Authenticate header value in extensions for the response phase
        ctx.extensions.insert(
            "digest_auth.challenge".to_string(),
            serde_json::Value::String(challenge),
        );

        PluginAction::Handled(401)
    }

    fn hash(&self, input: &str) -> String {
        match self.algorithm {
            DigestAlgorithm::Md5 => {
                let mut hasher = Md5::new();
                Digest::update(&mut hasher, input.as_bytes());
                format!("{:x}", hasher.finalize())
            }
            DigestAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                Digest::update(&mut hasher, input.as_bytes());
                format!("{:x}", hasher.finalize())
            }
        }
    }
}

/// Parse RFC 2617 digest auth parameter string.
///
/// Input: `username="admin", realm="test", nonce="abc", ...`
/// Returns: `HashMap<"username" → "admin", "realm" → "test", ...>`
fn parse_digest_params(s: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();

    for part in s.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim().trim_matches('"').to_string();
            params.insert(key, value);
        }
    }

    params
}

/// Generate a nonce for the digest challenge.
fn generate_nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let random = fastrand::u64(..);
    let mut hasher = Sha256::new();
    hasher.update(format!("{ts}:{random}").as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Constant-time comparison.
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
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_config() -> DigestAuthConfig {
        DigestAuthConfig {
            users: std::iter::once(("admin".to_string(), "secret".to_string())).collect(),
            realm: "TestRealm".to_string(),
            algorithm: "SHA-256".to_string(),
        }
    }

    fn make_plugin() -> DigestAuthPlugin {
        DigestAuthPlugin::try_new(make_config()).unwrap()
    }

    #[test]
    fn try_new_valid() {
        assert!(DigestAuthPlugin::try_new(make_config()).is_ok());
    }

    #[test]
    fn try_new_empty_users_rejected() {
        let mut cfg = make_config();
        cfg.users.clear();
        assert!(DigestAuthPlugin::try_new(cfg).is_err());
    }

    #[test]
    fn try_new_invalid_algorithm_rejected() {
        let mut cfg = make_config();
        cfg.algorithm = "BLAKE2".to_string();
        assert!(DigestAuthPlugin::try_new(cfg).is_err());
    }

    #[test]
    fn try_new_md5_accepted() {
        let mut cfg = make_config();
        cfg.algorithm = "MD5".to_string();
        assert!(DigestAuthPlugin::try_new(cfg).is_ok());
    }

    #[test]
    fn missing_auth_header_sends_challenge() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        let action = plugin.on_request(&req, &mut ctx);
        assert_eq!(action, PluginAction::Handled(401));
        assert!(ctx.extensions.contains_key("digest_auth.challenge"));
        let challenge = ctx.extensions["digest_auth.challenge"].as_str().unwrap();
        assert!(challenge.contains("Digest"));
        assert!(challenge.contains("TestRealm"));
        assert!(challenge.contains("SHA-256"));
    }

    #[test]
    fn basic_auth_header_sends_challenge() {
        let plugin = make_plugin();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("authorization", "Basic dGVzdDp0ZXN0")
            .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(401)
        );
    }

    #[test]
    fn valid_digest_response_accepted() {
        let plugin = make_plugin();

        // Compute a valid digest response
        let nonce = "testnonce123";
        let username = "admin";
        let password = "secret";
        let realm = "TestRealm";
        let uri = "/protected";
        let nc = "00000001";
        let cnonce = "clientnonce";
        let qop = "auth";

        let ha1 = sha256_hex(&format!("{username}:{realm}:{password}"));
        let ha2 = sha256_hex(&format!("GET:{uri}"));
        let response = sha256_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"));

        let auth_header = format!(
            "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", \
             uri=\"{uri}\", nc={nc}, cnonce=\"{cnonce}\", qop={qop}, \
             response=\"{response}\", algorithm=SHA-256"
        );

        let mut req = pingora_http::RequestHeader::build("GET", b"/protected", None).unwrap();
        req.insert_header("authorization", &auth_header).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn wrong_password_digest_rejected() {
        let plugin = make_plugin();

        let nonce = "testnonce123";
        let realm = "TestRealm";
        let uri = "/";

        // Use wrong password
        let ha1 = sha256_hex(&format!("admin:{realm}:wrongpass"));
        let ha2 = sha256_hex(&format!("GET:{uri}"));
        let response = sha256_hex(&format!("{ha1}:{nonce}:00000001:cn:auth:{ha2}"));

        let auth_header = format!(
            "Digest username=\"admin\", nonce=\"{nonce}\", uri=\"{uri}\", \
             nc=00000001, cnonce=\"cn\", qop=auth, response=\"{response}\""
        );

        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("authorization", &auth_header).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(401)
        );
    }

    #[test]
    fn parse_digest_params_basic() {
        let params = parse_digest_params(
            "username=\"admin\", realm=\"test\", nonce=\"abc\", response=\"def\"",
        );
        assert_eq!(params.get("username").unwrap(), "admin");
        assert_eq!(params.get("realm").unwrap(), "test");
        assert_eq!(params.get("nonce").unwrap(), "abc");
        assert_eq!(params.get("response").unwrap(), "def");
    }

    #[test]
    fn generate_nonce_is_unique() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64); // SHA-256 hex = 64 chars
    }

    fn sha256_hex(s: &str) -> String {
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        format!("{:x}", h.finalize())
    }
}
