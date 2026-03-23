//! CSRF protection plugin — double-submit cookie pattern with HMAC tokens.

use serde::Deserialize;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// CSRF protection configuration.
#[derive(Debug, Deserialize)]
pub struct CsrfConfig {
    /// Secret key for HMAC token generation.
    pub secret: String,

    /// Cookie name for the CSRF token. Default: "_csrf".
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Header name to check for the CSRF token. Default: "X-CSRF-Token".
    #[serde(default = "default_header_name")]
    pub header_name: String,

    /// Token TTL in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_ttl")]
    pub ttl: u64,

    /// HTTP methods that are exempt from CSRF checking (safe methods).
    /// Default: ["GET", "HEAD", "OPTIONS"].
    #[serde(default = "default_safe_methods")]
    pub safe_methods: Vec<String>,
}

fn default_cookie_name() -> String {
    "_csrf".to_string()
}
fn default_header_name() -> String {
    "X-CSRF-Token".to_string()
}
fn default_ttl() -> u64 {
    3600
}
fn default_safe_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string(), "OPTIONS".to_string()]
}

/// CSRF protection plugin.
#[derive(Debug)]
pub struct CsrfPlugin {
    secret: Vec<u8>,
    cookie_name: String,
    header_name: String,
    ttl: u64,
    safe_methods: Vec<String>,
}

impl CsrfPlugin {
    pub fn try_new(cfg: CsrfConfig) -> Result<Self, String> {
        if cfg.secret.is_empty() {
            return Err("csrf.secret must not be empty".to_string());
        }
        Ok(Self {
            secret: cfg.secret.into_bytes(),
            cookie_name: cfg.cookie_name,
            header_name: cfg.header_name,
            ttl: cfg.ttl,
            safe_methods: cfg.safe_methods,
        })
    }

    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        // Safe methods are exempt from CSRF checking
        let method = req.method.as_str();
        if self
            .safe_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            // For GET requests, generate and set a CSRF token cookie
            let token = self.generate_token();
            ctx.set_extension("csrf_token", serde_json::json!(token));
            return PluginAction::Continue;
        }

        // For unsafe methods, validate the token
        let cookie_token = self.extract_cookie_token(req);
        let header_token = req
            .headers
            .get(&self.header_name)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        match (cookie_token, header_token) {
            (Some(cookie_val), Some(header_val)) if cookie_val == header_val => {
                // Validate token structure and expiry
                if self.validate_token(&cookie_val) {
                    PluginAction::Continue
                } else {
                    ctx.plugin_response =
                        Some(crate::context::PluginResponse::Error { status: 403 });
                    PluginAction::Handled(403)
                }
            }
            _ => {
                ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 403 });
                PluginAction::Handled(403)
            }
        }
    }

    pub fn on_response(&self, resp: &mut pingora_http::ResponseHeader, ctx: &mut RequestContext) {
        // Set CSRF cookie on safe method responses
        if let Some(token) = ctx.get_extension("csrf_token").and_then(|v| v.as_str()) {
            let cookie = format!(
                "{}={}; Path=/; SameSite=Strict; HttpOnly; Max-Age={}",
                self.cookie_name, token, self.ttl
            );
            let _ = resp.append_header("Set-Cookie", &cookie);
        }
    }

    fn generate_token(&self) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let nonce = fastrand::u64(..);
        let payload = format!("{timestamp}.{nonce}");

        // HMAC-SHA256 the payload
        let mac = hmac_sha256(&self.secret, payload.as_bytes());
        let mac_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &mac);

        format!("{payload}.{mac_b64}")
    }

    fn validate_token(&self, token: &str) -> bool {
        // Token format: timestamp.nonce.hmac
        let parts: Vec<&str> = token.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return false;
        }
        let (mac_b64, payload) = (parts[0], parts[1]);

        // Verify HMAC
        let expected_mac = hmac_sha256(&self.secret, payload.as_bytes());
        let Ok(provided_mac) =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, mac_b64)
        else {
            return false;
        };
        if !constant_time_eq(&provided_mac, &expected_mac) {
            return false;
        }

        // Check expiry
        if let Some(ts_str) = payload.split('.').next() {
            if let Ok(ts) = ts_str.parse::<u64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if now > ts + self.ttl {
                    return false;
                }
            }
        }

        true
    }

    fn extract_cookie_token(&self, req: &pingora_http::RequestHeader) -> Option<String> {
        let cookie_header = req.headers.get("cookie")?.to_str().ok()?;
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some((name, value)) = cookie.split_once('=') {
                if name.trim() == self.cookie_name {
                    return Some(value.trim().to_string());
                }
            }
        }
        None
    }
}

/// HMAC-SHA256 (RFC 2104).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let block_size = 64;

    let key = if key.len() > block_size {
        sha2::Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };

    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }

    let mut inner = sha2::Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = sha2::Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_plugin() -> CsrfPlugin {
        CsrfPlugin::try_new(CsrfConfig {
            secret: "test-secret".to_string(),
            cookie_name: "_csrf".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            ttl: 3600,
            safe_methods: vec!["GET".to_string(), "HEAD".to_string(), "OPTIONS".to_string()],
        })
        .unwrap()
    }

    #[test]
    fn empty_secret_rejected() {
        let result = CsrfPlugin::try_new(CsrfConfig {
            secret: String::new(),
            cookie_name: "_csrf".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            ttl: 3600,
            safe_methods: vec![],
        });
        assert!(result.is_err());
    }

    #[test]
    fn get_request_passes() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn post_without_token_returns_403() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("POST", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn token_generation_and_validation() {
        let plugin = make_plugin();
        let token = plugin.generate_token();
        assert!(plugin.validate_token(&token));
    }

    #[test]
    fn tampered_token_rejected() {
        let plugin = make_plugin();
        let token = plugin.generate_token();
        let tampered = format!("{token}x");
        assert!(!plugin.validate_token(&tampered));
    }
}
