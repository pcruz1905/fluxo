//! JWT authentication plugin — validates JSON Web Tokens from header, query, or cookie.

use serde::Deserialize;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// JWT authentication configuration.
#[derive(Debug, Deserialize)]
pub struct JwtAuthConfig {
    /// HMAC secret key for HS256/HS384/HS512 validation.
    pub secret: String,

    /// Algorithm: "HS256" (default), "HS384", "HS512".
    #[serde(default = "default_algorithm")]
    pub algorithm: String,

    /// Where to look for the token. Default: "header".
    /// Valid: "header", "query", "cookie".
    #[serde(default = "default_token_source")]
    pub token_source: String,

    /// Header name when `token_source = "header"`. Default: "Authorization".
    /// The plugin strips the "Bearer " prefix automatically.
    #[serde(default = "default_header_name")]
    pub header_name: String,

    /// Query parameter name when `token_source = "query"`. Default: "token".
    #[serde(default = "default_query_param")]
    pub query_param: String,

    /// Cookie name when `token_source = "cookie"`. Default: "token".
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Required claims — if present, the JWT payload must contain these key-value pairs.
    #[serde(default)]
    pub required_claims: std::collections::HashMap<String, String>,
}

fn default_algorithm() -> String {
    "HS256".to_string()
}
fn default_token_source() -> String {
    "header".to_string()
}
fn default_header_name() -> String {
    "Authorization".to_string()
}
fn default_query_param() -> String {
    "token".to_string()
}
fn default_cookie_name() -> String {
    "token".to_string()
}

/// JWT authentication plugin.
#[derive(Debug)]
pub struct JwtAuthPlugin {
    secret: Vec<u8>,
    algorithm: Algorithm,
    token_source: TokenSource,
    header_name: String,
    query_param: String,
    cookie_name: String,
    required_claims: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
enum Algorithm {
    Hs256,
    Hs384,
    Hs512,
}

#[derive(Debug, Clone, Copy)]
enum TokenSource {
    Header,
    Query,
    Cookie,
}

impl JwtAuthPlugin {
    pub fn try_new(cfg: JwtAuthConfig) -> Result<Self, String> {
        let algorithm = match cfg.algorithm.to_uppercase().as_str() {
            "HS256" => Algorithm::Hs256,
            "HS384" => Algorithm::Hs384,
            "HS512" => Algorithm::Hs512,
            other => {
                return Err(format!(
                    "unsupported JWT algorithm: {other} (valid: HS256, HS384, HS512)"
                ));
            }
        };
        let token_source = match cfg.token_source.as_str() {
            "header" => TokenSource::Header,
            "query" => TokenSource::Query,
            "cookie" => TokenSource::Cookie,
            other => {
                return Err(format!(
                    "unsupported token_source: {other} (valid: header, query, cookie)"
                ));
            }
        };
        if cfg.secret.is_empty() {
            return Err("jwt_auth.secret must not be empty".to_string());
        }
        Ok(Self {
            secret: cfg.secret.into_bytes(),
            algorithm,
            token_source,
            header_name: cfg.header_name,
            query_param: cfg.query_param,
            cookie_name: cfg.cookie_name,
            required_claims: cfg.required_claims,
        })
    }

    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let token = match self.extract_token(req) {
            Some(t) => t,
            None => {
                ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 401 });
                return PluginAction::Handled(401);
            }
        };

        match self.validate_token(&token) {
            Ok(()) => PluginAction::Continue,
            Err(_) => {
                ctx.plugin_response = Some(crate::context::PluginResponse::Error { status: 401 });
                PluginAction::Handled(401)
            }
        }
    }

    fn extract_token(&self, req: &pingora_http::RequestHeader) -> Option<String> {
        match self.token_source {
            TokenSource::Header => {
                let val = req.headers.get(&self.header_name)?.to_str().ok()?;
                // Strip "Bearer " prefix if present
                if let Some(stripped) = val.strip_prefix("Bearer ") {
                    Some(stripped.to_string())
                } else if let Some(stripped) = val.strip_prefix("bearer ") {
                    Some(stripped.to_string())
                } else {
                    Some(val.to_string())
                }
            }
            TokenSource::Query => {
                let uri = &req.uri;
                let query = uri.query()?;
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
            TokenSource::Cookie => {
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
    }

    fn validate_token(&self, token: &str) -> Result<(), &'static str> {
        // JWT format: header.payload.signature
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err("malformed JWT");
        }

        let header_payload = format!("{}.{}", parts[0], parts[1]);
        let signature_bytes = base64_url_decode(parts[2]).ok_or("invalid signature encoding")?;

        // Verify HMAC signature
        let expected = self.compute_hmac(header_payload.as_bytes());
        if !constant_time_eq(&signature_bytes, &expected) {
            return Err("invalid signature");
        }

        // Decode payload and check claims
        let payload_bytes = base64_url_decode(parts[1]).ok_or("invalid payload encoding")?;
        let payload_str =
            std::str::from_utf8(&payload_bytes).map_err(|_| "invalid payload UTF-8")?;
        let claims: serde_json::Value =
            serde_json::from_str(payload_str).map_err(|_| "invalid payload JSON")?;

        // Check expiration
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now > exp {
                return Err("token expired");
            }
        }

        // Check required claims
        for (key, expected_value) in &self.required_claims {
            match claims.get(key).and_then(|v| v.as_str()) {
                Some(val) if val == expected_value => {}
                _ => return Err("missing or invalid required claim"),
            }
        }

        Ok(())
    }

    fn compute_hmac(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self.algorithm {
            Algorithm::Hs256 => hmac_sha2::<sha2::Sha256>(&self.secret, data),
            Algorithm::Hs384 => hmac_sha2::<sha2::Sha384>(&self.secret, data),
            Algorithm::Hs512 => hmac_sha2::<sha2::Sha512>(&self.secret, data),
        }
    }
}

/// HMAC implementation using SHA-2 (RFC 2104) — avoids pulling in the `hmac` crate.
fn hmac_sha2<D: sha2::Digest + Clone>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = 64usize; // SHA-256/384/512 block size for HMAC
    let actual_block = if D::output_size() > 32 {
        128
    } else {
        block_size
    };

    let key = if key.len() > actual_block {
        let mut hasher = D::new();
        sha2::Digest::update(&mut hasher, key);
        sha2::Digest::finalize(hasher).to_vec()
    } else {
        key.to_vec()
    };

    let mut ipad = vec![0x36u8; actual_block];
    let mut opad = vec![0x5cu8; actual_block];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }

    let mut inner = D::new();
    sha2::Digest::update(&mut inner, &ipad);
    sha2::Digest::update(&mut inner, data);
    let inner_hash = sha2::Digest::finalize(inner);

    let mut outer = D::new();
    sha2::Digest::update(&mut outer, &opad);
    sha2::Digest::update(&mut outer, &inner_hash);
    sha2::Digest::finalize(outer).to_vec()
}

/// Base64 URL-safe decode (no padding).
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
        .or_else(|| {
            // Try with padding
            base64::engine::general_purpose::URL_SAFE.decode(input).ok()
        })
}

/// Constant-time comparison to prevent timing attacks.
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

    fn make_plugin() -> JwtAuthPlugin {
        JwtAuthPlugin::try_new(JwtAuthConfig {
            secret: "test-secret".to_string(),
            algorithm: "HS256".to_string(),
            token_source: "header".to_string(),
            header_name: "Authorization".to_string(),
            query_param: "token".to_string(),
            cookie_name: "token".to_string(),
            required_claims: std::collections::HashMap::new(),
        })
        .unwrap()
    }

    #[test]
    fn empty_secret_rejected() {
        let result = JwtAuthPlugin::try_new(JwtAuthConfig {
            secret: String::new(),
            algorithm: "HS256".to_string(),
            token_source: "header".to_string(),
            header_name: "Authorization".to_string(),
            query_param: "token".to_string(),
            cookie_name: "token".to_string(),
            required_claims: std::collections::HashMap::new(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn invalid_algorithm_rejected() {
        let result = JwtAuthPlugin::try_new(JwtAuthConfig {
            secret: "secret".to_string(),
            algorithm: "RS256".to_string(),
            token_source: "header".to_string(),
            header_name: "Authorization".to_string(),
            query_param: "token".to_string(),
            cookie_name: "token".to_string(),
            required_claims: std::collections::HashMap::new(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn malformed_jwt_rejected() {
        let plugin = make_plugin();
        assert!(plugin.validate_token("not-a-jwt").is_err());
    }

    #[test]
    fn missing_token_returns_401() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(401)
        );
    }

    #[test]
    fn base64_url_decode_works() {
        let encoded = "aGVsbG8";
        let decoded = base64_url_decode(encoded).unwrap();
        assert_eq!(&decoded, b"hello");
    }

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"hello", b"hi"));
    }
}
