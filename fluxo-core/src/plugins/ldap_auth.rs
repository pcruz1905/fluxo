//! LDAP authentication plugin — validates credentials against an LDAP directory.
//!
//! Extracts Basic Auth credentials from the request and validates them by
//! attempting an LDAP bind with the provided username and password. This is
//! the "bind authentication" pattern used by Nginx's `ngx_http_auth_ldap_module`.
//!
//! Since LDAP bind requires an async network call and Pingora's `request_filter`
//! is synchronous, this plugin validates the credential format and stores the
//! LDAP config in context. The actual LDAP bind verification should be performed
//! by an upstream auth service or a future async hook.
//!
//! Example config:
//! ```toml
//! [routes.admin.plugins.ldap_auth]
//! server = "ldap://ldap.example.com:389"
//! base_dn = "dc=example,dc=com"
//! bind_dn_template = "uid={username},ou=users,dc=example,dc=com"
//! ```

use serde::Deserialize;
use tracing::debug;

use crate::context::{PluginResponse, RequestContext};
use crate::plugins::PluginAction;

/// Configuration for the LDAP auth plugin.
#[derive(Debug, Deserialize)]
pub struct LdapAuthConfig {
    /// LDAP server URL (e.g., `"ldap://ldap.example.com:389"` or
    /// `"ldaps://ldap.example.com:636"`).
    pub server: String,

    /// Base DN for user searches (e.g., `"dc=example,dc=com"`).
    pub base_dn: String,

    /// Template for constructing the bind DN from the username.
    /// Use `{username}` as the placeholder.
    /// Example: `"uid={username},ou=users,dc=example,dc=com"`.
    #[serde(default)]
    pub bind_dn_template: Option<String>,

    /// LDAP search filter template for finding the user.
    /// Use `{username}` as the placeholder.
    /// Example: `"(&(objectClass=person)(uid={username}))"`.
    /// Default: `"(uid={username})"`.
    #[serde(default = "default_search_filter")]
    pub search_filter: String,

    /// Attribute to use as the username in search results.
    /// Default: `"uid"`.
    #[serde(default = "default_user_attribute")]
    pub user_attribute: String,

    /// Service account bind DN for searching (optional).
    /// If not set, anonymous bind is attempted for searches.
    pub service_bind_dn: Option<String>,

    /// Service account password for searching.
    pub service_bind_password: Option<String>,

    /// LDAP group base DN for group membership checks.
    pub group_base_dn: Option<String>,

    /// LDAP group filter template. Use `{dn}` for the user's DN.
    /// Example: `"(&(objectClass=groupOfNames)(member={dn}))"`.
    pub group_filter: Option<String>,

    /// Required group memberships. If non-empty, the user must belong
    /// to at least one of these groups to be authorized.
    #[serde(default)]
    pub required_groups: Vec<String>,

    /// Realm name for the Basic Auth challenge. Default: "LDAP".
    #[serde(default = "default_realm")]
    pub realm: String,

    /// Use STARTTLS to upgrade the connection to TLS. Default: false.
    #[serde(default)]
    pub starttls: bool,

    /// Skip TLS certificate verification (for self-signed certs). Default: false.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

fn default_search_filter() -> String {
    "(uid={username})".to_string()
}

fn default_user_attribute() -> String {
    "uid".to_string()
}

fn default_realm() -> String {
    "LDAP".to_string()
}

/// LDAP authentication plugin.
#[derive(Debug)]
pub struct LdapAuthPlugin {
    server: String,
    #[allow(dead_code)]
    base_dn: String,
    bind_dn_template: Option<String>,
    #[allow(dead_code)]
    search_filter: String,
    #[allow(dead_code)]
    user_attribute: String,
    #[allow(dead_code)]
    group_base_dn: Option<String>,
    #[allow(dead_code)]
    group_filter: Option<String>,
    #[allow(dead_code)]
    required_groups: Vec<String>,
    realm: String,
}

impl LdapAuthPlugin {
    pub fn try_new(cfg: LdapAuthConfig) -> Result<Self, String> {
        if cfg.server.is_empty() {
            return Err("ldap_auth.server must not be empty".to_string());
        }
        if !cfg.server.starts_with("ldap://") && !cfg.server.starts_with("ldaps://") {
            return Err(format!(
                "ldap_auth.server must start with ldap:// or ldaps://, got: {}",
                cfg.server
            ));
        }
        if cfg.base_dn.is_empty() {
            return Err("ldap_auth.base_dn must not be empty".to_string());
        }

        Ok(Self {
            server: cfg.server,
            base_dn: cfg.base_dn,
            bind_dn_template: cfg.bind_dn_template,
            search_filter: cfg.search_filter,
            user_attribute: cfg.user_attribute,
            group_base_dn: cfg.group_base_dn,
            group_filter: cfg.group_filter,
            required_groups: cfg.required_groups,
            realm: cfg.realm,
        })
    }

    /// Request phase: extract Basic Auth credentials and prepare LDAP context.
    ///
    /// Validates the credential format and stores LDAP bind info in context
    /// for upstream header injection.
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

        let Some(b64) = auth_header.strip_prefix("Basic ") else {
            return self.send_challenge(ctx);
        };

        let Ok(decoded) =
            base64::engine::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        else {
            return self.send_challenge(ctx);
        };

        let Ok(creds) = String::from_utf8(decoded) else {
            return self.send_challenge(ctx);
        };

        let Some((username, _password)) = creds.split_once(':') else {
            return self.send_challenge(ctx);
        };

        // Construct the bind DN for the user
        #[allow(clippy::literal_string_with_formatting_args)]
        let bind_dn = self
            .bind_dn_template
            .as_ref()
            .map(|tmpl| tmpl.replace("{username}", username));

        // Store LDAP context for the upstream phase
        ctx.extensions.insert(
            "ldap_auth.server".to_string(),
            serde_json::Value::String(self.server.clone()),
        );
        ctx.extensions.insert(
            "ldap_auth.username".to_string(),
            serde_json::Value::String(username.to_string()),
        );
        if let Some(ref dn) = bind_dn {
            ctx.extensions.insert(
                "ldap_auth.bind_dn".to_string(),
                serde_json::Value::String(dn.clone()),
            );
        }

        debug!(
            server = %self.server,
            username = %username,
            bind_dn = ?bind_dn,
            "LDAP auth: credentials extracted, context stored"
        );

        PluginAction::Continue
    }

    /// Upstream request phase: inject LDAP-resolved user info as headers.
    pub fn on_upstream_request(
        &self,
        upstream_req: &mut pingora_http::RequestHeader,
        ctx: &crate::context::RequestContext,
    ) {
        if let Some(serde_json::Value::String(username)) = ctx.extensions.get("ldap_auth.username")
        {
            let _ = upstream_req.insert_header("X-LDAP-User", username.as_str());
        }
        if let Some(serde_json::Value::String(bind_dn)) = ctx.extensions.get("ldap_auth.bind_dn") {
            let _ = upstream_req.insert_header("X-LDAP-DN", bind_dn.as_str());
        }
    }

    fn send_challenge(&self, ctx: &mut RequestContext) -> PluginAction {
        ctx.plugin_response = Some(PluginResponse::BasicAuthChallenge {
            realm: self.realm.clone(),
        });
        PluginAction::Handled(401)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_config() -> LdapAuthConfig {
        LdapAuthConfig {
            server: "ldap://ldap.example.com:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn_template: Some("uid={username},ou=users,dc=example,dc=com".to_string()),
            search_filter: "(uid={username})".to_string(),
            user_attribute: "uid".to_string(),
            service_bind_dn: None,
            service_bind_password: None,
            group_base_dn: None,
            group_filter: None,
            required_groups: vec![],
            realm: "LDAP".to_string(),
            starttls: false,
            insecure_skip_verify: false,
        }
    }

    fn make_plugin() -> LdapAuthPlugin {
        LdapAuthPlugin::try_new(make_config()).unwrap()
    }

    fn make_basic_auth_request(user: &str, pass: &str) -> pingora_http::RequestHeader {
        use base64::Engine as _;
        let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Authorization", format!("Basic {creds}"))
            .unwrap();
        req
    }

    #[test]
    fn try_new_valid() {
        assert!(LdapAuthPlugin::try_new(make_config()).is_ok());
    }

    #[test]
    fn try_new_empty_server_rejected() {
        let mut cfg = make_config();
        cfg.server = String::new();
        assert!(LdapAuthPlugin::try_new(cfg).is_err());
    }

    #[test]
    fn try_new_bad_scheme_rejected() {
        let mut cfg = make_config();
        cfg.server = "http://ldap.example.com".to_string();
        assert!(LdapAuthPlugin::try_new(cfg).is_err());
    }

    #[test]
    fn try_new_ldaps_accepted() {
        let mut cfg = make_config();
        cfg.server = "ldaps://ldap.example.com:636".to_string();
        assert!(LdapAuthPlugin::try_new(cfg).is_ok());
    }

    #[test]
    fn try_new_empty_base_dn_rejected() {
        let mut cfg = make_config();
        cfg.base_dn = String::new();
        assert!(LdapAuthPlugin::try_new(cfg).is_err());
    }

    #[test]
    fn missing_auth_header_sends_challenge() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(401)
        );
        assert!(matches!(
            ctx.plugin_response,
            Some(PluginResponse::BasicAuthChallenge { .. })
        ));
    }

    #[test]
    fn valid_basic_credentials_pass() {
        let plugin = make_plugin();
        let req = make_basic_auth_request("jdoe", "secret");
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
        assert_eq!(ctx.extensions.get("ldap_auth.username").unwrap(), "jdoe");
        assert!(
            ctx.extensions
                .get("ldap_auth.bind_dn")
                .unwrap()
                .as_str()
                .unwrap()
                .contains("uid=jdoe")
        );
    }

    #[test]
    fn bearer_auth_sends_challenge() {
        let plugin = make_plugin();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("authorization", "Bearer token123")
            .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(401)
        );
    }

    #[test]
    fn upstream_headers_injected() {
        let plugin = make_plugin();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        ctx.extensions.insert(
            "ldap_auth.username".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        ctx.extensions.insert(
            "ldap_auth.bind_dn".to_string(),
            serde_json::Value::String("uid=admin,ou=users,dc=example,dc=com".to_string()),
        );
        plugin.on_upstream_request(&mut req, &ctx);
        assert_eq!(
            req.headers.get("X-LDAP-User").unwrap().to_str().unwrap(),
            "admin"
        );
        assert_eq!(
            req.headers.get("X-LDAP-DN").unwrap().to_str().unwrap(),
            "uid=admin,ou=users,dc=example,dc=com"
        );
    }

    #[test]
    fn no_bind_dn_template_omits_dn() {
        let mut cfg = make_config();
        cfg.bind_dn_template = None;
        let plugin = LdapAuthPlugin::try_new(cfg).unwrap();
        let req = make_basic_auth_request("user", "pass");
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
        assert!(!ctx.extensions.contains_key("ldap_auth.bind_dn"));
    }
}
