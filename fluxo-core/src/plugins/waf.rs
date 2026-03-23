//! WAF (Web Application Firewall) plugin — ModSecurity-inspired request inspection.
//!
//! Scans request URIs, headers, and query parameters for common attack patterns
//! (SQL injection, XSS, path traversal, command injection, etc.) using compiled
//! regex rule sets. Matching requests are blocked with 403 Forbidden.
//!
//! This is a lightweight, built-in WAF — not a full `ModSecurity` engine.
//! For advanced use cases (OWASP CRS, custom rule language), deploy `ModSecurity`
//! as a forward auth service and use the `forward_auth` plugin.
//!
//! Example config:
//! ```toml
//! [routes.api.plugins.waf]
//! # Enable/disable individual rule categories
//! sql_injection = true      # default: true
//! xss = true                # default: true
//! path_traversal = true     # default: true
//! command_injection = true  # default: true
//! protocol_attack = true    # default: true
//! scanner_detection = true  # default: true
//!
//! # Custom blocked patterns (additional regex rules)
//! custom_rules = ["(?i)evil\\.payload"]
//!
//! # Paths to exclude from WAF checks (exact prefix match)
//! exclude_paths = ["/health", "/metrics"]
//!
//! # Custom response status code (default: 403)
//! block_status = 403
//!
//! # Action: "block" (default) or "detect" (log only, don't block)
//! mode = "block"
//! ```

use regex::Regex;
use serde::Deserialize;
use tracing::warn;

use crate::context::{PluginResponse, RequestContext};
use crate::plugins::PluginAction;

/// Configuration for the WAF plugin.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize)]
pub struct WafConfig {
    /// Enable SQL injection detection. Default: true.
    #[serde(default = "default_true")]
    pub sql_injection: bool,

    /// Enable XSS (cross-site scripting) detection. Default: true.
    #[serde(default = "default_true")]
    pub xss: bool,

    /// Enable path traversal detection. Default: true.
    #[serde(default = "default_true")]
    pub path_traversal: bool,

    /// Enable command injection detection. Default: true.
    #[serde(default = "default_true")]
    pub command_injection: bool,

    /// Enable protocol-level attack detection. Default: true.
    #[serde(default = "default_true")]
    pub protocol_attack: bool,

    /// Enable scanner/bot detection. Default: true.
    #[serde(default = "default_true")]
    pub scanner_detection: bool,

    /// Additional custom regex rules. Matched against URI + query string.
    #[serde(default)]
    pub custom_rules: Vec<String>,

    /// Paths to exclude from WAF checks (prefix match).
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    /// HTTP status code for blocked requests. Default: 403.
    #[serde(default = "default_block_status")]
    pub block_status: u16,

    /// WAF mode: "block" (default) or "detect" (log only).
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_true() -> bool {
    true
}

fn default_block_status() -> u16 {
    403
}

fn default_mode() -> String {
    "block".to_string()
}

/// A compiled WAF rule with a name and regex pattern.
#[derive(Debug)]
struct WafRule {
    name: &'static str,
    category: &'static str,
    pattern: Regex,
}

/// WAF plugin — inspects requests for attack patterns.
#[derive(Debug)]
pub struct WafPlugin {
    rules: Vec<WafRule>,
    exclude_paths: Vec<String>,
    block_status: u16,
    detect_only: bool,
}

impl WafPlugin {
    pub fn try_new(cfg: WafConfig) -> Result<Self, String> {
        let mut rules = Vec::new();

        if cfg.sql_injection {
            for (name, pattern) in SQL_INJECTION_RULES {
                rules.push(WafRule {
                    name,
                    category: "sqli",
                    pattern: Regex::new(pattern)
                        .map_err(|e| format!("invalid SQLi rule '{name}': {e}"))?,
                });
            }
        }

        if cfg.xss {
            for (name, pattern) in XSS_RULES {
                rules.push(WafRule {
                    name,
                    category: "xss",
                    pattern: Regex::new(pattern)
                        .map_err(|e| format!("invalid XSS rule '{name}': {e}"))?,
                });
            }
        }

        if cfg.path_traversal {
            for (name, pattern) in PATH_TRAVERSAL_RULES {
                rules.push(WafRule {
                    name,
                    category: "traversal",
                    pattern: Regex::new(pattern)
                        .map_err(|e| format!("invalid traversal rule '{name}': {e}"))?,
                });
            }
        }

        if cfg.command_injection {
            for (name, pattern) in COMMAND_INJECTION_RULES {
                rules.push(WafRule {
                    name,
                    category: "cmdi",
                    pattern: Regex::new(pattern)
                        .map_err(|e| format!("invalid cmd injection rule '{name}': {e}"))?,
                });
            }
        }

        if cfg.protocol_attack {
            for (name, pattern) in PROTOCOL_ATTACK_RULES {
                rules.push(WafRule {
                    name,
                    category: "protocol",
                    pattern: Regex::new(pattern)
                        .map_err(|e| format!("invalid protocol rule '{name}': {e}"))?,
                });
            }
        }

        if cfg.scanner_detection {
            for (name, pattern) in SCANNER_DETECTION_RULES {
                rules.push(WafRule {
                    name,
                    category: "scanner",
                    pattern: Regex::new(pattern)
                        .map_err(|e| format!("invalid scanner rule '{name}': {e}"))?,
                });
            }
        }

        for (idx, pattern_str) in cfg.custom_rules.iter().enumerate() {
            let pattern = Regex::new(pattern_str)
                .map_err(|e| format!("invalid custom_rules[{idx}] pattern: {e}"))?;
            // Leak the name string for 'static lifetime — these live for the process lifetime
            let name: &'static str = Box::leak(format!("custom_{idx}").into_boxed_str());
            rules.push(WafRule {
                name,
                category: "custom",
                pattern,
            });
        }

        let detect_only = cfg.mode.eq_ignore_ascii_case("detect");

        Ok(Self {
            rules,
            exclude_paths: cfg.exclude_paths,
            block_status: cfg.block_status,
            detect_only,
        })
    }

    /// Request phase: scan URI, query string, and select headers for attack patterns.
    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        let path = req.uri.path();

        // Skip excluded paths
        if self
            .exclude_paths
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
        {
            return PluginAction::Continue;
        }

        // Build the inspection target: URI + query string, URL-decoded to catch encoded attacks.
        let uri_raw = req.uri.to_string();
        let uri_str = percent_encoding::percent_decode_str(&uri_raw)
            .decode_utf8_lossy()
            .into_owned();

        // Check URI against all rules
        if let Some(violation) = self.check_input(&uri_str) {
            return self.handle_violation(violation, "uri", &uri_str, ctx);
        }

        // Check select headers that are common attack vectors
        for header_name in &[
            "cookie",
            "referer",
            "user-agent",
            "content-type",
            "x-forwarded-for",
            "x-forwarded-host",
        ] {
            if let Some(value) = req.headers.get(*header_name) {
                if let Ok(val_str) = value.to_str() {
                    if let Some(violation) = self.check_input(val_str) {
                        return self.handle_violation(violation, header_name, val_str, ctx);
                    }
                }
            }
        }

        PluginAction::Continue
    }

    /// Check an input string against all WAF rules. Returns the first match.
    fn check_input(&self, input: &str) -> Option<(&'static str, &'static str)> {
        for rule in &self.rules {
            if rule.pattern.is_match(input) {
                return Some((rule.name, rule.category));
            }
        }
        None
    }

    /// Handle a WAF violation — block or log depending on mode.
    fn handle_violation(
        &self,
        (rule_name, category): (&'static str, &'static str),
        location: &str,
        _input: &str,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        if self.detect_only {
            warn!(
                rule = rule_name,
                category = category,
                location = location,
                "WAF violation detected (detect mode, not blocking)"
            );
            // Store detection info in extensions for logging
            ctx.extensions.insert(
                "waf.detected_rule".to_string(),
                serde_json::Value::String(rule_name.to_string()),
            );
            ctx.extensions.insert(
                "waf.detected_category".to_string(),
                serde_json::Value::String(category.to_string()),
            );
            return PluginAction::Continue;
        }

        warn!(
            rule = rule_name,
            category = category,
            location = location,
            "WAF blocked request"
        );

        ctx.plugin_response = Some(PluginResponse::Static {
            status: self.block_status,
            body: Some("Forbidden".to_string()),
            content_type: Some("text/plain".to_string()),
        });

        PluginAction::Handled(self.block_status)
    }
}

// ---------------------------------------------------------------------------
// Rule definitions — inspired by OWASP CRS (Core Rule Set)
// ---------------------------------------------------------------------------

/// SQL injection patterns (OWASP CRS 942xxx).
const SQL_INJECTION_RULES: &[(&str, &str)] = &[
    ("sqli_union_select", r"(?i)(?:union\s+(?:all\s+)?select)"),
    ("sqli_comment_sequence", r"(?:/\*!?\s*\d*|--\s*[\w(])"),
    (
        "sqli_conditional",
        r"(?i)(?:\b(?:select|insert|update|delete|drop|alter|create|truncate)\b\s+(?:\w+\s+)*(?:from|into|table|database)\b)",
    ),
    (
        "sqli_sleep_benchmark",
        r"(?i)(?:sleep\s*\(\s*\d|benchmark\s*\(\s*\d|waitfor\s+delay)",
    ),
    (
        "sqli_or_equals",
        r"(?i)(?:'\s*(?:or|and)\s*'?\s*\d*\s*[=<>])",
    ),
    ("sqli_hex_encoding", r"(?i)(?:0x[0-9a-f]{8,})"),
];

/// XSS (cross-site scripting) patterns (OWASP CRS 941xxx).
const XSS_RULES: &[(&str, &str)] = &[
    ("xss_script_tag", r"(?i)<\s*script[^>]*>"),
    (
        "xss_event_handler",
        r#"(?i)\bon\w+\s*=\s*["']?[^"']*(?:javascript|alert|confirm|prompt|eval|expression)"#,
    ),
    ("xss_javascript_uri", r"(?i)javascript\s*:"),
    ("xss_data_uri", r"(?i)data\s*:\s*text/html"),
    (
        "xss_svg_onload",
        r"(?i)<\s*(?:svg|img|body|iframe|input|details|math)\b[^>]*\bon\w+\s*=",
    ),
    (
        "xss_eval_expression",
        r"(?i)(?:eval|expression|fromcharcode)\s*\(",
    ),
];

/// Path traversal patterns (OWASP CRS 930xxx).
const PATH_TRAVERSAL_RULES: &[(&str, &str)] = &[
    ("traversal_dotdot", r"(?:\.\./|\.\.\\){2,}"),
    (
        "traversal_etc_passwd",
        r"(?i)(?:/etc/(?:passwd|shadow|group|hosts)|/proc/self/)",
    ),
    (
        "traversal_win_system",
        r"(?i)(?:(?:c|d):\\(?:windows|winnt|boot\.ini))",
    ),
    ("traversal_null_byte", r"(?:%00|\\x00)"),
];

/// Command injection patterns (OWASP CRS 932xxx).
const COMMAND_INJECTION_RULES: &[(&str, &str)] = &[
    (
        "cmdi_shell_metachar",
        r"(?:[;|`]\s*(?:cat|ls|dir|whoami|id|uname|pwd|wget|curl|nc|ncat|bash|sh|cmd)\b)",
    ),
    (
        "cmdi_backtick",
        r"`[^`]*(?:cat|ls|id|whoami|uname|pwd|wget|curl)\b",
    ),
    (
        "cmdi_dollar_paren",
        r"\$\(\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl)\b",
    ),
];

/// Protocol-level attack patterns (OWASP CRS 921xxx).
const PROTOCOL_ATTACK_RULES: &[(&str, &str)] = &[
    (
        "proto_http_splitting",
        r"(?:%0[da]|\\r|\\n)(?:.*?)(?:HTTP/|content-type|transfer-encoding)",
    ),
    (
        "proto_request_smuggling",
        r"(?i)(?:transfer-encoding\s*:\s*chunked.*?content-length|content-length.*?transfer-encoding\s*:\s*chunked)",
    ),
];

/// Scanner/bot detection patterns (OWASP CRS 913xxx).
const SCANNER_DETECTION_RULES: &[(&str, &str)] = &[
    (
        "scanner_common_tools",
        r"(?i)(?:nikto|sqlmap|nmap|masscan|burpsuite|dirbuster|gobuster|wfuzz|hydra|nessus|openvas)",
    ),
    (
        "scanner_common_paths",
        r"(?i)(?:/(?:wp-admin|phpmyadmin|phpinfo|\.env|\.git/config|server-status|server-info)(?:\b|$))",
    ),
];

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_config() -> WafConfig {
        WafConfig {
            sql_injection: true,
            xss: true,
            path_traversal: true,
            command_injection: true,
            protocol_attack: true,
            scanner_detection: true,
            custom_rules: vec![],
            exclude_paths: vec![],
            block_status: 403,
            mode: "block".to_string(),
        }
    }

    fn make_plugin() -> WafPlugin {
        WafPlugin::try_new(make_config()).unwrap()
    }

    #[test]
    fn try_new_valid() {
        assert!(WafPlugin::try_new(make_config()).is_ok());
    }

    #[test]
    fn try_new_all_disabled() {
        let cfg = WafConfig {
            sql_injection: false,
            xss: false,
            path_traversal: false,
            command_injection: false,
            protocol_attack: false,
            scanner_detection: false,
            custom_rules: vec![],
            exclude_paths: vec![],
            block_status: 403,
            mode: "block".to_string(),
        };
        let plugin = WafPlugin::try_new(cfg).unwrap();
        assert!(plugin.rules.is_empty());
    }

    #[test]
    fn try_new_invalid_custom_rule() {
        let mut cfg = make_config();
        cfg.custom_rules = vec!["[invalid".to_string()];
        assert!(WafPlugin::try_new(cfg).is_err());
    }

    #[test]
    fn clean_request_passes() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/api/users?page=1", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn sqli_union_select_blocked() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build(
            "GET",
            b"/search?q=1%20UNION%20SELECT%20*%20FROM%20users",
            None,
        )
        .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn sqli_sleep_blocked() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/api?id=1;sleep(5)", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn xss_script_tag_blocked() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build(
            "GET",
            b"/page?name=%3Cscript%3Ealert(1)%3C/script%3E",
            None,
        )
        .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn xss_javascript_uri_blocked() {
        let plugin = make_plugin();
        let req =
            pingora_http::RequestHeader::build("GET", b"/redir?url=javascript:alert(1)", None)
                .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn path_traversal_blocked() {
        let plugin = make_plugin();
        let req =
            pingora_http::RequestHeader::build("GET", b"/files/../../../etc/passwd", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn command_injection_blocked() {
        let plugin = make_plugin();
        let req =
            pingora_http::RequestHeader::build("GET", b"/api?cmd=test%3Bcat%20/etc/passwd", None)
                .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn scanner_path_blocked() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/.env", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn scanner_user_agent_blocked() {
        let plugin = make_plugin();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("user-agent", "sqlmap/1.5").unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn excluded_path_bypasses_waf() {
        let mut cfg = make_config();
        cfg.exclude_paths = vec!["/health".to_string(), "/metrics".to_string()];
        let plugin = WafPlugin::try_new(cfg).unwrap();

        let req = pingora_http::RequestHeader::build(
            "GET",
            b"/health?q=%3Cscript%3Ealert(1)%3C/script%3E",
            None,
        )
        .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn detect_mode_logs_but_continues() {
        let mut cfg = make_config();
        cfg.mode = "detect".to_string();
        let plugin = WafPlugin::try_new(cfg).unwrap();

        let req = pingora_http::RequestHeader::build(
            "GET",
            b"/search?q=UNION%20SELECT%20*%20FROM%20users",
            None,
        )
        .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
        assert!(ctx.extensions.contains_key("waf.detected_rule"));
    }

    #[test]
    fn custom_block_status() {
        let mut cfg = make_config();
        cfg.block_status = 406;
        let plugin = WafPlugin::try_new(cfg).unwrap();

        let req = pingora_http::RequestHeader::build(
            "GET",
            b"/page?q=%3Cscript%3Ealert(1)%3C/script%3E",
            None,
        )
        .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(406)
        );
    }

    #[test]
    fn custom_rule_matches() {
        let mut cfg = make_config();
        cfg.custom_rules = vec![r"(?i)evil\.payload".to_string()];
        let plugin = WafPlugin::try_new(cfg).unwrap();

        let req =
            pingora_http::RequestHeader::build("GET", b"/api?data=evil.payload", None).unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn xss_in_referer_header_blocked() {
        let plugin = make_plugin();
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("referer", "http://evil.com/<script>alert(1)</script>")
            .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );
    }

    #[test]
    fn sqli_only_mode() {
        let cfg = WafConfig {
            sql_injection: true,
            xss: false,
            path_traversal: false,
            command_injection: false,
            protocol_attack: false,
            scanner_detection: false,
            custom_rules: vec![],
            exclude_paths: vec![],
            block_status: 403,
            mode: "block".to_string(),
        };
        let plugin = WafPlugin::try_new(cfg).unwrap();

        // SQLi should still be blocked
        let req = pingora_http::RequestHeader::build(
            "GET",
            b"/api?q=UNION%20SELECT%20*%20FROM%20users",
            None,
        )
        .unwrap();
        let mut ctx = RequestContext::new();
        assert_eq!(
            plugin.on_request(&req, &mut ctx),
            PluginAction::Handled(403)
        );

        // XSS should pass since it's disabled
        let req2 = pingora_http::RequestHeader::build(
            "GET",
            b"/page?q=%3Cscript%3Ealert(1)%3C/script%3E",
            None,
        )
        .unwrap();
        let mut ctx2 = RequestContext::new();
        assert_eq!(plugin.on_request(&req2, &mut ctx2), PluginAction::Continue);
    }
}
