//! Traffic splitting plugin — weighted routing to alternate upstreams for canary/A-B testing.
//!
//! Unlike traffic mirroring (fire-and-forget copy), traffic splitting actually
//! routes the request to a different upstream and returns that upstream's response.

use serde::Deserialize;

use crate::context::RequestContext;
use crate::plugins::PluginAction;

/// Traffic splitting configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TrafficSplitConfig {
    /// Split rules evaluated in order. First match wins.
    pub rules: Vec<SplitRule>,

    /// Cookie name for sticky splits. When set, once a client is assigned
    /// to a split, subsequent requests use the same split.
    /// Default: none (no stickiness).
    pub sticky_cookie: Option<String>,

    /// Cookie TTL in seconds for sticky splits. Default: 3600.
    #[serde(default = "default_sticky_ttl")]
    pub sticky_ttl: u64,
}

/// A single split rule — routes a percentage of traffic to an alternate upstream.
#[derive(Debug, Clone, Deserialize)]
pub struct SplitRule {
    /// Name of the alternate upstream to route to.
    pub upstream: String,

    /// Weight (0-100) — percentage of traffic routed to this upstream.
    /// All weights across rules should sum to <= 100.
    /// Remaining traffic goes to the route's default upstream.
    pub weight: u8,

    /// Optional header match — only apply this rule when this header matches.
    pub match_header: Option<SplitHeaderMatch>,
}

/// Header-based split condition.
#[derive(Debug, Clone, Deserialize)]
pub struct SplitHeaderMatch {
    /// Header name to check.
    pub name: String,
    /// Expected header value (exact match).
    pub value: String,
}

fn default_sticky_ttl() -> u64 {
    3600
}

/// Traffic splitting plugin.
#[derive(Debug)]
pub struct TrafficSplitPlugin {
    rules: Vec<CompiledSplitRule>,
    sticky_cookie: Option<String>,
    sticky_ttl: u64,
}

#[derive(Debug)]
struct CompiledSplitRule {
    upstream: String,
    weight: u8,
    match_header: Option<SplitHeaderMatch>,
}

impl TrafficSplitPlugin {
    pub fn new(cfg: TrafficSplitConfig) -> Self {
        let rules = cfg
            .rules
            .into_iter()
            .map(|r| CompiledSplitRule {
                upstream: r.upstream,
                weight: r.weight,
                match_header: r.match_header,
            })
            .collect();
        Self {
            rules,
            sticky_cookie: cfg.sticky_cookie,
            sticky_ttl: cfg.sticky_ttl,
        }
    }

    pub fn on_request(
        &self,
        req: &pingora_http::RequestHeader,
        ctx: &mut RequestContext,
    ) -> PluginAction {
        // Check sticky cookie first
        if let Some(ref cookie_name) = self.sticky_cookie {
            if let Some(upstream) = self.read_sticky_cookie(req, cookie_name) {
                // Validate that this upstream is still in our rules
                if self.rules.iter().any(|r| r.upstream == upstream) {
                    ctx.set_extension("traffic_split_upstream", serde_json::json!(upstream));
                    return PluginAction::Continue;
                }
            }
        }

        // Evaluate split rules
        let roll = fastrand::u8(0..100);
        let mut cumulative = 0u8;

        for rule in &self.rules {
            // Check header match condition
            if let Some(ref header_match) = rule.match_header {
                let matches = req
                    .headers
                    .get(&header_match.name)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v == header_match.value);
                if !matches {
                    continue;
                }
            }

            cumulative = cumulative.saturating_add(rule.weight);
            if roll < cumulative {
                ctx.set_extension(
                    "traffic_split_upstream",
                    serde_json::json!(rule.upstream),
                );

                // Set sticky cookie if configured
                if self.sticky_cookie.is_some() {
                    ctx.set_extension(
                        "traffic_split_sticky",
                        serde_json::json!(rule.upstream),
                    );
                }
                return PluginAction::Continue;
            }
        }

        // No split matched — use default upstream
        PluginAction::Continue
    }

    pub fn on_response(
        &self,
        resp: &mut pingora_http::ResponseHeader,
        ctx: &mut RequestContext,
    ) {
        // Set sticky cookie if a split was assigned
        if let Some(ref cookie_name) = self.sticky_cookie {
            if let Some(upstream) = ctx
                .get_extension("traffic_split_sticky")
                .and_then(|v| v.as_str())
            {
                let cookie = format!(
                    "{cookie_name}={upstream}; Path=/; Max-Age={}; HttpOnly",
                    self.sticky_ttl
                );
                let _ = resp.append_header("Set-Cookie", &cookie);
            }
        }
    }

    fn read_sticky_cookie(
        &self,
        req: &pingora_http::RequestHeader,
        cookie_name: &str,
    ) -> Option<String> {
        let cookie_header = req.headers.get("cookie")?.to_str().ok()?;
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some((name, value)) = cookie.split_once('=') {
                if name.trim() == cookie_name {
                    return Some(value.trim().to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_plugin() -> TrafficSplitPlugin {
        TrafficSplitPlugin::new(TrafficSplitConfig {
            rules: vec![SplitRule {
                upstream: "canary".to_string(),
                weight: 50,
                match_header: None,
            }],
            sticky_cookie: None,
            sticky_ttl: 3600,
        })
    }

    #[test]
    fn traffic_split_always_continues() {
        let plugin = make_plugin();
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        // Should always return Continue (split or not)
        assert_eq!(plugin.on_request(&req, &mut ctx), PluginAction::Continue);
    }

    #[test]
    fn header_match_rule() {
        let plugin = TrafficSplitPlugin::new(TrafficSplitConfig {
            rules: vec![SplitRule {
                upstream: "canary".to_string(),
                weight: 100, // Always route when header matches
                match_header: Some(SplitHeaderMatch {
                    name: "X-Canary".to_string(),
                    value: "true".to_string(),
                }),
            }],
            sticky_cookie: None,
            sticky_ttl: 3600,
        });

        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-Canary", "true").unwrap();
        let mut ctx = RequestContext::new();
        plugin.on_request(&req, &mut ctx);
        assert_eq!(
            ctx.get_extension("traffic_split_upstream"),
            Some(&serde_json::json!("canary"))
        );
    }

    #[test]
    fn header_match_no_match() {
        let plugin = TrafficSplitPlugin::new(TrafficSplitConfig {
            rules: vec![SplitRule {
                upstream: "canary".to_string(),
                weight: 100,
                match_header: Some(SplitHeaderMatch {
                    name: "X-Canary".to_string(),
                    value: "true".to_string(),
                }),
            }],
            sticky_cookie: None,
            sticky_ttl: 3600,
        });

        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let mut ctx = RequestContext::new();
        plugin.on_request(&req, &mut ctx);
        // No header match → no split
        assert!(ctx.get_extension("traffic_split_upstream").is_none());
    }
}
