//! Routing — route table compilation and request matching.
//!
//! Routes are compiled from config at load time into `CompiledRoute`s with
//! pre-built matchers. At request time, the `RouteTable` performs a linear
//! scan (first-match-wins) over compiled routes.

pub mod matcher;

use std::sync::Arc;

use matcher::{
    HeaderMatcher, HostMatcher, MethodMatcher, PathMatcher, RequestHeaders, RouteMatcher,
};
use thiserror::Error;

use crate::config::{FluxoConfig, RouteConfig};
use crate::plugins::PluginPipeline;
use crate::upstream::UpstreamName;

/// Errors that can occur during route compilation.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// An invalid glob pattern was specified.
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob {
        /// The pattern that failed to compile.
        pattern: String,
        /// The underlying glob error.
        source: glob::PatternError,
    },

    /// An invalid regex pattern was specified.
    #[error("invalid regex '{pattern}': {source}")]
    InvalidRegex {
        /// The pattern that failed to compile.
        pattern: String,
        /// The underlying regex error.
        source: regex::Error,
    },

    /// A plugin configuration error.
    #[error("plugin config error: {0}")]
    PluginConfig(#[from] crate::plugins::config::PluginConfigError),

    /// A cycle was detected in parent route references.
    #[error("cycle detected in route parent chain: route '{0}' is part of a cycle")]
    CycleDetected(String),

    /// A parent route was referenced but not found.
    #[error("unknown parent route '{0}': no route with this name exists")]
    UnknownParent(String),
}

/// A compiled route table, built from config at load time.
///
/// Routes are evaluated in config order (first match wins).
/// Linear scan on `Vec<CompiledRoute>` — simple and fast for < 100 routes.
/// The abstraction hides the implementation, so we can swap to a trie later.
#[derive(Debug)]
pub struct RouteTable {
    routes: Vec<CompiledRoute>,
}

/// A single route with pre-compiled matchers, ready for request-time matching.
#[derive(Debug)]
pub struct CompiledRoute {
    /// All matchers must pass for this route to match.
    pub matchers: Vec<RouteMatcher>,
    /// Which upstream group to forward matching requests to.
    pub upstream: UpstreamName,
    /// Display name for logging.
    pub name: Option<Arc<str>>,
    /// Index of this route in the table (for `MatchedRoute` references).
    pub index: usize,
    /// Plugin pipeline for this route (compiled at config load time).
    pub pipeline: PluginPipeline,
    /// Maximum request body size in bytes. `None` = unlimited.
    /// Parsed at compile time from `RouteConfig::max_request_body`.
    pub max_body_bytes: Option<u64>,
}

impl CompiledRoute {
    /// Test whether all matchers in this route match the given request.
    pub fn matches(&self, host: Option<&str>, path: &str, method: &str) -> bool {
        // Empty matchers = catch-all route (matches everything)
        self.matchers.iter().all(|m| m.matches(host, path, method))
    }

    /// Test whether all matchers match, including header matchers.
    pub fn matches_with_headers(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &dyn RequestHeaders,
    ) -> bool {
        self.matchers
            .iter()
            .all(|m| m.matches_with_headers(host, path, method, headers))
    }
}

impl RouteTable {
    /// Build a route table from the full config.
    ///
    /// Uses a 2-pass compilation (Traefik-inspired):
    /// 1. Build a name→config lookup for all named routes
    /// 2. Resolve parent chains, inheriting matchers + plugins from parents
    ///
    /// Detects cycles in parent references (A→B→A).
    /// Routes without `parent` work identically to before (backward-compatible).
    pub fn build(config: &FluxoConfig) -> Result<Self, RoutingError> {
        let mut routes = Vec::new();
        let mut index = 0;

        // Collect all routes across all services, preserving order
        let mut all_routes: Vec<&RouteConfig> = Vec::new();
        for service in config.services.values() {
            for route_config in &service.routes {
                all_routes.push(route_config);
            }
        }

        // Pass 1: build name→config lookup for parent resolution
        let mut named_routes: std::collections::HashMap<&str, &RouteConfig> =
            std::collections::HashMap::new();
        for rc in &all_routes {
            if let Some(name) = &rc.name {
                named_routes.insert(name.as_str(), rc);
            }
        }

        // Pass 2: compile routes, resolving parent chains
        for route_config in &all_routes {
            let merged = Self::resolve_parents(route_config, &named_routes)?;
            let compiled = Self::compile_route(&merged, index, &config.global.plugins)?;
            routes.push(compiled);
            index += 1;
        }

        Ok(Self { routes })
    }

    /// Resolve parent chain for a route, merging matchers and plugins.
    ///
    /// Parent matchers are prepended, parent plugins are prepended (run first).
    /// Detects cycles via a visited set.
    fn resolve_parents(
        route: &RouteConfig,
        named: &std::collections::HashMap<&str, &RouteConfig>,
    ) -> Result<RouteConfig, RoutingError> {
        let parent_name = match &route.parent {
            None => return Ok(route.clone()),
            Some(name) => name.clone(),
        };

        // Collect parent chain (child → parent → grandparent → ...)
        let mut chain: Vec<&RouteConfig> = vec![route];
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        if let Some(name) = &route.name {
            visited.insert(name.clone());
        }

        let mut current_parent = parent_name;
        loop {
            if visited.contains(&current_parent) {
                return Err(RoutingError::CycleDetected(current_parent));
            }
            visited.insert(current_parent.clone());

            let parent = named
                .get(current_parent.as_str())
                .ok_or_else(|| RoutingError::UnknownParent(current_parent.clone()))?;
            chain.push(parent);

            match &parent.parent {
                Some(next) => current_parent = next.clone(),
                None => break,
            }
        }

        // Merge: start from the root parent, layer each child's config on top
        chain.reverse(); // root-first order
        let mut merged = chain[0].clone();
        for child in &chain[1..] {
            // Append child's matchers (child's matchers are additional constraints)
            if !child.match_host.is_empty() {
                merged.match_host = child.match_host.clone();
            }
            if !child.match_path.is_empty() {
                merged.match_path = child.match_path.clone();
            }
            if !child.match_method.is_empty() {
                merged.match_method = child.match_method.clone();
            }
            for (k, v) in &child.match_header {
                merged.match_header.insert(k.clone(), v.clone());
            }
            // Child's plugins are merged on top of parent's (parent plugins run first)
            for (k, v) in &child.plugins {
                merged.plugins.insert(k.clone(), v.clone());
            }
            // Child overrides name, upstream, max_body
            if child.name.is_some() {
                merged.name = child.name.clone();
            }
            merged.upstream = child.upstream.clone();
            if child.max_request_body.is_some() {
                merged.max_request_body = child.max_request_body.clone();
            }
            // parent field not carried forward
            merged.parent = None;
        }

        Ok(merged)
    }

    /// Access compiled routes by slice (for pipeline lookups by index).
    pub fn routes(&self) -> &[CompiledRoute] {
        &self.routes
    }

    /// Compile a single route config into a `CompiledRoute`.
    fn compile_route(
        config: &RouteConfig,
        index: usize,
        global_plugins: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<CompiledRoute, RoutingError> {
        let mut matchers = Vec::new();

        // Compile host matchers (OR within, AND with other matcher types)
        if !config.match_host.is_empty() {
            let host_matchers: Vec<HostMatcher> = config
                .match_host
                .iter()
                .map(|p| HostMatcher::compile(p))
                .collect();
            matchers.push(RouteMatcher::Host(host_matchers));
        }

        // Compile path matchers (OR within, AND with other matcher types)
        if !config.match_path.is_empty() {
            let path_matchers: Vec<PathMatcher> = config
                .match_path
                .iter()
                .map(|p| PathMatcher::compile(p))
                .collect::<Result<_, _>>()?;
            matchers.push(RouteMatcher::Path(path_matchers));
        }

        // Compile method matchers
        if !config.match_method.is_empty() {
            matchers.push(RouteMatcher::Method(MethodMatcher::compile(
                &config.match_method,
            )));
        }

        // Compile header matchers
        for (name, value) in &config.match_header {
            matchers.push(RouteMatcher::Header(HeaderMatcher::compile(name, value)?));
        }

        // Compile plugin pipeline
        let plugin_list = crate::plugins::config::compile_plugins(&config.plugins, global_plugins)?;
        let pipeline = PluginPipeline::new(plugin_list);

        Ok(CompiledRoute {
            matchers,
            upstream: UpstreamName::from(config.upstream.as_str()),
            name: config.name.as_deref().map(Arc::from),
            index,
            pipeline,
            max_body_bytes: config
                .max_request_body
                .as_deref()
                .and_then(|s| crate::config::parse_size(s).ok()),
        })
    }

    /// Match an incoming request against all routes.
    ///
    /// Returns the first matching route (config order, first match wins).
    /// Returns `None` if no route matches.
    pub fn match_route(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
    ) -> Option<&CompiledRoute> {
        self.routes.iter().find(|r| r.matches(host, path, method))
    }

    /// Match an incoming request against all routes, including header matchers.
    pub fn match_route_with_headers(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &dyn RequestHeaders,
    ) -> Option<&CompiledRoute> {
        self.routes
            .iter()
            .find(|r| r.matches_with_headers(host, path, method, headers))
    }

    /// Return the number of compiled routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return whether the route table is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_config(toml_str: &str) -> FluxoConfig {
        // Use toml::from_str directly to skip validation (which checks upstreams)
        toml::from_str(toml_str).expect("test config should parse")
    }

    #[test]
    fn build_and_match_host_route() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "api"
  match_host = ["api.example.com"]
  upstream = "api-servers"

  [[services.web.routes]]
  name = "web"
  match_host = ["*.example.com"]
  upstream = "web-servers"

[upstreams.api-servers]
targets = ["10.0.1.1:8080"]
[upstreams.web-servers]
targets = ["10.0.2.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();
        assert_eq!(table.len(), 2);

        // Exact host match should hit "api" route
        let matched = table.match_route(Some("api.example.com"), "/anything", "GET");
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name.as_deref(), Some("api"));

        // Wildcard should hit "web" route (not api, since api is exact)
        let matched = table.match_route(Some("www.example.com"), "/", "GET");
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name.as_deref(), Some("web"));

        // No match
        let matched = table.match_route(Some("other.com"), "/", "GET");
        assert!(matched.is_none());
    }

    #[test]
    fn first_match_wins() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "specific"
  match_path = ["/api/v1/*"]
  upstream = "v1"

  [[services.web.routes]]
  name = "catch-all"
  upstream = "default"

[upstreams.v1]
targets = ["10.0.1.1:8080"]
[upstreams.default]
targets = ["10.0.2.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();

        // Specific route matches first
        let matched = table.match_route(None, "/api/v1/users", "GET");
        assert_eq!(matched.unwrap().name.as_deref(), Some("specific"));

        // Catch-all matches everything else
        let matched = table.match_route(None, "/other", "GET");
        assert_eq!(matched.unwrap().name.as_deref(), Some("catch-all"));
    }

    #[test]
    fn catch_all_route() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "catch-all"
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();

        // Empty matchers = matches everything
        let matched = table.match_route(Some("anything.com"), "/any/path", "POST");
        assert!(matched.is_some());
    }

    #[test]
    fn header_matching_route() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "debug"
  upstream = "backend"
  [services.web.routes.match_header]
  "X-Debug" = "true"

  [[services.web.routes]]
  name = "catch-all"
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();

        // Helper implementing RequestHeaders
        struct H(std::collections::HashMap<String, String>);
        impl matcher::RequestHeaders for H {
            fn get_header(&self, name: &str) -> Option<&str> {
                self.0.get(name).map(|s| s.as_str())
            }
        }

        // With X-Debug header → should match "debug" route
        let hdrs = H([("x-debug".to_string(), "true".to_string())]
            .into_iter()
            .collect());
        let matched = table.match_route_with_headers(None, "/", "GET", &hdrs);
        assert_eq!(matched.unwrap().name.as_deref(), Some("debug"));

        // Without header → falls through to catch-all
        let hdrs = H(std::collections::HashMap::new());
        let matched = table.match_route_with_headers(None, "/", "GET", &hdrs);
        assert_eq!(matched.unwrap().name.as_deref(), Some("catch-all"));
    }

    #[test]
    fn multi_host_matches_any() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "multi"
  match_host = ["api.example.com", "www.example.com"]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();

        // Both hosts should match the same route (OR semantics)
        let matched = table.match_route(Some("api.example.com"), "/", "GET");
        assert_eq!(matched.unwrap().name.as_deref(), Some("multi"));

        let matched = table.match_route(Some("www.example.com"), "/", "GET");
        assert_eq!(matched.unwrap().name.as_deref(), Some("multi"));

        // Non-listed host should NOT match
        let matched = table.match_route(Some("other.com"), "/", "GET");
        assert!(matched.is_none());
    }

    #[test]
    fn multi_path_matches_any() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "multi-path"
  match_path = ["/api/*", "/v2/*"]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();

        assert_eq!(
            table
                .match_route(None, "/api/users", "GET")
                .unwrap()
                .name
                .as_deref(),
            Some("multi-path")
        );
        assert_eq!(
            table
                .match_route(None, "/v2/items", "GET")
                .unwrap()
                .name
                .as_deref(),
            Some("multi-path")
        );
        assert!(table.match_route(None, "/other", "GET").is_none());
    }

    #[test]
    fn method_filtering() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "get-only"
  match_method = ["GET"]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();

        assert!(table.match_route(None, "/", "GET").is_some());
        assert!(table.match_route(None, "/", "POST").is_none());
    }

    #[test]
    fn hierarchical_route_inherits_parent_matchers() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "api-gateway"
  match_path = ["/api/*"]
  upstream = "backend"

  [[services.web.routes]]
  name = "api-users"
  parent = "api-gateway"
  match_path = ["/api/users/*"]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();

        // Parent route matches /api/*
        let m = table.match_route(None, "/api/v1", "GET");
        assert_eq!(m.unwrap().name.as_deref(), Some("api-gateway"));

        // Child route has its own path, overriding parent's
        let m = table.match_route(None, "/api/users/123", "GET");
        assert!(m.is_some());
    }

    #[test]
    fn hierarchical_route_cycle_detection() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "a"
  parent = "b"
  upstream = "backend"

  [[services.web.routes]]
  name = "b"
  parent = "a"
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let err = RouteTable::build(&cfg).unwrap_err();
        assert!(matches!(err, RoutingError::CycleDetected(_)));
    }

    #[test]
    fn hierarchical_route_unknown_parent() {
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "orphan"
  parent = "nonexistent"
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let err = RouteTable::build(&cfg).unwrap_err();
        assert!(matches!(err, RoutingError::UnknownParent(_)));
    }

    #[test]
    fn backward_compat_no_parent() {
        // Routes without parent work exactly as before
        let cfg = make_config(
            r#"
[services.web]
  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [[services.web.routes]]
  name = "simple"
  match_path = ["/hello"]
  upstream = "backend"

[upstreams.backend]
targets = ["127.0.0.1:3000"]
"#,
        );

        let table = RouteTable::build(&cfg).unwrap();
        assert!(table.match_route(None, "/hello", "GET").is_some());
        assert!(table.match_route(None, "/other", "GET").is_none());
    }
}
