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
    /// Compiles all routes from all services into a single flat table.
    /// Fails if any route pattern is invalid.
    pub fn build(config: &FluxoConfig) -> Result<Self, RoutingError> {
        let mut routes = Vec::new();
        let mut index = 0;

        for service in config.services.values() {
            for route_config in &service.routes {
                let compiled = Self::compile_route(route_config, index)?;
                routes.push(compiled);
                index += 1;
            }
        }

        Ok(Self { routes })
    }

    /// Compile a single route config into a `CompiledRoute`.
    fn compile_route(config: &RouteConfig, index: usize) -> Result<CompiledRoute, RoutingError> {
        let mut matchers = Vec::new();

        // Compile host matchers
        if !config.match_host.is_empty() {
            for host_pattern in &config.match_host {
                matchers.push(RouteMatcher::Host(HostMatcher::compile(host_pattern)));
            }
        }

        // Compile path matchers
        if !config.match_path.is_empty() {
            for path_pattern in &config.match_path {
                matchers.push(RouteMatcher::Path(PathMatcher::compile(path_pattern)?));
            }
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

        Ok(CompiledRoute {
            matchers,
            upstream: UpstreamName::from(config.upstream.as_str()),
            name: config.name.as_deref().map(Arc::from),
            index,
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
}
