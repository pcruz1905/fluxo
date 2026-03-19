//! Route matchers — host, path, method, and header matching.
//!
//! Matchers are compiled from config strings at load time and used
//! for fast matching on the hot path. Uses enum dispatch (not trait objects)
//! because the set of matcher types is closed and this is on the hot path.

use crate::routing::RoutingError;

/// A single match condition, pre-compiled from config at load time.
///
/// Uses enum dispatch for zero vtable overhead on the hot path.
/// Host and Path variants hold a vec — any match within the vec satisfies
/// the condition (OR semantics), while different matcher types are AND'd.
#[derive(Debug)]
pub enum RouteMatcher {
    /// Match on the Host header (any of the patterns).
    Host(Vec<HostMatcher>),
    /// Match on the request path (any of the patterns).
    Path(Vec<PathMatcher>),
    /// Match on the HTTP method.
    Method(MethodMatcher),
    /// Match on a request header value.
    Header(HeaderMatcher),
}

/// Request headers abstraction for matching.
///
/// Used by `RouteMatcher::matches_with_headers` to look up arbitrary headers.
pub trait RequestHeaders {
    /// Get the value of a header by name, or `None` if not present.
    fn get_header(&self, name: &str) -> Option<&str>;
}

impl RouteMatcher {
    /// Test whether this matcher matches the given request.
    ///
    /// For non-header matchers, this uses the pre-extracted host/path/method.
    /// Header matchers always return true here — use `matches_with_headers` for full matching.
    pub fn matches(&self, host: Option<&str>, path: &str, method: &str) -> bool {
        match self {
            Self::Host(matchers) => host.is_some_and(|h| matchers.iter().any(|m| m.matches(h))),
            Self::Path(matchers) => matchers.iter().any(|m| m.matches(path)),
            Self::Method(m) => m.matches(method),
            Self::Header(_) => true, // header matching requires headers; see matches_with_headers
        }
    }

    /// Test whether this matcher matches, with access to request headers.
    pub fn matches_with_headers(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &dyn RequestHeaders,
    ) -> bool {
        match self {
            Self::Host(matchers) => host.is_some_and(|h| matchers.iter().any(|m| m.matches(h))),
            Self::Path(matchers) => matchers.iter().any(|m| m.matches(path)),
            Self::Method(m) => m.matches(method),
            Self::Header(m) => m.matches(headers),
        }
    }
}

// ---------------------------------------------------------------------------
// Host matching
// ---------------------------------------------------------------------------

/// Matches request Host header values.
#[derive(Debug)]
pub enum HostMatcher {
    /// Exact match (e.g., "api.example.com").
    Exact(String),
    /// Wildcard suffix match (e.g., "*.example.com").
    /// Stores the suffix including the dot: ".example.com"
    Wildcard { suffix: String },
}

impl HostMatcher {
    /// Compile a host pattern from config.
    pub fn compile(pattern: &str) -> Self {
        pattern.strip_prefix('*').map_or_else(
            || Self::Exact(pattern.to_lowercase()),
            |suffix| Self::Wildcard {
                suffix: suffix.to_lowercase(),
            },
        )
    }

    /// Test whether this matcher matches the given host string.
    pub fn matches(&self, host: &str) -> bool {
        // Strip port if present (e.g., "example.com:443" → "example.com")
        let host_name = host.split(':').next().unwrap_or(host);
        match self {
            Self::Exact(expected) => host_name.eq_ignore_ascii_case(expected),
            Self::Wildcard { suffix } => {
                // suffix is stored lowercase; compare case-insensitively
                host_name.len() >= suffix.len()
                    && host_name[host_name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Path matching
// ---------------------------------------------------------------------------

/// Matches request paths.
#[derive(Debug)]
pub enum PathMatcher {
    /// Exact match (e.g., "/health").
    Exact(String),
    /// Prefix match (e.g., "/v1/" matches "/v1/users").
    Prefix(String),
    /// Glob match (e.g., "/api/*/resource").
    Glob(glob::Pattern),
}

impl PathMatcher {
    /// Compile a path pattern from config.
    ///
    /// Heuristics:
    /// - Contains `*` or `?` → glob
    /// - Ends with `/` or `*` → prefix (after stripping trailing `*`)
    /// - Otherwise → exact
    pub fn compile(pattern: &str) -> Result<Self, RoutingError> {
        if pattern.contains('?') || (pattern.contains('*') && pattern != "/*") {
            // Glob pattern
            let glob_pat = glob::Pattern::new(pattern).map_err(|e| RoutingError::InvalidGlob {
                pattern: pattern.to_string(),
                source: e,
            })?;
            Ok(Self::Glob(glob_pat))
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            // "/v1/*" → prefix "/v1/"
            Ok(Self::Prefix(prefix.to_string()))
        } else if pattern.ends_with('/') && pattern != "/" {
            // "/v1/" → prefix "/v1/"
            Ok(Self::Prefix(pattern.to_string()))
        } else {
            Ok(Self::Exact(pattern.to_string()))
        }
    }

    /// Test whether this matcher matches the given path.
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(expected) => path == expected,
            Self::Prefix(prefix) => path.starts_with(prefix),
            Self::Glob(pattern) => pattern.matches(path),
        }
    }
}

// ---------------------------------------------------------------------------
// Method matching
// ---------------------------------------------------------------------------

/// Matches HTTP methods.
#[derive(Debug)]
pub struct MethodMatcher {
    methods: Vec<String>,
}

impl MethodMatcher {
    /// Compile from a list of method strings (e.g., ["GET", "POST"]).
    pub fn compile(methods: &[String]) -> Self {
        Self {
            methods: methods.iter().map(|m| m.to_uppercase()).collect(),
        }
    }

    /// Test whether this matcher matches the given method.
    pub fn matches(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == method)
    }
}

// ---------------------------------------------------------------------------
// Header matching
// ---------------------------------------------------------------------------

/// Matches a request header value.
#[derive(Debug)]
pub struct HeaderMatcher {
    /// The header name to look up (lowercased for case-insensitive matching).
    pub name: String,
    /// How to match the header value.
    pub value_matcher: HeaderValueMatcher,
}

/// How to match a header value.
#[derive(Debug)]
pub enum HeaderValueMatcher {
    /// Exact string match.
    Exact(String),
    /// Regex match (pattern prefixed with `~` in config).
    Regex(regex::Regex),
}

impl HeaderMatcher {
    /// Compile a header matcher from a config name-value pair.
    ///
    /// If the value starts with `~`, the remainder is compiled as a regex.
    /// Otherwise, it's an exact match.
    pub fn compile(name: &str, value: &str) -> Result<Self, RoutingError> {
        let value_matcher = if let Some(pattern) = value.strip_prefix('~') {
            let re = regex::Regex::new(pattern).map_err(|e| RoutingError::InvalidRegex {
                pattern: pattern.to_string(),
                source: e,
            })?;
            HeaderValueMatcher::Regex(re)
        } else {
            HeaderValueMatcher::Exact(value.to_string())
        };

        Ok(Self {
            name: name.to_lowercase(),
            value_matcher,
        })
    }

    /// Test whether this matcher matches the given request headers.
    pub fn matches(&self, headers: &dyn RequestHeaders) -> bool {
        headers
            .get_header(&self.name)
            .is_some_and(|val| match &self.value_matcher {
                HeaderValueMatcher::Exact(expected) => val == expected,
                HeaderValueMatcher::Regex(re) => re.is_match(val),
            })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // --- Host matching ---

    #[test]
    fn host_exact_match() {
        let m = HostMatcher::compile("api.example.com");
        assert!(m.matches("api.example.com"));
        assert!(m.matches("API.Example.COM")); // case insensitive
        assert!(!m.matches("other.example.com"));
    }

    #[test]
    fn host_exact_with_port() {
        let m = HostMatcher::compile("api.example.com");
        assert!(m.matches("api.example.com:443"));
    }

    #[test]
    fn host_wildcard_match() {
        let m = HostMatcher::compile("*.example.com");
        assert!(m.matches("api.example.com"));
        assert!(m.matches("www.example.com"));
        assert!(m.matches("deep.sub.example.com"));
        assert!(!m.matches("example.com")); // no subdomain
        assert!(!m.matches("other.com"));
    }

    // --- Path matching ---

    #[test]
    fn path_exact_match() {
        let m = PathMatcher::compile("/health").unwrap();
        assert!(m.matches("/health"));
        assert!(!m.matches("/health/"));
        assert!(!m.matches("/healthz"));
    }

    #[test]
    fn path_prefix_match_with_star() {
        let m = PathMatcher::compile("/v1/*").unwrap();
        assert!(m.matches("/v1/users"));
        assert!(m.matches("/v1/"));
        assert!(!m.matches("/v2/users"));
    }

    #[test]
    fn path_prefix_match_with_slash() {
        let m = PathMatcher::compile("/api/").unwrap();
        assert!(m.matches("/api/users"));
        assert!(m.matches("/api/"));
        assert!(!m.matches("/api"));
    }

    #[test]
    fn path_glob_match() {
        let m = PathMatcher::compile("/api/*/items").unwrap();
        assert!(m.matches("/api/v1/items"));
        assert!(m.matches("/api/v2/items"));
        assert!(!m.matches("/api/v1/other"));
    }

    #[test]
    fn path_root_exact() {
        let m = PathMatcher::compile("/").unwrap();
        assert!(m.matches("/"));
        assert!(!m.matches("/foo"));
    }

    // --- Method matching ---

    #[test]
    fn method_match() {
        let m = MethodMatcher::compile(&["GET".to_string(), "POST".to_string()]);
        assert!(m.matches("GET"));
        assert!(m.matches("POST"));
        assert!(!m.matches("DELETE"));
    }

    #[test]
    fn method_case_insensitive_compile() {
        let m = MethodMatcher::compile(&["get".to_string()]);
        assert!(m.matches("GET"));
    }

    // --- Header matching ---

    /// Simple test helper for header matching.
    struct TestHeaders(std::collections::HashMap<String, String>);

    impl RequestHeaders for TestHeaders {
        fn get_header(&self, name: &str) -> Option<&str> {
            self.0.get(name).map(String::as_str)
        }
    }

    fn test_headers(pairs: &[(&str, &str)]) -> TestHeaders {
        TestHeaders(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn header_exact_match() {
        let m = HeaderMatcher::compile("X-Debug", "true").unwrap();
        let h = test_headers(&[("x-debug", "true")]);
        assert!(m.matches(&h));

        let h = test_headers(&[("x-debug", "false")]);
        assert!(!m.matches(&h));
    }

    #[test]
    fn header_missing_returns_false() {
        let m = HeaderMatcher::compile("X-Debug", "true").unwrap();
        let h = test_headers(&[]);
        assert!(!m.matches(&h));
    }

    #[test]
    fn header_regex_match() {
        let m = HeaderMatcher::compile("X-Version", "~^v[0-9]+").unwrap();
        let h = test_headers(&[("x-version", "v2")]);
        assert!(m.matches(&h));

        let h = test_headers(&[("x-version", "v123")]);
        assert!(m.matches(&h));

        let h = test_headers(&[("x-version", "latest")]);
        assert!(!m.matches(&h));
    }

    #[test]
    fn header_regex_invalid_pattern() {
        let result = HeaderMatcher::compile("X-Test", "~[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn header_name_case_insensitive() {
        let m = HeaderMatcher::compile("Content-Type", "application/json").unwrap();
        let h = test_headers(&[("content-type", "application/json")]);
        assert!(m.matches(&h));
    }
}
