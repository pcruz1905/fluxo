//! Route matchers — host, path, method, and header matching.
//!
//! Matchers are compiled from config strings at load time and used
//! for fast matching on the hot path. Uses enum dispatch (not trait objects)
//! because the set of matcher types is closed and this is on the hot path.

use crate::routing::RoutingError;

/// A single match condition, pre-compiled from config at load time.
///
/// Uses enum dispatch for zero vtable overhead on the hot path.
#[derive(Debug)]
pub enum RouteMatcher {
    /// Match on the Host header.
    Host(HostMatcher),
    /// Match on the request path.
    Path(PathMatcher),
    /// Match on the HTTP method.
    Method(MethodMatcher),
}

impl RouteMatcher {
    /// Test whether this matcher matches the given request headers.
    pub fn matches(&self, host: Option<&str>, path: &str, method: &str) -> bool {
        match self {
            Self::Host(m) => match host {
                Some(h) => m.matches(h),
                None => false,
            },
            Self::Path(m) => m.matches(path),
            Self::Method(m) => m.matches(method),
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
        if let Some(suffix) = pattern.strip_prefix('*') {
            HostMatcher::Wildcard {
                suffix: suffix.to_lowercase(),
            }
        } else {
            HostMatcher::Exact(pattern.to_lowercase())
        }
    }

    /// Test whether this matcher matches the given host string.
    pub fn matches(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        // Strip port if present (e.g., "example.com:443" → "example.com")
        let host_name = host_lower.split(':').next().unwrap_or(&host_lower);
        match self {
            HostMatcher::Exact(expected) => host_name == expected,
            HostMatcher::Wildcard { suffix } => host_name.ends_with(suffix.as_str()),
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
            Ok(PathMatcher::Glob(glob_pat))
        } else if pattern.ends_with('*') {
            // "/v1/*" → prefix "/v1/"
            let prefix = &pattern[..pattern.len() - 1];
            Ok(PathMatcher::Prefix(prefix.to_string()))
        } else if pattern.ends_with('/') && pattern != "/" {
            // "/v1/" → prefix "/v1/"
            Ok(PathMatcher::Prefix(pattern.to_string()))
        } else {
            Ok(PathMatcher::Exact(pattern.to_string()))
        }
    }

    /// Test whether this matcher matches the given path.
    pub fn matches(&self, path: &str) -> bool {
        match self {
            PathMatcher::Exact(expected) => path == expected,
            PathMatcher::Prefix(prefix) => path.starts_with(prefix),
            PathMatcher::Glob(pattern) => pattern.matches(path),
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

#[cfg(test)]
mod tests {
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
}
