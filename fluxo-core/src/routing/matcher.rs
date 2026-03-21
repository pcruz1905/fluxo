//! Route matchers — host, path, method, header, query, and client IP matching.
//!
//! Matchers are compiled from config strings at load time and used
//! for fast matching on the hot path. Uses enum dispatch (not trait objects)
//! because the set of matcher types is closed and this is on the hot path.

use std::net::IpAddr;

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
    /// Match on query string parameters.
    Query(QueryMatcher),
    /// Match on client IP address (supports CIDR notation).
    ClientIP(ClientIPMatcher),
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
    /// Header/Query/ClientIP matchers always return true here — use `matches_full` for full matching.
    pub fn matches(&self, host: Option<&str>, path: &str, method: &str) -> bool {
        match self {
            Self::Host(matchers) => host.is_some_and(|h| matchers.iter().any(|m| m.matches(h))),
            Self::Path(matchers) => matchers.iter().any(|m| m.matches(path)),
            Self::Method(m) => m.matches(method),
            Self::Header(_) | Self::Query(_) | Self::ClientIP(_) => true,
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
            Self::Query(_) | Self::ClientIP(_) => true,
        }
    }

    /// Full matching with all request context: headers, query string, and client IP.
    ///
    /// This is the primary matcher used in the proxy hot path.
    pub fn matches_full(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &dyn RequestHeaders,
        query: Option<&str>,
        client_ip: Option<&str>,
    ) -> bool {
        match self {
            Self::Host(matchers) => host.is_some_and(|h| matchers.iter().any(|m| m.matches(h))),
            Self::Path(matchers) => matchers.iter().any(|m| m.matches(path)),
            Self::Method(m) => m.matches(method),
            Self::Header(m) => m.matches(headers),
            Self::Query(m) => m.matches(query),
            Self::ClientIP(m) => m.matches(client_ip),
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
    /// Regex match (e.g., "~^api-[0-9]+\\.example\\.com$").
    /// Pattern prefixed with `~` in config.
    Regex(regex::Regex),
}

impl HostMatcher {
    /// Compile a host pattern from config.
    ///
    /// - `~pattern` → regex
    /// - `*suffix` → wildcard
    /// - otherwise → exact
    pub fn compile(pattern: &str) -> Result<Self, RoutingError> {
        if let Some(re_pattern) = pattern.strip_prefix('~') {
            let re = regex::Regex::new(re_pattern).map_err(|e| RoutingError::InvalidRegex {
                pattern: re_pattern.to_string(),
                source: e,
            })?;
            Ok(Self::Regex(re))
        } else if let Some(suffix) = pattern.strip_prefix('*') {
            Ok(Self::Wildcard {
                suffix: suffix.to_lowercase(),
            })
        } else {
            Ok(Self::Exact(pattern.to_lowercase()))
        }
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
            Self::Regex(re) => re.is_match(host_name),
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
    /// Regex match (e.g., "~^/api/v[0-9]+/").
    /// Pattern prefixed with `~` in config.
    Regex(regex::Regex),
}

impl PathMatcher {
    /// Compile a path pattern from config.
    ///
    /// Heuristics:
    /// - Starts with `~` → regex
    /// - Contains `*` or `?` → glob
    /// - Ends with `/` or `*` → prefix (after stripping trailing `*`)
    /// - Otherwise → exact
    pub fn compile(pattern: &str) -> Result<Self, RoutingError> {
        if let Some(re_pattern) = pattern.strip_prefix('~') {
            let re = regex::Regex::new(re_pattern).map_err(|e| RoutingError::InvalidRegex {
                pattern: re_pattern.to_string(),
                source: e,
            })?;
            Ok(Self::Regex(re))
        } else if pattern.contains('?') || (pattern.contains('*') && pattern != "/*") {
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
            Self::Regex(re) => re.is_match(path),
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

// ---------------------------------------------------------------------------
// Query string matching
// ---------------------------------------------------------------------------

/// How to match a query parameter value.
#[derive(Debug)]
pub enum QueryValueMatcher {
    /// Key must be present (any value or no value).
    Present,
    /// Exact string match.
    Exact(String),
    /// Regex match (pattern prefixed with `~` in config).
    Regex(regex::Regex),
}

/// Matches a query string parameter.
#[derive(Debug)]
pub struct QueryMatcher {
    /// The query parameter key to look up.
    pub key: String,
    /// How to match the value.
    pub value_matcher: QueryValueMatcher,
}

impl QueryMatcher {
    /// Compile a query matcher from a config key-value pair.
    ///
    /// - Empty value → `Present` (key must exist)
    /// - Value starts with `~` → regex
    /// - Otherwise → exact match
    pub fn compile(key: &str, value: &str) -> Result<Self, RoutingError> {
        let value_matcher = if value.is_empty() {
            QueryValueMatcher::Present
        } else if let Some(pattern) = value.strip_prefix('~') {
            let re = regex::Regex::new(pattern).map_err(|e| RoutingError::InvalidRegex {
                pattern: pattern.to_string(),
                source: e,
            })?;
            QueryValueMatcher::Regex(re)
        } else {
            QueryValueMatcher::Exact(value.to_string())
        };
        Ok(Self {
            key: key.to_string(),
            value_matcher,
        })
    }

    /// Test whether this matcher matches the given query string.
    ///
    /// `query` is the raw query string without the leading `?`.
    pub fn matches(&self, query: Option<&str>) -> bool {
        let Some(qs) = query else { return false };
        // Parse query params: split on `&`, then key=value
        for pair in qs.split('&') {
            let (k, v) = pair.split_once('=').map_or((pair, ""), |(k, v)| (k, v));
            if k == self.key {
                return match &self.value_matcher {
                    QueryValueMatcher::Present => true,
                    QueryValueMatcher::Exact(expected) => v == expected,
                    QueryValueMatcher::Regex(re) => re.is_match(v),
                };
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Client IP matching
// ---------------------------------------------------------------------------

/// Matches client IP addresses against CIDR ranges.
#[derive(Debug)]
pub struct ClientIPMatcher {
    /// Allowed networks. Client IP must match at least one.
    pub networks: Vec<ipnet::IpNet>,
}

impl ClientIPMatcher {
    /// Compile from a list of CIDR strings (e.g., ["10.0.0.0/8", "192.168.1.0/24"]).
    ///
    /// Plain IP addresses (without `/prefix`) are treated as single-host CIDRs.
    pub fn compile(cidrs: &[String]) -> Result<Self, RoutingError> {
        let mut networks = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            // If no prefix length, append /32 (IPv4) or /128 (IPv6)
            let net: ipnet::IpNet = if cidr.contains('/') {
                cidr.parse().map_err(|_| RoutingError::InvalidCidr {
                    cidr: cidr.clone(),
                })?
            } else {
                // Bare IP → single-host network
                let ip: IpAddr = cidr.parse().map_err(|_| RoutingError::InvalidCidr {
                    cidr: cidr.clone(),
                })?;
                ipnet::IpNet::from(ip)
            };
            networks.push(net);
        }
        Ok(Self { networks })
    }

    /// Test whether the given client IP matches any of the configured networks.
    pub fn matches(&self, client_ip: Option<&str>) -> bool {
        let Some(ip_str) = client_ip else {
            return false;
        };
        // Strip port if present ("1.2.3.4:5678" → "1.2.3.4")
        let ip_part = ip_str.split(':').next().unwrap_or(ip_str);
        let Ok(ip) = ip_part.parse::<IpAddr>() else {
            return false;
        };
        self.networks.iter().any(|net| net.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // --- Host matching ---

    #[test]
    fn host_exact_match() {
        let m = HostMatcher::compile("api.example.com").unwrap();
        assert!(m.matches("api.example.com"));
        assert!(m.matches("API.Example.COM")); // case insensitive
        assert!(!m.matches("other.example.com"));
    }

    #[test]
    fn host_exact_with_port() {
        let m = HostMatcher::compile("api.example.com").unwrap();
        assert!(m.matches("api.example.com:443"));
    }

    #[test]
    fn host_wildcard_match() {
        let m = HostMatcher::compile("*.example.com").unwrap();
        assert!(m.matches("api.example.com"));
        assert!(m.matches("www.example.com"));
        assert!(m.matches("deep.sub.example.com"));
        assert!(!m.matches("example.com")); // no subdomain
        assert!(!m.matches("other.com"));
    }

    #[test]
    fn host_regex_match() {
        let m = HostMatcher::compile("~^api-[0-9]+\\.example\\.com$").unwrap();
        assert!(m.matches("api-1.example.com"));
        assert!(m.matches("api-42.example.com"));
        assert!(!m.matches("api.example.com"));
        assert!(!m.matches("www.example.com"));
    }

    #[test]
    fn host_regex_invalid_pattern() {
        let result = HostMatcher::compile("~[invalid");
        assert!(result.is_err());
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

    #[test]
    fn path_regex_match() {
        let m = PathMatcher::compile("~^/api/v[0-9]+/").unwrap();
        assert!(m.matches("/api/v1/users"));
        assert!(m.matches("/api/v2/items"));
        assert!(!m.matches("/api/latest/users"));
    }

    #[test]
    fn path_regex_invalid_pattern() {
        let result = PathMatcher::compile("~[invalid");
        assert!(result.is_err());
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

    // --- Query matching ---

    #[test]
    fn query_exact_match() {
        let m = QueryMatcher::compile("page", "1").unwrap();
        assert!(m.matches(Some("page=1&sort=asc")));
        assert!(!m.matches(Some("page=2")));
        assert!(!m.matches(Some("other=1")));
    }

    #[test]
    fn query_present_match() {
        let m = QueryMatcher::compile("debug", "").unwrap();
        assert!(m.matches(Some("debug=true")));
        assert!(m.matches(Some("debug=")));
        assert!(m.matches(Some("debug")));
        assert!(!m.matches(Some("other=1")));
    }

    #[test]
    fn query_regex_match() {
        let m = QueryMatcher::compile("version", "~^v[0-9]+").unwrap();
        assert!(m.matches(Some("version=v2")));
        assert!(m.matches(Some("version=v123")));
        assert!(!m.matches(Some("version=latest")));
    }

    #[test]
    fn query_no_query_string() {
        let m = QueryMatcher::compile("page", "1").unwrap();
        assert!(!m.matches(None));
    }

    #[test]
    fn query_invalid_regex() {
        let result = QueryMatcher::compile("q", "~[invalid");
        assert!(result.is_err());
    }

    // --- ClientIP matching ---

    #[test]
    fn client_ip_single_match() {
        let m = ClientIPMatcher::compile(&["10.0.0.1".to_string()]).unwrap();
        assert!(m.matches(Some("10.0.0.1")));
        assert!(!m.matches(Some("10.0.0.2")));
    }

    #[test]
    fn client_ip_cidr_match() {
        let m = ClientIPMatcher::compile(&["10.0.0.0/24".to_string()]).unwrap();
        assert!(m.matches(Some("10.0.0.1")));
        assert!(m.matches(Some("10.0.0.255")));
        assert!(!m.matches(Some("10.0.1.1")));
    }

    #[test]
    fn client_ip_multiple_cidrs() {
        let m = ClientIPMatcher::compile(&[
            "10.0.0.0/8".to_string(),
            "192.168.0.0/16".to_string(),
        ])
        .unwrap();
        assert!(m.matches(Some("10.1.2.3")));
        assert!(m.matches(Some("192.168.1.1")));
        assert!(!m.matches(Some("172.16.0.1")));
    }

    #[test]
    fn client_ip_no_ip() {
        let m = ClientIPMatcher::compile(&["10.0.0.0/8".to_string()]).unwrap();
        assert!(!m.matches(None));
    }

    #[test]
    fn client_ip_invalid_cidr() {
        let result = ClientIPMatcher::compile(&["not-a-cidr".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn client_ip_with_port() {
        let m = ClientIPMatcher::compile(&["10.0.0.0/8".to_string()]).unwrap();
        assert!(m.matches(Some("10.1.2.3:8080")));
    }
}
