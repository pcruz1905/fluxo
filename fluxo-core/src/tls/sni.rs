//! SNI-based certificate selection — serve different certificates per hostname.
//!
//! Supports multiple TLS certificates per service listener, selecting the
//! appropriate cert based on the TLS `ClientHello` SNI extension.
//! Nginx equivalent: multiple `ssl_certificate` directives + SNI.
//! Traefik equivalent: TLS stores with dynamic certificate selection.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A certificate entry for SNI-based selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniCertConfig {
    /// Hostnames this certificate covers (exact or wildcard like "*.example.com").
    pub domains: Vec<String>,
    /// Path to the certificate PEM file.
    pub cert_path: String,
    /// Path to the private key PEM file.
    pub key_path: String,
}

/// Compiled SNI certificate map for fast lookup.
#[derive(Debug, Clone)]
pub struct SniCertMap {
    /// Exact hostname → cert index.
    exact: HashMap<String, usize>,
    /// Wildcard entries (e.g., "*.example.com") → cert index.
    wildcards: Vec<(String, usize)>,
    /// Certificate entries.
    certs: Vec<SniCertEntry>,
}

/// A loaded certificate ready for use.
#[derive(Debug, Clone)]
pub struct SniCertEntry {
    /// PEM certificate content.
    pub cert_pem: String,
    /// PEM key content.
    pub key_pem: String,
    /// Original config domains.
    pub domains: Vec<String>,
}

impl SniCertMap {
    /// Build an SNI cert map from a list of certificate configs.
    pub fn build(configs: &[SniCertConfig]) -> Result<Self, String> {
        let mut exact = HashMap::new();
        let mut wildcards = Vec::new();
        let mut certs = Vec::new();

        for (idx, config) in configs.iter().enumerate() {
            // Validate cert/key files exist
            if !Path::new(&config.cert_path).exists() {
                return Err(format!(
                    "SNI certificate file not found: {}",
                    config.cert_path
                ));
            }
            if !Path::new(&config.key_path).exists() {
                return Err(format!("SNI key file not found: {}", config.key_path));
            }

            // Load cert/key content
            let cert_pem = std::fs::read_to_string(&config.cert_path)
                .map_err(|e| format!("failed to read cert '{}': {e}", config.cert_path))?;
            let key_pem = std::fs::read_to_string(&config.key_path)
                .map_err(|e| format!("failed to read key '{}': {e}", config.key_path))?;

            certs.push(SniCertEntry {
                cert_pem,
                key_pem,
                domains: config.domains.clone(),
            });

            // Index domains
            for domain in &config.domains {
                let lower = domain.to_lowercase();
                if lower.starts_with("*.") {
                    wildcards.push((lower, idx));
                } else {
                    exact.insert(lower, idx);
                }
            }
        }

        Ok(Self {
            exact,
            wildcards,
            certs,
        })
    }

    /// Look up the certificate for a given SNI hostname.
    /// Returns None if no matching cert is found.
    pub fn lookup(&self, sni: &str) -> Option<&SniCertEntry> {
        let lower = sni.to_lowercase();

        // Try exact match first
        if let Some(&idx) = self.exact.get(&lower) {
            return self.certs.get(idx);
        }

        // Try wildcard match
        for (pattern, idx) in &self.wildcards {
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if lower.ends_with(suffix) && lower.len() > suffix.len() {
                    // Ensure there's exactly one label before the suffix
                    let prefix = &lower[..lower.len() - suffix.len() - 1];
                    if !prefix.contains('.') {
                        return self.certs.get(*idx);
                    }
                }
            }
        }

        None
    }

    /// Whether the map is empty (no certificates configured).
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty()
    }

    /// Number of certificates in the map.
    pub fn len(&self) -> usize {
        self.certs.len()
    }

    /// Get the first certificate (fallback/default).
    pub fn default_cert(&self) -> Option<&SniCertEntry> {
        self.certs.first()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn make_map(entries: &[(Vec<&str>, &str, &str)]) -> SniCertMap {
        // Use in-memory entries without file I/O
        let mut exact = HashMap::new();
        let mut wildcards = Vec::new();
        let mut certs = Vec::new();

        for (idx, (domains, cert, key)) in entries.iter().enumerate() {
            certs.push(SniCertEntry {
                cert_pem: cert.to_string(),
                key_pem: key.to_string(),
                domains: domains.iter().copied().map(String::from).collect(),
            });
            for domain in domains {
                let lower = domain.to_lowercase();
                if lower.starts_with("*.") {
                    wildcards.push((lower, idx));
                } else {
                    exact.insert(lower, idx);
                }
            }
        }

        SniCertMap {
            exact,
            wildcards,
            certs,
        }
    }

    #[test]
    fn exact_match() {
        let map = make_map(&[
            (vec!["api.example.com"], "cert-a", "key-a"),
            (vec!["web.example.com"], "cert-b", "key-b"),
        ]);
        let cert = map.lookup("api.example.com").unwrap();
        assert_eq!(cert.cert_pem, "cert-a");
        let cert = map.lookup("web.example.com").unwrap();
        assert_eq!(cert.cert_pem, "cert-b");
    }

    #[test]
    fn case_insensitive_lookup() {
        let map = make_map(&[(vec!["API.Example.COM"], "cert-a", "key-a")]);
        assert!(map.lookup("api.example.com").is_some());
        assert!(map.lookup("API.EXAMPLE.COM").is_some());
    }

    #[test]
    fn wildcard_match() {
        let map = make_map(&[(vec!["*.example.com"], "cert-wild", "key-wild")]);
        assert!(map.lookup("api.example.com").is_some());
        assert!(map.lookup("web.example.com").is_some());
        // Should NOT match bare domain or nested subdomains
        assert!(map.lookup("example.com").is_none());
        assert!(map.lookup("deep.sub.example.com").is_none());
    }

    #[test]
    fn exact_takes_priority_over_wildcard() {
        let map = make_map(&[
            (vec!["*.example.com"], "cert-wild", "key-wild"),
            (vec!["api.example.com"], "cert-exact", "key-exact"),
        ]);
        let cert = map.lookup("api.example.com").unwrap();
        assert_eq!(cert.cert_pem, "cert-exact");
        let cert = map.lookup("web.example.com").unwrap();
        assert_eq!(cert.cert_pem, "cert-wild");
    }

    #[test]
    fn no_match_returns_none() {
        let map = make_map(&[(vec!["api.example.com"], "cert-a", "key-a")]);
        assert!(map.lookup("other.com").is_none());
    }

    #[test]
    fn empty_map() {
        let map = make_map(&[]);
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(map.default_cert().is_none());
        assert!(map.lookup("any.com").is_none());
    }

    #[test]
    fn default_cert_returns_first() {
        let map = make_map(&[
            (vec!["first.com"], "cert-1", "key-1"),
            (vec!["second.com"], "cert-2", "key-2"),
        ]);
        assert_eq!(map.default_cert().unwrap().cert_pem, "cert-1");
    }

    #[test]
    fn multiple_domains_per_cert() {
        let map = make_map(&[(
            vec!["example.com", "www.example.com"],
            "cert-multi",
            "key-multi",
        )]);
        assert!(map.lookup("example.com").is_some());
        assert!(map.lookup("www.example.com").is_some());
        assert!(map.lookup("other.com").is_none());
    }
}
