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

    #[test]
    fn len_returns_cert_count() {
        let map = make_map(&[
            (vec!["a.com"], "cert-a", "key-a"),
            (vec!["b.com"], "cert-b", "key-b"),
            (vec!["c.com"], "cert-c", "key-c"),
        ]);
        assert_eq!(map.len(), 3);
        assert!(!map.is_empty());
    }

    #[test]
    fn wildcard_case_insensitive() {
        let map = make_map(&[(vec!["*.Example.COM"], "cert-w", "key-w")]);
        assert!(map.lookup("sub.example.com").is_some());
        assert!(map.lookup("SUB.EXAMPLE.COM").is_some());
        assert!(map.lookup("Sub.Example.Com").is_some());
    }

    #[test]
    fn wildcard_does_not_match_bare_suffix() {
        // *.example.com should NOT match "example.com"
        let map = make_map(&[(vec!["*.example.com"], "cert-w", "key-w")]);
        assert!(map.lookup("example.com").is_none());
    }

    #[test]
    fn wildcard_matches_dot_prefix() {
        // ".example.com" ends up matching because the prefix is empty (no dots)
        let map = make_map(&[(vec!["*.example.com"], "cert-w", "key-w")]);
        assert!(map.lookup(".example.com").is_some());
    }

    #[test]
    fn wildcard_requires_single_label_prefix() {
        let map = make_map(&[(vec!["*.example.com"], "cert-w", "key-w")]);
        // Single label: OK
        assert!(map.lookup("api.example.com").is_some());
        // Two labels: NOT OK
        assert!(map.lookup("a.b.example.com").is_none());
        // Three labels: NOT OK
        assert!(map.lookup("a.b.c.example.com").is_none());
    }

    #[test]
    fn multiple_wildcards() {
        let map = make_map(&[
            (vec!["*.example.com"], "cert-ex", "key-ex"),
            (vec!["*.other.org"], "cert-ot", "key-ot"),
        ]);
        let cert = map.lookup("api.example.com").unwrap();
        assert_eq!(cert.cert_pem, "cert-ex");
        let cert = map.lookup("api.other.org").unwrap();
        assert_eq!(cert.cert_pem, "cert-ot");
        assert!(map.lookup("api.unknown.com").is_none());
    }

    #[test]
    fn lookup_returns_correct_key_pem() {
        let map = make_map(&[(vec!["host.com"], "my-cert", "my-key")]);
        let entry = map.lookup("host.com").unwrap();
        assert_eq!(entry.key_pem, "my-key");
        assert_eq!(entry.cert_pem, "my-cert");
    }

    #[test]
    fn lookup_returns_domains_in_entry() {
        let map = make_map(&[(vec!["example.com", "www.example.com"], "cert", "key")]);
        let entry = map.lookup("example.com").unwrap();
        assert_eq!(entry.domains.len(), 2);
        assert_eq!(entry.domains[0], "example.com");
        assert_eq!(entry.domains[1], "www.example.com");
    }

    #[test]
    fn build_missing_cert_file() {
        let configs = vec![SniCertConfig {
            domains: vec!["test.com".to_string()],
            cert_path: "/nonexistent/cert.pem".to_string(),
            key_path: "/nonexistent/key.pem".to_string(),
        }];
        let result = SniCertMap::build(&configs);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("certificate file not found"));
    }

    #[test]
    fn build_missing_key_file() {
        // Create a temp cert file but no key file
        let dir = std::env::temp_dir().join("fluxo_sni_test_key");
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("cert.pem");
        std::fs::write(&cert_path, "fake-cert").unwrap();

        let configs = vec![SniCertConfig {
            domains: vec!["test.com".to_string()],
            cert_path: cert_path.to_string_lossy().to_string(),
            key_path: "/nonexistent/key.pem".to_string(),
        }];
        let result = SniCertMap::build(&configs);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("key file not found"));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_with_valid_files() {
        let dir = std::env::temp_dir().join("fluxo_sni_test_valid");
        let _ = std::fs::create_dir_all(&dir);
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, "cert-content").unwrap();
        std::fs::write(&key_path, "key-content").unwrap();

        let configs = vec![SniCertConfig {
            domains: vec!["test.com".to_string(), "*.test.com".to_string()],
            cert_path: cert_path.to_string_lossy().to_string(),
            key_path: key_path.to_string_lossy().to_string(),
        }];
        let map = SniCertMap::build(&configs).unwrap();
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());

        let entry = map.lookup("test.com").unwrap();
        assert_eq!(entry.cert_pem, "cert-content");
        assert_eq!(entry.key_pem, "key-content");

        let entry = map.lookup("sub.test.com").unwrap();
        assert_eq!(entry.cert_pem, "cert-content");

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_empty_configs() {
        let map = SniCertMap::build(&[]).unwrap();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn sni_cert_config_serde_roundtrip() {
        let config = SniCertConfig {
            domains: vec!["example.com".to_string(), "*.example.com".to_string()],
            cert_path: "/etc/ssl/cert.pem".to_string(),
            key_path: "/etc/ssl/key.pem".to_string(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SniCertConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.domains, config.domains);
        assert_eq!(deserialized.cert_path, config.cert_path);
        assert_eq!(deserialized.key_path, config.key_path);
    }

    #[test]
    fn sni_cert_config_clone() {
        let config = SniCertConfig {
            domains: vec!["a.com".to_string()],
            cert_path: "/cert".to_string(),
            key_path: "/key".to_string(),
        };
        let cloned = config.clone();
        assert_eq!(cloned.domains, config.domains);
        assert_eq!(cloned.cert_path, config.cert_path);
        assert_eq!(cloned.key_path, config.key_path);
    }

    #[test]
    fn sni_cert_entry_clone() {
        let entry = SniCertEntry {
            cert_pem: "cert-data".to_string(),
            key_pem: "key-data".to_string(),
            domains: vec!["d.com".to_string()],
        };
        let cloned = entry;
        assert_eq!(cloned.cert_pem, "cert-data");
        assert_eq!(cloned.key_pem, "key-data");
        assert_eq!(cloned.domains, vec!["d.com"]);
    }

    #[test]
    fn default_cert_from_nonempty_map() {
        let map = make_map(&[
            (vec!["first.com"], "cert-first", "key-first"),
            (vec!["second.com"], "cert-second", "key-second"),
        ]);
        let default = map.default_cert().unwrap();
        assert_eq!(default.cert_pem, "cert-first");
        assert_eq!(default.key_pem, "key-first");
    }

    #[test]
    fn sni_cert_map_clone() {
        let map = make_map(&[(vec!["a.com", "*.a.com"], "cert-a", "key-a")]);
        let cloned = map;
        assert_eq!(cloned.len(), 1);
        assert!(cloned.lookup("a.com").is_some());
        assert!(cloned.lookup("sub.a.com").is_some());
    }

    #[test]
    fn wildcard_mixed_with_exact_same_cert() {
        let map = make_map(&[(
            vec!["example.com", "*.example.com"],
            "cert-both",
            "key-both",
        )]);
        // Exact match for base domain
        let entry = map.lookup("example.com").unwrap();
        assert_eq!(entry.cert_pem, "cert-both");
        // Wildcard match for subdomain
        let entry = map.lookup("api.example.com").unwrap();
        assert_eq!(entry.cert_pem, "cert-both");
    }
}
