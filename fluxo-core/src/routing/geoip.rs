//! GeoIP-based route matching using `MaxMind` DB files.
//!
//! Supports matching by country code (ISO 3166-1 alpha-2).
//! Requires a `MaxMind` `GeoLite2` or `GeoIP2` database file (`.mmdb`).

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::Reader;
use serde::Deserialize;

/// A shared `GeoIP` database reader (thread-safe).
#[derive(Debug, Clone)]
pub struct GeoIpDb {
    reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIpDb {
    /// Open a `MaxMind` DB file.
    pub fn open(path: &str) -> Result<Self, String> {
        if !Path::new(path).exists() {
            return Err(format!("GeoIP database not found: {path}"));
        }
        let reader = Reader::open_readfile(path)
            .map_err(|e| format!("failed to open GeoIP database '{path}': {e}"))?;
        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    /// Look up the ISO country code for an IP address.
    /// Returns None if the IP is not found or the DB has no country data.
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        #[derive(Deserialize)]
        struct Country {
            iso_code: Option<String>,
        }
        #[derive(Deserialize)]
        struct GeoResult {
            country: Option<Country>,
        }

        let result: GeoResult = self.reader.lookup(ip).ok()?;
        result.country?.iso_code
    }
}

/// `GeoIP` route matcher configuration.
#[derive(Debug, Clone)]
pub struct GeoIpMatcher {
    /// Allowed country codes (uppercase ISO 3166-1 alpha-2).
    pub countries: Vec<String>,
    /// If true, match when country is NOT in the list (deny list).
    pub negate: bool,
}

impl GeoIpMatcher {
    /// Check if the given country code matches.
    pub fn matches(&self, country_code: Option<&str>) -> bool {
        let code = match country_code {
            Some(c) => c.to_uppercase(),
            None => return self.negate, // Unknown IP: match if negated (allow-by-default for deny lists)
        };
        let found = self.countries.iter().any(|c| c.eq_ignore_ascii_case(&code));
        if self.negate { !found } else { found }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn matcher_allows_listed_country() {
        let m = GeoIpMatcher {
            countries: vec!["US".to_string(), "CA".to_string()],
            negate: false,
        };
        assert!(m.matches(Some("US")));
        assert!(m.matches(Some("CA")));
        assert!(!m.matches(Some("DE")));
    }

    #[test]
    fn matcher_denies_listed_country() {
        let m = GeoIpMatcher {
            countries: vec!["CN".to_string(), "RU".to_string()],
            negate: true,
        };
        assert!(m.matches(Some("US"))); // not in deny list
        assert!(!m.matches(Some("CN"))); // in deny list
    }

    #[test]
    fn matcher_case_insensitive() {
        let m = GeoIpMatcher {
            countries: vec!["us".to_string()],
            negate: false,
        };
        assert!(m.matches(Some("US")));
        assert!(m.matches(Some("us")));
    }

    #[test]
    fn matcher_none_country_allow_list() {
        let m = GeoIpMatcher {
            countries: vec!["US".to_string()],
            negate: false,
        };
        assert!(!m.matches(None)); // unknown → no match
    }

    #[test]
    fn matcher_none_country_deny_list() {
        let m = GeoIpMatcher {
            countries: vec!["CN".to_string()],
            negate: true,
        };
        assert!(m.matches(None)); // unknown → match (not in deny list)
    }

    #[test]
    fn matcher_empty_list_allow() {
        let m = GeoIpMatcher {
            countries: vec![],
            negate: false,
        };
        assert!(!m.matches(Some("US"))); // nothing allowed
    }

    #[test]
    fn matcher_empty_list_deny() {
        let m = GeoIpMatcher {
            countries: vec![],
            negate: true,
        };
        assert!(m.matches(Some("US"))); // nothing denied
    }
}
