//! Certificate Transparency (CT) — SCT extraction and `Expect-CT` header support.
//!
//! Extracts Signed Certificate Timestamps (SCTs) embedded in X.509 certificates
//! (RFC 6962) and provides the information for logging and header injection.
//!
//! Modern browsers enforce CT by default (Chrome since 2018, Safari, Firefox).
//! This module verifies that certificates carry valid SCTs and can inject
//! the `Expect-CT` response header for reporting.
//!
//! Example config:
//! ```toml
//! [services.web.tls]
//! cert_path = "/etc/certs/cert.pem"
//! key_path = "/etc/certs/key.pem"
//! certificate_transparency = true  # Enable CT checking (default: false)
//! ct_enforce = false               # Enforce CT (fail handshake without SCTs, default: false)
//! ct_report_uri = "https://example.com/ct-report"  # Optional report URI
//! ```

use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};
use x509_parser::prelude::*;

use ::pem as pem_crate;

/// DER-encoded OID bytes for the SCT List extension (RFC 6962, Section 3.3).
/// OID: `1.3.6.1.4.1.11129.2.4.2`
const SCT_LIST_OID_BYTES: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02];

/// A parsed Signed Certificate Timestamp.
#[derive(Debug, Clone)]
pub struct Sct {
    /// SCT version (currently only v1 = 0).
    pub version: u8,
    /// Log ID — SHA-256 hash of the log's public key (32 bytes).
    pub log_id: [u8; 32],
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp: u64,
    /// Length of the extensions field.
    pub extensions_len: u16,
}

/// Certificate Transparency state for a service.
#[derive(Clone)]
pub struct CtState {
    /// Parsed SCTs from the certificate.
    inner: Arc<RwLock<Vec<Sct>>>,
}

impl Default for CtState {
    fn default() -> Self {
        Self::new()
    }
}

impl CtState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Store parsed SCTs.
    pub fn set(&self, scts: Vec<Sct>) {
        *self.inner.write() = scts;
    }

    /// Get the number of embedded SCTs.
    pub fn count(&self) -> usize {
        self.inner.read().len()
    }

    /// Check if certificate has valid SCTs.
    pub fn has_scts(&self) -> bool {
        !self.inner.read().is_empty()
    }

    /// Get SCT details for logging/debugging.
    pub fn sct_info(&self) -> Vec<SctInfo> {
        self.inner
            .read()
            .iter()
            .map(|sct| SctInfo {
                log_id_hex: hex_encode(&sct.log_id),
                timestamp: sct.timestamp,
                version: sct.version,
            })
            .collect()
    }
}

/// Human-readable SCT information for JSON serialization.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SctInfo {
    pub log_id_hex: String,
    pub timestamp: u64,
    pub version: u8,
}

/// Extract SCTs from a PEM-encoded certificate file.
///
/// Returns the list of parsed SCTs, or an empty vec if no SCT extension is found.
pub fn extract_scts_from_pem(cert_pem: &str) -> Vec<Sct> {
    let pems = match pem_crate::parse_many(cert_pem) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "CT: failed to parse PEM certificate");
            return Vec::new();
        }
    };

    for p in &pems {
        if p.tag() != "CERTIFICATE" {
            continue;
        }
        match X509Certificate::from_der(p.contents()) {
            Ok((_, cert)) => {
                let scts = extract_scts_from_cert(&cert);
                if !scts.is_empty() {
                    info!(
                        count = scts.len(),
                        subject = %cert.subject(),
                        "CT: found SCTs in certificate"
                    );
                    return scts;
                }
            }
            Err(e) => {
                warn!(error = %e, "CT: failed to parse DER certificate");
            }
        }
    }

    debug!("CT: no SCT extension found in certificate chain");
    Vec::new()
}

/// Extract SCTs from a parsed X.509 certificate's SCT List extension.
fn extract_scts_from_cert(cert: &X509Certificate<'_>) -> Vec<Sct> {
    for ext in cert.extensions() {
        if ext.oid.as_bytes() == SCT_LIST_OID_BYTES {
            return parse_sct_list(ext.value);
        }
    }

    Vec::new()
}

/// Parse the SCT List from the raw extension value.
///
/// The SCT List is a TLS-encoded structure:
/// ```text
/// opaque SCTList<1..2^16-1>;  // outer length prefix (2 bytes)
///   struct {
///     opaque sct<1..2^16-1>;  // per-SCT length prefix (2 bytes)
///       struct {
///         Version version;        // 1 byte (v1 = 0)
///         LogID log_id;           // 32 bytes
///         uint64 timestamp;       // 8 bytes
///         opaque extensions<0..2^16-1>; // 2-byte length + data
///         digitally-signed ...    // signature (variable)
///       }
///   }
/// ```
fn parse_sct_list(data: &[u8]) -> Vec<Sct> {
    let mut scts = Vec::new();

    // The extension value is wrapped in an OCTET STRING by DER encoding.
    // The actual SCT list starts with a 2-byte length prefix.
    if data.len() < 2 {
        return scts;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list_data = if data.len() >= 2 + list_len {
        &data[2..2 + list_len]
    } else {
        &data[2..]
    };

    let mut offset = 0;
    while offset + 2 <= list_data.len() {
        let sct_len = u16::from_be_bytes([list_data[offset], list_data[offset + 1]]) as usize;
        offset += 2;

        if offset + sct_len > list_data.len() {
            break;
        }

        let sct_data = &list_data[offset..offset + sct_len];
        offset += sct_len;

        if let Some(sct) = parse_single_sct(sct_data) {
            scts.push(sct);
        }
    }

    scts
}

/// Parse a single SCT from its TLS-encoded bytes.
fn parse_single_sct(data: &[u8]) -> Option<Sct> {
    // Minimum: 1 (version) + 32 (log_id) + 8 (timestamp) + 2 (extensions_len) = 43
    if data.len() < 43 {
        return None;
    }

    let version = data[0];
    if version != 0 {
        // Only SCT v1 (version = 0) is defined
        debug!(version, "CT: unsupported SCT version");
        return None;
    }

    let mut log_id = [0u8; 32];
    log_id.copy_from_slice(&data[1..33]);

    let timestamp = u64::from_be_bytes([
        data[33], data[34], data[35], data[36], data[37], data[38], data[39], data[40],
    ]);

    let extensions_len = u16::from_be_bytes([data[41], data[42]]);

    Some(Sct {
        version,
        log_id,
        timestamp,
        extensions_len,
    })
}

/// Build the `Expect-CT` header value.
///
/// - `max_age`: Duration in seconds for the client to cache the CT policy.
/// - `enforce`: If true, the browser should refuse connections without valid SCTs.
/// - `report_uri`: Optional URI to report CT failures to.
pub fn expect_ct_header(max_age: u64, enforce: bool, report_uri: Option<&str>) -> String {
    let mut value = format!("max-age={max_age}");
    if enforce {
        value.push_str(", enforce");
    }
    if let Some(uri) = report_uri {
        value.push_str(&format!(", report-uri=\"{uri}\""));
    }
    value
}

/// Hex-encode a byte slice (lowercase).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Configuration for Certificate Transparency.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CtConfig {
    /// Enable CT checking. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Enforce CT — reject certificates without SCTs. Default: false.
    #[serde(default)]
    pub enforce: bool,

    /// `Expect-CT` header max-age in seconds. Default: 86400 (1 day).
    #[serde(default = "default_max_age")]
    pub max_age: u64,

    /// Optional report URI for `Expect-CT` failures.
    pub report_uri: Option<String>,
}

impl Default for CtConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enforce: false,
            max_age: default_max_age(),
            report_uri: None,
        }
    }
}

fn default_max_age() -> u64 {
    86400 // 1 day
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_single_sct_valid() {
        // Build a minimal valid SCT: version(1) + log_id(32) + timestamp(8) + ext_len(2) = 43
        let mut data = vec![0u8]; // version = 0 (v1)
        data.extend_from_slice(&[0xAB; 32]); // log_id
        data.extend_from_slice(&0x0000_0171_0000_0000u64.to_be_bytes()); // timestamp
        data.extend_from_slice(&0u16.to_be_bytes()); // extensions_len = 0

        let sct = parse_single_sct(&data).unwrap();
        assert_eq!(sct.version, 0);
        assert_eq!(sct.log_id, [0xAB; 32]);
        assert_eq!(sct.timestamp, 0x0000_0171_0000_0000);
        assert_eq!(sct.extensions_len, 0);
    }

    #[test]
    fn parse_single_sct_too_short() {
        let data = vec![0u8; 10]; // too short
        assert!(parse_single_sct(&data).is_none());
    }

    #[test]
    fn parse_single_sct_unsupported_version() {
        let mut data = vec![1u8]; // version = 1 (unsupported)
        data.extend_from_slice(&[0; 42]); // padding
        assert!(parse_single_sct(&data).is_none());
    }

    #[test]
    fn parse_sct_list_empty() {
        // 2-byte length = 0
        let data = [0u8, 0];
        assert!(parse_sct_list(&data).is_empty());
    }

    #[test]
    fn parse_sct_list_single_sct() {
        // Build an SCT list with one SCT
        let mut sct_data = vec![0u8]; // version
        sct_data.extend_from_slice(&[0xCD; 32]); // log_id
        sct_data.extend_from_slice(&1_700_000_000_000u64.to_be_bytes()); // timestamp
        sct_data.extend_from_slice(&0u16.to_be_bytes()); // extensions_len = 0
        // Add signature placeholder (2 bytes hash_algo + sig_algo, 2 bytes sig_len, signature)
        sct_data.extend_from_slice(&[4, 3]); // SHA-256, ECDSA
        sct_data.extend_from_slice(&2u16.to_be_bytes()); // sig len = 2
        sct_data.extend_from_slice(&[0xFF, 0xFE]); // dummy signature

        let sct_len = sct_data.len() as u16;

        let mut list = Vec::new();
        // Outer list length: 2 (sct_len prefix) + sct_len
        let outer_len = (2 + sct_len) as u16;
        list.extend_from_slice(&outer_len.to_be_bytes());
        list.extend_from_slice(&sct_len.to_be_bytes());
        list.extend_from_slice(&sct_data);

        let scts = parse_sct_list(&list);
        assert_eq!(scts.len(), 1);
        assert_eq!(scts[0].log_id, [0xCD; 32]);
        assert_eq!(scts[0].timestamp, 1_700_000_000_000);
    }

    #[test]
    fn parse_sct_list_too_short_for_length() {
        let data = [0u8]; // only 1 byte, need 2
        assert!(parse_sct_list(&data).is_empty());
    }

    #[test]
    fn expect_ct_header_basic() {
        let header = expect_ct_header(86400, false, None);
        assert_eq!(header, "max-age=86400");
    }

    #[test]
    fn expect_ct_header_enforce() {
        let header = expect_ct_header(86400, true, None);
        assert_eq!(header, "max-age=86400, enforce");
    }

    #[test]
    fn expect_ct_header_with_report_uri() {
        let header = expect_ct_header(86400, true, Some("https://example.com/ct-report"));
        assert_eq!(
            header,
            "max-age=86400, enforce, report-uri=\"https://example.com/ct-report\""
        );
    }

    #[test]
    fn ct_state_default_empty() {
        let state = CtState::new();
        assert!(!state.has_scts());
        assert_eq!(state.count(), 0);
    }

    #[test]
    fn ct_state_with_scts() {
        let state = CtState::new();
        state.set(vec![Sct {
            version: 0,
            log_id: [0xAA; 32],
            timestamp: 1_700_000_000_000,
            extensions_len: 0,
        }]);
        assert!(state.has_scts());
        assert_eq!(state.count(), 1);
        let info = state.sct_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].version, 0);
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xFF]), "00ff");
    }

    #[test]
    fn ct_config_defaults() {
        let cfg = CtConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.enforce);
        assert_eq!(cfg.max_age, 86400);
        assert!(cfg.report_uri.is_none());
    }
}
