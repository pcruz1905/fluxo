//! OCSP stapling — fetch and cache OCSP responses for TLS certificates.
//!
//! Extracts the OCSP responder URL from the certificate's Authority Information
//! Access (AIA) extension, builds an OCSP request, and periodically refreshes
//! the cached response. The cached response bytes can be provided during the
//! TLS handshake for OCSP stapling.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;

// Use the `pem` crate explicitly (x509_parser re-exports its own `pem` module).
use ::pem as pem_crate;

/// Default refresh interval for OCSP responses (4 hours).
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(4 * 3600);

/// Shared cached OCSP response bytes (DER-encoded).
#[derive(Clone)]
pub struct OcspCache {
    inner: Arc<RwLock<Option<Vec<u8>>>>,
}

impl Default for OcspCache {
    fn default() -> Self {
        Self::new()
    }
}

impl OcspCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Get the cached OCSP response, if available.
    pub fn get(&self) -> Option<Vec<u8>> {
        self.inner.read().clone()
    }

    /// Update the cached OCSP response.
    pub fn set(&self, response: Vec<u8>) {
        *self.inner.write() = Some(response);
    }
}

/// Parse PEM file into a list of DER blocks.
fn parse_pem_chain(cert_pem_path: &str) -> Option<Vec<Vec<u8>>> {
    let pem_data = std::fs::read(cert_pem_path).ok()?;
    let pems = pem_crate::parse_many(&pem_data).ok()?;
    Some(
        pems.into_iter()
            .map(pem_crate::Pem::into_contents)
            .collect(),
    )
}

/// Extract the OCSP responder URL from a PEM-encoded certificate chain.
///
/// Parses the leaf certificate and looks for the Authority Information Access
/// extension containing an OCSP responder URI.
pub fn extract_ocsp_url(cert_pem_path: &str) -> Option<String> {
    let chain = parse_pem_chain(cert_pem_path)?;
    let leaf_der = chain.first()?;

    let (_, cert) = X509Certificate::from_der(leaf_der).ok()?;

    // OID for OCSP access method: 1.3.6.1.5.5.7.48.1
    // DER encoding: 06 08 2B 06 01 05 05 07 30 01
    let ocsp_oid_bytes: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                if desc.access_method.as_bytes() == ocsp_oid_bytes {
                    if let GeneralName::URI(uri) = &desc.access_location {
                        return Some((*uri).to_string());
                    }
                }
            }
        }
    }

    None
}

/// Build a minimal DER-encoded OCSP request for a given certificate.
///
/// The OCSP request contains a single `CertID` identifying the certificate
/// by its issuer name hash, issuer key hash, and serial number.
fn build_ocsp_request(cert_pem_path: &str) -> Option<Vec<u8>> {
    let chain = parse_pem_chain(cert_pem_path)?;

    let leaf_der = chain.first()?;
    let (_, leaf) = X509Certificate::from_der(leaf_der).ok()?;

    // Get issuer name hash (SHA-256 of issuer's DER-encoded Name)
    let issuer_name_hash = Sha256::digest(leaf.issuer().as_raw());

    // Get issuer key hash (SHA-256 of issuer's public key)
    let issuer_key_hash = if let Some(issuer_der) = chain.get(1) {
        let (_, issuer_cert) = X509Certificate::from_der(issuer_der).ok()?;
        // Hash the raw public key bytes (BIT STRING content, not the SubjectPublicKeyInfo wrapper)
        Sha256::digest(&*issuer_cert.public_key().subject_public_key.data)
    } else {
        // No issuer in chain — use a placeholder (some responders accept this)
        warn!("no issuer cert in chain — OCSP request may be rejected");
        Sha256::digest(b"")
    };

    // Serial number (big-endian bytes)
    let serial = leaf.serial.to_bytes_be();

    Some(encode_ocsp_request(
        &issuer_name_hash,
        &issuer_key_hash,
        &serial,
    ))
}

/// DER-encode an OCSP request with a single `CertID` using SHA-256.
fn encode_ocsp_request(issuer_name_hash: &[u8], issuer_key_hash: &[u8], serial: &[u8]) -> Vec<u8> {
    // SHA-256 AlgorithmIdentifier: SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
    let sha256_oid: &[u8] = &[
        0x30, 0x0d, // SEQUENCE, 13 bytes
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, // OID 2.16.840.1.101.3.4.2.1 (SHA-256)
        0x05, 0x00, // NULL
    ];

    // CertID: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    let cert_id_content = [
        sha256_oid,
        &der_octet_string(issuer_name_hash),
        &der_octet_string(issuer_key_hash),
        &der_integer(serial),
    ]
    .concat();
    let cert_id = der_sequence(&cert_id_content);

    // Request: SEQUENCE { reqCert CertID }
    let request = der_sequence(&cert_id);

    // requestList: SEQUENCE OF Request
    let request_list = der_sequence(&request);

    // TBSRequest: SEQUENCE { requestList }
    let tbs_request = der_sequence(&request_list);

    // OCSPRequest: SEQUENCE { tbsRequest }
    der_sequence(&tbs_request)
}

/// DER-encode a SEQUENCE wrapper.
fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30]; // SEQUENCE tag
    out.extend(der_length(content.len()));
    out.extend(content);
    out
}

/// DER-encode an OCTET STRING wrapper.
fn der_octet_string(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04]; // OCTET STRING tag
    out.extend(der_length(content.len()));
    out.extend(content);
    out
}

/// DER-encode an INTEGER.
fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x02]; // INTEGER tag
    // Ensure the integer is positive (add leading 0 if high bit set)
    if !value.is_empty() && value[0] & 0x80 != 0 {
        out.extend(der_length(value.len() + 1));
        out.push(0x00);
    } else {
        out.extend(der_length(value.len()));
    }
    out.extend(value);
    out
}

/// DER-encode a length field.
fn der_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Fetch an OCSP response from the given responder URL.
///
/// Sends an HTTP POST with the DER-encoded OCSP request and returns the
/// raw DER-encoded OCSP response.
async fn fetch_ocsp_response(responder_url: &str, request_der: &[u8]) -> Option<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()?;

    let response = client
        .post(responder_url)
        .header("Content-Type", "application/ocsp-request")
        .body(request_der.to_vec())
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        warn!(
            status = %response.status(),
            url = responder_url,
            "OCSP responder returned non-200"
        );
        return None;
    }

    response.bytes().await.ok().map(|b| b.to_vec())
}

/// Start a background task that periodically fetches and caches the OCSP response.
///
/// Returns the `OcspCache` that can be read during TLS handshakes.
pub async fn start_ocsp_stapling(
    cert_path: String,
    responder_url_override: Option<String>,
    refresh_interval: Option<Duration>,
) -> Option<OcspCache> {
    let responder_url = responder_url_override.or_else(|| extract_ocsp_url(&cert_path));
    let Some(responder_url) = responder_url else {
        warn!(
            cert = cert_path,
            "no OCSP responder URL found in certificate — stapling disabled"
        );
        return None;
    };

    let Some(request_der) = build_ocsp_request(&cert_path) else {
        warn!(cert = cert_path, "failed to build OCSP request");
        return None;
    };

    let cache = OcspCache::new();
    let interval = refresh_interval.unwrap_or(DEFAULT_REFRESH_INTERVAL);

    // Fetch the initial response
    if let Some(response) = fetch_ocsp_response(&responder_url, &request_der).await {
        info!(
            url = responder_url,
            size = response.len(),
            "OCSP response fetched"
        );
        cache.set(response);
    } else {
        warn!(url = responder_url, "initial OCSP response fetch failed");
    }

    // Spawn background refresh task
    let cache_bg = cache.clone();
    let url = responder_url.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            debug!(url = url, "refreshing OCSP response");
            match fetch_ocsp_response(&url, &request_der).await {
                Some(response) => {
                    debug!(size = response.len(), "OCSP response refreshed");
                    cache_bg.set(response);
                }
                None => {
                    error!(url = url, "OCSP response refresh failed");
                }
            }
        }
    });

    Some(cache)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn der_sequence_encoding() {
        let seq = der_sequence(&[]);
        assert_eq!(seq, vec![0x30, 0x00]);

        let seq = der_sequence(&[0x01, 0x02, 0x03]);
        assert_eq!(seq, vec![0x30, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn der_octet_string_encoding() {
        let oct = der_octet_string(&[0xAA, 0xBB]);
        assert_eq!(oct, vec![0x04, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn der_integer_encoding() {
        let int = der_integer(&[0x42]);
        assert_eq!(int, vec![0x02, 0x01, 0x42]);

        // Integer with high bit set (needs leading zero)
        let int = der_integer(&[0x80, 0x01]);
        assert_eq!(int, vec![0x02, 0x03, 0x00, 0x80, 0x01]);
    }

    #[test]
    fn der_length_short() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(127), vec![0x7F]);
    }

    #[test]
    fn der_length_long() {
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(255), vec![0x81, 0xFF]);
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn ocsp_request_structure() {
        let name_hash = [0u8; 32];
        let key_hash = [0u8; 32];
        let serial = [0x01, 0x02, 0x03];

        let req = encode_ocsp_request(&name_hash, &key_hash, &serial);

        // Should start with SEQUENCE tag
        assert_eq!(req[0], 0x30);
        assert!(req.len() > 10);
    }

    #[test]
    fn ocsp_cache_get_set() {
        let cache = OcspCache::new();
        assert!(cache.get().is_none());

        cache.set(vec![1, 2, 3]);
        assert_eq!(cache.get(), Some(vec![1, 2, 3]));

        cache.set(vec![4, 5]);
        assert_eq!(cache.get(), Some(vec![4, 5]));
    }
}
