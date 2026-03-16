//! Certificate storage — load, save, and check expiry of PEM certificates.
//!
//! Certificates are stored on disk in a deterministic layout:
//! ```text
//! {base_dir}/
//! ├── accounts/
//! │   └── {server_host}/
//! │       └── account.json
//! └── live/
//!     └── {domain}/
//!         ├── cert.pem
//!         └── key.pem
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use thiserror::Error;
use x509_parser::prelude::*;

use ::pem as pem_crate;

/// Errors from certificate store operations.
#[derive(Debug, Error)]
pub enum CertStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PEM parsing error: {0}")]
    Pem(#[from] pem_crate::PemError),

    #[error("X.509 parsing error: {0}")]
    X509(String),
}

/// Information about a stored certificate.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
    /// When the leaf certificate expires.
    pub not_after: SystemTime,
    /// Domains covered by this certificate (from SAN extension).
    pub domains: Vec<String>,
}

/// On-disk certificate storage with deterministic paths.
#[derive(Debug, Clone)]
pub struct CertStore {
    base_dir: PathBuf,
}

impl CertStore {
    /// Create a new cert store rooted at the given directory.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Default cert store location: `~/.local/share/fluxo/certs` (Unix)
    /// or `%LOCALAPPDATA%/fluxo/certs` (Windows).
    pub fn default_dir() -> PathBuf {
        if cfg!(windows) {
            let base = std::env::var("LOCALAPPDATA")
                .unwrap_or_else(|_| std::env::var("USERPROFILE").unwrap_or_default());
            PathBuf::from(base).join("fluxo").join("certs")
        } else {
            let base = std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_default();
                format!("{}/.local/share", home)
            });
            PathBuf::from(base).join("fluxo").join("certs")
        }
    }

    /// Path to the certificate PEM for a domain.
    pub fn cert_path(&self, domain: &str) -> PathBuf {
        self.base_dir.join("live").join(domain).join("cert.pem")
    }

    /// Path to the private key PEM for a domain.
    pub fn key_path(&self, domain: &str) -> PathBuf {
        self.base_dir.join("live").join(domain).join("key.pem")
    }

    /// Path to ACME account credentials for a given server.
    pub fn account_path(&self, server_host: &str) -> PathBuf {
        self.base_dir
            .join("accounts")
            .join(server_host)
            .join("account.json")
    }

    /// Base directory for this store.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Load a certificate and key from disk for the given domain.
    ///
    /// Returns `Ok(None)` if the cert files don't exist.
    pub fn load_cert(&self, domain: &str) -> Result<Option<CertInfo>, CertStoreError> {
        let cert_path = self.cert_path(domain);
        let key_path = self.key_path(domain);

        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }

        let cert_pem = fs::read_to_string(&cert_path)?;
        let key_pem = fs::read_to_string(&key_path)?;

        let info = parse_cert_info(&cert_pem, &key_pem)?;
        Ok(Some(info))
    }

    /// Save a certificate and key to disk for the given domain.
    ///
    /// Uses atomic write (write to temp file + rename) to prevent serving partial certs.
    pub fn save_cert(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), CertStoreError> {
        let cert_path = self.cert_path(domain);
        let key_path = self.key_path(domain);

        // Ensure parent directories exist
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Atomic write: write to .tmp then rename
        atomic_write(&cert_path, cert_pem)?;
        atomic_write(&key_path, key_pem)?;

        Ok(())
    }

    /// Check whether a domain's certificate needs renewal.
    ///
    /// Returns `true` if:
    /// - No certificate exists on disk
    /// - The certificate expires within `days_before` days
    pub fn needs_renewal(&self, domain: &str, days_before: u32) -> Result<bool, CertStoreError> {
        match self.load_cert(domain)? {
            None => Ok(true),
            Some(info) => {
                let now = SystemTime::now();
                let renewal_threshold =
                    std::time::Duration::from_secs(u64::from(days_before) * 86400);
                match info.not_after.duration_since(now) {
                    Ok(remaining) => Ok(remaining < renewal_threshold),
                    Err(_) => Ok(true), // already expired
                }
            }
        }
    }

    /// Save ACME account credentials to disk.
    pub fn save_account(
        &self,
        server_host: &str,
        credentials_json: &str,
    ) -> Result<(), CertStoreError> {
        let path = self.account_path(server_host);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        atomic_write(&path, credentials_json)?;
        Ok(())
    }

    /// Load ACME account credentials from disk.
    ///
    /// Returns `Ok(None)` if the account file doesn't exist.
    pub fn load_account(&self, server_host: &str) -> Result<Option<String>, CertStoreError> {
        let path = self.account_path(server_host);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(fs::read_to_string(&path)?))
    }
}

/// Parse certificate info (expiry + domains) from a PEM-encoded cert chain.
fn parse_cert_info(cert_pem: &str, key_pem: &str) -> Result<CertInfo, CertStoreError> {
    let pems = pem_crate::parse_many(cert_pem)?;

    // First PEM block is the leaf certificate
    let leaf = pems
        .first()
        .ok_or_else(|| CertStoreError::X509("no certificate found in PEM".to_string()))?;

    let (_, cert) = X509Certificate::from_der(leaf.contents())
        .map_err(|e| CertStoreError::X509(format!("failed to parse X.509: {}", e)))?;

    // Extract expiry
    let not_after = cert.validity().not_after.to_datetime();
    let not_after =
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(not_after.unix_timestamp() as u64);

    // Extract domains from Subject Alternative Names
    let mut domains = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                domains.push(dns.to_string());
            }
        }
    }

    // Fallback: extract CN from subject if no SANs
    if domains.is_empty()
        && let Some(cn) = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
    {
        domains.push(cn.to_string());
    }

    Ok(CertInfo {
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
        not_after,
        domains,
    })
}

/// Write content to a file atomically (write temp + rename).
fn atomic_write(path: &Path, content: &str) -> Result<(), std::io::Error> {
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, content)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (CertStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = CertStore::new(dir.path());
        (store, dir)
    }

    // Self-signed cert for testing (generated with rcgen)
    fn generate_test_cert(domain: &str) -> (String, String) {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);

        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    fn generate_expired_cert(domain: &str) -> (String, String) {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2020, 2, 1);

        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn cert_paths_are_deterministic() {
        let store = CertStore::new("/var/fluxo/certs");
        assert_eq!(
            store.cert_path("example.com"),
            PathBuf::from("/var/fluxo/certs/live/example.com/cert.pem")
        );
        assert_eq!(
            store.key_path("example.com"),
            PathBuf::from("/var/fluxo/certs/live/example.com/key.pem")
        );
    }

    #[test]
    fn account_path_is_deterministic() {
        let store = CertStore::new("/var/fluxo/certs");
        assert_eq!(
            store.account_path("acme-v02.api.letsencrypt.org"),
            PathBuf::from("/var/fluxo/certs/accounts/acme-v02.api.letsencrypt.org/account.json")
        );
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let (store, _dir) = temp_store();
        assert!(store.load_cert("missing.com").unwrap().is_none());
    }

    #[test]
    fn save_and_load_round_trip() {
        let (store, _dir) = temp_store();
        let (cert_pem, key_pem) = generate_test_cert("test.example.com");

        store
            .save_cert("test.example.com", &cert_pem, &key_pem)
            .unwrap();

        let info = store.load_cert("test.example.com").unwrap().unwrap();
        assert_eq!(info.cert_pem, cert_pem);
        assert_eq!(info.key_pem, key_pem);
        assert!(info.domains.contains(&"test.example.com".to_string()));
        assert!(info.not_after > SystemTime::now());
    }

    #[test]
    fn needs_renewal_missing_cert() {
        let (store, _dir) = temp_store();
        assert!(store.needs_renewal("missing.com", 30).unwrap());
    }

    #[test]
    fn needs_renewal_expired_cert() {
        let (store, _dir) = temp_store();
        let (cert_pem, key_pem) = generate_expired_cert("expired.example.com");

        store
            .save_cert("expired.example.com", &cert_pem, &key_pem)
            .unwrap();

        assert!(store.needs_renewal("expired.example.com", 30).unwrap());
    }

    #[test]
    fn needs_renewal_valid_cert() {
        let (store, _dir) = temp_store();
        let (cert_pem, key_pem) = generate_test_cert("valid.example.com");

        store
            .save_cert("valid.example.com", &cert_pem, &key_pem)
            .unwrap();

        // Cert expires in 2099, so it doesn't need renewal
        assert!(!store.needs_renewal("valid.example.com", 30).unwrap());
    }

    #[test]
    fn save_and_load_account() {
        let (store, _dir) = temp_store();
        let creds = r#"{"id":"acct-123","key":"abc"}"#;

        store
            .save_account("acme-v02.api.letsencrypt.org", creds)
            .unwrap();

        let loaded = store
            .load_account("acme-v02.api.letsencrypt.org")
            .unwrap()
            .unwrap();

        assert_eq!(loaded, creds);
    }

    #[test]
    fn load_account_nonexistent_returns_none() {
        let (store, _dir) = temp_store();
        assert!(store.load_account("missing.server.com").unwrap().is_none());
    }
}
