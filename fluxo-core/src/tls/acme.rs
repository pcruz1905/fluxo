//! ACME client wrapper — certificate acquisition via Let's Encrypt.
//!
//! Wraps `instant-acme` to provide a high-level API for obtaining and
//! renewing TLS certificates using the ACME HTTP-01 and DNS-01 challenge flows.

use std::sync::Arc;
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    RetryPolicy,
};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::challenge::ChallengeState;
use super::dns_provider::{self, AcmeDnsConfig, DnsProviderError};
use super::store::{CertStore, CertStoreError};

/// Errors from ACME operations.
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME protocol error: {0}")]
    Protocol(#[from] instant_acme::Error),

    #[error("certificate store error: {0}")]
    Store(#[from] CertStoreError),

    #[error("CSR generation error: {0}")]
    Csr(#[from] rcgen::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("no HTTP-01 challenge found for {0}")]
    NoHttp01Challenge(String),

    #[error("no DNS-01 challenge found for {0}")]
    NoDns01Challenge(String),

    #[error("DNS provider error: {0}")]
    DnsProvider(#[from] DnsProviderError),

    #[error("order failed: {0}")]
    OrderFailed(String),

    #[error("{0}")]
    Other(String),
}

/// ACME manager for obtaining and renewing certificates.
pub struct AcmeManager {
    account: Account,
    store: CertStore,
    #[allow(dead_code)] // used for account path resolution
    server_host: String,
}

impl AcmeManager {
    /// Create or restore an ACME account.
    ///
    /// If account credentials exist on disk, restores them.
    /// Otherwise, creates a new account with the given email.
    pub async fn new(
        email: &str,
        directory_url: &str,
        store: CertStore,
    ) -> Result<Self, AcmeError> {
        let server_host = extract_host(directory_url);

        // Try to load existing account
        if let Some(json) = store.load_account(&server_host)? {
            let credentials: AccountCredentials = serde_json::from_str(&json)?;
            let account = Account::builder()?.from_credentials(credentials).await?;
            info!(server = %server_host, "restored ACME account");
            return Ok(Self {
                account,
                store,
                server_host,
            });
        }

        // Create new account
        let contact = format!("mailto:{email}");
        let (account, credentials): (Account, AccountCredentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url.to_string(),
                None,
            )
            .await?;

        // Persist account credentials
        let json = serde_json::to_string_pretty(&credentials)?;
        store.save_account(&server_host, &json)?;
        info!(server = %server_host, id = %account.id(), "created new ACME account");

        Ok(Self {
            account,
            store,
            server_host,
        })
    }

    /// Obtain a certificate for the given domains using HTTP-01 challenges.
    ///
    /// The `challenge_state` is shared with the proxy's `request_filter` so
    /// it can serve challenge tokens at `/.well-known/acme-challenge/{token}`.
    ///
    /// Returns the PEM-encoded certificate chain and private key.
    pub async fn obtain_cert(
        &mut self,
        domains: &[String],
        challenge_state: &Arc<ChallengeState>,
    ) -> Result<(String, String), AcmeError> {
        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

        info!(domains = ?domains, "starting ACME order (HTTP-01)");

        // Create order
        let mut order = self.account.new_order(&NewOrder::new(&identifiers)).await?;

        // Process authorizations
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;

            // Find HTTP-01 challenge
            let identifier_name = authz.identifier().to_string();
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| AcmeError::NoHttp01Challenge(identifier_name))?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();

            // Register token so the proxy can serve it
            challenge_state.set(token.clone(), key_auth);

            // Tell the ACME server we're ready
            challenge.set_ready().await?;

            info!(token = %token, "ACME challenge registered, waiting for validation");
        }

        // Wait for order to become ready
        let retry = RetryPolicy::new();
        order.poll_ready(&retry).await?;

        info!("ACME order ready, finalizing");

        // Generate key and CSR, then finalize
        let key_pem = order.finalize().await?;

        // Download certificate
        let cert_pem = order.poll_certificate(&retry).await?;

        // Save to store
        let primary_domain = domains
            .first()
            .ok_or_else(|| AcmeError::Other("no domains provided".into()))?;
        self.store.save_cert(primary_domain, &cert_pem, &key_pem)?;

        info!(domain = %primary_domain, "certificate obtained and saved");

        Ok((cert_pem, key_pem))
    }

    /// Obtain a certificate for the given domains using DNS-01 challenges.
    ///
    /// Creates TXT records via the configured DNS provider for domain validation.
    /// Required for wildcard certificates (`*.example.com`).
    ///
    /// Returns the PEM-encoded certificate chain and private key.
    pub async fn obtain_cert_dns01(
        &mut self,
        domains: &[String],
        dns_config: &AcmeDnsConfig,
    ) -> Result<(String, String), AcmeError> {
        let provider = dns_provider::create_provider(dns_config)?;

        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

        info!(domains = ?domains, "starting ACME order (DNS-01)");

        let mut order = self.account.new_order(&NewOrder::new(&identifiers)).await?;

        // Track created DNS records for cleanup
        let mut dns_record_ids: Vec<String> = Vec::new();

        // Process authorizations
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;

            let identifier_name = authz.identifier().to_string();
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| AcmeError::NoDns01Challenge(identifier_name.clone()))?;

            // DNS-01: TXT record at _acme-challenge.<domain> with dns_value
            let dns_value = challenge.key_authorization().dns_value();
            let record_name = format!("_acme-challenge.{identifier_name}");

            debug!(
                domain = %identifier_name,
                record_name = %record_name,
                "creating DNS TXT record for ACME challenge"
            );

            let record_id = provider
                .create_txt_record(&identifier_name, &record_name, &dns_value)
                .await?;
            dns_record_ids.push(record_id);

            // Wait for DNS propagation
            let wait =
                parse_duration(&dns_config.propagation_wait).unwrap_or(Duration::from_secs(30));
            info!(
                wait_secs = wait.as_secs(),
                domain = %identifier_name,
                "waiting for DNS propagation"
            );
            tokio::time::sleep(wait).await;

            // Tell the ACME server we're ready
            challenge.set_ready().await?;

            info!(domain = %identifier_name, "DNS-01 challenge set ready");
        }

        // Wait for order to become ready
        let retry = RetryPolicy::new();
        let ready_result = order.poll_ready(&retry).await;

        // Clean up DNS records regardless of outcome
        for record_id in &dns_record_ids {
            if let Err(e) = provider.delete_txt_record(record_id).await {
                warn!(record_id = %record_id, error = %e, "failed to clean up DNS TXT record");
            }
        }

        ready_result?;

        info!("ACME order ready, finalizing");

        let key_pem = order.finalize().await?;
        let cert_pem = order.poll_certificate(&retry).await?;

        let primary_domain = domains
            .first()
            .ok_or_else(|| AcmeError::Other("no domains provided".into()))?;
        self.store.save_cert(primary_domain, &cert_pem, &key_pem)?;

        info!(domain = %primary_domain, "certificate obtained via DNS-01 and saved");

        Ok((cert_pem, key_pem))
    }

    /// Get the cert store reference.
    pub fn store(&self) -> &CertStore {
        &self.store
    }

    /// Get the directory URL for Let's Encrypt production.
    pub fn lets_encrypt_production() -> &'static str {
        LetsEncrypt::Production.url()
    }

    /// Get the directory URL for Let's Encrypt staging.
    pub fn lets_encrypt_staging() -> &'static str {
        LetsEncrypt::Staging.url()
    }
}

/// Parse a human-friendly duration string like "30s", "5m", "1h".
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1u64),
        Some(b'm') => (&s[..s.len() - 1], 60u64),
        Some(b'h') => (&s[..s.len() - 1], 3600u64),
        _ => (s, 1u64),
    };

    num_str
        .parse::<u64>()
        .ok()
        .map(|n| Duration::from_secs(n * unit))
}

/// Extract the host portion from a URL for use as a storage key.
fn extract_host(url: &str) -> String {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn extract_host_from_url() {
        assert_eq!(
            extract_host("https://acme-v02.api.letsencrypt.org/directory"),
            "acme-v02.api.letsencrypt.org"
        );
        assert_eq!(
            extract_host("https://acme-staging-v02.api.letsencrypt.org/directory"),
            "acme-staging-v02.api.letsencrypt.org"
        );
    }

    #[test]
    fn lets_encrypt_urls() {
        assert!(AcmeManager::lets_encrypt_production().contains("acme-v02"));
        assert!(AcmeManager::lets_encrypt_staging().contains("staging"));
    }

    #[test]
    fn extract_host_no_scheme() {
        assert_eq!(extract_host("example.com/path"), "example.com");
    }

    #[test]
    fn extract_host_http_scheme() {
        assert_eq!(extract_host("http://localhost:8080/api"), "localhost:8080");
    }

    #[test]
    fn extract_host_bare_domain() {
        assert_eq!(extract_host("example.com"), "example.com");
    }

    #[test]
    fn extract_host_trailing_slash() {
        assert_eq!(
            extract_host("https://acme.example.com/"),
            "acme.example.com"
        );
    }

    #[test]
    fn extract_host_empty_string() {
        assert_eq!(extract_host(""), "");
    }

    #[test]
    fn acme_error_display() {
        let err = AcmeError::NoHttp01Challenge("example.com".to_string());
        assert!(err.to_string().contains("example.com"));
        assert!(err.to_string().contains("HTTP-01"));

        let err = AcmeError::OrderFailed("timeout".to_string());
        assert!(err.to_string().contains("timeout"));

        let err = AcmeError::Other("something went wrong".to_string());
        assert!(err.to_string().contains("something went wrong"));
    }

    #[test]
    fn lets_encrypt_urls_are_different() {
        let prod = AcmeManager::lets_encrypt_production();
        let staging = AcmeManager::lets_encrypt_staging();
        assert_ne!(prod, staging);
        assert!(prod.starts_with("https://"));
        assert!(staging.starts_with("https://"));
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("0s"), Some(Duration::from_secs(0)));
        assert_eq!(parse_duration("120s"), Some(Duration::from_secs(120)));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("1m"), Some(Duration::from_secs(60)));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
    }

    #[test]
    fn parse_duration_no_unit() {
        assert_eq!(parse_duration("60"), Some(Duration::from_secs(60)));
    }

    #[test]
    fn parse_duration_empty() {
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("  "), None);
    }

    #[test]
    fn parse_duration_invalid() {
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("xs"), None);
    }

    #[test]
    fn acme_error_dns01_display() {
        let err = AcmeError::NoDns01Challenge("example.com".to_string());
        assert!(err.to_string().contains("example.com"));
        assert!(err.to_string().contains("DNS-01"));
    }
}
