//! ACME client wrapper — certificate acquisition via Let's Encrypt.
//!
//! Wraps `instant-acme` to provide a high-level API for obtaining and
//! renewing TLS certificates using the ACME HTTP-01 challenge flow.

use std::sync::Arc;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    RetryPolicy,
};
use thiserror::Error;
use tracing::info;

use super::challenge::ChallengeState;
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

    #[error("order failed: {0}")]
    OrderFailed(String),
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
        let contact = format!("mailto:{}", email);
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

        info!(domains = ?domains, "starting ACME order");

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
        let primary_domain = domains.first().unwrap();
        self.store.save_cert(primary_domain, &cert_pem, &key_pem)?;

        info!(domain = %primary_domain, "certificate obtained and saved");

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
}
