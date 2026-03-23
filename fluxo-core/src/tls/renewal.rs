//! Certificate renewal background service.
//!
//! Periodically checks ACME-managed certificates for upcoming expiry
//! and triggers renewal. Runs as a Pingora `BackgroundService` alongside
//! health check services.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time;
use tracing::{error, info, warn};

use super::acme::AcmeManager;
use super::challenge::ChallengeState;
use super::dns_provider::AcmeDnsConfig;
use super::store::CertStore;

/// Configuration for the renewal service.
#[derive(Debug, Clone)]
pub struct RenewalConfig {
    /// How often to check for cert renewal (default: 12 hours).
    pub check_interval: Duration,
    /// Renew certs this many days before expiry (default: 30).
    pub renew_before_days: u32,
    /// ACME directory URL.
    pub directory_url: String,
    /// ACME account email.
    pub email: String,
    /// Domains to manage.
    pub domains: Vec<String>,
    /// Challenge type: "http-01" (default) or "dns-01".
    pub challenge_type: String,
    /// DNS provider configuration (required when `challenge_type` is "dns-01").
    pub dns_config: Option<AcmeDnsConfig>,
}

/// Background service that checks and renews ACME certificates.
pub struct CertRenewalService {
    config: RenewalConfig,
    store: CertStore,
    challenge_state: Arc<ChallengeState>,
}

impl CertRenewalService {
    /// Create a new renewal service.
    pub fn new(
        config: RenewalConfig,
        store: CertStore,
        challenge_state: Arc<ChallengeState>,
    ) -> Self {
        Self {
            config,
            store,
            challenge_state,
        }
    }
}

#[async_trait]
impl pingora_core::services::background::BackgroundService for CertRenewalService {
    async fn start(&self, mut shutdown: pingora_core::server::ShutdownWatch) {
        info!(
            interval_hours = self.config.check_interval.as_secs() / 3600,
            renew_before_days = self.config.renew_before_days,
            domains = ?self.config.domains,
            "certificate renewal service started"
        );

        let mut interval = time::interval(self.config.check_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.check_and_renew().await;
                }
                _ = shutdown.changed() => {
                    info!("certificate renewal service shutting down");
                    return;
                }
            }
        }
    }
}

impl CertRenewalService {
    async fn check_and_renew(&self) {
        let Some(primary_domain) = self.config.domains.first() else {
            return;
        };

        let needs_renewal = match self
            .store
            .needs_renewal(primary_domain, self.config.renew_before_days)
        {
            Ok(needs) => needs,
            Err(e) => {
                error!(domain = primary_domain, error = %e, "failed to check cert expiry");
                return;
            }
        };

        if !needs_renewal {
            info!(
                domain = primary_domain,
                "certificate is still valid, no renewal needed"
            );
            return;
        }

        warn!(
            domain = primary_domain,
            "certificate needs renewal, starting ACME flow"
        );

        let mut acme = match AcmeManager::new(
            &self.config.email,
            &self.config.directory_url,
            self.store.clone(),
        )
        .await
        {
            Ok(a) => a,
            Err(e) => {
                error!(error = %e, "failed to initialize ACME manager for renewal");
                return;
            }
        };

        let result = if self.config.challenge_type == "dns-01" {
            if let Some(ref dns_config) = self.config.dns_config {
                acme.obtain_cert_dns01(&self.config.domains, dns_config)
                    .await
            } else {
                error!("DNS-01 challenge configured but no dns_config provided");
                return;
            }
        } else {
            acme.obtain_cert(&self.config.domains, &self.challenge_state)
                .await
        };

        match result {
            Ok(_) => {
                info!(
                    domain = primary_domain,
                    "certificate renewed successfully — restart required to apply new cert"
                );
            }
            Err(e) => {
                error!(
                    domain = primary_domain,
                    error = %e,
                    "certificate renewal failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::time::Duration;

    fn test_renewal_config() -> RenewalConfig {
        RenewalConfig {
            check_interval: Duration::from_secs(3600),
            renew_before_days: 30,
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            email: "admin@example.com".to_string(),
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            challenge_type: "http-01".to_string(),
            dns_config: None,
        }
    }

    #[test]
    fn renewal_config_fields() {
        let cfg = test_renewal_config();
        assert_eq!(cfg.check_interval, Duration::from_secs(3600));
        assert_eq!(cfg.renew_before_days, 30);
        assert!(cfg.directory_url.contains("staging"));
        assert_eq!(cfg.email, "admin@example.com");
        assert_eq!(cfg.domains.len(), 2);
    }

    #[test]
    fn renewal_config_clone() {
        let cfg = test_renewal_config();
        let cloned = cfg.clone();
        assert_eq!(cfg.domains, cloned.domains);
        assert_eq!(cfg.check_interval, cloned.check_interval);
    }

    #[test]
    fn renewal_config_debug() {
        let cfg = test_renewal_config();
        let debug = format!("{cfg:?}");
        assert!(debug.contains("RenewalConfig"));
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn renewal_service_construction() {
        let cfg = test_renewal_config();
        let store = CertStore::new(std::path::PathBuf::from("/tmp/test-certs"));
        let challenge = Arc::new(ChallengeState::new());
        let svc = CertRenewalService::new(cfg.clone(), store, challenge);
        assert_eq!(svc.config.domains, cfg.domains);
        assert_eq!(svc.config.renew_before_days, 30);
    }

    #[test]
    fn renewal_config_empty_domains() {
        let cfg = RenewalConfig {
            check_interval: Duration::from_secs(3600),
            renew_before_days: 30,
            directory_url: "https://example.com".to_string(),
            email: String::new(),
            domains: vec![],
            challenge_type: "http-01".to_string(),
            dns_config: None,
        };
        assert!(cfg.domains.is_empty());
    }

    #[test]
    fn renewal_config_single_domain() {
        let cfg = RenewalConfig {
            check_interval: Duration::from_secs(43200),
            renew_before_days: 7,
            directory_url: "https://example.com/dir".to_string(),
            email: "user@test.com".to_string(),
            domains: vec!["single.example.com".to_string()],
            challenge_type: "http-01".to_string(),
            dns_config: None,
        };
        assert_eq!(cfg.renew_before_days, 7);
        assert_eq!(cfg.domains.len(), 1);
    }
}
