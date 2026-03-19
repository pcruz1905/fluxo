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

        match acme
            .obtain_cert(&self.config.domains, &self.challenge_state)
            .await
        {
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
