//! `FluxoApp` — top-level orchestrator that wires config, proxy, and server together.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tracing::{info, warn};

use crate::config::FluxoConfig;
use crate::error::FluxoError;
use crate::proxy::{FluxoBuild, FluxoProxy, FluxoState};
use crate::tls::acme::AcmeManager;
use crate::tls::renewal::{CertRenewalService, RenewalConfig};
use crate::tls::store::CertStore;

/// Resolved TLS paths for a service — either from manual config or ACME.
#[derive(Debug, Clone)]
pub struct ResolvedTls {
    pub cert_path: String,
    pub key_path: String,
}

/// The top-level Fluxo application.
pub struct FluxoApp {
    config: FluxoConfig,
    proxy: FluxoProxy,
    /// Background services that need to be registered with the Pingora Server.
    health_check_services: Vec<Box<dyn pingora_core::services::ServiceWithDependents>>,
    /// Resolved TLS cert paths per service (from ACME or manual config).
    resolved_tls: HashMap<String, ResolvedTls>,
}

impl FluxoApp {
    /// Create a new FluxoApp from a validated config.
    ///
    /// Builds the pre-computed `FluxoState` (compiled routes, initialized load
    /// balancers) and wraps it in a `FluxoProxy` with ArcSwap.
    pub fn from_config(config: FluxoConfig) -> Result<Self, FluxoError> {
        let FluxoBuild {
            state,
            health_check_services,
        } = FluxoState::build(config.clone())?;
        let proxy = FluxoProxy::new(state);
        Ok(Self {
            config,
            proxy,
            health_check_services,
            resolved_tls: HashMap::new(),
        })
    }

    /// Ensure all ACME-managed certificates are available on disk.
    ///
    /// For each service with `acme = true`, checks the cert store. If certs
    /// are missing or expired, acquires them via ACME HTTP-01 challenges.
    ///
    /// This is a blocking operation that should run before starting the server.
    /// The `challenge_state` is used only if we need to start a temporary
    /// HTTP server for challenges (future enhancement — for now, certs must
    /// be obtained before the server starts).
    pub async fn ensure_certs(&mut self) -> Result<(), FluxoError> {
        let cert_store = self.cert_store();

        for (service_name, service) in &self.config.services {
            let tls = match &service.tls {
                Some(tls) if tls.acme => tls,
                Some(tls) if tls.cert_path.is_some() && tls.key_path.is_some() => {
                    // Manual TLS — just record the paths
                    self.resolved_tls.insert(
                        service_name.clone(),
                        ResolvedTls {
                            cert_path: tls.cert_path.clone().unwrap(),
                            key_path: tls.key_path.clone().unwrap(),
                        },
                    );
                    continue;
                }
                _ => continue,
            };

            let domains = collect_acme_domains(service);

            if domains.is_empty() {
                warn!(
                    service = service_name,
                    "ACME enabled but no non-wildcard match_host patterns found — skipping"
                );
                continue;
            }

            let primary_domain = &domains[0];

            // Check if we already have a valid cert
            if !cert_store
                .needs_renewal(primary_domain, 30)
                .map_err(|e| FluxoError::Acme(crate::tls::acme::AcmeError::Store(e)))?
            {
                info!(
                    service = service_name,
                    domain = primary_domain,
                    "existing certificate is valid"
                );
                self.resolved_tls.insert(
                    service_name.clone(),
                    ResolvedTls {
                        cert_path: cert_store
                            .cert_path(primary_domain)
                            .to_string_lossy()
                            .to_string(),
                        key_path: cert_store
                            .key_path(primary_domain)
                            .to_string_lossy()
                            .to_string(),
                    },
                );
                continue;
            }

            // Need to acquire cert
            info!(
                service = service_name,
                domains = ?domains,
                "acquiring ACME certificate"
            );

            let directory_url = tls.acme_directory.as_deref().unwrap_or_else(|| {
                if tls.acme_staging {
                    AcmeManager::lets_encrypt_staging()
                } else {
                    AcmeManager::lets_encrypt_production()
                }
            });

            let email = tls.acme_email.as_deref().unwrap_or_default();
            let challenge_state = self.proxy.challenge_state();

            let mut acme = AcmeManager::new(email, directory_url, cert_store.clone()).await?;
            acme.obtain_cert(&domains, &challenge_state).await?;

            self.resolved_tls.insert(
                service_name.clone(),
                ResolvedTls {
                    cert_path: cert_store
                        .cert_path(primary_domain)
                        .to_string_lossy()
                        .to_string(),
                    key_path: cert_store
                        .key_path(primary_domain)
                        .to_string_lossy()
                        .to_string(),
                },
            );

            info!(
                service = service_name,
                domain = primary_domain,
                "certificate acquired successfully"
            );
        }

        Ok(())
    }

    /// Get resolved TLS paths for a service (from ACME or manual config).
    pub fn resolved_tls(&self, service_name: &str) -> Option<&ResolvedTls> {
        self.resolved_tls.get(service_name)
    }

    /// Build the cert store from config.
    pub fn cert_store(&self) -> CertStore {
        match &self.config.global.cert_dir {
            Some(dir) => CertStore::new(PathBuf::from(dir)),
            None => CertStore::new(CertStore::default_dir()),
        }
    }

    /// Get a clone of the proxy for registering with Pingora services.
    ///
    /// `FluxoProxy` is cheap to clone (it's an `Arc<ArcSwap<FluxoState>>`).
    pub fn proxy(&self) -> FluxoProxy {
        self.proxy.clone()
    }

    /// Get a reference to the original config.
    pub fn config(&self) -> &FluxoConfig {
        &self.config
    }

    /// Take ownership of health check background services.
    ///
    /// These must be registered with the Pingora Server for periodic health checking.
    /// Can only be called once (drains the internal vec).
    pub fn take_health_check_services(
        &mut self,
    ) -> Vec<Box<dyn pingora_core::services::ServiceWithDependents>> {
        std::mem::take(&mut self.health_check_services)
    }

    /// Create background renewal services for all ACME-managed domains.
    ///
    /// Returns boxed services ready to register with the Pingora Server.
    pub fn renewal_services(&self) -> Vec<Box<dyn pingora_core::services::ServiceWithDependents>> {
        use pingora_core::services::background::GenBackgroundService;

        let cert_store = self.cert_store();
        let challenge_state = self.proxy.challenge_state();
        let mut services: Vec<Box<dyn pingora_core::services::ServiceWithDependents>> = Vec::new();

        for (service_name, service) in &self.config.services {
            let tls = match &service.tls {
                Some(tls) if tls.acme => tls,
                _ => continue,
            };

            let domains = collect_acme_domains(service);

            if domains.is_empty() {
                continue;
            }

            let directory_url = tls.acme_directory.clone().unwrap_or_else(|| {
                if tls.acme_staging {
                    AcmeManager::lets_encrypt_staging().to_string()
                } else {
                    AcmeManager::lets_encrypt_production().to_string()
                }
            });

            let renewal_config = RenewalConfig {
                check_interval: std::time::Duration::from_secs(12 * 3600), // 12 hours
                renew_before_days: 30,
                directory_url,
                email: tls.acme_email.clone().unwrap_or_default(),
                domains,
            };

            let renewal_svc = CertRenewalService::new(
                renewal_config,
                cert_store.clone(),
                challenge_state.clone(),
            );

            let bg_name = format!("BG cert-renewal {service_name}");
            services.push(Box::new(GenBackgroundService::new(
                bg_name,
                Arc::new(renewal_svc),
            )));
        }

        services
    }

    /// Create the Admin API background service.
    pub fn admin_service(&self) -> Box<dyn pingora_core::services::ServiceWithDependents> {
        use pingora_core::services::background::GenBackgroundService;

        // Safe: validated at config load time by config::validate()
        let address: std::net::SocketAddr = self.config.global.admin.parse().unwrap();

        let admin = crate::admin::AdminService {
            address,
            proxy: Arc::new(self.proxy.clone()),
            metrics: self.proxy.metrics(),
        };

        let svc = GenBackgroundService::new("admin API".to_string(), Arc::new(admin));
        Box::new(svc)
    }
}

/// Collect unique non-wildcard domains from a service's route host patterns.
fn collect_acme_domains(service: &crate::config::ServiceConfig) -> Vec<String> {
    service
        .routes
        .iter()
        .flat_map(|r| r.match_host.iter())
        .filter(|h| !h.starts_with('*'))
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
}

impl FluxoApp {
    /// Reload the proxy with a new config.
    ///
    /// Builds a new `FluxoState` and atomically swaps it into the proxy.
    /// Returns an error if the new config is invalid; the old config remains active.
    pub fn reload(&self, new_config: FluxoConfig) -> Result<(), FluxoError> {
        let new_state = FluxoState::try_from_config(new_config)?;
        self.proxy.reload(new_state);
        Ok(())
    }
}
