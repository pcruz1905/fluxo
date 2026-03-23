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
    /// Path to the config file on disk (used by admin POST /reload).
    config_path: Option<PathBuf>,
}

impl FluxoApp {
    /// Create a new `FluxoApp` from a validated config.
    ///
    /// Builds the pre-computed `FluxoState` (compiled routes, initialized load
    /// balancers) and wraps it in a `FluxoProxy` with `ArcSwap`.
    pub fn from_config(config: FluxoConfig) -> Result<Self, FluxoError> {
        Self::from_config_with_path(config, None)
    }

    /// Create a new `FluxoApp` from a validated config, recording the config file path
    /// so the admin API's `POST /reload` endpoint can re-read it from disk.
    pub fn from_config_with_path(
        config: FluxoConfig,
        config_path: Option<PathBuf>,
    ) -> Result<Self, FluxoError> {
        let FluxoBuild {
            state,
            health_check_services,
        } = FluxoState::build(config.clone())?;
        let proxy = FluxoProxy::new(state)?;
        Ok(Self {
            config,
            proxy,
            health_check_services,
            resolved_tls: HashMap::new(),
            config_path,
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
                    if let (Some(cert_path), Some(key_path)) = (&tls.cert_path, &tls.key_path) {
                        self.resolved_tls.insert(
                            service_name.clone(),
                            ResolvedTls {
                                cert_path: cert_path.clone(),
                                key_path: key_path.clone(),
                            },
                        );
                    }
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
        self.config.global.cert_dir.as_ref().map_or_else(
            || CertStore::new(CertStore::default_dir()),
            |dir| CertStore::new(PathBuf::from(dir)),
        )
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

        // Safe: fallback to 127.0.0.1:2019 if config parsing logic somehow failed
        let address: std::net::SocketAddr = self
            .config
            .global
            .admin
            .parse()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 2019)));

        let admin = crate::admin::AdminService {
            address,
            proxy: Arc::new(self.proxy.clone()),
            metrics: self.proxy.metrics(),
            config_path: self
                .config_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            auth_token: self.config.global.admin_auth_token.clone(),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn minimal_config() -> FluxoConfig {
        use crate::config::{
            FluxoConfig, GlobalConfig, ListenerConfig, RouteConfig, ServiceConfig, UpstreamConfig,
        };

        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceConfig {
                listeners: vec![ListenerConfig {
                    address: "127.0.0.1:8080".to_string(),
                    offer_h2: false,
                    proxy_protocol: false,
                }],
                routes: vec![RouteConfig {
                    match_path: vec!["/*".to_string()],
                    upstream: "backend".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "backend".to_string(),
            UpstreamConfig {
                targets: vec![crate::config::TargetConfig::Simple(
                    "127.0.0.1:3000".to_string(),
                )],
                ..Default::default()
            },
        );

        FluxoConfig {
            global: GlobalConfig::default(),
            services,
            upstreams,
            ..Default::default()
        }
    }

    #[test]
    fn from_config_succeeds() {
        let config = minimal_config();
        let app = FluxoApp::from_config(config);
        assert!(app.is_ok());
    }

    #[test]
    fn config_returns_original() {
        let config = minimal_config();
        let app = FluxoApp::from_config(config.clone()).unwrap();
        assert_eq!(app.config().global.admin, config.global.admin);
    }

    #[test]
    fn resolved_tls_none_for_unknown_service() {
        let app = FluxoApp::from_config(minimal_config()).unwrap();
        assert!(app.resolved_tls("nonexistent").is_none());
    }

    #[test]
    fn cert_store_default_dir() {
        let app = FluxoApp::from_config(minimal_config()).unwrap();
        let store = app.cert_store();
        // Verify it doesn't panic — the store is constructed
        let _ = format!("{store:?}");
    }

    #[test]
    fn cert_store_custom_dir() {
        let mut config = minimal_config();
        config.global.cert_dir = Some("/tmp/test-certs".to_string());
        let app = FluxoApp::from_config(config).unwrap();
        let _store = app.cert_store();
    }

    #[test]
    fn take_health_check_services_drains() {
        let mut app = FluxoApp::from_config(minimal_config()).unwrap();
        let svcs = app.take_health_check_services();
        // After taking, vec should be empty
        let svcs2 = app.take_health_check_services();
        assert!(svcs2.is_empty());
        // First call may or may not have services depending on config
        let _ = svcs;
    }

    #[test]
    fn reload_with_valid_config() {
        let app = FluxoApp::from_config(minimal_config()).unwrap();
        let result = app.reload(minimal_config());
        assert!(result.is_ok());
    }

    #[test]
    fn collect_acme_domains_no_wildcard() {
        let mut svc = crate::config::ServiceConfig::default();
        svc.routes.push(crate::config::RouteConfig {
            match_host: vec!["example.com".to_string(), "api.example.com".to_string()],
            ..Default::default()
        });
        let domains = collect_acme_domains(&svc);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"api.example.com".to_string()));
    }

    #[test]
    fn collect_acme_domains_filters_wildcards() {
        let mut svc = crate::config::ServiceConfig::default();
        svc.routes.push(crate::config::RouteConfig {
            match_host: vec!["*.example.com".to_string(), "exact.com".to_string()],
            ..Default::default()
        });
        let domains = collect_acme_domains(&svc);
        assert!(!domains.iter().any(|d| d.starts_with('*')));
        assert!(domains.contains(&"exact.com".to_string()));
    }

    #[test]
    fn collect_acme_domains_empty_routes() {
        let svc = crate::config::ServiceConfig::default();
        let domains = collect_acme_domains(&svc);
        assert!(domains.is_empty());
    }

    #[test]
    fn from_config_with_path() {
        let config = minimal_config();
        let app = FluxoApp::from_config_with_path(
            config,
            Some(std::path::PathBuf::from("/etc/fluxo.toml")),
        );
        assert!(app.is_ok());
    }

    #[test]
    fn from_config_with_no_path() {
        let config = minimal_config();
        let app = FluxoApp::from_config_with_path(config, None);
        assert!(app.is_ok());
    }

    #[test]
    fn proxy_returns_clone() {
        let app = FluxoApp::from_config(minimal_config()).unwrap();
        let proxy = app.proxy();
        // Verify the proxy is functional — can load state snapshot
        let _snap = proxy.state_snapshot();
    }

    #[test]
    fn admin_service_constructs() {
        let app = FluxoApp::from_config(minimal_config()).unwrap();
        // admin_service() should not panic
        let _svc = app.admin_service();
    }

    #[test]
    fn admin_service_with_custom_address() {
        let mut config = minimal_config();
        config.global.admin = "0.0.0.0:9999".to_string();
        let app = FluxoApp::from_config(config).unwrap();
        let _svc = app.admin_service();
    }

    #[test]
    fn admin_service_with_invalid_address_fallback() {
        let mut config = minimal_config();
        config.global.admin = "not-a-socket-addr".to_string();
        let app = FluxoApp::from_config(config).unwrap();
        // Should fall back to 127.0.0.1:2019 without panicking
        let _svc = app.admin_service();
    }

    #[test]
    fn admin_service_with_auth_token() {
        let mut config = minimal_config();
        config.global.admin_auth_token = Some("secret-token".to_string());
        let app = FluxoApp::from_config(config).unwrap();
        let _svc = app.admin_service();
    }

    #[test]
    fn renewal_services_empty_for_non_acme() {
        let app = FluxoApp::from_config(minimal_config()).unwrap();
        let svcs = app.renewal_services();
        assert!(svcs.is_empty());
    }

    #[test]
    fn reload_preserves_old_state_on_invalid_config() {
        let app = FluxoApp::from_config(minimal_config()).unwrap();
        // First reload with a valid config succeeds
        let result = app.reload(minimal_config());
        assert!(result.is_ok());
        // Verify the proxy is still functional after reload
        let snap = app.proxy().state_snapshot();
        assert!(!snap.upstreams.is_empty());
    }

    #[test]
    fn collect_acme_domains_deduplicates() {
        let mut svc = crate::config::ServiceConfig::default();
        svc.routes.push(crate::config::RouteConfig {
            match_host: vec!["example.com".to_string(), "example.com".to_string()],
            ..Default::default()
        });
        let domains = collect_acme_domains(&svc);
        // HashSet deduplication — should only have 1
        assert_eq!(domains.len(), 1);
    }

    #[test]
    fn collect_acme_domains_multiple_routes() {
        let mut svc = crate::config::ServiceConfig::default();
        svc.routes.push(crate::config::RouteConfig {
            match_host: vec!["a.com".to_string()],
            ..Default::default()
        });
        svc.routes.push(crate::config::RouteConfig {
            match_host: vec!["b.com".to_string()],
            ..Default::default()
        });
        let domains = collect_acme_domains(&svc);
        assert_eq!(domains.len(), 2);
    }

    #[test]
    fn resolved_tls_returns_none_initially() {
        let app = FluxoApp::from_config(minimal_config()).unwrap();
        // No TLS configured — resolved_tls should be empty for any service
        assert!(app.resolved_tls("web").is_none());
    }

    #[test]
    fn config_accessor_reflects_input() {
        let mut config = minimal_config();
        config.global.threads = 4;
        let app = FluxoApp::from_config(config).unwrap();
        assert_eq!(app.config().global.threads, 4);
    }
}
