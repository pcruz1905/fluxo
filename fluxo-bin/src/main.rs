//! Fluxo — the fast, simple, memory-safe reverse proxy.
//!
//! This is the thin CLI binary that bootstraps the Pingora server.

use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use tracing_subscriber::EnvFilter;

use fluxo_core::config;
use fluxo_core::FluxoApp;

fn main() -> anyhow::Result<()> {
    // Initialize tracing (structured logging)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("starting fluxo v{}", env!("CARGO_PKG_VERSION"));

    // Load config from default paths (./fluxo.toml or /etc/fluxo/fluxo.toml)
    // Falls back to a hardcoded upstream for now
    let fluxo_config = config::load_from_default_paths().unwrap_or_else(|e| {
        tracing::warn!("failed to load config: {}, using default", e);
        config::config_from_upstream("1.1.1.1:80")
    });

    // Build the app (compiles routes, initializes load balancers)
    let app = FluxoApp::from_config(fluxo_config.clone())?;

    // Create Pingora server
    let mut server = Server::new(None)?;
    server.bootstrap();

    // Register services from config
    for (service_name, service_config) in &fluxo_config.services {
        let mut svc = http_proxy_service(&server.configuration, app.proxy());

        for listener in &service_config.listeners {
            // TLS will be wired in Step 5
            svc.add_tcp(&listener.address);
            tracing::info!(
                service = service_name,
                address = &listener.address,
                "listening"
            );
        }

        server.add_service(svc);
    }

    tracing::info!("fluxo is ready");
    server.run_forever();
}
