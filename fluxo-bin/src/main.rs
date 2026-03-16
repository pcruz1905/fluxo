//! Fluxo — the fast, simple, memory-safe reverse proxy.
//!
//! This is the thin CLI binary that bootstraps the Pingora server.

use pingora::server::Server;
use pingora::proxy::http_proxy_service;
use tracing_subscriber::EnvFilter;

use fluxo_core::FluxoProxy;

fn main() -> anyhow::Result<()> {
    // Initialize tracing (structured logging)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("starting fluxo v{}", env!("CARGO_PKG_VERSION"));

    // For v0.1 scaffold: hardcoded upstream
    let proxy = FluxoProxy::new("1.1.1.1:80".to_string());

    // Create Pingora server
    let mut server = Server::new(None)?;
    server.bootstrap();

    // Create HTTP proxy service and add a TCP listener
    let mut svc = http_proxy_service(&server.configuration, proxy);
    svc.add_tcp("0.0.0.0:8080");

    tracing::info!("listening on 0.0.0.0:8080, proxying to 1.1.1.1:80");

    server.add_service(svc);
    server.run_forever();
}
