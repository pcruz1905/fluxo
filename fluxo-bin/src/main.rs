//! Fluxo — the fast, simple, memory-safe reverse proxy.
//!
//! This is the thin CLI binary that bootstraps the Pingora server.

use std::path::Path;

use clap::Parser;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use tracing_subscriber::EnvFilter;

use fluxo_core::config;
use fluxo_core::FluxoApp;

/// The fast, simple, memory-safe reverse proxy.
#[derive(Parser, Debug)]
#[command(name = "fluxo", version, about)]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "fluxo.toml")]
    config: String,

    /// Quick-start: proxy all traffic to this upstream address
    #[arg(long, value_name = "ADDR")]
    upstream: Option<String>,

    /// Log level override (trace, debug, info, warn, error)
    #[arg(long, value_name = "LEVEL")]
    log_level: Option<String>,

    /// Number of worker threads (0 = auto-detect)
    #[arg(long)]
    threads: Option<usize>,

    /// Validate config and exit
    #[arg(long)]
    test: bool,

    /// Print default config to stdout and exit
    #[arg(long)]
    init: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // --init: print default config and exit
    if cli.init {
        print!("{}", config::default_config_toml());
        return Ok(());
    }

    // Determine log level: CLI flag > env var > config default
    let log_level = cli
        .log_level
        .as_deref()
        .unwrap_or("info");

    // Initialize tracing (structured logging)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .init();

    tracing::info!("starting fluxo v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let fluxo_config = if let Some(ref upstream) = cli.upstream {
        // --upstream shorthand: create minimal config
        tracing::info!(upstream = upstream.as_str(), "using --upstream shorthand");
        config::config_from_upstream(upstream)
    } else {
        let config_path = Path::new(&cli.config);
        if config_path.exists() {
            config::load_from_file(config_path)?
        } else if cli.config == "fluxo.toml" {
            // Default path doesn't exist — try other defaults or use fallback
            config::load_from_default_paths()?
        } else {
            // User specified a non-default path that doesn't exist
            anyhow::bail!("config file not found: {}", cli.config);
        }
    };

    // --test: validate and exit
    if cli.test {
        tracing::info!("configuration is valid");
        // Also try to build the state to catch compilation errors
        let _state = fluxo_core::FluxoState::try_from_config(fluxo_config)?;
        tracing::info!("state compiled successfully");
        return Ok(());
    }

    // Build the app (compiles routes, initializes load balancers)
    let mut app = FluxoApp::from_config(fluxo_config.clone())?;

    // Create Pingora server
    let mut server = Server::new(None)?;
    server.bootstrap();

    // Ensure ACME certificates are available (blocking on first run)
    let has_acme = fluxo_config
        .services
        .values()
        .any(|s| s.tls.as_ref().is_some_and(|t| t.acme));

    if has_acme {
        tracing::info!("checking ACME certificates...");
        // Run the async cert acquisition on Tokio
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(app.ensure_certs())?;
    }

    // Register services from config
    for (service_name, service_config) in &fluxo_config.services {
        let mut svc = http_proxy_service(&server.configuration, app.proxy());

        for listener in &service_config.listeners {
            // Check for resolved TLS (from ACME or manual config via ensure_certs)
            if let Some(resolved) = app.resolved_tls(service_name) {
                svc.add_tls(&listener.address, &resolved.cert_path, &resolved.key_path)?;
                tracing::info!(
                    service = service_name,
                    address = &listener.address,
                    tls = true,
                    "listening"
                );
            } else {
                // Fallback: check raw config for manual TLS (non-ACME path)
                match &service_config.tls {
                    Some(tls) if tls.cert_path.is_some() && tls.key_path.is_some() => {
                        let cert = tls.cert_path.as_ref().unwrap();
                        let key = tls.key_path.as_ref().unwrap();
                        svc.add_tls(&listener.address, cert, key)?;
                        tracing::info!(
                            service = service_name,
                            address = &listener.address,
                            tls = true,
                            "listening"
                        );
                    }
                    _ => {
                        svc.add_tcp(&listener.address);
                        tracing::info!(
                            service = service_name,
                            address = &listener.address,
                            tls = false,
                            "listening"
                        );
                    }
                }
            }
        }

        server.add_service(svc);
    }

    // Register health check background services
    for hc_svc in app.take_health_check_services() {
        server.add_boxed_service(hc_svc);
    }

    // Register cert renewal background services (for ACME-managed domains)
    for renewal_svc in app.renewal_services() {
        server.add_boxed_service(renewal_svc);
    }

    tracing::info!("fluxo is ready");
    server.run_forever();
}
