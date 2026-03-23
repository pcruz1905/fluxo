//! Fluxo — the fast, simple, memory-safe reverse proxy.
//!
//! This is the thin CLI binary that bootstraps the Pingora server.

use std::path::Path;

use clap::Parser;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use pingora::server::configuration::Opt;
use tracing_subscriber::EnvFilter;

use fluxo_core::FluxoApp;
use fluxo_core::config;

/// The fast, simple, memory-safe reverse proxy.
#[allow(clippy::struct_excessive_bools)]
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

    /// Lint config for warnings (unused upstreams, security issues, etc.)
    #[arg(long)]
    lint: bool,

    /// Graceful binary upgrade — new process takes over from old process.
    /// Start the new binary with this flag to receive listening sockets
    /// from the running instance via the upgrade socket (Unix only).
    #[arg(long)]
    upgrade: bool,

    /// Run as a daemon (background process, Unix only).
    #[arg(long)]
    daemon: bool,
}

#[allow(clippy::too_many_lines)]
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // --init: print default config and exit
    if cli.init {
        print!("{}", config::default_config_toml());
        return Ok(());
    }

    // Load configuration first (before tracing init so we can respect access_log_format)
    let fluxo_config = if let Some(ref upstream) = cli.upstream {
        config::config_from_upstream(upstream)?
    } else {
        let config_path = Path::new(&cli.config);
        if config_path.exists() {
            config::load_from_file(config_path)?
        } else if cli.config == "fluxo.toml" {
            config::load_from_default_paths()?
        } else {
            anyhow::bail!("config file not found: {}", cli.config);
        }
    };

    // Determine log level: CLI flag > env var > config default
    let log_level = cli
        .log_level
        .as_deref()
        .unwrap_or(&fluxo_config.global.log_level);

    // Initialize tracing (structured logging + optional OTLP export)
    // If OTLP is enabled, init_otlp_tracer sets up a combined subscriber (fmt + OTLP).
    // Otherwise fall back to plain fmt subscriber.
    let otlp_guard = fluxo_core::observability::init_otlp_tracer(
        &fluxo_config.global.tracing,
        log_level,
        fluxo_config.global.access_log_format,
    );
    if otlp_guard.is_none() {
        // OTLP not enabled or failed — use plain tracing subscriber
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
        match fluxo_config.global.access_log_format {
            config::AccessLogFormat::Json => {
                tracing_subscriber::fmt()
                    .json()
                    .with_env_filter(env_filter)
                    .init();
            }
            config::AccessLogFormat::Compact => {
                tracing_subscriber::fmt().with_env_filter(env_filter).init();
            }
        }
    }

    // Initialize access log file writer (if configured) with rotation
    let log_max_size =
        fluxo_core::config::parse_size(&fluxo_config.global.access_log_max_size).unwrap_or(0);
    fluxo_core::observability::init_file_logger(
        fluxo_config.global.access_log_file.as_deref(),
        log_max_size,
        fluxo_config.global.access_log_max_backups,
    );

    // Initialize syslog output (if configured)
    if let Some(ref syslog_config) = fluxo_config.global.syslog {
        fluxo_core::observability::init_syslog(syslog_config);
    }

    // Initialize disk cache storage (if configured)
    if let Some(ref cache_dir) = fluxo_config.global.cache_dir {
        let max_size =
            fluxo_core::cache::DiskCache::parse_max_size(&fluxo_config.global.cache_max_disk_size);
        let cache_path = std::path::PathBuf::from(cache_dir);
        if let Err(e) = std::fs::create_dir_all(&cache_path) {
            tracing::warn!(path = %cache_dir, error = %e, "failed to create cache directory");
        } else {
            fluxo_core::proxy::init_disk_cache(cache_path, max_size);
            tracing::info!(path = %cache_dir, max_size_bytes = max_size, "disk cache initialized");
        }
    }

    // Initialize cache stampede protection (Pingora cache lock)
    let cache_lock_timeout =
        fluxo_core::config::parse_duration(&fluxo_config.global.cache_lock_timeout)
            .unwrap_or(std::time::Duration::from_secs(3));
    fluxo_core::proxy::init_cache_lock(cache_lock_timeout);

    tracing::info!("starting fluxo v{}", env!("CARGO_PKG_VERSION"));

    // --test: validate and exit
    if cli.test {
        tracing::info!("configuration is valid");
        // Also try to build the state to catch compilation errors
        let _state = fluxo_core::FluxoState::try_from_config(fluxo_config)?;
        tracing::info!("state compiled successfully");
        return Ok(());
    }

    // --lint: validate, check for warnings, and exit
    if cli.lint {
        tracing::info!("configuration is valid");
        let warnings = fluxo_core::config::lint::lint(&fluxo_config);
        if warnings.is_empty() {
            tracing::info!("no lint warnings found");
        } else {
            let warn_count = warnings
                .iter()
                .filter(|w| w.level == fluxo_core::config::lint::LintLevel::Warn)
                .count();
            let info_count = warnings
                .iter()
                .filter(|w| w.level == fluxo_core::config::lint::LintLevel::Info)
                .count();
            for w in &warnings {
                match w.level {
                    fluxo_core::config::lint::LintLevel::Warn => {
                        tracing::warn!("{}", w.message);
                    }
                    fluxo_core::config::lint::LintLevel::Info => {
                        tracing::info!("{}", w.message);
                    }
                }
            }
            tracing::info!("{warn_count} warning(s), {info_count} info(s)");
        }
        return Ok(());
    }

    // Determine the config file path for hot-reload (not available in --upstream mode)
    let config_file_path = if cli.upstream.is_none() {
        let p = Path::new(&cli.config);
        if p.exists() {
            Some(p.to_path_buf())
        } else {
            None
        }
    } else {
        None
    };

    // Build the app (compiles routes, initializes load balancers)
    let mut app = FluxoApp::from_config_with_path(fluxo_config.clone(), config_file_path.clone())?;

    // Create Pingora server with upgrade/daemon options
    let opt = Opt {
        conf: None,
        daemon: cli.daemon,
        upgrade: cli.upgrade,
        test: false,
        nocapture: false,
    };
    let mut server = Server::new(Some(opt))?;

    // Configure graceful shutdown (Traefik-inspired two-phase drain)
    // ServerConf is behind Arc, so we build a new one with the shutdown settings.
    let mut conf = pingora::server::configuration::ServerConf::default();
    if let Some(ref drain_delay) = fluxo_config.global.shutdown_drain_delay {
        if let Ok(d) = config::parse_duration(drain_delay) {
            conf.grace_period_seconds = Some(d.as_secs());
        }
    }
    if let Some(ref timeout) = fluxo_config.global.shutdown_timeout {
        if let Ok(d) = config::parse_duration(timeout) {
            conf.graceful_shutdown_timeout_seconds = Some(d.as_secs());
        }
    }
    // Wire pid_file and upgrade_socket to Pingora
    if let Some(ref pid_file) = fluxo_config.global.pid_file {
        conf.pid_file.clone_from(pid_file);
    }
    if let Some(ref upgrade_socket) = fluxo_config.global.upgrade_socket {
        conf.upgrade_sock.clone_from(upgrade_socket);
    }
    // Preserve thread count from our config
    if fluxo_config.global.threads > 0 {
        conf.threads = fluxo_config.global.threads;
    }
    server.configuration = std::sync::Arc::new(conf);

    server.bootstrap();

    // Ensure ACME certificates are available (blocking on first run)
    let has_acme = fluxo_config
        .services
        .values()
        .any(|s| s.tls.as_ref().is_some_and(|t| t.acme));

    if has_acme {
        tracing::info!("checking ACME certificates...");
        // Run the async cert acquisition — reuse existing runtime if available
        // (Pingora may have already started one), otherwise create a temporary one.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.block_on(app.ensure_certs())?;
        } else {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(app.ensure_certs())?;
        }
    }

    // Register services from config
    for (service_name, service_config) in &fluxo_config.services {
        let mut svc = http_proxy_service(&server.configuration, app.proxy());

        for listener in &service_config.listeners {
            // Check for resolved TLS (from ACME or manual config via ensure_certs)
            if let Some(resolved) = app.resolved_tls(service_name) {
                let settings = build_tls_settings(
                    &resolved.cert_path,
                    &resolved.key_path,
                    service_config.tls.as_ref(),
                )?;
                svc.add_tls_with_settings(&listener.address, None, settings);
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
                        // SAFETY: guarded by is_some() checks above
                        let Some(cert) = tls.cert_path.as_ref() else {
                            continue;
                        };
                        let Some(key) = tls.key_path.as_ref() else {
                            continue;
                        };
                        let settings = build_tls_settings(cert, key, Some(tls))?;
                        svc.add_tls_with_settings(&listener.address, None, settings);
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

    // Register L4 TCP proxy services
    for (name, tcp_config) in &fluxo_config.l4.tcp_services {
        let tcp_proxy = std::sync::Arc::new(fluxo_core::l4::TcpProxy::new(tcp_config.clone()));
        let listen_addr = tcp_config.listen.clone();
        let svc_name = name.clone();
        tokio::spawn(async move {
            tracing::info!(
                service = svc_name,
                address = listen_addr,
                "L4 TCP proxy listening"
            );
            if let Err(e) = tcp_proxy.run().await {
                tracing::error!(service = svc_name, error = %e, "L4 TCP proxy failed");
            }
        });
    }

    // Register L4 UDP proxy services
    for (name, udp_config) in &fluxo_config.l4.udp_services {
        let udp_proxy = std::sync::Arc::new(fluxo_core::l4::UdpProxy::new(udp_config.clone()));
        let listen_addr = udp_config.listen.clone();
        let svc_name = name.clone();
        tokio::spawn(async move {
            tracing::info!(
                service = svc_name,
                address = listen_addr,
                "L4 UDP proxy listening"
            );
            if let Err(e) = udp_proxy.run().await {
                tracing::error!(service = svc_name, error = %e, "L4 UDP proxy failed");
            }
        });
    }

    // Register L4 mail proxy services
    for (name, mail_config) in &fluxo_config.l4.mail_services {
        let mail_proxy = std::sync::Arc::new(fluxo_core::l4::MailProxy::new(mail_config.clone()));
        let listen_addr = mail_config.listen.clone();
        let svc_name = name.clone();
        tokio::spawn(async move {
            tracing::info!(
                service = svc_name,
                address = listen_addr,
                "L4 mail proxy listening"
            );
            if let Err(e) = mail_proxy.run().await {
                tracing::error!(service = svc_name, error = %e, "L4 mail proxy failed");
            }
        });
    }

    // Register Admin API
    let admin_service = app.admin_service();
    server.add_boxed_service(admin_service);
    tracing::info!(admin = %app.config().global.admin, "admin API registered");

    tracing::info!("fluxo is ready");

    // Set draining flag on shutdown signal (lets /health return 503 during drain)
    let draining = app.proxy().static_state.draining.clone();
    tokio::spawn(async move {
        // Wait for shutdown notification via Pingora's shutdown watch
        // Since Pingora handles signals internally, we listen for SIGTERM ourselves
        // to set the draining flag before Pingora starts its grace period.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("failed to register SIGTERM: {e}");
                    return;
                }
            };
            let mut int = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("failed to register SIGINT: {e}");
                    return;
                }
            };
            tokio::select! {
                _ = term.recv() => {},
                _ = int.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        tracing::info!("shutdown signal received, setting drain flag");
        draining.store(true, std::sync::atomic::Ordering::Relaxed);
    });

    // Hot-reload config pipeline (FileProvider -> ConfigWatcher -> Proxy)
    if let Some(path) = config_file_path {
        let proxy_for_watcher = app.proxy();
        let (tx, rx) = tokio::sync::mpsc::channel(4);

        let file_provider = fluxo_core::config::file_provider::FileProvider::new(path);
        let mut watcher = fluxo_core::config::watcher::ConfigWatcher::new(rx, proxy_for_watcher);

        // Spawn provider loop
        tokio::spawn(async move {
            use fluxo_core::config::provider::ConfigProvider;
            if let Err(e) = file_provider.watch(tx).await {
                tracing::error!("FileProvider exited with error: {e}");
            }
        });

        // Spawn watcher loop
        tokio::spawn(async move {
            watcher.run().await;
        });
    }

    // `otlp_guard` must stay alive until process exit — `run_forever()` never returns,
    // so the guard is held for the lifetime of the process, flushing spans on shutdown.
    let _otlp_keep = otlp_guard;
    server.run_forever();
}

/// Build `TlsSettings` from cert/key paths, applying cipher and version configuration,
/// mTLS client verification, and OCSP stapling from the service's TLS config block.
fn build_tls_settings(
    cert_path: &str,
    key_path: &str,
    tls_config: Option<&config::TlsConfig>,
) -> anyhow::Result<pingora::listeners::tls::TlsSettings> {
    let mut settings = pingora::listeners::tls::TlsSettings::intermediate(cert_path, key_path)
        .map_err(|e| anyhow::anyhow!("failed to create TLS settings: {e}"))?;

    if let Some(tls) = tls_config {
        apply_tls_options(&mut settings, tls, cert_path);

        // Certificate Transparency: extract and validate SCTs at startup
        if tls.certificate_transparency {
            match std::fs::read_to_string(cert_path) {
                Ok(pem) => {
                    let scts = fluxo_core::tls::ct::extract_scts_from_pem(&pem);
                    if scts.is_empty() {
                        if tls.ct_enforce {
                            tracing::warn!(
                                cert = cert_path,
                                "CT enforce: certificate has no embedded SCTs"
                            );
                        } else {
                            tracing::info!(
                                cert = cert_path,
                                "CT: no embedded SCTs found in certificate"
                            );
                        }
                    } else {
                        tracing::info!(
                            cert = cert_path,
                            sct_count = scts.len(),
                            "CT: certificate has valid SCTs"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        cert = cert_path,
                        error = %e,
                        "CT: failed to read certificate for SCT extraction"
                    );
                }
            }
        }
    }

    Ok(settings)
}

/// Apply cipher list, TLS 1.3 ciphersuites, version bounds, and mTLS client
/// certificate verification to TLS settings.
///
/// On `BoringSSL`, `TlsSettings` derefs to `SslAcceptorBuilder` which exposes the full
/// OpenSSL configuration API. On rustls, mTLS uses `WebPkiClientVerifier` but cipher/version
/// options are not configurable via Pingora's API.
#[allow(unused_variables, clippy::needless_pass_by_ref_mut)]
fn apply_tls_options(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &config::TlsConfig,
    cert_path: &str,
) {
    let has_custom = tls.cipher_list.is_some()
        || tls.tls13_ciphersuites.is_some()
        || tls.min_version.is_some()
        || tls.max_version.is_some();

    #[cfg(feature = "boringssl")]
    {
        if let Some(ref ciphers) = tls.cipher_list {
            if let Err(e) = settings.set_cipher_list(ciphers) {
                tracing::warn!(error = %e, ciphers, "failed to set TLS cipher list");
            }
        }
        if tls.tls13_ciphersuites.is_some() {
            tracing::warn!(
                "tls13_ciphersuites is not supported with BoringSSL — TLS 1.3 uses a built-in cipher preference order"
            );
        }
        if let Some(ref min) = tls.min_version {
            if let Some(ver) = parse_tls_version(min) {
                if let Err(e) = settings.set_min_proto_version(Some(ver)) {
                    tracing::warn!(error = %e, version = min, "failed to set min TLS version");
                }
            }
        }
        if let Some(ref max) = tls.max_version {
            if let Some(ver) = parse_tls_version(max) {
                if let Err(e) = settings.set_max_proto_version(Some(ver)) {
                    tracing::warn!(error = %e, version = max, "failed to set max TLS version");
                }
            }
        }

        // mTLS: configure client certificate verification
        apply_mtls_boringssl(settings, tls);

        // OCSP stapling
        if tls.ocsp_stapling {
            apply_ocsp_stapling_boringssl(settings, tls, cert_path);
        }
    }

    #[cfg(not(feature = "boringssl"))]
    {
        if has_custom {
            tracing::warn!(
                "cipher_list, tls13_ciphersuites, min_version, max_version are only supported with the boringssl feature"
            );
        }

        // mTLS: configure client certificate verification
        apply_mtls_rustls(settings, tls);

        // OCSP stapling not supported on rustls (Pingora doesn't expose the callback)
        if tls.ocsp_stapling {
            tracing::warn!(
                "OCSP stapling is only supported with the boringssl feature — \
                 Pingora's rustls TlsSettings does not expose OCSP response injection"
            );
        }
    }
}

/// Apply mTLS client certificate verification on BoringSSL.
///
/// Uses OpenSSL API: `set_verify()` to control verification mode and `set_ca_file()` to
/// load the trusted CA pool.
#[cfg(feature = "boringssl")]
fn apply_mtls_boringssl(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &config::TlsConfig,
) {
    use fluxo_core::tls::ClientAuthType;
    use pingora::tls::ssl::SslVerifyMode;

    let auth_type: ClientAuthType = match tls.client_auth_type.parse() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "invalid client_auth_type, skipping mTLS");
            return;
        }
    };

    match auth_type {
        ClientAuthType::None => {}
        ClientAuthType::Request => {
            // Request client cert but don't require it
            settings.set_verify(SslVerifyMode::PEER);
            if let Some(ref ca_path) = tls.client_ca_path {
                if let Err(e) = settings.set_ca_file(ca_path) {
                    tracing::warn!(error = %e, path = ca_path, "failed to load client CA file");
                }
            }
            tracing::info!(
                auth_type = "request",
                "mTLS client cert verification enabled"
            );
        }
        ClientAuthType::Require => {
            // Require client cert but don't validate against CA
            settings.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            tracing::info!(
                auth_type = "require",
                "mTLS client cert required (no CA validation)"
            );
        }
        ClientAuthType::Verify => {
            // Require client cert and validate against CA
            settings.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
            if let Some(ref ca_path) = tls.client_ca_path {
                if let Err(e) = settings.set_ca_file(ca_path) {
                    tracing::warn!(error = %e, path = ca_path, "failed to load client CA file");
                }
            } else {
                tracing::warn!(
                    "client_auth_type is 'verify' but no client_ca_path provided — clients will fail verification"
                );
            }
            tracing::info!(
                auth_type = "verify",
                "mTLS client cert verification enabled (CA-validated)"
            );
        }
    }
}

/// Configure OCSP stapling on BoringSSL.
///
/// Creates an `OcspCache`, spawns a background task to periodically fetch OCSP
/// responses, and registers a TLS status callback that provides the cached
/// response during handshakes.
#[cfg(feature = "boringssl")]
fn apply_ocsp_stapling_boringssl(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &config::TlsConfig,
    cert_path: &str,
) {
    use fluxo_core::tls::ocsp;

    let cache = ocsp::OcspCache::new();
    let cert_path_owned = cert_path.to_string();
    let responder_override = tls.ocsp_responder.clone();

    // Spawn background OCSP fetcher — runs once the tokio runtime starts.
    // The fetcher populates the shared cache with periodic refreshes.
    let cache_bg = cache.clone();
    tokio::spawn(async move {
        if let Some(fetched_cache) =
            ocsp::start_ocsp_stapling(cert_path_owned, responder_override, None).await
        {
            // Transfer the initial response to our shared cache
            if let Some(response) = fetched_cache.get() {
                cache_bg.set(response);
            }
        }
    });

    // Register the TLS status callback to provide OCSP responses during handshakes
    if let Err(e) = settings.set_status_callback(move |ssl| {
        if let Some(response) = cache.get() {
            ssl.set_ocsp_status(&response)?;
            Ok(true) // send the OCSP response
        } else {
            Ok(false) // no OCSP response available yet
        }
    }) {
        tracing::warn!(error = %e, "failed to set OCSP status callback");
    } else {
        tracing::info!(cert = cert_path, "OCSP stapling enabled");
    }
}

/// Apply mTLS client certificate verification on rustls.
///
/// Uses `WebPkiClientVerifier` to build a client cert verifier from the CA file.
#[cfg(not(feature = "boringssl"))]
fn apply_mtls_rustls(settings: &mut pingora::listeners::tls::TlsSettings, tls: &config::TlsConfig) {
    use fluxo_core::tls::ClientAuthType;

    let auth_type: ClientAuthType = match tls.client_auth_type.parse() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "invalid client_auth_type, skipping mTLS");
            return;
        }
    };

    if auth_type == ClientAuthType::None {
        return;
    }

    let Some(ref ca_path) = tls.client_ca_path else {
        if auth_type == ClientAuthType::Require {
            tracing::warn!(
                "client_auth_type 'require' on rustls needs client_ca_path — \
                 rustls always validates client certs against a CA"
            );
        } else {
            tracing::warn!(
                "mTLS enabled but no client_ca_path provided — cannot configure client verification"
            );
        }
        return;
    };

    // Load CA certificates into a root store
    let mut root_store = pingora::tls::RootCertStore::empty();
    if let Err(e) = pingora::tls::load_ca_file_into_store(ca_path, &mut root_store) {
        tracing::warn!(error = %e, path = ca_path, "failed to load client CA file");
        return;
    }

    let root_store = std::sync::Arc::new(root_store);

    // Build the verifier — allow_unauthenticated for Request mode, strict for Verify/Require
    let verifier = match auth_type {
        ClientAuthType::Request => {
            match pingora::tls::WebPkiClientVerifier::builder(root_store)
                .allow_unauthenticated()
                .build()
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to build client cert verifier");
                    return;
                }
            }
        }
        ClientAuthType::Require | ClientAuthType::Verify => {
            match pingora::tls::WebPkiClientVerifier::builder(root_store).build() {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to build client cert verifier");
                    return;
                }
            }
        }
        ClientAuthType::None => unreachable!(),
    };

    settings.set_client_cert_verifier(verifier);
    tracing::info!(
        auth_type = ?auth_type,
        "mTLS client cert verification enabled"
    );
}

/// Parse a TLS version string ("1.0", "1.1", "1.2", "1.3") to an OpenSSL `SslVersion`.
#[cfg(feature = "boringssl")]
fn parse_tls_version(s: &str) -> Option<pingora::tls::ssl::SslVersion> {
    use pingora::tls::ssl::SslVersion;
    match s {
        "1.0" => Some(SslVersion::TLS1),
        "1.1" => Some(SslVersion::TLS1_1),
        "1.2" => Some(SslVersion::TLS1_2),
        "1.3" => Some(SslVersion::TLS1_3),
        _ => {
            tracing::warn!(version = s, "unknown TLS version, expected 1.0/1.1/1.2/1.3");
            None
        }
    }
}
