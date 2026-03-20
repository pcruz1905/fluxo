#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::type_complexity,
    dead_code
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Custom test runner (harness = false)
// ---------------------------------------------------------------------------
// Pingora's `run_forever()` spawns threads that never exit, which prevents
// the process from terminating after tests complete.  All E2E tests use
// `harness = false` and this runner, which calls `std::process::exit(0)`
// once every test has passed.

/// Run a list of named async test functions and exit the process.
///
/// Usage (in each E2E test file):
/// ```ignore
/// fn main() { helpers::run_tests(&[("test_name", test_name)]); }
/// ```
pub fn run_tests(
    tests: &[(
        &str,
        fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
    )],
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut passed = 0;

    for (name, test_fn) in tests {
        print!("test {name} ... ");
        rt.block_on(test_fn());
        println!("ok");
        passed += 1;
    }

    println!(
        "\ntest result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
    );
    std::process::exit(0);
}

use axum::Router;
use axum::routing::get;
use pingora_core::server::Server;
use pingora_core::server::configuration::Opt;
use pingora_proxy::http_proxy_service;

use fluxo_core::config::{
    FluxoConfig, ListenerConfig, RouteConfig, ServiceConfig, TargetConfig, UpstreamConfig,
};
use fluxo_core::proxy::{FluxoProxy, FluxoState};

// ---------------------------------------------------------------------------
// Mock upstream helpers
// ---------------------------------------------------------------------------

/// Start a mock upstream with custom routes.
pub async fn start_mock_upstream(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Start a mock upstream with standard routes: `/echo`, `/large`, `/headers`, `/status/500`.
pub async fn default_mock_upstream() -> SocketAddr {
    let app = Router::new()
        .route("/echo", get(|| async { "echo" }))
        .route("/", get(|| async { "root" }))
        .route("/large", get(|| async { "A".repeat(1024) }))
        .route(
            "/headers",
            get(|headers: axum::http::HeaderMap| async move {
                let mut out = String::new();
                let mut keys: Vec<_> = headers.keys().collect();
                keys.sort_by_key(|k| k.as_str());
                for k in keys {
                    let v = headers.get(k).unwrap();
                    out.push_str(&format!("{}: {}\n", k, v.to_str().unwrap_or("")));
                }
                out
            }),
        )
        .route(
            "/status/500",
            get(|| async { (hyper::StatusCode::INTERNAL_SERVER_ERROR, "failed") }),
        );
    start_mock_upstream(app).await
}

// ---------------------------------------------------------------------------
// Config builders (Traefik-inspired fluent helpers)
// ---------------------------------------------------------------------------

/// Create a standard upstream config pointing at a mock backend.
pub fn mock_upstream_config(addr: SocketAddr) -> UpstreamConfig {
    UpstreamConfig {
        discovery: "static".to_string(),
        targets: vec![TargetConfig::Simple(addr.to_string())],
        load_balancing: "round_robin".to_string(),
        connect_timeout: "1s".to_string(),
        read_timeout: "5s".to_string(),
        write_timeout: "5s".to_string(),
        ..Default::default()
    }
}

/// Create a minimal route matching a host.
pub fn simple_route(name: &str, host: &str, upstream: &str) -> RouteConfig {
    RouteConfig {
        name: Some(name.to_string()),
        match_host: vec![host.to_string()],
        upstream: upstream.to_string(),
        ..Default::default()
    }
}

/// Create a route with plugins.
pub fn route_with_plugins(
    name: &str,
    host: &str,
    upstream: &str,
    plugins: HashMap<String, serde_json::Value>,
) -> RouteConfig {
    RouteConfig {
        name: Some(name.to_string()),
        match_host: vec![host.to_string()],
        upstream: upstream.to_string(),
        plugins,
        ..Default::default()
    }
}

/// Wrap routes in a service with a `0.0.0.0:0` listener (Pingora picks a random port).
pub fn minimal_service(routes: Vec<RouteConfig>) -> ServiceConfig {
    ServiceConfig {
        listeners: vec![ListenerConfig {
            address: "0.0.0.0:0".to_string(),
            offer_h2: false,
            proxy_protocol: false,
        }],
        routes,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Proxy bootstrap
// ---------------------------------------------------------------------------

/// Start a full Pingora proxy server with the given config.
///
/// Returns `(proxy_url, reqwest::Client)`. The proxy is running in a background thread.
/// Uses `wait_for_server` to ensure the proxy is ready before returning.
pub async fn start_proxy(config: FluxoConfig) -> (String, reqwest::Client) {
    let random_port = fastrand::u16(10000..60000);
    let proxy_addr = format!("127.0.0.1:{random_port}");

    let mut server = Server::new(Some(Opt {
        conf: None,
        daemon: false,
        upgrade: false,
        test: true,
        nocapture: false,
    }))
    .unwrap();
    server.bootstrap();

    let build = FluxoState::build(config).expect("failed to build proxy state");
    let proxy = FluxoProxy::new(build.state).expect("failed to init proxy");

    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&proxy_addr);
    server.add_service(proxy_service);

    std::thread::spawn(move || {
        server.run_forever();
    });

    let proxy_url = format!("http://{proxy_addr}");
    wait_for_server(&proxy_url, Duration::from_secs(5)).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap();

    (proxy_url, client)
}

/// Wait for a server to become ready.
///
/// Pingora needs time to bootstrap workers after binding.
/// We first wait for TCP accept, then give workers time to initialize.
async fn wait_for_server(url: &str, timeout: Duration) {
    let start = std::time::Instant::now();
    let addr = url.trim_start_matches("http://");
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        assert!(
            start.elapsed() <= timeout,
            "server at {url} did not become ready within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Give Pingora workers time to initialize after the socket is bound
    tokio::time::sleep(Duration::from_millis(500)).await;
}
