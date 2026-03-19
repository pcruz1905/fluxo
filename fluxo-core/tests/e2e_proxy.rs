use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use axum::{routing::get, Router};
use hyper::StatusCode;
use pingora_core::server::Server;
use pingora_core::server::configuration::Opt;
use pingora_proxy::http_proxy_service;

use fluxo_core::config::{
    FluxoConfig, RouteConfig, ServiceConfig, UpstreamConfig, TargetConfig, ListenerConfig,
};
use fluxo_core::proxy::{FluxoProxy, FluxoState};

/// Helper to start the mock Upstream server.
async fn start_mock_upstream() -> SocketAddr {
    let app = Router::new()
        .route("/echo", get(|| async { "echo" }))
        .route("/prefixed/echo", get(|| async { "prefixed echo" }))
        .route("/large", get(|| async { "A".repeat(1024) })) // Large enough to trigger compression
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
            get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "failed") }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    
    addr
}

#[tokio::test]
async fn test_end_to_end_proxy_complete_suite() {
    // 1. Start Mock Upstream
    let upstream_addr = start_mock_upstream().await;

    // 2. Build the Global Test Configuration
    let mut config = FluxoConfig::default();
    
    // Add the mock upstream
    config.upstreams.insert(
        "mock_backend".to_string(),
        UpstreamConfig {
            discovery: "static".to_string(),
            targets: vec![TargetConfig::Simple(upstream_addr.to_string())],
            load_balancing: "round_robin".to_string(),
            circuit_breaker: None,
            health_check: None,
            connect_timeout: "1s".to_string(),
            read_timeout: "1s".to_string(),
            write_timeout: "1s".to_string(),
            keepalive_timeout: "60s".to_string(),
            keepalive_pool_size: 128,
            ..Default::default()
        },
    );

    // Add a dead upstream for 502 testing
    config.upstreams.insert(
        "dead_backend".to_string(),
        UpstreamConfig {
            discovery: "static".to_string(),
            targets: vec![TargetConfig::Simple("127.0.0.1:1".to_string())], // Port 1 is likely closed
            load_balancing: "round_robin".to_string(),
            connect_timeout: "100ms".to_string(),
            ..Default::default()
        },
    );

    let mut svc = ServiceConfig {
        listeners: vec![ListenerConfig {
            address: "0.0.0.0:0".to_string(),
            offer_h2: false,
            proxy_protocol: false,
        }],
        routes: vec![],
        ..Default::default()
    };

    // --- CORE PLUGINS ---
    
    // Static & Redirect
    svc.routes.push(RouteConfig {
        name: Some("static".to_string()),
        match_host: vec!["static.test".to_string()],
        upstream: "mock_backend".to_string(),
        plugins: HashMap::from([("static_response".to_string(), serde_json::json!({"status": 201, "body": "static"}))]),
        ..Default::default()
    });
    svc.routes.push(RouteConfig {
        name: Some("redirect".to_string()),
        match_host: vec!["redirect.test".to_string()],
        upstream: "mock_backend".to_string(),
        plugins: HashMap::from([("redirect".to_string(), serde_json::json!({"url": "http://new.test", "status": 301}))]),
        ..Default::default()
    });

    // Prefixes
    svc.routes.push(RouteConfig {
        name: Some("prefixes".to_string()),
        match_host: vec!["prefix.test".to_string()],
        upstream: "mock_backend".to_string(),
        plugins: HashMap::from([
            ("strip_prefix".to_string(), serde_json::json!({"prefixes": ["/api"]})),
            ("add_prefix".to_string(), serde_json::json!({"prefix": "/prefixed"}))
        ]),
        ..Default::default()
    });

    // --- ADVANCED PLUGINS ---

    // Rate Limiting (1 request per second)
    svc.routes.push(RouteConfig {
        name: Some("rate_limit".to_string()),
        match_host: vec!["limit.test".to_string()],
        upstream: "mock_backend".to_string(),
        plugins: HashMap::from([("rate_limit".to_string(), serde_json::json!({"requests_per_second": 1, "burst": 1}))]),
        ..Default::default()
    });

    // Compression
    svc.routes.push(RouteConfig {
        name: Some("compression".to_string()),
        match_host: vec!["compress.test".to_string()],
        upstream: "mock_backend".to_string(),
        plugins: HashMap::from([("compression".to_string(), serde_json::json!({"algorithms": ["gzip"], "min_size": 100}))]),
        ..Default::default()
    });

    // IP Restriction (Deny all)
    svc.routes.push(RouteConfig {
        name: Some("ip_deny".to_string()),
        match_host: vec!["deny.test".to_string()],
        upstream: "mock_backend".to_string(),
        plugins: HashMap::from([("ip_restrict".to_string(), serde_json::json!({"deny": ["0.0.0.0/0"]}))]),
        ..Default::default()
    });

    // --- RESILIENCE ---
    svc.routes.push(RouteConfig {
        name: Some("offline".to_string()),
        match_host: vec!["offline.test".to_string()],
        upstream: "dead_backend".to_string(),
        ..Default::default()
    });

    config.services.insert("main".to_string(), svc);

    // 3. Start Pingora Server
    let random_port = fastrand::u16(10000..60000);
    let proxy_addr = format!("127.0.0.1:{}", random_port);

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

    // Wait for server to boot
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let proxy_url = format!("http://{}", proxy_addr);

    // === EXECUTE TESTS ===

    // Test: Basic Routing
    let resp = client.get(&proxy_url).header("Host", "static.test").send().await.unwrap();
    assert_eq!(resp.status(), 201);

    // Test: Rate Limiting
    let resp1 = client.get(&proxy_url).header("Host", "limit.test").send().await.unwrap();
    assert_eq!(resp1.status(), 200);
    let resp2 = client.get(&proxy_url).header("Host", "limit.test").send().await.unwrap();
    assert_eq!(resp2.status(), 429);

    // Test: Compression
    let resp = client.get(format!("{}/large", proxy_url))
        .header("Host", "compress.test")
        .header("Accept-Encoding", "gzip")
        .send().await.unwrap();
    assert_eq!(resp.status(), 200);
    // reqwest handles decoding, but we can check if it was encoded
    assert_eq!(resp.headers().get("content-encoding").unwrap(), "gzip");

    // Test: IP Restriction
    let resp = client.get(&proxy_url).header("Host", "deny.test").send().await.unwrap();
    assert_eq!(resp.status(), 403);

    // Test: Upstream Offline (502)
    let resp = client.get(&proxy_url).header("Host", "offline.test").send().await.unwrap();
    assert_eq!(resp.status(), 502);

    println!("All behavioral tests passed!");
}
