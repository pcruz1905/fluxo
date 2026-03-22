#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod helpers;

use std::collections::HashMap;

use axum::Router;
use axum::routing::get;
use fluxo_core::config::{FluxoConfig, TargetConfig, UpstreamConfig};
use helpers::{
    default_mock_upstream, minimal_service, mock_upstream_config, route_with_plugins, simple_route,
    start_mock_upstream, start_proxy,
};

fn main() {
    helpers::run_tests(&[
        ("static_response_returns_configured_status", || {
            Box::pin(static_response_returns_configured_status())
        }),
        ("redirect_returns_301", || {
            Box::pin(redirect_returns_301())
        }),
        ("strip_and_add_prefix_rewrites_path", || {
            Box::pin(strip_and_add_prefix_rewrites_path())
        }),
        ("rate_limit_blocks_after_burst", || {
            Box::pin(rate_limit_blocks_after_burst())
        }),
        ("compression_gzip_applied", || {
            Box::pin(compression_gzip_applied())
        }),
        ("ip_deny_blocks_all", || Box::pin(ip_deny_blocks_all())),
        ("upstream_offline_returns_502", || {
            Box::pin(upstream_offline_returns_502())
        }),
    ]);
}

async fn static_response_returns_configured_status() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "static",
            "static.test",
            "backend",
            HashMap::from([(
                "static_response".into(),
                serde_json::json!({"status": 201, "body": "static"}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(&url)
        .header("Host", "static.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
}

async fn redirect_returns_301() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "redirect",
            "redirect.test",
            "backend",
            HashMap::from([(
                "redirect".into(),
                serde_json::json!({"url": "http://new.test", "status": 301}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(&url)
        .header("Host", "redirect.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 301);
}

async fn strip_and_add_prefix_rewrites_path() {
    let app = Router::new()
        .route("/", get(|| async { "root" }))
        .route("/prefixed/echo", get(|| async { "prefixed echo" }));
    let upstream = start_mock_upstream(app).await;

    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "prefixes",
            "prefix.test",
            "backend",
            HashMap::from([
                (
                    "strip_prefix".into(),
                    serde_json::json!({"prefixes": ["/api"]}),
                ),
                (
                    "add_prefix".into(),
                    serde_json::json!({"prefix": "/prefixed"}),
                ),
            ]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/api/echo"))
        .header("Host", "prefix.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "prefixed echo");
}

async fn rate_limit_blocks_after_burst() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "rate_limit",
            "limit.test",
            "backend",
            HashMap::from([(
                "rate_limit".into(),
                serde_json::json!({"requests_per_second": 1, "burst": 1}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp1 = client
        .get(&url)
        .header("Host", "limit.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);
    let resp2 = client
        .get(&url)
        .header("Host", "limit.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 429);
}

async fn compression_gzip_applied() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "compression",
            "compress.test",
            "backend",
            HashMap::from([(
                "compression".into(),
                serde_json::json!({"algorithms": ["gzip"], "min_size": 100}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/large"))
        .header("Host", "compress.test")
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-encoding").unwrap(), "gzip");
}

async fn ip_deny_blocks_all() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "ip_deny",
            "deny.test",
            "backend",
            HashMap::from([(
                "ip_restrict".into(),
                serde_json::json!({"deny": ["0.0.0.0/0"]}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(&url)
        .header("Host", "deny.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

async fn upstream_offline_returns_502() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    // Live upstream for route compilation
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    // Dead upstream for 502 testing
    config.upstreams.insert(
        "dead".into(),
        UpstreamConfig {
            discovery: "static".into(),
            targets: vec![TargetConfig::Simple("127.0.0.1:1".into())],
            load_balancing: "round_robin".into(),
            connect_timeout: "100ms".into(),
            ..Default::default()
        },
    );
    config.services.insert(
        "main".into(),
        minimal_service(vec![simple_route("offline", "offline.test", "dead")]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(&url)
        .header("Host", "offline.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502);
}
