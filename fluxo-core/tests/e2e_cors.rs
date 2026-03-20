#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use std::collections::HashMap;

use fluxo_core::config::FluxoConfig;
use helpers::{default_mock_upstream, minimal_service, mock_upstream_config, route_with_plugins, start_proxy};

fn main() {
    helpers::run_tests(&[
        ("cors_preflight_returns_allow_headers", || {
            Box::pin(cors_preflight_returns_allow_headers())
        }),
        ("cors_normal_request_has_origin_header", || {
            Box::pin(cors_normal_request_has_origin_header())
        }),
    ]);
}

async fn cors_preflight_returns_allow_headers() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "cors",
            "cors.test",
            "backend",
            HashMap::from([(
                "cors".into(),
                serde_json::json!({
                    "allowed_origins": ["https://example.com"],
                    "allowed_methods": ["GET", "POST"],
                    "allowed_headers": ["Content-Type"],
                    "allow_credentials": false
                }),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .request(reqwest::Method::OPTIONS, format!("{url}/echo"))
        .header("Host", "cors.test")
        .header("Origin", "https://example.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    let headers = resp.headers();
    assert!(
        headers.contains_key("access-control-allow-origin"),
        "should have access-control-allow-origin"
    );
    assert!(
        headers.contains_key("access-control-allow-methods"),
        "should have access-control-allow-methods"
    );
}

async fn cors_normal_request_has_origin_header() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "cors",
            "cors.test",
            "backend",
            HashMap::from([(
                "cors".into(),
                serde_json::json!({
                    "allowed_origins": ["https://example.com"],
                    "allowed_methods": ["GET"],
                    "allow_credentials": false
                }),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/echo"))
        .header("Host", "cors.test")
        .header("Origin", "https://example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .contains_key("access-control-allow-origin"));
}
