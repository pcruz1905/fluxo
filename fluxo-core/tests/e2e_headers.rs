#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use std::collections::HashMap;

use fluxo_core::config::FluxoConfig;
use helpers::{default_mock_upstream, minimal_service, mock_upstream_config, route_with_plugins, start_proxy};

fn main() {
    helpers::run_tests(&[
        ("headers_plugin_adds_response_header", || {
            Box::pin(headers_plugin_adds_response_header())
        }),
        ("headers_plugin_removes_request_header", || {
            Box::pin(headers_plugin_removes_request_header())
        }),
    ]);
}

async fn headers_plugin_adds_response_header() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "hdrs",
            "hdrs.test",
            "backend",
            HashMap::from([(
                "headers".into(),
                serde_json::json!({
                    "response_set": {"X-Powered-By": "fluxo"}
                }),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/echo"))
        .header("Host", "hdrs.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-powered-by")
            .unwrap()
            .to_str()
            .unwrap(),
        "fluxo"
    );
}

async fn headers_plugin_removes_request_header() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "hdrs",
            "hdrs.test",
            "backend",
            HashMap::from([(
                "headers".into(),
                serde_json::json!({
                    "request_remove": ["X-Remove-Me"]
                }),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/headers"))
        .header("Host", "hdrs.test")
        .header("X-Remove-Me", "should-be-gone")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        !body.to_lowercase().contains("x-remove-me"),
        "header should have been removed, got: {body}"
    );
}
