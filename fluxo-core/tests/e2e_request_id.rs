#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use std::collections::HashMap;

use fluxo_core::config::FluxoConfig;
use helpers::{
    default_mock_upstream, minimal_service, mock_upstream_config, route_with_plugins, start_proxy,
};

fn main() {
    helpers::run_tests(&[
        ("request_id_injected", || {
            Box::pin(request_id_injected())
        }),
        ("request_id_custom_header", || {
            Box::pin(request_id_custom_header())
        }),
    ]);
}

async fn request_id_injected() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "reqid",
            "reqid.test",
            "backend",
            HashMap::from([("request_id".into(), serde_json::json!({}))]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/headers"))
        .header("Host", "reqid.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.to_lowercase().contains("x-request-id"),
        "upstream should receive x-request-id header, got: {body}"
    );
}

async fn request_id_custom_header() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "reqid",
            "reqid.test",
            "backend",
            HashMap::from([(
                "request_id".into(),
                serde_json::json!({"header": "X-Trace-ID"}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/headers"))
        .header("Host", "reqid.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.to_lowercase().contains("x-trace-id"),
        "upstream should receive x-trace-id header, got: {body}"
    );
}
