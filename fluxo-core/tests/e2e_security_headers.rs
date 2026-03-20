#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use std::collections::HashMap;

use fluxo_core::config::FluxoConfig;
use helpers::{
    default_mock_upstream, minimal_service, mock_upstream_config, route_with_plugins, start_proxy,
};

fn main() {
    helpers::run_tests(&[
        ("security_headers_added", || {
            Box::pin(security_headers_added())
        }),
        ("security_headers_csp", || Box::pin(security_headers_csp())),
    ]);
}

async fn security_headers_added() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "secure",
            "secure.test",
            "backend",
            HashMap::from([(
                "security_headers".into(),
                serde_json::json!({
                    "hsts_max_age": 31536000,
                    "frame_options": "DENY",
                    "content_type_nosniff": true
                }),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/echo"))
        .header("Host", "secure.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("strict-transport-security").is_some());
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .unwrap()
            .to_str()
            .unwrap(),
        "DENY"
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .unwrap()
            .to_str()
            .unwrap(),
        "nosniff"
    );
}

async fn security_headers_csp() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "csp",
            "csp.test",
            "backend",
            HashMap::from([(
                "security_headers".into(),
                serde_json::json!({
                    "content_security_policy": "default-src 'self'",
                    "referrer_policy": "no-referrer"
                }),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/echo"))
        .header("Host", "csp.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap(),
        "default-src 'self'"
    );
    assert_eq!(
        resp.headers()
            .get("referrer-policy")
            .unwrap()
            .to_str()
            .unwrap(),
        "no-referrer"
    );
}
