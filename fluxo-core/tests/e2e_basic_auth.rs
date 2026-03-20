#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use std::collections::HashMap;

use fluxo_core::config::FluxoConfig;
use helpers::{
    default_mock_upstream, minimal_service, mock_upstream_config, route_with_plugins, start_proxy,
};

fn main() {
    helpers::run_tests(&[
        ("basic_auth_rejects_without_credentials", || {
            Box::pin(basic_auth_rejects_without_credentials())
        }),
        ("basic_auth_accepts_valid_credentials", || {
            Box::pin(basic_auth_accepts_valid_credentials())
        }),
        ("basic_auth_rejects_wrong_password", || {
            Box::pin(basic_auth_rejects_wrong_password())
        }),
    ]);
}

async fn basic_auth_rejects_without_credentials() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "auth",
            "auth.test",
            "backend",
            HashMap::from([(
                "basic_auth".into(),
                serde_json::json!({"users": {"admin": "pass123"}}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/echo"))
        .header("Host", "auth.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("www-authenticate"));
}

async fn basic_auth_accepts_valid_credentials() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "auth",
            "auth.test",
            "backend",
            HashMap::from([(
                "basic_auth".into(),
                serde_json::json!({"users": {"admin": "pass123"}}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/echo"))
        .header("Host", "auth.test")
        .header("Authorization", "Basic YWRtaW46cGFzczEyMw==") // admin:pass123
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "echo");
}

async fn basic_auth_rejects_wrong_password() {
    let upstream = default_mock_upstream().await;
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "auth",
            "auth.test",
            "backend",
            HashMap::from([(
                "basic_auth".into(),
                serde_json::json!({"users": {"admin": "pass123"}}),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/echo"))
        .header("Host", "auth.test")
        .header("Authorization", "Basic YWRtaW46d3Jvbmc=") // admin:wrong
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
