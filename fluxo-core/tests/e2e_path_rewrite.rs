#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use std::collections::HashMap;

use axum::Router;
use axum::routing::get;
use fluxo_core::config::FluxoConfig;
use helpers::{
    minimal_service, mock_upstream_config, route_with_plugins, start_mock_upstream, start_proxy,
};

fn main() {
    helpers::run_tests(&[
        ("path_rewrite_transforms_url", || {
            Box::pin(path_rewrite_transforms_url())
        }),
        ("path_rewrite_sets_x_replaced_path", || {
            Box::pin(path_rewrite_sets_x_replaced_path())
        }),
    ]);
}

async fn path_rewrite_transforms_url() {
    let app = Router::new().route("/v2/users", get(|| async { "rewritten" }));
    let upstream = start_mock_upstream(app).await;

    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "rewrite",
            "rewrite.test",
            "backend",
            HashMap::from([(
                "path_rewrite".into(),
                serde_json::json!({
                    "pattern": "^/api/v1/(.*)",
                    "replacement": "/v2/$1"
                }),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/api/v1/users"))
        .header("Host", "rewrite.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "rewritten");
}

async fn path_rewrite_sets_x_replaced_path() {
    let app = Router::new().route(
        "/new",
        get(|headers: axum::http::HeaderMap| async move {
            headers
                .get("X-Replaced-Path")
                .map(|v| v.to_str().unwrap_or("").to_string())
                .unwrap_or_default()
        }),
    );
    let upstream = start_mock_upstream(app).await;

    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![route_with_plugins(
            "rewrite",
            "rewrite.test",
            "backend",
            HashMap::from([(
                "path_rewrite".into(),
                serde_json::json!({
                    "pattern": "^/old",
                    "replacement": "/new"
                }),
            )]),
        )]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(format!("{url}/old"))
        .header("Host", "rewrite.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "/old");
}
