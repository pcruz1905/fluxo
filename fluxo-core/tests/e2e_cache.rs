#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use axum::Router;
use axum::routing::get;
use fluxo_core::config::{FluxoConfig, RouteConfig};
use helpers::{minimal_service, mock_upstream_config, start_mock_upstream, start_proxy};

fn main() {
    helpers::run_tests(&[
        ("cache_miss_then_hit", || Box::pin(cache_miss_then_hit())),
        ("cache_bypass_with_no_cache", || {
            Box::pin(cache_bypass_with_no_cache())
        }),
    ]);
}

async fn cache_miss_then_hit() {
    let app = Router::new().route(
        "/cacheable",
        get(|| async {
            (
                [("Cache-Control", "public, max-age=3600")],
                "cached content",
            )
        }),
    );
    let upstream = start_mock_upstream(app).await;

    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![RouteConfig {
            name: Some("cached".into()),
            match_host: vec!["cache.test".into()],
            upstream: "backend".into(),
            cache: Some(
                serde_json::from_value(serde_json::json!({
                    "default_ttl": "3600s"
                }))
                .unwrap(),
            ),
            ..Default::default()
        }]),
    );

    let (url, client) = start_proxy(config).await;

    // First request — should be a miss
    let resp1 = client
        .get(format!("{url}/cacheable"))
        .header("Host", "cache.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);
    let cache_status1 = resp1
        .headers()
        .get("x-cache-status")
        .map(|v| v.to_str().unwrap().to_string());
    let body1 = resp1.text().await.unwrap();
    assert_eq!(body1, "cached content");

    // Second request — should be a hit
    let resp2 = client
        .get(format!("{url}/cacheable"))
        .header("Host", "cache.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 200);
    let cache_status2 = resp2
        .headers()
        .get("x-cache-status")
        .map(|v| v.to_str().unwrap().to_string());
    let body2 = resp2.text().await.unwrap();
    assert_eq!(body2, "cached content");

    // First should be miss, second should be hit
    assert_eq!(
        cache_status1.as_deref(),
        Some("MISS"),
        "first request should be a cache miss"
    );
    assert_eq!(
        cache_status2.as_deref(),
        Some("HIT"),
        "second request should be a cache hit"
    );
}

async fn cache_bypass_with_no_cache() {
    let app = Router::new().route(
        "/cacheable",
        get(|| async { ([("Cache-Control", "public, max-age=3600")], "fresh content") }),
    );
    let upstream = start_mock_upstream(app).await;

    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![RouteConfig {
            name: Some("cached".into()),
            match_host: vec!["cache2.test".into()],
            upstream: "backend".into(),
            cache: Some(
                serde_json::from_value(serde_json::json!({
                    "default_ttl": "3600s"
                }))
                .unwrap(),
            ),
            ..Default::default()
        }]),
    );

    let (url, client) = start_proxy(config).await;

    // Request with no-cache should bypass
    let resp = client
        .get(format!("{url}/cacheable"))
        .header("Host", "cache2.test")
        .header("Cache-Control", "no-cache")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Should be bypass or miss (not hit)
    if let Some(status) = resp.headers().get("x-cache-status") {
        let s = status.to_str().unwrap();
        assert_ne!(s, "HIT", "no-cache request should not be a cache hit");
    }
}
