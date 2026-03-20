#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use axum::Router;
use axum::routing::get;
use fluxo_core::config::FluxoConfig;
use helpers::{
    minimal_service, mock_upstream_config, simple_route, start_mock_upstream, start_proxy,
};

fn main() {
    helpers::run_tests(&[("custom_error_page_on_upstream_5xx", || {
        Box::pin(custom_error_page_on_upstream_5xx())
    })]);
}

async fn custom_error_page_on_upstream_5xx() {
    let app = Router::new().route(
        "/",
        get(|| async { (hyper::StatusCode::BAD_GATEWAY, "upstream error") }),
    );
    let upstream = start_mock_upstream(app).await;

    let mut config = FluxoConfig::default();
    config.global.intercept_errors = true;
    config
        .global
        .error_pages
        .insert(502, "<html><body>Custom 502 page</body></html>".to_string());
    config
        .upstreams
        .insert("bad".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![simple_route("err", "err.test", "bad")]),
    );

    let (url, client) = start_proxy(config).await;
    let resp = client
        .get(&url)
        .header("Host", "err.test")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 502);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("Custom 502 page"),
        "should serve custom error page, got: {body}"
    );
}
