#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use axum::Router;
use axum::routing::get;
use fluxo_core::config::{FluxoConfig, TargetConfig, UpstreamConfig};
use helpers::{minimal_service, simple_route, start_mock_upstream, start_proxy};

fn main() {
    helpers::run_tests(&[(
        "weighted_distribution",
        || Box::pin(weighted_distribution()),
    )]);
}

async fn weighted_distribution() {
    let app1 = Router::new().route("/", get(|| async { "backend-A" }));
    let app2 = Router::new().route("/", get(|| async { "backend-B" }));
    let addr1 = start_mock_upstream(app1).await;
    let addr2 = start_mock_upstream(app2).await;

    let mut config = FluxoConfig::default();
    config.upstreams.insert(
        "weighted".into(),
        UpstreamConfig {
            targets: vec![
                TargetConfig::Weighted {
                    address: addr1.to_string(),
                    weight: 3,
                },
                TargetConfig::Weighted {
                    address: addr2.to_string(),
                    weight: 1,
                },
            ],
            load_balancing: "weighted_edf".to_string(),
            ..Default::default()
        },
    );
    config.services.insert(
        "main".into(),
        minimal_service(vec![simple_route("lb", "lb.test", "weighted")]),
    );

    let (url, client) = start_proxy(config).await;

    let mut count_a = 0u32;
    let mut count_b = 0u32;
    let total = 40;

    for _ in 0..total {
        let resp = client
            .get(&url)
            .header("Host", "lb.test")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        if body.contains("backend-A") {
            count_a += 1;
        } else if body.contains("backend-B") {
            count_b += 1;
        }
    }

    assert!(
        count_a > count_b,
        "backend-A (weight=3) should get more traffic than backend-B (weight=1): A={count_a}, B={count_b}"
    );
    assert!(
        count_b > 0,
        "backend-B should get at least some traffic: A={count_a}, B={count_b}"
    );
}
