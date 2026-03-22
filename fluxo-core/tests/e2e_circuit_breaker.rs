#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use fluxo_core::config::{FluxoConfig, TargetConfig, UpstreamConfig};
use helpers::{minimal_service, simple_route, start_proxy};

fn main() {
    helpers::run_tests(&[("circuit_opens_after_failures", || {
        Box::pin(circuit_opens_after_failures())
    })]);
}

async fn circuit_opens_after_failures() {
    let mut config = FluxoConfig::default();

    // Dead backend — port 1 is always closed
    config.upstreams.insert(
        "dead".into(),
        UpstreamConfig {
            targets: vec![TargetConfig::Simple("127.0.0.1:1".to_string())],
            load_balancing: "round_robin".to_string(),
            connect_timeout: "100ms".to_string(),
            circuit_breaker: Some(
                serde_json::from_value(serde_json::json!({
                    "failure_threshold": 2
                }))
                .unwrap(),
            ),
            ..Default::default()
        },
    );
    config.services.insert(
        "main".into(),
        minimal_service(vec![simple_route("cb", "cb.test", "dead")]),
    );

    let (url, client) = start_proxy(config).await;

    // Send requests to a dead backend.
    // First requests fail with 502 (upstream unreachable), then the circuit
    // breaker opens (failure_threshold=2) and returns 503 directly.
    let mut statuses = Vec::new();
    for _ in 0..5 {
        let resp = client
            .get(&url)
            .header("Host", "cb.test")
            .send()
            .await
            .unwrap();
        statuses.push(resp.status().as_u16());
    }

    // All statuses should be errors (502 = upstream down, 503 = circuit open)
    assert!(
        statuses.iter().all(|&s| s == 502 || s == 503),
        "all requests should fail with 502 or 503, got: {statuses:?}"
    );
    // At least one 502 (before circuit opens) and at least one 503 (after)
    assert!(
        statuses.contains(&502),
        "should see 502 before circuit opens, got: {statuses:?}"
    );
    assert!(
        statuses.contains(&503),
        "circuit breaker should open and return 503, got: {statuses:?}"
    );
}
