#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! E2E test verifying WebSocket proxying through Fluxo.
//!
//! Pingora handles WebSocket connections natively via HTTP/1.1 Upgrade.
//! This test boots a real proxy + mock WS upstream and verifies bidirectional
//! message exchange through the proxy.

mod helpers;

use std::time::Duration;

use axum::{
    Router,
    extract::WebSocketUpgrade,
    extract::ws::{Message, WebSocket},
    response::IntoResponse,
    routing::get,
};
use fluxo_core::config::FluxoConfig;
use futures_util::{SinkExt, StreamExt};
use helpers::{
    minimal_service, mock_upstream_config, simple_route, start_mock_upstream, start_proxy,
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

fn main() {
    helpers::run_tests(&[("websocket_echo_through_proxy", || {
        Box::pin(websocket_echo_through_proxy())
    })]);
}

// ---------------------------------------------------------------------------
// WS echo upstream
// ---------------------------------------------------------------------------

async fn ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
    while let Some(Ok(msg)) = socket.next().await {
        match msg {
            Message::Text(text) => {
                let echo = format!("echo: {text}");
                if socket.send(Message::Text(echo.into())).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

async fn websocket_echo_through_proxy() {
    // 1. Start WS echo upstream
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(|| async { "ok" }));
    let upstream = start_mock_upstream(app).await;

    // 2. Build config
    let mut config = FluxoConfig::default();
    config
        .upstreams
        .insert("ws_backend".into(), mock_upstream_config(upstream));
    config.services.insert(
        "main".into(),
        minimal_service(vec![simple_route("websocket", "ws.test", "ws_backend")]),
    );

    // 3. Start proxy (uses shared helper — random port, waits for ready)
    let (url, client) = start_proxy(config).await;

    // 4. Verify basic HTTP works through the proxy first
    let health_resp = client
        .get(format!("{url}/health"))
        .header("Host", "ws.test")
        .send()
        .await
        .unwrap();
    assert_eq!(
        health_resp.status(),
        200,
        "HTTP routing through proxy works"
    );

    // 5. Connect via WebSocket through the proxy
    let ws_url = url.replace("http://", "ws://") + "/ws";
    let mut request = ws_url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Host", "ws.test".parse().unwrap());

    let (ws_stream, response) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(request),
    )
    .await
    .expect("WebSocket connect timed out")
    .expect("WebSocket connect failed");

    assert_eq!(response.status(), 101, "Expected 101 Switching Protocols");

    let (mut write, mut read) = ws_stream.split();

    // 6. Send a message through the proxy and verify the echo
    write
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "hello fluxo".into(),
        ))
        .await
        .unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(5), read.next())
        .await
        .expect("timeout waiting for WS response")
        .expect("stream ended")
        .expect("WS read error");

    match msg {
        tokio_tungstenite::tungstenite::Message::Text(text) => {
            assert_eq!(text, "echo: hello fluxo");
        }
        other => panic!("expected text message, got: {other:?}"),
    }
}
