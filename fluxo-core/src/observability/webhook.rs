//! Webhook notifications — send alerts for health status changes and events.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Webhook notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL to POST notifications to.
    pub url: String,

    /// Events that trigger notifications.
    /// Valid: "health_change", "config_reload", "circuit_breaker".
    #[serde(default = "default_events")]
    pub events: Vec<String>,

    /// Custom headers to include in webhook requests.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// Request timeout. Default: "5s".
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

fn default_events() -> Vec<String> {
    vec!["health_change".to_string()]
}

fn default_timeout() -> String {
    "5s".to_string()
}

/// A webhook notification payload.
#[derive(Debug, Serialize)]
pub struct WebhookPayload {
    /// Event type (e.g., "health_change", "config_reload").
    pub event: String,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
    /// Event-specific message.
    pub message: String,
    /// Severity: "info", "warning", "error".
    pub severity: String,
    /// Additional context data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Webhook sender — sends notifications in the background.
pub struct WebhookSender {
    configs: Vec<WebhookConfig>,
    client: reqwest::Client,
}

impl WebhookSender {
    /// Create a new webhook sender. Returns None if no webhooks are configured.
    pub fn new(configs: Vec<WebhookConfig>) -> Option<Arc<Self>> {
        if configs.is_empty() {
            return None;
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .ok()?;
        Some(Arc::new(Self { configs, client }))
    }

    /// Send a notification to all configured webhooks that match the event type.
    pub fn notify(&self, payload: WebhookPayload) {
        let json = match serde_json::to_string(&payload) {
            Ok(j) => j,
            Err(_) => return,
        };

        for config in &self.configs {
            if !config.events.contains(&payload.event) {
                continue;
            }

            let client = self.client.clone();
            let url = config.url.clone();
            let headers = config.headers.clone();
            let body = json.clone();

            tokio::spawn(async move {
                let mut req = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(body);

                for (key, value) in &headers {
                    req = req.header(key.as_str(), value.as_str());
                }

                if let Err(e) = req.send().await {
                    tracing::warn!(url = %url, error = %e, "webhook notification failed");
                }
            });
        }
    }

    /// Send a health change notification.
    pub fn notify_health_change(&self, upstream: &str, target: &str, healthy: bool) {
        let status = if healthy { "healthy" } else { "unhealthy" };
        self.notify(WebhookPayload {
            event: "health_change".to_string(),
            timestamp: super::access_log::chrono_now_rfc3339(),
            message: format!("upstream {upstream} target {target} is now {status}"),
            severity: if healthy {
                "info".to_string()
            } else {
                "warning".to_string()
            },
            data: Some(serde_json::json!({
                "upstream": upstream,
                "target": target,
                "healthy": healthy,
            })),
        });
    }

    /// Send a config reload notification.
    pub fn notify_config_reload(&self, success: bool, error: Option<&str>) {
        self.notify(WebhookPayload {
            event: "config_reload".to_string(),
            timestamp: super::access_log::chrono_now_rfc3339(),
            message: if success {
                "configuration reloaded successfully".to_string()
            } else {
                format!(
                    "configuration reload failed: {}",
                    error.unwrap_or("unknown error")
                )
            },
            severity: if success {
                "info".to_string()
            } else {
                "error".to_string()
            },
            data: None,
        });
    }

    /// Send a circuit breaker state change notification.
    pub fn notify_circuit_breaker(&self, upstream: &str, state: &str) {
        self.notify(WebhookPayload {
            event: "circuit_breaker".to_string(),
            timestamp: super::access_log::chrono_now_rfc3339(),
            message: format!("circuit breaker for upstream {upstream} is now {state}"),
            severity: if state == "closed" {
                "info".to_string()
            } else {
                "warning".to_string()
            },
            data: Some(serde_json::json!({
                "upstream": upstream,
                "state": state,
            })),
        });
    }
}

impl std::fmt::Debug for WebhookSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSender")
            .field("webhook_count", &self.configs.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_webhooks_returns_none() {
        assert!(WebhookSender::new(vec![]).is_none());
    }

    #[test]
    fn webhook_payload_serializes() {
        let payload = WebhookPayload {
            event: "health_change".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            message: "test".to_string(),
            severity: "info".to_string(),
            data: None,
        };
        let json = serde_json::to_string(&payload);
        assert!(json.is_ok());
    }
}
