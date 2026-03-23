//! Prometheus push mode — periodically pushes metrics to a remote Pushgateway.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Prometheus push configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusPushConfig {
    /// Pushgateway URL (e.g., "<http://pushgateway:9091>").
    /// When set, enables push mode.
    pub url: Option<String>,

    /// Push interval. Default: "15s".
    #[serde(default = "default_push_interval")]
    pub interval: String,

    /// Job name for the push. Default: "fluxo".
    #[serde(default = "default_job_name")]
    pub job: String,

    /// Instance label. Default: hostname.
    pub instance: Option<String>,

    /// Additional labels to attach to all pushed metrics.
    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
}

impl Default for PrometheusPushConfig {
    fn default() -> Self {
        Self {
            url: None,
            interval: default_push_interval(),
            job: default_job_name(),
            instance: None,
            labels: std::collections::HashMap::new(),
        }
    }
}

fn default_push_interval() -> String {
    "15s".to_string()
}

fn default_job_name() -> String {
    "fluxo".to_string()
}

/// Start the Prometheus push background task.
pub fn start_prometheus_push(
    config: &PrometheusPushConfig,
    registry: Arc<crate::observability::MetricsRegistry>,
) {
    let Some(url) = config.url.clone() else {
        return;
    };

    let interval = crate::config::parse_duration(&config.interval)
        .unwrap_or(std::time::Duration::from_secs(15));
    let job = config.job.clone();
    let instance = config
        .instance
        .clone()
        .unwrap_or_else(|| hostname().unwrap_or_else(|| "unknown".to_string()));
    let labels = config.labels.clone();
    let log_url = url.clone();

    tokio::spawn(async move {
        let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .inspect_err(|e| {
                tracing::error!(error = %e, "failed to create HTTP client for Prometheus push");
            })
        else {
            return;
        };

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;

            // Gather metrics from the registry
            let metrics_text = registry.export_text();

            // Build the push URL: /metrics/job/{job}/instance/{instance}
            let mut push_url = format!("{url}/metrics/job/{job}/instance/{instance}");
            for (key, value) in &labels {
                push_url = format!("{push_url}/{key}/{value}");
            }

            match client
                .post(&push_url)
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(metrics_text)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("prometheus metrics pushed successfully");
                }
                Ok(resp) => {
                    tracing::warn!(status = %resp.status(), "prometheus push returned non-success");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "prometheus push failed");
                }
            }
        }
    });

    tracing::info!(url = %log_url, interval = ?interval, "prometheus push mode started");
}

/// Get the system hostname.
fn hostname() -> Option<String> {
    #[cfg(unix)]
    {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_push_config() {
        let cfg = PrometheusPushConfig::default();
        assert!(cfg.url.is_none());
        assert_eq!(cfg.job, "fluxo");
    }
}
