//! Config provider trait — Traefik-inspired multi-source configuration.
//!
//! Providers push `FluxoConfig` changes into a channel. The `ConfigWatcher`
//! deduplicates and applies them via the two-stage reload pipeline.

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::FluxoConfig;

/// A source of configuration updates.
///
/// Traefik-inspired: each provider watches a different source (file, HTTP API,
/// Consul, Kubernetes, etc.) and pushes config changes into a shared channel.
#[async_trait]
pub trait ConfigProvider: Send + Sync {
    /// Human-readable name for this provider (used in namespace qualification).
    fn name(&self) -> &str;

    /// Start watching and push `(provider_name, FluxoConfig)` changes into the channel.
    ///
    /// This method should run indefinitely (or until the sender is dropped).
    /// Implementations should handle their own errors (log + retry) rather than
    /// returning early.
    async fn watch(
        &self,
        tx: mpsc::Sender<(String, FluxoConfig)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
