//! Configuration watcher — Traefik-inspired dedup + merge pipeline.
//!
//! Receives config updates from one or more providers, deduplicates them
//! (skips unchanged configs), and applies valid ones via the two-stage
//! reload pipeline (precommit → commit).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use tokio::sync::mpsc;
use tracing::{error, info};

use super::FluxoConfig;
use crate::proxy::FluxoProxy;

/// Hash a config for deduplication.
///
/// Uses the serialized TOML representation for a stable hash.
/// This is cheaper than full structural equality.
fn hash_config(config: &FluxoConfig) -> u64 {
    let mut hasher = DefaultHasher::new();
    toml::to_string(config)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

/// Watches for config changes from providers and applies them to the proxy.
///
/// Traefik-inspired two-goroutine pipeline adapted for Rust:
/// - Receives configs from `mpsc::Receiver` (fed by one or more `ConfigProvider`s)
/// - Deduplicates via config hash (skips unchanged configs)
/// - Validates via `FluxoProxy::precommit_reload()` (two-stage: precommit → commit)
/// - Atomically swaps the config via `FluxoProxy::reload()`
pub struct ConfigWatcher {
    rx: mpsc::Receiver<(String, FluxoConfig)>,
    provider_configs: std::collections::HashMap<String, FluxoConfig>,
    last_merged_hash: Option<u64>,
    proxy: FluxoProxy,
    reload_count: u64,
}

impl ConfigWatcher {
    /// Create a new watcher that reads from `rx` and applies to `proxy`.
    pub fn new(rx: mpsc::Receiver<(String, FluxoConfig)>, proxy: FluxoProxy) -> Self {
        Self {
            rx,
            provider_configs: std::collections::HashMap::new(),
            last_merged_hash: None,
            proxy,
            reload_count: 0,
        }
    }

    /// Run the watcher loop. Blocks until the sender is dropped.
    pub async fn run(&mut self) {
        while let Some((provider_name, mut new_config)) = self.rx.recv().await {
            // Add provider namespace to all resources
            new_config.qualify_namespace(&provider_name);

            // Store the provider's config state
            self.provider_configs
                .insert(provider_name.clone(), new_config);

            // Merge all active configs into a cohesive state
            let mut merged_config = FluxoConfig::default();
            for (name, cfg) in &self.provider_configs {
                // The main config typically comes from the 'file' provider,
                // so we prioritize its global block.
                if name == "file" || merged_config.global.threads == 0 {
                    merged_config.global = cfg.global.clone();
                }
                merged_config.merge(cfg.clone());
            }

            let hash = hash_config(&merged_config);

            // Dedup: skip if merged config hasn't changed
            if Some(hash) == self.last_merged_hash {
                tracing::debug!("config unchanged (hash match) — skipping reload");
                continue;
            }

            // Two-stage reload (Monolake pattern):
            // Stage 1: Precommit — build new state, validate it compiles
            match FluxoProxy::precommit_reload(merged_config) {
                Ok(new_state) => {
                    // Stage 2: Commit — atomic swap with pool preservation
                    self.proxy.reload(new_state);
                    self.last_merged_hash = Some(hash);
                    self.reload_count += 1;
                    info!(
                        reload_count = self.reload_count,
                        "config reloaded via watcher"
                    );
                }
                Err(e) => {
                    error!("config reload ABORTED (validation failed): {e}");
                }
            }
        }
        info!("config watcher shutting down — all providers stopped");
    }

    /// Number of successful reloads performed.
    pub fn reload_count(&self) -> u64 {
        self.reload_count
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hash_config_deterministic() {
        let c1 = FluxoConfig::default();
        let c2 = FluxoConfig::default();
        assert_eq!(hash_config(&c1), hash_config(&c2));
    }

    #[test]
    fn hash_config_changes_with_content() {
        let c1 = FluxoConfig::default();
        let mut c2 = FluxoConfig::default();
        c2.global.log_level = "debug".to_string();
        assert_ne!(hash_config(&c1), hash_config(&c2));
    }

    #[test]
    fn hash_config_changes_with_upstream() {
        let c1 = FluxoConfig::default();
        let mut c2 = FluxoConfig::default();
        c2.upstreams.insert(
            "backend".to_string(),
            crate::config::UpstreamConfig::default(),
        );
        assert_ne!(hash_config(&c1), hash_config(&c2));
    }

    #[test]
    fn hash_config_changes_with_service() {
        let c1 = FluxoConfig::default();
        let mut c2 = FluxoConfig::default();
        c2.services.insert(
            "web".to_string(),
            crate::config::ServiceConfig::default(),
        );
        assert_ne!(hash_config(&c1), hash_config(&c2));
    }

    #[test]
    fn hash_config_same_after_clone() {
        let mut c1 = FluxoConfig::default();
        c1.global.log_level = "warn".to_string();
        c1.upstreams.insert(
            "api".to_string(),
            crate::config::UpstreamConfig::default(),
        );
        let c2 = c1.clone();
        assert_eq!(hash_config(&c1), hash_config(&c2));
    }
}
