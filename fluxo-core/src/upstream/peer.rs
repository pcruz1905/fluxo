//! Peer selection and `HttpPeer` construction.
//!
//! Wraps Pingora's `LoadBalancer` to bundle TLS config, timeouts, and
//! load balancing strategy per upstream group.

use std::sync::Arc;
use std::time::Duration;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_load_balancing::selection::{Consistent, Random, RoundRobin};
use pingora_load_balancing::LoadBalancer;

use pingora_core::services::background::GenBackgroundService;
use pingora_core::services::ServiceWithDependents;

use crate::upstream::UpstreamError;
use crate::upstream::UpstreamName;

/// TLS configuration for connections to an upstream group.
///
/// Uses `Arc<str>` for SNI so cloning the config is a refcount bump.
#[derive(Debug, Clone, Default)]
pub struct UpstreamTlsConfig {
    /// Whether to use TLS for upstream connections.
    pub enabled: bool,
    /// SNI hostname to send.
    pub sni: Option<Arc<str>>,
}

/// Timeout configuration for connections to an upstream group.
#[derive(Debug, Clone)]
pub struct UpstreamTimeouts {
    /// Timeout for establishing a connection.
    pub connect: Duration,
    /// Timeout for reading from the upstream.
    pub read: Duration,
    /// Timeout for writing to the upstream.
    pub write: Duration,
}

impl Default for UpstreamTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(30),
            write: Duration::from_secs(30),
        }
    }
}

/// The supported load balancing strategies.
///
/// Uses enum dispatch to avoid trait objects while supporting multiple
/// Pingora `LoadBalancer<S>` generic instantiations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbStrategy {
    RoundRobin,
    Random,
    FnvHash,
    ConsistentHash,
}

impl LbStrategy {
    /// Parse a strategy name from the config string.
    pub fn from_config(s: &str) -> Result<Self, UpstreamError> {
        match s {
            "round_robin" => Ok(Self::RoundRobin),
            "random" => Ok(Self::Random),
            "fnv_hash" => Ok(Self::FnvHash),
            "consistent_hash" => Ok(Self::ConsistentHash),
            other => Err(UpstreamError::InvalidStrategy(other.to_string())),
        }
    }
}

/// Type-erased load balancer that wraps different Pingora `LoadBalancer<S>` types.
///
/// Each variant holds an `Arc<LoadBalancer<S>>` and dispatches `select()` calls.
enum AnyLoadBalancer {
    RoundRobin(Arc<LoadBalancer<RoundRobin>>),
    Random(Arc<LoadBalancer<Random>>),
    FnvHash(Arc<LoadBalancer<pingora_load_balancing::selection::FNVHash>>),
    ConsistentHash(Arc<LoadBalancer<Consistent>>),
}

impl AnyLoadBalancer {
    /// Build a load balancer from targets with the given strategy.
    fn build(
        targets: &[String],
        strategy: LbStrategy,
    ) -> Result<Self, UpstreamError> {
        let map_err = |e: std::io::Error| UpstreamError::InvalidAddress {
            address: targets.join(", "),
            reason: e.to_string(),
        };

        match strategy {
            LbStrategy::RoundRobin => {
                let lb = LoadBalancer::<RoundRobin>::try_from_iter(targets.iter())
                    .map_err(map_err)?;
                Ok(Self::RoundRobin(Arc::new(lb)))
            }
            LbStrategy::Random => {
                let lb = LoadBalancer::<Random>::try_from_iter(targets.iter())
                    .map_err(map_err)?;
                Ok(Self::Random(Arc::new(lb)))
            }
            LbStrategy::FnvHash => {
                let lb = LoadBalancer::<pingora_load_balancing::selection::FNVHash>::try_from_iter(
                    targets.iter(),
                )
                .map_err(map_err)?;
                Ok(Self::FnvHash(Arc::new(lb)))
            }
            LbStrategy::ConsistentHash => {
                let lb = LoadBalancer::<Consistent>::try_from_iter(targets.iter())
                    .map_err(map_err)?;
                Ok(Self::ConsistentHash(Arc::new(lb)))
            }
        }
    }

    /// Select a backend using the configured strategy.
    fn select(&self, key: &[u8], max_iterations: usize) -> Option<pingora_load_balancing::Backend> {
        match self {
            Self::RoundRobin(lb) => lb.select(key, max_iterations),
            Self::Random(lb) => lb.select(key, max_iterations),
            Self::FnvHash(lb) => lb.select(key, max_iterations),
            Self::ConsistentHash(lb) => lb.select(key, max_iterations),
        }
    }

    /// Set a health check on the underlying load balancer.
    fn set_health_check(
        &mut self,
        hc: Box<dyn pingora_load_balancing::health_check::HealthCheck + Send + Sync + 'static>,
    ) {
        match self {
            Self::RoundRobin(lb) => Arc::get_mut(lb).unwrap().set_health_check(hc),
            Self::Random(lb) => Arc::get_mut(lb).unwrap().set_health_check(hc),
            Self::FnvHash(lb) => Arc::get_mut(lb).unwrap().set_health_check(hc),
            Self::ConsistentHash(lb) => Arc::get_mut(lb).unwrap().set_health_check(hc),
        }
    }

    /// Get as a background service for health check scheduling.
    /// Returns `None` if no health check is configured (no frequency set).
    fn as_background_service(&self, name: &str) -> Option<Box<dyn ServiceWithDependents>> {
        let svc_name = format!("BG health-check {name}");
        match self {
            Self::RoundRobin(lb) if lb.health_check_frequency.is_some() => {
                Some(Box::new(GenBackgroundService::new(svc_name, lb.clone())))
            }
            Self::Random(lb) if lb.health_check_frequency.is_some() => {
                Some(Box::new(GenBackgroundService::new(svc_name, lb.clone())))
            }
            Self::FnvHash(lb) if lb.health_check_frequency.is_some() => {
                Some(Box::new(GenBackgroundService::new(svc_name, lb.clone())))
            }
            Self::ConsistentHash(lb) if lb.health_check_frequency.is_some() => {
                Some(Box::new(GenBackgroundService::new(svc_name, lb.clone())))
            }
            _ => None,
        }
    }

    /// Set health check frequency.
    fn set_health_check_frequency(&mut self, freq: Duration) {
        match self {
            Self::RoundRobin(lb) => {
                Arc::get_mut(lb).unwrap().health_check_frequency = Some(freq);
            }
            Self::Random(lb) => {
                Arc::get_mut(lb).unwrap().health_check_frequency = Some(freq);
            }
            Self::FnvHash(lb) => {
                Arc::get_mut(lb).unwrap().health_check_frequency = Some(freq);
            }
            Self::ConsistentHash(lb) => {
                Arc::get_mut(lb).unwrap().health_check_frequency = Some(freq);
            }
        }
    }
}

/// An upstream group wrapping Pingora's `LoadBalancer` with per-group
/// TLS settings, timeouts, and configurable load balancing strategy.
pub struct UpstreamGroup {
    /// Display name for logging.
    pub name: UpstreamName,
    /// The load balancer (type-erased across strategies).
    lb: AnyLoadBalancer,
    /// Which strategy is in use.
    pub strategy: LbStrategy,
    /// TLS settings for connections to this group.
    tls: UpstreamTlsConfig,
    /// Timeout settings for connections to this group.
    timeouts: UpstreamTimeouts,
}

// Manual Debug because LoadBalancer doesn't impl Debug
impl std::fmt::Debug for UpstreamGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamGroup")
            .field("name", &self.name)
            .field("strategy", &self.strategy)
            .field("tls", &self.tls)
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

impl UpstreamGroup {
    /// Create a new upstream group from a list of target addresses and a strategy.
    pub fn new(
        name: UpstreamName,
        targets: &[String],
        strategy: LbStrategy,
        tls: UpstreamTlsConfig,
        timeouts: UpstreamTimeouts,
    ) -> Result<Self, UpstreamError> {
        let lb = AnyLoadBalancer::build(targets, strategy)?;

        Ok(Self {
            name,
            lb,
            strategy,
            tls,
            timeouts,
        })
    }

    /// Set a health check on this upstream group.
    pub fn set_health_check(
        &mut self,
        hc: Box<dyn pingora_load_balancing::health_check::HealthCheck + Send + Sync + 'static>,
        frequency: Duration,
    ) {
        self.lb.set_health_check(hc);
        self.lb.set_health_check_frequency(frequency);
    }

    /// Get the underlying load balancer as a background service for health check scheduling.
    /// Returns `None` if no health check is configured.
    pub fn background_service(&self) -> Option<Box<dyn ServiceWithDependents>> {
        self.lb.as_background_service(&self.name.0)
    }

    /// Select a peer using the configured strategy, then wrap it as an `HttpPeer`
    /// with this group's TLS and timeout settings.
    pub fn select_peer(&self) -> Result<Box<HttpPeer>, UpstreamError> {
        let backend = self
            .lb
            .select(b"", 256)
            .ok_or_else(|| UpstreamError::NoHealthyBackends(self.name.clone()))?;

        let mut peer = HttpPeer::new(
            backend.addr,
            self.tls.enabled,
            self.tls.sni.as_deref().unwrap_or_default().to_string(),
        );

        // Apply timeouts
        peer.options.connection_timeout = Some(self.timeouts.connect);
        peer.options.read_timeout = Some(self.timeouts.read);
        peer.options.write_timeout = Some(self.timeouts.write);

        Ok(Box::new(peer))
    }

    /// Select a peer using a hash key (for hash-based strategies like fnv_hash, consistent_hash).
    pub fn select_peer_with_key(&self, key: &[u8]) -> Result<Box<HttpPeer>, UpstreamError> {
        let backend = self
            .lb
            .select(key, 256)
            .ok_or_else(|| UpstreamError::NoHealthyBackends(self.name.clone()))?;

        let mut peer = HttpPeer::new(
            backend.addr,
            self.tls.enabled,
            self.tls.sni.as_deref().unwrap_or_default().to_string(),
        );

        peer.options.connection_timeout = Some(self.timeouts.connect);
        peer.options.read_timeout = Some(self.timeouts.read);
        peer.options.write_timeout = Some(self.timeouts.write);

        Ok(Box::new(peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::UpstreamName;
    use pingora_core::upstreams::peer::Peer;

    #[test]
    fn lb_strategy_from_config() {
        assert_eq!(LbStrategy::from_config("round_robin").unwrap(), LbStrategy::RoundRobin);
        assert_eq!(LbStrategy::from_config("random").unwrap(), LbStrategy::Random);
        assert_eq!(LbStrategy::from_config("fnv_hash").unwrap(), LbStrategy::FnvHash);
        assert_eq!(LbStrategy::from_config("consistent_hash").unwrap(), LbStrategy::ConsistentHash);
        assert!(LbStrategy::from_config("invalid").is_err());
    }

    #[test]
    fn upstream_group_round_robin() {
        let targets = vec!["127.0.0.1:3000".to_string(), "127.0.0.1:3001".to_string()];
        let group = UpstreamGroup::new(
            UpstreamName::from("test"),
            &targets,
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        // Should be able to select peers
        let peer1 = group.select_peer().unwrap();
        let peer2 = group.select_peer().unwrap();
        // Both should succeed (round robin across 2 backends)
        assert!(peer1.address().as_inet().is_some());
        assert!(peer2.address().as_inet().is_some());
    }

    #[test]
    fn upstream_group_all_strategies() {
        let targets = vec!["127.0.0.1:3000".to_string(), "127.0.0.1:3001".to_string()];
        for strategy in &[
            LbStrategy::RoundRobin,
            LbStrategy::Random,
            LbStrategy::FnvHash,
            LbStrategy::ConsistentHash,
        ] {
            let group = UpstreamGroup::new(
                UpstreamName::from("test"),
                &targets,
                *strategy,
                Default::default(),
                Default::default(),
            )
            .unwrap_or_else(|e| panic!("strategy {:?} should work: {}", strategy, e));
            let peer = group.select_peer().unwrap();
            assert!(peer.address().as_inet().is_some());
        }
    }

    #[test]
    fn upstream_group_consistent_hash_same_key() {
        let targets = vec![
            "127.0.0.1:3000".to_string(),
            "127.0.0.1:3001".to_string(),
            "127.0.0.1:3002".to_string(),
        ];
        let group = UpstreamGroup::new(
            UpstreamName::from("test"),
            &targets,
            LbStrategy::ConsistentHash,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Same key should consistently select the same peer
        let peer1 = group.select_peer_with_key(b"user-123").unwrap();
        let peer2 = group.select_peer_with_key(b"user-123").unwrap();
        assert_eq!(
            peer1.address().as_inet().unwrap(),
            peer2.address().as_inet().unwrap()
        );
    }

    #[test]
    fn upstream_group_no_health_check_no_bg_service() {
        let targets = vec!["127.0.0.1:3000".to_string()];
        let group = UpstreamGroup::new(
            UpstreamName::from("test"),
            &targets,
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        assert!(group.background_service().is_none());
    }
}
