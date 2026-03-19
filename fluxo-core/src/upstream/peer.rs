//! Peer selection and `HttpPeer` construction.
//!
//! Wraps Pingora's `LoadBalancer` to bundle TLS config, timeouts, and
//! load balancing strategy per upstream group.

use std::sync::Arc;
use std::time::Duration;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_load_balancing::LoadBalancer;
use pingora_load_balancing::selection::{Consistent, Random, RoundRobin};

use pingora_core::services::ServiceWithDependents;
use pingora_core::services::background::GenBackgroundService;

use crate::config::TargetConfig;
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

/// TCP keepalive settings — mirrors Pingora's TcpKeepalive.
#[derive(Debug, Clone)]
pub struct TcpKeepaliveSettings {
    pub idle: Duration,
    pub interval: Duration,
    pub count: usize,
}

/// Timeout and connection configuration for an upstream group.
#[derive(Debug, Clone)]
pub struct UpstreamTimeouts {
    /// Timeout for establishing a connection.
    pub connect: Duration,
    /// Timeout for reading from the upstream.
    pub read: Duration,
    /// Timeout for writing to the upstream.
    pub write: Duration,
    /// Idle timeout for keepalive connections.
    pub idle: Duration,
    /// Total connection timeout (entire connection attempt).
    pub total_connection_timeout: Option<Duration>,
    /// TCP keepalive settings.
    pub tcp_keepalive: Option<TcpKeepaliveSettings>,
    /// Max concurrent H2 streams per connection.
    pub max_h2_streams: Option<usize>,
    /// TCP receive buffer size.
    pub tcp_recv_buf: Option<usize>,
    /// H2 ping interval for connection keepalive.
    pub h2_ping_interval: Option<Duration>,
}

impl Default for UpstreamTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            read: Duration::from_secs(60),
            write: Duration::from_secs(60),
            idle: Duration::from_secs(60),
            total_connection_timeout: None,
            tcp_keepalive: None,
            max_h2_streams: None,
            tcp_recv_buf: None,
            h2_ping_interval: None,
        }
    }
}

impl UpstreamTimeouts {
    /// Build timeouts from an upstream config, parsing duration strings.
    pub fn from_config(c: &crate::config::UpstreamConfig) -> Self {
        use crate::config::parse_duration;
        Self {
            connect: parse_duration(&c.connect_timeout)
                .unwrap_or(Duration::from_secs(5)),
            read: parse_duration(&c.read_timeout)
                .unwrap_or(Duration::from_secs(60)),
            write: parse_duration(&c.write_timeout)
                .unwrap_or(Duration::from_secs(60)),
            idle: parse_duration(&c.keepalive_timeout)
                .unwrap_or(Duration::from_secs(60)),
            total_connection_timeout: c.total_connection_timeout
                .as_ref()
                .and_then(|s| parse_duration(s).ok()),
            tcp_keepalive: c.tcp_keepalive.as_ref().map(|ka| {
                TcpKeepaliveSettings {
                    idle: parse_duration(&ka.idle).unwrap_or(Duration::from_secs(60)),
                    interval: parse_duration(&ka.interval).unwrap_or(Duration::from_secs(15)),
                    count: ka.count,
                }
            }),
            max_h2_streams: c.max_h2_streams,
            tcp_recv_buf: c.tcp_recv_buf,
            h2_ping_interval: c.h2_ping_interval
                .as_ref()
                .and_then(|s| parse_duration(s).ok()),
        }
    }
}

/// The supported load balancing strategies.
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
enum AnyLoadBalancer {
    RoundRobin(Arc<LoadBalancer<RoundRobin>>),
    Random(Arc<LoadBalancer<Random>>),
    FnvHash(Arc<LoadBalancer<pingora_load_balancing::selection::FNVHash>>),
    ConsistentHash(Arc<LoadBalancer<Consistent>>),
}

impl AnyLoadBalancer {
    /// Build a load balancer from `TargetConfig` entries.
    ///
    /// Weighted targets are expanded by repetition: a target with `weight = 3`
    /// appears 3 times in the rotation, achieving weighted round robin.
    fn build(targets: &[TargetConfig], strategy: LbStrategy) -> Result<Self, UpstreamError> {
        // Expand targets by weight (weight=N → N copies in the rotation)
        let expanded: Vec<String> = targets
            .iter()
            .flat_map(|t| {
                let addr = t.address().to_string();
                let weight = (t.weight() as usize).max(1);
                std::iter::repeat_n(addr, weight)
            })
            .collect();

        let addr_list = targets
            .iter()
            .map(|t| t.address())
            .collect::<Vec<_>>()
            .join(", ");

        let map_err = move |e: std::io::Error| UpstreamError::InvalidAddress {
            address: addr_list.clone(),
            reason: e.to_string(),
        };

        match strategy {
            LbStrategy::RoundRobin => {
                let lb = LoadBalancer::<RoundRobin>::try_from_iter(expanded.iter())
                    .map_err(map_err)?;
                Ok(Self::RoundRobin(Arc::new(lb)))
            }
            LbStrategy::Random => {
                let lb =
                    LoadBalancer::<Random>::try_from_iter(expanded.iter()).map_err(map_err)?;
                Ok(Self::Random(Arc::new(lb)))
            }
            LbStrategy::FnvHash => {
                let lb =
                    LoadBalancer::<pingora_load_balancing::selection::FNVHash>::try_from_iter(
                        expanded.iter(),
                    )
                    .map_err(map_err)?;
                Ok(Self::FnvHash(Arc::new(lb)))
            }
            LbStrategy::ConsistentHash => {
                let lb = LoadBalancer::<Consistent>::try_from_iter(expanded.iter())
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
    /// Create a new upstream group from target configs, a strategy, and timeout settings.
    ///
    /// Weighted targets are expanded by repetition in the load balancer rotation.
    pub fn new(
        name: UpstreamName,
        targets: &[TargetConfig],
        strategy: LbStrategy,
        tls: UpstreamTlsConfig,
        timeouts: UpstreamTimeouts,
    ) -> Result<Self, UpstreamError> {
        let lb = AnyLoadBalancer::build(targets, strategy)?;
        Ok(Self { name, lb, strategy, tls, timeouts })
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
    pub fn background_service(&self) -> Option<Box<dyn ServiceWithDependents>> {
        self.lb.as_background_service(&self.name.0)
    }

    /// Select a peer and wrap it as an `HttpPeer` with this group's settings.
    pub fn select_peer(&self) -> Result<Box<HttpPeer>, UpstreamError> {
        self.select_peer_with_key(b"")
    }

    /// Apply all configured timeouts and options to a peer.
    fn apply_peer_options(&self, peer: &mut HttpPeer) {
        peer.options.connection_timeout = Some(self.timeouts.connect);
        peer.options.read_timeout = Some(self.timeouts.read);
        peer.options.write_timeout = Some(self.timeouts.write);
        peer.options.idle_timeout = Some(self.timeouts.idle);
        peer.options.total_connection_timeout = self.timeouts.total_connection_timeout;
        if let Some(ref ka) = self.timeouts.tcp_keepalive {
            peer.options.tcp_keepalive = Some(pingora_core::protocols::TcpKeepalive {
                idle: ka.idle,
                interval: ka.interval,
                count: ka.count,
                #[cfg(target_os = "linux")]
                user_timeout: Duration::ZERO,
            });
        }
        if let Some(streams) = self.timeouts.max_h2_streams {
            peer.options.max_h2_streams = streams;
        }
        if let Some(buf) = self.timeouts.tcp_recv_buf {
            peer.options.tcp_recv_buf = Some(buf);
        }
        if let Some(interval) = self.timeouts.h2_ping_interval {
            peer.options.h2_ping_interval = Some(interval);
        }
    }

    /// Select a peer whose address matches the given sticky cookie hash.
    ///
    /// Iterates all backends to find one whose SHA256 hash prefix matches.
    /// Returns `None` if no match found (backend removed/changed).
    pub fn select_peer_by_sticky_hash(&self, cookie_hash: &str) -> Option<Box<HttpPeer>> {
        use sha2::{Digest, Sha256};

        // Try all backends (up to 256 iterations to handle weighted duplicates)
        for _ in 0..256 {
            if let Some(backend) = self.lb.select(b"", 256) {
                let addr_str = format!("{}", backend.addr);
                let hash = format!("{:x}", Sha256::digest(addr_str.as_bytes()));
                if hash.starts_with(cookie_hash) {
                    let mut peer = HttpPeer::new(
                        backend.addr,
                        self.tls.enabled,
                        self.tls.sni.as_deref().unwrap_or_default().to_string(),
                    );
                    self.apply_peer_options(&mut peer);
                    return Some(Box::new(peer));
                }
            }
        }
        None
    }

    /// Select a peer using a hash key (for hash-based strategies).
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
        self.apply_peer_options(&mut peer);

        Ok(Box::new(peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TargetConfig;
    use crate::upstream::UpstreamName;
    use pingora_core::upstreams::peer::Peer;

    fn simple_targets(addrs: &[&str]) -> Vec<TargetConfig> {
        addrs.iter().map(|a| TargetConfig::Simple(a.to_string())).collect()
    }

    #[test]
    fn lb_strategy_from_config() {
        assert_eq!(LbStrategy::from_config("round_robin").unwrap(), LbStrategy::RoundRobin);
        assert_eq!(LbStrategy::from_config("random").unwrap(), LbStrategy::Random);
        assert_eq!(LbStrategy::from_config("fnv_hash").unwrap(), LbStrategy::FnvHash);
        assert_eq!(
            LbStrategy::from_config("consistent_hash").unwrap(),
            LbStrategy::ConsistentHash
        );
        assert!(LbStrategy::from_config("invalid").is_err());
    }

    #[test]
    fn upstream_group_round_robin() {
        let targets = simple_targets(&["127.0.0.1:3000", "127.0.0.1:3001"]);
        let group = UpstreamGroup::new(
            UpstreamName::from("test"),
            &targets,
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let peer1 = group.select_peer().unwrap();
        let peer2 = group.select_peer().unwrap();
        assert!(peer1.address().as_inet().is_some());
        assert!(peer2.address().as_inet().is_some());
    }

    #[test]
    fn upstream_group_all_strategies() {
        let targets = simple_targets(&["127.0.0.1:3000", "127.0.0.1:3001"]);
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
        let targets = simple_targets(&["127.0.0.1:3000", "127.0.0.1:3001", "127.0.0.1:3002"]);
        let group = UpstreamGroup::new(
            UpstreamName::from("test"),
            &targets,
            LbStrategy::ConsistentHash,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let peer1 = group.select_peer_with_key(b"user-123").unwrap();
        let peer2 = group.select_peer_with_key(b"user-123").unwrap();
        assert_eq!(
            peer1.address().as_inet().unwrap(),
            peer2.address().as_inet().unwrap()
        );
    }

    #[test]
    fn upstream_group_no_health_check_no_bg_service() {
        let targets = simple_targets(&["127.0.0.1:3000"]);
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

    #[test]
    fn weighted_targets_expand_correctly() {
        // weight=3 means 3 entries in LB rotation
        let targets = vec![
            TargetConfig::Weighted { address: "127.0.0.1:3000".to_string(), weight: 3 },
            TargetConfig::Weighted { address: "127.0.0.1:3001".to_string(), weight: 1 },
        ];
        // Build should succeed — 4 entries in rotation
        let group = UpstreamGroup::new(
            UpstreamName::from("weighted"),
            &targets,
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();
        let peer = group.select_peer().unwrap();
        assert!(peer.address().as_inet().is_some());
    }

    #[test]
    fn timeouts_from_config() {
        use crate::config::{UpstreamConfig, TcpKeepaliveConfig};
        let uc = UpstreamConfig {
            discovery: "static".to_string(),
            targets: vec![],
            load_balancing: "round_robin".to_string(),
            health_check: None,
            connect_timeout: "3s".to_string(),
            read_timeout: "45s".to_string(),
            write_timeout: "30s".to_string(),
            total_connection_timeout: Some("10s".to_string()),
            retry: None,
            passive_health: None,
            sticky: None,
            circuit_breaker: None,
            keepalive_timeout: "120s".to_string(),
            keepalive_pool_size: 64,
            tcp_keepalive: Some(TcpKeepaliveConfig {
                idle: "30s".to_string(),
                interval: "10s".to_string(),
                count: 3,
            }),
            max_h2_streams: Some(100),
            tcp_recv_buf: Some(65536),
            h2_ping_interval: Some("30s".to_string()),
        };
        let t = UpstreamTimeouts::from_config(&uc);
        assert_eq!(t.connect, Duration::from_secs(3));
        assert_eq!(t.read, Duration::from_secs(45));
        assert_eq!(t.write, Duration::from_secs(30));
        assert_eq!(t.idle, Duration::from_secs(120));
        assert_eq!(t.total_connection_timeout, Some(Duration::from_secs(10)));
        let ka = t.tcp_keepalive.unwrap();
        assert_eq!(ka.idle, Duration::from_secs(30));
        assert_eq!(ka.interval, Duration::from_secs(10));
        assert_eq!(ka.count, 3);
        assert_eq!(t.max_h2_streams, Some(100));
        assert_eq!(t.tcp_recv_buf, Some(65536));
        assert_eq!(t.h2_ping_interval, Some(Duration::from_secs(30)));
    }
}
