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
use crate::upstream::circuit_breaker::PassiveHealthTracker;

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

/// TCP keepalive settings — mirrors Pingora's `TcpKeepalive`.
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
            connect: parse_duration(&c.connect_timeout).unwrap_or(Duration::from_secs(5)),
            read: parse_duration(&c.read_timeout).unwrap_or(Duration::from_secs(60)),
            write: parse_duration(&c.write_timeout).unwrap_or(Duration::from_secs(60)),
            idle: parse_duration(&c.keepalive_timeout).unwrap_or(Duration::from_secs(60)),
            total_connection_timeout: c
                .total_connection_timeout
                .as_ref()
                .and_then(|s| parse_duration(s).ok()),
            tcp_keepalive: c.tcp_keepalive.as_ref().map(|ka| TcpKeepaliveSettings {
                idle: parse_duration(&ka.idle).unwrap_or(Duration::from_secs(60)),
                interval: parse_duration(&ka.interval).unwrap_or(Duration::from_secs(15)),
                count: ka.count,
            }),
            max_h2_streams: c.max_h2_streams,
            tcp_recv_buf: c.tcp_recv_buf,
            h2_ping_interval: c
                .h2_ping_interval
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
    /// Earliest Deadline First — heap-based precise weighted distribution (Traefik-inspired).
    WeightedEdf,
    /// Least Connections — picks the backend with fewest active requests.
    LeastConnections,
}

impl LbStrategy {
    /// Parse a strategy name from the config string.
    pub fn from_config(s: &str) -> Result<Self, UpstreamError> {
        match s {
            "round_robin" => Ok(Self::RoundRobin),
            "random" => Ok(Self::Random),
            "fnv_hash" => Ok(Self::FnvHash),
            "consistent_hash" => Ok(Self::ConsistentHash),
            "weighted_edf" => Ok(Self::WeightedEdf),
            "least_connections" => Ok(Self::LeastConnections),
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
    /// EDF-based weighted scheduler — doesn't use Pingora's `LoadBalancer`.
    Edf(Arc<super::edf::EdfScheduler>),
    /// Least connections scheduler — picks the backend with fewest active requests.
    LeastConn(Arc<super::least_conn::LeastConnScheduler>),
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
            .map(TargetConfig::address)
            .collect::<Vec<_>>()
            .join(", ");

        let map_err = move |e: std::io::Error| UpstreamError::InvalidAddress {
            address: addr_list.clone(),
            reason: e.to_string(),
        };

        match strategy {
            LbStrategy::RoundRobin => {
                let lb =
                    LoadBalancer::<RoundRobin>::try_from_iter(expanded.iter()).map_err(map_err)?;
                Ok(Self::RoundRobin(Arc::new(lb)))
            }
            LbStrategy::Random => {
                let lb = LoadBalancer::<Random>::try_from_iter(expanded.iter()).map_err(map_err)?;
                Ok(Self::Random(Arc::new(lb)))
            }
            LbStrategy::FnvHash => {
                let lb = LoadBalancer::<pingora_load_balancing::selection::FNVHash>::try_from_iter(
                    expanded.iter(),
                )
                .map_err(map_err)?;
                Ok(Self::FnvHash(Arc::new(lb)))
            }
            LbStrategy::ConsistentHash => {
                let lb =
                    LoadBalancer::<Consistent>::try_from_iter(expanded.iter()).map_err(map_err)?;
                Ok(Self::ConsistentHash(Arc::new(lb)))
            }
            LbStrategy::WeightedEdf => {
                let edf_targets: Vec<super::edf::EdfTarget> = targets
                    .iter()
                    .map(|t| super::edf::EdfTarget {
                        address: t.address().to_string(),
                        weight: t.weight(),
                    })
                    .collect();
                Ok(Self::Edf(Arc::new(super::edf::EdfScheduler::new(
                    edf_targets,
                ))))
            }
            LbStrategy::LeastConnections => {
                let addresses: Vec<String> =
                    targets.iter().map(|t| t.address().to_string()).collect();
                Ok(Self::LeastConn(Arc::new(
                    super::least_conn::LeastConnScheduler::new(addresses),
                )))
            }
        }
    }

    /// Select a backend using the configured strategy.
    ///
    /// For EDF and `LeastConn`, an optional health filter is used to skip
    /// unhealthy peers. Pingora's built-in strategies (`RoundRobin`, Random, etc.)
    /// already integrate with Pingora's health check framework.
    fn select(
        &self,
        key: &[u8],
        max_iterations: usize,
        health_filter: Option<&dyn Fn(&str) -> bool>,
    ) -> Option<pingora_load_balancing::Backend> {
        match self {
            Self::RoundRobin(lb) => lb.select(key, max_iterations),
            Self::Random(lb) => lb.select(key, max_iterations),
            Self::FnvHash(lb) => lb.select(key, max_iterations),
            Self::ConsistentHash(lb) => lb.select(key, max_iterations),
            Self::Edf(scheduler) => {
                let (_, addr) = if let Some(is_healthy) = health_filter {
                    scheduler.select_healthy(is_healthy)?
                } else {
                    scheduler.select()?
                };
                // Create a Backend from the address string
                Some(pingora_load_balancing::Backend {
                    addr: addr.parse().ok()?,
                    weight: 1, // Weight is handled by the EDF scheduler itself
                    ext: Default::default(),
                })
            }
            Self::LeastConn(scheduler) => {
                let (_, addr) = if let Some(is_healthy) = health_filter {
                    scheduler.select_healthy(is_healthy)?
                } else {
                    scheduler.select()?
                };
                Some(pingora_load_balancing::Backend {
                    addr: addr.parse().ok()?,
                    weight: 1,
                    ext: Default::default(),
                })
            }
        }
    }

    fn set_health_check(
        &mut self,
        hc: Box<dyn pingora_load_balancing::health_check::HealthCheck + Send + Sync + 'static>,
    ) {
        match self {
            Self::RoundRobin(lb) => {
                if let Some(mut_lb) = Arc::get_mut(lb) {
                    mut_lb.set_health_check(hc);
                }
            }
            Self::Random(lb) => {
                if let Some(mut_lb) = Arc::get_mut(lb) {
                    mut_lb.set_health_check(hc);
                }
            }
            Self::FnvHash(lb) => {
                if let Some(mut_lb) = Arc::get_mut(lb) {
                    mut_lb.set_health_check(hc);
                }
            }
            Self::ConsistentHash(lb) => {
                if let Some(mut_lb) = Arc::get_mut(lb) {
                    mut_lb.set_health_check(hc);
                }
            }
            Self::Edf(_) | Self::LeastConn(_) => {
                // Custom schedulers don't use Pingora's LoadBalancer health checking.
            }
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
            // EDF and LeastConn do not support Pingora-integrated health checks
            _ => None,
        }
    }

    fn set_health_check_frequency(&mut self, freq: Duration) {
        match self {
            Self::RoundRobin(lb) => {
                if let Some(mut_lb) = Arc::get_mut(lb) {
                    mut_lb.health_check_frequency = Some(freq);
                }
            }
            Self::Random(lb) => {
                if let Some(mut_lb) = Arc::get_mut(lb) {
                    mut_lb.health_check_frequency = Some(freq);
                }
            }
            Self::FnvHash(lb) => {
                if let Some(mut_lb) = Arc::get_mut(lb) {
                    mut_lb.health_check_frequency = Some(freq);
                }
            }
            Self::ConsistentHash(lb) => {
                if let Some(mut_lb) = Arc::get_mut(lb) {
                    mut_lb.health_check_frequency = Some(freq);
                }
            }
            Self::Edf(_) | Self::LeastConn(_) => {}
        }
    }
}

/// Passive health check parameters for filtering unhealthy peers.
///
/// Stored in the upstream group so EDF/LeastConn schedulers can skip
/// peers that the `PassiveHealthTracker` has marked unhealthy.
#[derive(Debug, Clone)]
pub struct PassiveHealthParams {
    /// Shared tracker that records per-peer failure counts.
    pub tracker: Arc<PassiveHealthTracker>,
    /// Number of consecutive failures before a peer is considered unhealthy.
    pub max_fails: u32,
    /// Window during which failures count — after this, the peer is considered healthy again.
    pub fail_timeout: Duration,
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
    /// Passive health filter for EDF/LeastConn (Pingora LB strategies have built-in health).
    passive_health: Option<PassiveHealthParams>,
}

impl std::fmt::Debug for UpstreamGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamGroup")
            .field("name", &self.name)
            .field("strategy", &self.strategy)
            .field("tls", &self.tls)
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
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
        Ok(Self {
            name,
            lb,
            strategy,
            tls,
            timeouts,
            passive_health: None,
        })
    }

    /// Set passive health parameters for EDF/LeastConn health-aware selection.
    ///
    /// When set, the EDF and `LeastConn` schedulers will skip peers that the
    /// `PassiveHealthTracker` considers unhealthy (consecutive failures >= `max_fails`
    /// within `fail_timeout`). Pingora's built-in strategies already integrate with
    /// Pingora's health check framework and don't need this.
    pub fn set_passive_health(&mut self, params: PassiveHealthParams) {
        self.passive_health = Some(params);
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

    /// Build a health filter closure from passive health params, if configured.
    ///
    /// Returns `None` when no passive health is configured (Pingora LB strategies
    /// handle health internally, EDF/LeastConn fall back to unfiltered selection).
    fn health_filter(&self) -> Option<impl Fn(&str) -> bool + '_> {
        self.passive_health.as_ref().map(|ph| {
            move |addr: &str| -> bool {
                !ph.tracker.is_unhealthy(addr, ph.max_fails, ph.fail_timeout)
            }
        })
    }

    /// Select a peer whose address matches the given sticky cookie hash.
    ///
    /// Iterates all backends to find one whose SHA256 hash prefix matches.
    /// Returns `None` if no match found (backend removed/changed).
    pub fn select_peer_by_sticky_hash(&self, cookie_hash: &str) -> Option<Box<HttpPeer>> {
        use sha2::{Digest, Sha256};

        let filter = self.health_filter();
        let filter_ref: Option<&dyn Fn(&str) -> bool> =
            filter.as_ref().map(|f| f as &dyn Fn(&str) -> bool);

        // Try all backends (up to 256 iterations to handle weighted duplicates)
        for _ in 0..256 {
            if let Some(backend) = self.lb.select(b"", 256, filter_ref) {
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
        let filter = self.health_filter();
        let filter_ref: Option<&dyn Fn(&str) -> bool> =
            filter.as_ref().map(|f| f as &dyn Fn(&str) -> bool);

        let backend = self
            .lb
            .select(key, 256, filter_ref)
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::config::TargetConfig;
    use crate::upstream::UpstreamName;
    use pingora_core::upstreams::peer::Peer;

    fn simple_targets(addrs: &[&str]) -> Vec<TargetConfig> {
        addrs
            .iter()
            .map(|a| TargetConfig::Simple(a.to_string()))
            .collect()
    }

    #[test]
    fn lb_strategy_from_config() {
        assert_eq!(
            LbStrategy::from_config("round_robin").unwrap(),
            LbStrategy::RoundRobin
        );
        assert_eq!(
            LbStrategy::from_config("random").unwrap(),
            LbStrategy::Random
        );
        assert_eq!(
            LbStrategy::from_config("fnv_hash").unwrap(),
            LbStrategy::FnvHash
        );
        assert_eq!(
            LbStrategy::from_config("consistent_hash").unwrap(),
            LbStrategy::ConsistentHash
        );
        assert_eq!(
            LbStrategy::from_config("least_connections").unwrap(),
            LbStrategy::LeastConnections
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
            .unwrap_or_else(|e| panic!("strategy {strategy:?} should work: {e}"));
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
            TargetConfig::Weighted {
                address: "127.0.0.1:3000".to_string(),
                weight: 3,
            },
            TargetConfig::Weighted {
                address: "127.0.0.1:3001".to_string(),
                weight: 1,
            },
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
        use crate::config::{TcpKeepaliveConfig, UpstreamConfig};
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
            response_buffer_size: None,
            upstream_type: None,
            services: vec![],
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

    #[test]
    fn sticky_hash_finds_matching_backend() {
        use sha2::{Digest, Sha256};

        let targets = simple_targets(&["127.0.0.1:4000", "127.0.0.1:4001", "127.0.0.1:4002"]);
        let group = UpstreamGroup::new(
            UpstreamName::from("sticky"),
            &targets,
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Compute the expected hash for one of the backends
        let addr = "127.0.0.1:4001";
        let hash = format!("{:x}", Sha256::digest(addr.as_bytes()));
        let prefix = &hash[..8];

        let peer = group.select_peer_by_sticky_hash(prefix);
        assert!(peer.is_some(), "should find a matching peer");
        let peer = peer.unwrap();
        assert_eq!(format!("{}", peer.address()), addr);
    }

    #[test]
    fn sticky_hash_returns_none_for_unknown() {
        let targets = simple_targets(&["127.0.0.1:5000", "127.0.0.1:5001"]);
        let group = UpstreamGroup::new(
            UpstreamName::from("sticky"),
            &targets,
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let peer = group.select_peer_by_sticky_hash("ffffffff");
        assert!(peer.is_none(), "no backend should match arbitrary hash");
    }

    #[test]
    fn sticky_hash_with_single_backend() {
        use sha2::{Digest, Sha256};

        let targets = simple_targets(&["127.0.0.1:6000"]);
        let group = UpstreamGroup::new(
            UpstreamName::from("sticky"),
            &targets,
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let addr = "127.0.0.1:6000";
        let hash = format!("{:x}", Sha256::digest(addr.as_bytes()));
        let prefix = &hash[..8];

        let peer = group.select_peer_by_sticky_hash(prefix);
        assert!(peer.is_some());
        assert_eq!(format!("{}", peer.unwrap().address()), addr);
    }

    #[test]
    fn sticky_hash_applies_timeouts() {
        use sha2::{Digest, Sha256};

        let targets = simple_targets(&["127.0.0.1:7000"]);
        let timeouts = UpstreamTimeouts {
            connect: Duration::from_secs(2),
            read: Duration::from_secs(10),
            write: Duration::from_secs(10),
            idle: Duration::from_secs(60),
            ..Default::default()
        };
        let group = UpstreamGroup::new(
            UpstreamName::from("sticky"),
            &targets,
            LbStrategy::RoundRobin,
            Default::default(),
            timeouts,
        )
        .unwrap();

        let addr = "127.0.0.1:7000";
        let hash = format!("{:x}", Sha256::digest(addr.as_bytes()));
        let prefix = &hash[..8];

        let peer = group.select_peer_by_sticky_hash(prefix).unwrap();
        assert_eq!(
            peer.options.connection_timeout,
            Some(Duration::from_secs(2))
        );
    }

    /// Verify the sticky-session fallback contract: when a backend is removed
    /// (config reload, scale-down), `select_peer_by_sticky_hash` returns `None`
    /// so the caller can fall back to normal load balancing and issue a new cookie.
    ///
    /// The proxy layer (`proxy.rs`) relies on this `None` to:
    ///  1. Fall back to `select_peer()` (normal LB).
    ///  2. Set `ctx.sticky_cookie_new = true` so a fresh cookie is sent.
    #[test]
    fn sticky_fallback_when_backend_removed() {
        use sha2::{Digest, Sha256};

        // --- Phase 1: build a group with backend A and B, get sticky hash for A ---
        let addr_a = "127.0.0.1:9000";
        let addr_b = "127.0.0.1:9001";
        let hash_a = format!("{:x}", Sha256::digest(addr_a.as_bytes()));
        let prefix_a = &hash_a[..8];

        let group_v1 = UpstreamGroup::new(
            UpstreamName::from("sticky-fallback"),
            &simple_targets(&[addr_a, addr_b]),
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Sticky lookup succeeds while backend A is present
        let peer = group_v1.select_peer_by_sticky_hash(prefix_a);
        assert!(peer.is_some(), "backend A is present, sticky should match");
        assert_eq!(format!("{}", peer.unwrap().address()), addr_a);

        // --- Phase 2: simulate config reload that removes backend A ---
        let group_v2 = UpstreamGroup::new(
            UpstreamName::from("sticky-fallback"),
            &simple_targets(&[addr_b]), // only B remains
            LbStrategy::RoundRobin,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        // Sticky lookup for removed backend A must return None
        let peer = group_v2.select_peer_by_sticky_hash(prefix_a);
        assert!(
            peer.is_none(),
            "backend A was removed, sticky must return None so caller falls back"
        );

        // Normal load balancing still works — the caller would use this path
        let fallback = group_v2.select_peer();
        assert!(
            fallback.is_ok(),
            "normal LB should succeed with remaining backends"
        );
        assert_eq!(format!("{}", fallback.unwrap().address()), addr_b);
    }

    #[test]
    fn edf_skips_unhealthy_peers_via_passive_health() {
        let tracker = Arc::new(PassiveHealthTracker::new());
        let targets = simple_targets(&["127.0.0.1:3000", "127.0.0.1:3001", "127.0.0.1:3002"]);
        let mut group = UpstreamGroup::new(
            UpstreamName::from("edf-health"),
            &targets,
            LbStrategy::WeightedEdf,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        group.set_passive_health(PassiveHealthParams {
            tracker: Arc::clone(&tracker),
            max_fails: 3,
            fail_timeout: Duration::from_secs(30),
        });

        // Mark 127.0.0.1:3000 as unhealthy (3 consecutive failures)
        tracker.record_failure("127.0.0.1:3000");
        tracker.record_failure("127.0.0.1:3000");
        tracker.record_failure("127.0.0.1:3000");

        // Select peers — unhealthy one should be skipped
        let mut selected_addrs = std::collections::HashSet::new();
        for _ in 0..50 {
            let peer = group.select_peer().unwrap();
            selected_addrs.insert(format!("{}", peer.address()));
        }
        assert!(
            !selected_addrs.contains("127.0.0.1:3000"),
            "unhealthy peer should be skipped by EDF"
        );
        assert!(
            selected_addrs.contains("127.0.0.1:3001"),
            "healthy peer :3001 should receive traffic"
        );
        assert!(
            selected_addrs.contains("127.0.0.1:3002"),
            "healthy peer :3002 should receive traffic"
        );
    }

    #[test]
    fn least_conn_skips_unhealthy_peers_via_passive_health() {
        let tracker = Arc::new(PassiveHealthTracker::new());
        let targets = simple_targets(&["127.0.0.1:4000", "127.0.0.1:4001", "127.0.0.1:4002"]);
        let mut group = UpstreamGroup::new(
            UpstreamName::from("lc-health"),
            &targets,
            LbStrategy::LeastConnections,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        group.set_passive_health(PassiveHealthParams {
            tracker: Arc::clone(&tracker),
            max_fails: 2,
            fail_timeout: Duration::from_secs(30),
        });

        // Mark 127.0.0.1:4001 as unhealthy (2 consecutive failures)
        tracker.record_failure("127.0.0.1:4001");
        tracker.record_failure("127.0.0.1:4001");

        // Select peers — unhealthy one should be skipped
        let mut selected_addrs = std::collections::HashSet::new();
        for _ in 0..50 {
            let peer = group.select_peer().unwrap();
            selected_addrs.insert(format!("{}", peer.address()));
        }
        assert!(
            !selected_addrs.contains("127.0.0.1:4001"),
            "unhealthy peer should be skipped by LeastConn"
        );
        assert!(
            selected_addrs.contains("127.0.0.1:4000"),
            "healthy peer :4000 should receive traffic"
        );
        assert!(
            selected_addrs.contains("127.0.0.1:4002"),
            "healthy peer :4002 should receive traffic"
        );
    }

    #[test]
    fn edf_without_passive_health_selects_all_peers() {
        // Without passive health configured, all peers should be selectable
        let targets = simple_targets(&["127.0.0.1:5000", "127.0.0.1:5001"]);
        let group = UpstreamGroup::new(
            UpstreamName::from("edf-no-health"),
            &targets,
            LbStrategy::WeightedEdf,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        let mut selected_addrs = std::collections::HashSet::new();
        for _ in 0..20 {
            let peer = group.select_peer().unwrap();
            selected_addrs.insert(format!("{}", peer.address()));
        }
        assert_eq!(
            selected_addrs.len(),
            2,
            "both peers should be selected without passive health"
        );
    }

    #[test]
    fn passive_health_recovery_allows_peer_back() {
        let tracker = Arc::new(PassiveHealthTracker::new());
        let targets = simple_targets(&["127.0.0.1:6000", "127.0.0.1:6001"]);
        let mut group = UpstreamGroup::new(
            UpstreamName::from("edf-recovery"),
            &targets,
            LbStrategy::WeightedEdf,
            Default::default(),
            Default::default(),
        )
        .unwrap();

        group.set_passive_health(PassiveHealthParams {
            tracker: Arc::clone(&tracker),
            max_fails: 2,
            fail_timeout: Duration::from_secs(30),
        });

        // Mark :6000 as unhealthy
        tracker.record_failure("127.0.0.1:6000");
        tracker.record_failure("127.0.0.1:6000");

        // Verify it's skipped
        let mut saw_6000 = false;
        for _ in 0..20 {
            let peer = group.select_peer().unwrap();
            if format!("{}", peer.address()) == "127.0.0.1:6000" {
                saw_6000 = true;
            }
        }
        assert!(!saw_6000, ":6000 should be skipped while unhealthy");

        // Record a success to recover the peer
        tracker.record_success("127.0.0.1:6000");

        // Now :6000 should be selectable again
        let mut saw_6000 = false;
        for _ in 0..20 {
            let peer = group.select_peer().unwrap();
            if format!("{}", peer.address()) == "127.0.0.1:6000" {
                saw_6000 = true;
            }
        }
        assert!(saw_6000, ":6000 should be back in rotation after recovery");
    }
}
