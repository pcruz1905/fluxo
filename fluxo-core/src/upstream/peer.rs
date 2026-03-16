//! Peer selection and `HttpPeer` construction.
//!
//! Wraps Pingora's `LoadBalancer` to bundle TLS config and timeouts per-group.

use std::sync::Arc;
use std::time::Duration;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::LoadBalancer;

use crate::upstream::UpstreamError;
use crate::upstream::UpstreamName;

/// TLS configuration for connections to an upstream group.
#[derive(Debug, Clone)]
pub struct UpstreamTlsConfig {
    /// Whether to use TLS for upstream connections.
    pub enabled: bool,
    /// SNI hostname to send.
    pub sni: Option<String>,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sni: None,
        }
    }
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

/// An upstream group wrapping Pingora's `LoadBalancer` with per-group
/// TLS settings and timeouts.
pub struct UpstreamGroup {
    /// Display name for logging.
    pub name: UpstreamName,
    /// The Pingora load balancer with round-robin selection.
    lb: Arc<LoadBalancer<RoundRobin>>,
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
            .field("tls", &self.tls)
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

impl UpstreamGroup {
    /// Create a new upstream group from a list of target addresses.
    pub fn new(
        name: UpstreamName,
        targets: &[String],
        tls: UpstreamTlsConfig,
        timeouts: UpstreamTimeouts,
    ) -> Result<Self, UpstreamError> {
        let lb: LoadBalancer<RoundRobin> =
            LoadBalancer::try_from_iter(targets.iter()).map_err(|e| {
                UpstreamError::InvalidAddress {
                    address: targets.join(", "),
                    reason: e.to_string(),
                }
            })?;

        Ok(Self {
            name,
            lb: Arc::new(lb),
            tls,
            timeouts,
        })
    }

    /// Select a peer using round-robin, then wrap it as an `HttpPeer`
    /// with this group's TLS and timeout settings.
    pub fn select_peer(&self) -> Result<Box<HttpPeer>, UpstreamError> {
        let backend = self
            .lb
            .select(b"", 256)
            .ok_or_else(|| UpstreamError::NoHealthyBackends(self.name.clone()))?;

        let mut peer = HttpPeer::new(
            backend.addr,
            self.tls.enabled,
            self.tls.sni.clone().unwrap_or_default(),
        );

        // Apply timeouts
        peer.options.connection_timeout = Some(self.timeouts.connect);
        peer.options.read_timeout = Some(self.timeouts.read);
        peer.options.write_timeout = Some(self.timeouts.write);

        Ok(Box::new(peer))
    }
}
