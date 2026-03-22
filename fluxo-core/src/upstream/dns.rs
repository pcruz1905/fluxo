//! DNS-based upstream discovery — resolve hostnames to IP addresses.
//!
//! Periodically resolves DNS records (A/AAAA or SRV) to discover upstream targets.
//! Traefik equivalent: DNS-based service discovery.
//! Nginx equivalent: `resolver` directive with re-resolution.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::time::interval;
use tracing::{debug, warn};

/// Configuration for DNS-based upstream discovery.
#[derive(Debug, Clone)]
pub struct DnsDiscoveryConfig {
    /// Hostname to resolve (e.g., "backend.service.consul").
    pub hostname: String,
    /// Default port to use when DNS returns only IP addresses (A/AAAA records).
    pub port: u16,
    /// How often to re-resolve DNS. Default: 30s.
    pub refresh_interval: Duration,
}

/// A DNS discovery service that periodically resolves a hostname.
#[derive(Debug)]
pub struct DnsDiscovery {
    config: DnsDiscoveryConfig,
    /// Current resolved addresses (shared, lock-free reads via `RwLock`).
    targets: Arc<RwLock<Vec<SocketAddr>>>,
}

impl DnsDiscovery {
    /// Create a new DNS discovery instance.
    pub fn new(config: DnsDiscoveryConfig) -> Self {
        Self {
            config,
            targets: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get the current resolved targets.
    pub fn targets(&self) -> Vec<SocketAddr> {
        self.targets.read().clone()
    }

    /// Get shared handle to the target list.
    pub fn targets_handle(&self) -> Arc<RwLock<Vec<SocketAddr>>> {
        Arc::clone(&self.targets)
    }

    /// Resolve the hostname once and update targets.
    pub async fn resolve_once(&self) -> Result<Vec<SocketAddr>, String> {
        let resolver = hickory_resolver::Resolver::builder_tokio()
            .map_err(|e| format!("failed to create DNS resolver: {e}"))?
            .build();

        let response = resolver
            .lookup_ip(&self.config.hostname)
            .await
            .map_err(|e| format!("DNS lookup failed for '{}': {e}", self.config.hostname))?;

        let addrs: Vec<SocketAddr> = response
            .iter()
            .map(|ip| SocketAddr::new(ip, self.config.port))
            .collect();

        if addrs.is_empty() {
            return Err(format!(
                "DNS lookup returned no addresses for '{}'",
                self.config.hostname
            ));
        }

        debug!(
            hostname = %self.config.hostname,
            count = addrs.len(),
            "DNS discovery resolved targets"
        );

        // Update shared targets
        self.targets.write().clone_from(&addrs);

        Ok(addrs)
    }

    /// Start periodic DNS resolution in a background task.
    /// Returns a `JoinHandle` that can be used to cancel the task.
    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let refresh = self.config.refresh_interval;
        tokio::spawn(async move {
            let mut tick = interval(refresh);
            loop {
                tick.tick().await;
                if let Err(e) = self.resolve_once().await {
                    warn!(error = %e, "DNS discovery refresh failed");
                }
            }
        })
    }
}

/// Parse DNS discovery config from upstream config fields.
pub fn parse_dns_config(
    hostname: &str,
    port: u16,
    refresh_interval: Option<&str>,
) -> Result<DnsDiscoveryConfig, String> {
    let refresh = match refresh_interval {
        Some(s) => parse_duration(s)?,
        None => Duration::from_secs(30),
    };

    if hostname.is_empty() {
        return Err("DNS discovery hostname cannot be empty".to_string());
    }

    Ok(DnsDiscoveryConfig {
        hostname: hostname.to_string(),
        port,
        refresh_interval: refresh,
    })
}

/// Parse a human-readable duration string (e.g., "30s", "5m", "1h").
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num_str, multiplier) = s
        .strip_suffix('s')
        .map(|v| (v, 1))
        .or_else(|| s.strip_suffix('m').map(|v| (v, 60)))
        .or_else(|| s.strip_suffix('h').map(|v| (v, 3600)))
        .unwrap_or((s, 1));
    num_str
        .parse::<u64>()
        .map(|n| Duration::from_secs(n * multiplier))
        .map_err(|_| format!("invalid duration: {s} (expected format: 30s, 5m, 1h)"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_dns_config_valid() {
        let cfg = parse_dns_config("backend.local", 8080, Some("60s")).unwrap();
        assert_eq!(cfg.hostname, "backend.local");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.refresh_interval, Duration::from_secs(60));
    }

    #[test]
    fn parse_dns_config_default_interval() {
        let cfg = parse_dns_config("backend.local", 80, None).unwrap();
        assert_eq!(cfg.refresh_interval, Duration::from_secs(30));
    }

    #[test]
    fn parse_dns_config_empty_hostname_fails() {
        assert!(parse_dns_config("", 80, None).is_err());
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_bare_number() {
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn dns_discovery_targets_initially_empty() {
        let cfg = DnsDiscoveryConfig {
            hostname: "test.local".to_string(),
            port: 80,
            refresh_interval: Duration::from_secs(30),
        };
        let discovery = DnsDiscovery::new(cfg);
        assert!(discovery.targets().is_empty());
    }
}
