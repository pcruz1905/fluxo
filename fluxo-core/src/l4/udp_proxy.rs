//! UDP proxy — transparent L4 UDP forwarding.
//!
//! Provides UDP proxying with session tracking (maps client addr to upstream).
//! Nginx equivalent: `stream { ... }` with `udp` protocol.
//! Traefik equivalent: UDP routers/services.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use super::config::UdpServiceConfig;

/// A single UDP session tracking entry.
struct UdpSession {
    /// The upstream socket bound for this client.
    upstream: Arc<UdpSocket>,
    /// Last activity timestamp for idle timeout.
    last_active: std::time::Instant,
}

/// A running UDP proxy service.
pub struct UdpProxy {
    config: UdpServiceConfig,
    /// Pre-parsed idle timeout.
    idle_timeout: Duration,
    /// Round-robin index for target selection.
    next_target: std::sync::atomic::AtomicUsize,
}

impl UdpProxy {
    pub fn new(config: UdpServiceConfig) -> Self {
        let idle_timeout =
            crate::config::parse_duration(&config.idle_timeout).unwrap_or(Duration::from_secs(30));
        Self {
            config,
            idle_timeout,
            next_target: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Select the next upstream target (round-robin).
    fn select_target(&self) -> Option<&str> {
        if self.config.targets.is_empty() {
            return None;
        }
        let idx = self
            .next_target
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.config.targets.len();
        Some(&self.config.targets[idx])
    }

    /// Start the UDP proxy listener.
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let listener = UdpSocket::bind(&self.config.listen).await?;
        let listener = Arc::new(listener);
        info!(address = %self.config.listen, "UDP proxy listening");

        // Session table: maps client address to upstream socket
        let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn idle session cleanup task
        let sessions_cleanup = Arc::clone(&sessions);
        let idle_timeout = self.idle_timeout;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle_timeout).await;
                let mut table = sessions_cleanup.lock();
                let before = table.len();
                table.retain(|_, session| session.last_active.elapsed() < idle_timeout);
                let evicted = before - table.len();
                if evicted > 0 {
                    debug!(evicted, remaining = table.len(), "UDP session cleanup");
                }
            }
        });

        let mut buf = vec![0u8; self.config.max_packet_size as usize];

        loop {
            match listener.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let data = buf[..len].to_vec();

                    // Check for existing session (lock scoped tightly — no await)
                    let existing = {
                        let mut table = sessions.lock();
                        table.get_mut(&client_addr).map(|session| {
                            session.last_active = std::time::Instant::now();
                            Arc::clone(&session.upstream)
                        })
                    };

                    let upstream_socket = if let Some(sock) = existing {
                        sock
                    } else {
                        // Create new session (async work outside the lock)
                        let Some(target) = self.select_target() else {
                            warn!(client = %client_addr, "no UDP upstream target available");
                            continue;
                        };
                        let target = target.to_string();

                        let upstream = match UdpSocket::bind("0.0.0.0:0").await {
                            Ok(s) => s,
                            Err(e) => {
                                error!(error = %e, "failed to bind UDP upstream socket");
                                continue;
                            }
                        };

                        if let Err(e) = upstream.connect(&target).await {
                            warn!(target, error = %e, "UDP upstream connect failed");
                            continue;
                        }

                        let upstream = Arc::new(upstream);
                        debug!(client = %client_addr, target, "new UDP session");

                        // Insert into session table (re-acquire lock, no await)
                        {
                            let mut table = sessions.lock();
                            table.insert(
                                client_addr,
                                UdpSession {
                                    upstream: Arc::clone(&upstream),
                                    last_active: std::time::Instant::now(),
                                },
                            );
                        }

                        // Spawn response relay: upstream -> client
                        let upstream_rx = Arc::clone(&upstream);
                        let listener_tx = Arc::clone(&listener);
                        let sessions_ref = Arc::clone(&sessions);
                        let idle = self.idle_timeout;
                        let max_pkt = self.config.max_packet_size as usize;
                        tokio::spawn(async move {
                            let mut resp_buf = vec![0u8; max_pkt];
                            loop {
                                match tokio::time::timeout(idle, upstream_rx.recv(&mut resp_buf))
                                    .await
                                {
                                    Ok(Ok(n)) => {
                                        if let Err(e) =
                                            listener_tx.send_to(&resp_buf[..n], client_addr).await
                                        {
                                            debug!(error = %e, "UDP relay to client failed");
                                            break;
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        debug!(error = %e, "UDP upstream recv error");
                                        break;
                                    }
                                    Err(_) => {
                                        debug!(client = %client_addr, "UDP session idle timeout");
                                        break;
                                    }
                                }
                            }
                            sessions_ref.lock().remove(&client_addr);
                        });

                        upstream
                    };

                    // Forward client data to upstream
                    if let Err(e) = upstream_socket.send(&data).await {
                        debug!(error = %e, "UDP forward to upstream failed");
                    }
                }
                Err(e) => {
                    error!(error = %e, "UDP proxy recv error");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn select_target_round_robin() {
        let config = UdpServiceConfig {
            listen: "0.0.0.0:0".to_string(),
            targets: vec!["a:53".to_string(), "b:53".to_string()],
            idle_timeout: "30s".to_string(),
            max_packet_size: 65535,
            max_sessions: 0,
        };
        let proxy = UdpProxy::new(config);
        assert_eq!(proxy.select_target(), Some("a:53"));
        assert_eq!(proxy.select_target(), Some("b:53"));
        assert_eq!(proxy.select_target(), Some("a:53"));
    }

    #[test]
    fn select_target_empty() {
        let config = UdpServiceConfig {
            listen: "0.0.0.0:0".to_string(),
            targets: vec![],
            idle_timeout: "30s".to_string(),
            max_packet_size: 65535,
            max_sessions: 0,
        };
        let proxy = UdpProxy::new(config);
        assert_eq!(proxy.select_target(), None);
    }

    #[test]
    fn default_idle_timeout() {
        let config = UdpServiceConfig {
            listen: "0.0.0.0:0".to_string(),
            targets: vec!["dns:53".to_string()],
            idle_timeout: "invalid".to_string(),
            max_packet_size: 65535,
            max_sessions: 0,
        };
        let proxy = UdpProxy::new(config);
        assert_eq!(proxy.idle_timeout, Duration::from_secs(30));
    }
}
