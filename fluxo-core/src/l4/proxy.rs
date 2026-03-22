//! TCP proxy — transparent L4 forwarding with optional SNI routing.
//!
//! Uses Tokio's TCP listener and bidirectional copy for raw TCP proxying.
//! This is a standalone proxy separate from the HTTP `ProxyHttp` implementation.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use super::config::TcpServiceConfig;

/// A running TCP proxy service.
pub struct TcpProxy {
    config: TcpServiceConfig,
    /// Pre-parsed connect timeout (avoids re-parsing per connection).
    connect_timeout: Duration,
    /// Round-robin index for load balancing.
    next_target: std::sync::atomic::AtomicUsize,
}

impl TcpProxy {
    pub fn new(config: TcpServiceConfig) -> Self {
        let connect_timeout = crate::config::parse_duration(&config.connect_timeout)
            .unwrap_or(Duration::from_secs(5));
        Self {
            config,
            connect_timeout,
            next_target: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Select the next upstream target (round-robin).
    fn select_target(&self, sni: Option<&str>) -> Option<String> {
        // Check SNI routes first
        if let Some(sni_host) = sni {
            if let Some(targets) = self.config.sni_routes.get(sni_host) {
                if !targets.is_empty() {
                    let idx = self
                        .next_target
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        % targets.len();
                    return Some(targets[idx].clone());
                }
            }
        }

        // Fall back to default targets
        if self.config.targets.is_empty() {
            return None;
        }
        let idx = self
            .next_target
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.config.targets.len();
        Some(self.config.targets[idx].clone())
    }

    /// Extract SNI hostname from TLS `ClientHello` (first bytes of connection).
    /// Returns (SNI hostname if found, the peeked bytes to replay).
    fn extract_sni(buf: &[u8]) -> Option<String> {
        // TLS record: type(1) + version(2) + length(2) + handshake
        if buf.len() < 5 || buf[0] != 0x16 {
            return None; // Not a TLS ClientHello
        }

        let handshake_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if buf.len() < 5 + handshake_len {
            return None;
        }

        let handshake = &buf[5..];
        if handshake.is_empty() || handshake[0] != 0x01 {
            return None; // Not ClientHello
        }

        // Skip: type(1) + length(3) + version(2) + random(32) = 38
        if handshake.len() < 38 {
            return None;
        }
        let mut pos = 38;

        // Session ID length + skip
        if pos >= handshake.len() {
            return None;
        }
        let session_id_len = handshake[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suites length + skip
        if pos + 2 > handshake.len() {
            return None;
        }
        let cipher_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
        pos += 2 + cipher_len;

        // Compression methods length + skip
        if pos >= handshake.len() {
            return None;
        }
        let comp_len = handshake[pos] as usize;
        pos += 1 + comp_len;

        // Extensions
        if pos + 2 > handshake.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
        pos += 2;

        let ext_end = pos + ext_len;
        while pos + 4 <= ext_end && pos + 4 <= handshake.len() {
            let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
            let ext_data_len =
                u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
            pos += 4;

            if ext_type == 0x0000 {
                // SNI extension
                if pos + 2 > handshake.len() {
                    return None;
                }
                let sni_list_len =
                    u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
                let _ = sni_list_len;
                pos += 2;

                if pos + 3 > handshake.len() {
                    return None;
                }
                let name_type = handshake[pos];
                let name_len =
                    u16::from_be_bytes([handshake[pos + 1], handshake[pos + 2]]) as usize;
                pos += 3;

                if name_type == 0x00 && pos + name_len <= handshake.len() {
                    return String::from_utf8(handshake[pos..pos + name_len].to_vec()).ok();
                }
                return None;
            }
            pos += ext_data_len;
        }

        None
    }

    /// Handle a single TCP connection.
    async fn handle_connection(
        self: &Arc<Self>,
        downstream: TcpStream,
        client_addr: SocketAddr,
    ) -> io::Result<()> {
        // Peek at first bytes to detect SNI
        let mut peek_buf = vec![0u8; 1024];
        let n = downstream.peek(&mut peek_buf).await?;
        let sni = Self::extract_sni(&peek_buf[..n]);

        let Some(target) = self.select_target(sni.as_deref()) else {
            warn!(client = %client_addr, "no upstream target available");
            return Ok(());
        };

        debug!(
            client = %client_addr,
            target = %target,
            sni = ?sni,
            "TCP proxy connecting"
        );

        // Connect to upstream with configured timeout
        let connect_timeout = self.connect_timeout;
        let upstream =
            match tokio::time::timeout(connect_timeout, TcpStream::connect(&target)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    warn!(target = %target, error = %e, "TCP upstream connect failed");
                    return Ok(());
                }
                Err(_) => {
                    warn!(target = %target, "TCP upstream connect timeout");
                    return Ok(());
                }
            };

        // Bidirectional copy
        let (mut down_read, mut down_write) = downstream.into_split();
        let (mut up_read, mut up_write) = upstream.into_split();

        let client_to_server = tokio::io::copy(&mut down_read, &mut up_write);
        let server_to_client = tokio::io::copy(&mut up_read, &mut down_write);

        tokio::select! {
            result = client_to_server => {
                if let Err(e) = result {
                    debug!(error = %e, "client -> server copy ended");
                }
            }
            result = server_to_client => {
                if let Err(e) = result {
                    debug!(error = %e, "server -> client copy ended");
                }
            }
        }

        Ok(())
    }

    /// Start the TCP proxy listener.
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let listener = TcpListener::bind(&self.config.listen).await?;
        info!(address = %self.config.listen, "TCP proxy listening");

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let proxy = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_connection(stream, addr).await {
                            error!(error = %e, "TCP proxy connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "TCP proxy accept error");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_target_round_robin() {
        let config = TcpServiceConfig {
            listen: "0.0.0.0:0".to_string(),
            targets: vec!["a:80".to_string(), "b:80".to_string()],
            sni_routes: Default::default(),
            connect_timeout: "5s".to_string(),
            proxy_protocol: false,
            max_connections: 0,
        };
        let proxy = TcpProxy::new(config);
        assert_eq!(proxy.select_target(None), Some("a:80".to_string()));
        assert_eq!(proxy.select_target(None), Some("b:80".to_string()));
        assert_eq!(proxy.select_target(None), Some("a:80".to_string()));
    }

    #[test]
    fn select_target_sni_route() {
        let mut sni_routes = std::collections::HashMap::new();
        sni_routes.insert("api.example.com".to_string(), vec!["api:443".to_string()]);
        let config = TcpServiceConfig {
            listen: "0.0.0.0:443".to_string(),
            targets: vec!["default:443".to_string()],
            sni_routes,
            connect_timeout: "5s".to_string(),
            proxy_protocol: false,
            max_connections: 0,
        };
        let proxy = TcpProxy::new(config);
        assert_eq!(
            proxy.select_target(Some("api.example.com")),
            Some("api:443".to_string())
        );
        assert_eq!(
            proxy.select_target(Some("unknown.com")),
            Some("default:443".to_string())
        );
    }

    #[test]
    fn select_target_no_targets() {
        let config = TcpServiceConfig {
            listen: "0.0.0.0:0".to_string(),
            targets: vec![],
            sni_routes: Default::default(),
            connect_timeout: "5s".to_string(),
            proxy_protocol: false,
            max_connections: 0,
        };
        let proxy = TcpProxy::new(config);
        assert_eq!(proxy.select_target(None), None);
    }

    #[test]
    fn extract_sni_non_tls() {
        assert_eq!(TcpProxy::extract_sni(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn extract_sni_too_short() {
        assert_eq!(TcpProxy::extract_sni(&[0x16, 0x03, 0x01]), None);
    }
}
