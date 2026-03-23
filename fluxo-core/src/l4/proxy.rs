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
    /// Current number of active connections (for `max_connections` enforcement).
    active_connections: std::sync::atomic::AtomicU32,
}

impl TcpProxy {
    pub fn new(config: TcpServiceConfig) -> Self {
        let connect_timeout = crate::config::parse_duration(&config.connect_timeout)
            .unwrap_or(Duration::from_secs(5));
        Self {
            config,
            connect_timeout,
            next_target: std::sync::atomic::AtomicUsize::new(0),
            active_connections: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Check if accepting a new connection is allowed under `max_connections`.
    /// Returns `true` if the connection should be accepted.
    fn try_acquire_connection(&self) -> bool {
        let max = self.config.max_connections;
        if max == 0 {
            // Unlimited
            self.active_connections
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
        // CAS loop to atomically check-and-increment
        loop {
            let current = self
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed);
            if current >= max {
                return false;
            }
            if self
                .active_connections
                .compare_exchange_weak(
                    current,
                    current + 1,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Release a connection slot.
    fn release_connection(&self) {
        self.active_connections
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
        mut downstream: TcpStream,
        client_addr: SocketAddr,
    ) -> io::Result<()> {
        // When PROXY protocol is enabled, read and strip the header first.
        // The remaining bytes (after the header) are application data that must
        // be forwarded to the upstream.
        let (effective_client, sni, leftover) = if self.config.proxy_protocol {
            use tokio::io::AsyncReadExt;

            // Read enough for PROXY header + start of TLS ClientHello
            let mut buf = vec![0u8; 1536];
            let n = downstream.read(&mut buf).await?;
            buf.truncate(n);

            #[allow(clippy::option_if_let_else)]
            let (real_client, app_data_start) = if let Some(hlen) =
                crate::proxy_protocol::proxy_header_len(&buf)
            {
                if hlen <= n {
                    if let Ok(Some(info)) = crate::proxy_protocol::parse_proxy_header(&buf[..hlen])
                    {
                        debug!(
                            client = %client_addr,
                            real_client = %info.source_addr,
                            version = ?info.version,
                            "PROXY protocol header parsed"
                        );
                        (info.source_addr, hlen)
                    } else {
                        warn!(client = %client_addr, "PROXY protocol header parse failed, passing through");
                        (client_addr, 0)
                    }
                } else {
                    warn!(client = %client_addr, "incomplete PROXY protocol header");
                    (client_addr, 0)
                }
            } else {
                warn!(client = %client_addr, "expected PROXY protocol header not found");
                (client_addr, 0)
            };

            let app_data = buf[app_data_start..].to_vec();
            let sni = Self::extract_sni(&app_data);
            (real_client, sni, app_data)
        } else {
            // No PROXY protocol — peek for SNI without consuming
            let mut peek_buf = vec![0u8; 1024];
            let n = downstream.peek(&mut peek_buf).await?;
            let sni = Self::extract_sni(&peek_buf[..n]);
            (client_addr, sni, vec![])
        };

        let Some(target) = self.select_target(sni.as_deref()) else {
            warn!(client = %effective_client, "no upstream target available");
            return Ok(());
        };

        debug!(
            client = %effective_client,
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

        // Split streams for bidirectional copy
        let (mut down_read, mut down_write) = downstream.into_split();
        let (mut up_read, mut up_write) = upstream.into_split();

        // Replay buffered application data that was read with the PROXY header
        if !leftover.is_empty() {
            use tokio::io::AsyncWriteExt;
            up_write.write_all(&leftover).await?;
        }

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
                    if !self.try_acquire_connection() {
                        warn!(
                            client = %addr,
                            max = self.config.max_connections,
                            "TCP proxy max connections reached, rejecting"
                        );
                        drop(stream);
                        continue;
                    }
                    let proxy = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_connection(stream, addr).await {
                            error!(error = %e, "TCP proxy connection error");
                        }
                        proxy.release_connection();
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

    // ── Helper ────────────────────────────────────────────────────────

    /// Build a minimal TLS 1.2 `ClientHello` with an SNI extension.
    fn build_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len();

        // SNI extension data: list_len(2) + type(1) + name_len(2) + name
        let sni_ext_data_len = 2 + 1 + 2 + name_len;
        // Extension header: type(2) + length(2) + data
        let sni_ext_len = 4 + sni_ext_data_len;
        // Extensions block: total_len(2) + extensions
        let extensions_len = 2 + sni_ext_len;

        // Handshake body: version(2) + random(32) + session_id_len(1)
        //   + cipher_suites_len(2) + cipher(2) + comp_len(1) + comp(1) + extensions
        let handshake_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + extensions_len;
        let handshake_len = 1 + 3 + handshake_body_len; // type + 3-byte length + body

        let mut buf = Vec::new();

        // TLS record header
        buf.push(0x16); // ContentType: Handshake
        buf.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());

        // Handshake header
        buf.push(0x01); // HandshakeType: ClientHello
        // 3-byte length
        buf.push(0);
        buf.extend_from_slice(&(handshake_body_len as u16).to_be_bytes());

        // ClientHello body
        buf.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
        buf.extend_from_slice(&[0u8; 32]); // Random
        buf.push(0); // Session ID length: 0
        buf.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites length: 2
        buf.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA
        buf.push(1); // Compression methods length: 1
        buf.push(0); // null compression

        // Extensions
        buf.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // Extensions total length

        // SNI extension
        buf.extend_from_slice(&[0x00, 0x00]); // Extension type: SNI
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        buf.extend_from_slice(&((1 + 2 + name_len) as u16).to_be_bytes()); // Server name list length
        buf.push(0x00); // Name type: hostname
        buf.extend_from_slice(&(name_len as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        buf
    }

    /// Build a minimal TLS 1.2 `ClientHello` with NO extensions at all.
    fn build_client_hello_no_extensions() -> Vec<u8> {
        // Handshake body: version(2) + random(32) + session_id_len(1)
        //   + cipher_suites_len(2) + cipher(2) + comp_len(1) + comp(1) = 41
        let handshake_body_len: usize = 2 + 32 + 1 + 2 + 2 + 1 + 1;
        let handshake_len = 1 + 3 + handshake_body_len;

        let mut buf = Vec::new();

        // TLS record header
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());

        // Handshake header
        buf.push(0x01); // ClientHello
        buf.push(0);
        buf.extend_from_slice(&(handshake_body_len as u16).to_be_bytes());

        // ClientHello body (no extensions)
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0); // session ID len
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x2F]);
        buf.push(1);
        buf.push(0);

        buf
    }

    fn make_config(targets: Vec<&str>, max_connections: u32) -> TcpServiceConfig {
        TcpServiceConfig {
            listen: "0.0.0.0:0".to_string(),
            targets: targets.into_iter().map(String::from).collect(),
            sni_routes: Default::default(),
            connect_timeout: "5s".to_string(),
            proxy_protocol: false,
            max_connections,
        }
    }

    // ── SNI extraction tests ──────────────────────────────────────────

    #[test]
    fn extract_sni_valid_client_hello() {
        let buf = build_client_hello_with_sni("example.com");
        assert_eq!(TcpProxy::extract_sni(&buf), Some("example.com".to_string()));
    }

    #[test]
    fn extract_sni_long_hostname() {
        let hostname = "very-long-subdomain.deeply.nested.example.com";
        let buf = build_client_hello_with_sni(hostname);
        assert_eq!(TcpProxy::extract_sni(&buf), Some(hostname.to_string()));
    }

    #[test]
    fn extract_sni_no_extensions() {
        let buf = build_client_hello_no_extensions();
        assert_eq!(TcpProxy::extract_sni(&buf), None);
    }

    #[test]
    fn extract_sni_empty_buffer() {
        assert_eq!(TcpProxy::extract_sni(&[]), None);
    }

    #[test]
    fn extract_sni_tls_record_header_only() {
        // 5 bytes: valid TLS record header but handshake_len says more data
        // than is present.
        let buf = [0x16, 0x03, 0x01, 0x00, 0x50]; // claims 80 bytes follow
        assert_eq!(TcpProxy::extract_sni(&buf), None);
    }

    #[test]
    fn extract_sni_wrong_handshake_type() {
        // Build a valid-looking TLS record but with handshake type 0x02
        // (ServerHello) instead of 0x01 (ClientHello).
        let mut buf = build_client_hello_with_sni("example.com");
        // The handshake type byte is at offset 5 (right after 5-byte record header).
        buf[5] = 0x02;
        assert_eq!(TcpProxy::extract_sni(&buf), None);
    }

    #[test]
    fn extract_sni_not_tls_content_type() {
        // Content type 0x17 = Application Data, not Handshake (0x16)
        let buf = [0x17, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(TcpProxy::extract_sni(&buf), None);
    }

    // ── Connection limiting tests ─────────────────────────────────────

    #[test]
    fn try_acquire_unlimited_always_allows() {
        let proxy = TcpProxy::new(make_config(vec!["a:80"], 0));
        // Should always succeed when max_connections = 0
        for _ in 0..100 {
            assert!(proxy.try_acquire_connection());
        }
    }

    #[test]
    fn try_acquire_respects_limit() {
        let proxy = TcpProxy::new(make_config(vec!["a:80"], 2));
        assert!(proxy.try_acquire_connection()); // 1st
        assert!(proxy.try_acquire_connection()); // 2nd
        assert!(!proxy.try_acquire_connection()); // 3rd — rejected
    }

    #[test]
    fn release_allows_new_connection() {
        let proxy = TcpProxy::new(make_config(vec!["a:80"], 2));
        assert!(proxy.try_acquire_connection());
        assert!(proxy.try_acquire_connection());
        assert!(!proxy.try_acquire_connection()); // full

        proxy.release_connection(); // free one slot
        assert!(proxy.try_acquire_connection()); // should succeed now
        assert!(!proxy.try_acquire_connection()); // full again
    }

    #[test]
    fn concurrent_acquire_release_correct_count() {
        use std::sync::Arc;
        use std::thread;

        let proxy = Arc::new(TcpProxy::new(make_config(vec!["a:80"], 0)));
        let mut handles = vec![];

        // Spawn threads that each acquire, then release
        for _ in 0..50 {
            let p = Arc::clone(&proxy);
            handles.push(thread::spawn(move || {
                assert!(p.try_acquire_connection());
                // Simulate work
                thread::yield_now();
                p.release_connection();
            }));
        }
        for h in handles {
            assert!(h.join().is_ok(), "thread panicked");
        }

        // All connections released — counter should be back to 0
        assert_eq!(
            proxy
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    // ── Select target edge cases ──────────────────────────────────────

    #[test]
    fn select_target_sni_route_round_robin() {
        let mut sni_routes = std::collections::HashMap::new();
        sni_routes.insert(
            "db.example.com".to_string(),
            vec![
                "db1:3306".to_string(),
                "db2:3306".to_string(),
                "db3:3306".to_string(),
            ],
        );
        let config = TcpServiceConfig {
            listen: "0.0.0.0:3306".to_string(),
            targets: vec!["default:3306".to_string()],
            sni_routes,
            connect_timeout: "5s".to_string(),
            proxy_protocol: false,
            max_connections: 0,
        };
        let proxy = TcpProxy::new(config);
        assert_eq!(
            proxy.select_target(Some("db.example.com")),
            Some("db1:3306".to_string())
        );
        assert_eq!(
            proxy.select_target(Some("db.example.com")),
            Some("db2:3306".to_string())
        );
        assert_eq!(
            proxy.select_target(Some("db.example.com")),
            Some("db3:3306".to_string())
        );
        // Wraps around
        assert_eq!(
            proxy.select_target(Some("db.example.com")),
            Some("db1:3306".to_string())
        );
    }

    #[test]
    fn select_target_sni_route_empty_targets_falls_through() {
        let mut sni_routes = std::collections::HashMap::new();
        sni_routes.insert("empty.example.com".to_string(), vec![]);
        let config = TcpServiceConfig {
            listen: "0.0.0.0:443".to_string(),
            targets: vec!["fallback:443".to_string()],
            sni_routes,
            connect_timeout: "5s".to_string(),
            proxy_protocol: false,
            max_connections: 0,
        };
        let proxy = TcpProxy::new(config);
        // Empty SNI route should fall through to default targets
        assert_eq!(
            proxy.select_target(Some("empty.example.com")),
            Some("fallback:443".to_string())
        );
    }

    #[test]
    fn select_target_single_default_always_same() {
        let proxy = TcpProxy::new(make_config(vec!["only:80"], 0));
        for _ in 0..10 {
            assert_eq!(proxy.select_target(None), Some("only:80".to_string()));
        }
    }

    // ── TcpProxy::new edge cases ─────────────────────────────────────

    #[test]
    fn new_parses_connect_timeout() {
        let mut config = make_config(vec!["a:80"], 0);
        config.connect_timeout = "10s".to_string();
        let proxy = TcpProxy::new(config);
        assert_eq!(proxy.connect_timeout, Duration::from_secs(10));
    }

    #[test]
    fn new_invalid_timeout_defaults_to_5s() {
        let mut config = make_config(vec!["a:80"], 0);
        config.connect_timeout = "invalid".to_string();
        let proxy = TcpProxy::new(config);
        assert_eq!(proxy.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn new_millisecond_timeout() {
        let mut config = make_config(vec!["a:80"], 0);
        config.connect_timeout = "500ms".to_string();
        let proxy = TcpProxy::new(config);
        assert_eq!(proxy.connect_timeout, Duration::from_millis(500));
    }

    // ── SNI extraction edge cases ────────────────────────────────────

    #[test]
    fn extract_sni_truncated_handshake_body() {
        // Valid TLS record header, but handshake body is too short (< 38 bytes)
        let mut buf = Vec::new();
        buf.push(0x16); // Handshake
        buf.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        let body_len = 10u16;
        buf.extend_from_slice(&body_len.to_be_bytes());
        buf.push(0x01); // ClientHello
        buf.push(0);
        buf.extend_from_slice(&7u16.to_be_bytes()); // 3-byte length
        // Only 7 bytes of body — way shorter than needed 38
        buf.extend_from_slice(&[0x03, 0x03, 0, 0, 0, 0, 0]);
        assert_eq!(TcpProxy::extract_sni(&buf), None);
    }

    #[test]
    fn extract_sni_with_non_zero_session_id() {
        // Build a ClientHello with a 32-byte session ID
        let hostname = "test.example.com";
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len();

        let sni_ext_data_len = 2 + 1 + 2 + name_len;
        let sni_ext_len = 4 + sni_ext_data_len;
        let extensions_len = 2 + sni_ext_len;
        let session_id_len: usize = 32;

        // version(2) + random(32) + session_id_len(1) + session_id(32)
        // + cipher_suites_len(2) + cipher(2) + comp_len(1) + comp(1) + extensions
        let handshake_body_len = 2 + 32 + 1 + session_id_len + 2 + 2 + 1 + 1 + extensions_len;
        let handshake_len = 1 + 3 + handshake_body_len;

        let mut buf = Vec::new();
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());

        buf.push(0x01); // ClientHello
        buf.push(0);
        buf.extend_from_slice(&(handshake_body_len as u16).to_be_bytes());

        buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        buf.extend_from_slice(&[0u8; 32]); // Random
        buf.push(session_id_len as u8); // Session ID length: 32
        buf.extend_from_slice(&[0xABu8; 32]); // Session ID data
        buf.extend_from_slice(&2u16.to_be_bytes()); // Cipher suites length
        buf.extend_from_slice(&[0x00, 0x2F]);
        buf.push(1); // Compression methods length
        buf.push(0);

        // Extensions
        buf.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // SNI type
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        buf.extend_from_slice(&((1 + 2 + name_len) as u16).to_be_bytes());
        buf.push(0x00); // hostname type
        buf.extend_from_slice(&(name_len as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        assert_eq!(
            TcpProxy::extract_sni(&buf),
            Some("test.example.com".to_string())
        );
    }

    #[test]
    fn extract_sni_with_non_sni_extension_before_sni() {
        // Build a ClientHello with a dummy extension before the SNI extension
        let hostname = "multi-ext.example.com";
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len();

        let sni_ext_data_len = 2 + 1 + 2 + name_len;
        let sni_ext_header_len = 4 + sni_ext_data_len;

        // Dummy extension (type 0x0010, 4 bytes of data)
        let dummy_ext_len = 4 + 4; // header(4) + data(4)

        let extensions_total = 2 + dummy_ext_len + sni_ext_header_len;
        let handshake_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + extensions_total;
        let handshake_len = 1 + 3 + handshake_body_len;

        let mut buf = Vec::new();
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());
        buf.push(0x01);
        buf.push(0);
        buf.extend_from_slice(&(handshake_body_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0); // session ID length
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x2F]);
        buf.push(1);
        buf.push(0);

        // Extensions total length
        buf.extend_from_slice(&((dummy_ext_len + sni_ext_header_len) as u16).to_be_bytes());

        // Dummy extension (type 0x0010 = supported_groups)
        buf.extend_from_slice(&[0x00, 0x10]); // type
        buf.extend_from_slice(&4u16.to_be_bytes()); // length
        buf.extend_from_slice(&[0x00, 0x17, 0x00, 0x18]); // data

        // SNI extension
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        buf.extend_from_slice(&((1 + 2 + name_len) as u16).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&(name_len as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        assert_eq!(
            TcpProxy::extract_sni(&buf),
            Some("multi-ext.example.com".to_string())
        );
    }

    // ── Connection management edge cases ─────────────────────────────

    #[test]
    fn max_connections_of_one() {
        let proxy = TcpProxy::new(make_config(vec!["a:80"], 1));
        assert!(proxy.try_acquire_connection());
        assert!(!proxy.try_acquire_connection());
        proxy.release_connection();
        assert!(proxy.try_acquire_connection());
    }

    #[test]
    fn release_below_zero_wraps() {
        // This tests the atomic behavior — releasing without acquiring
        // should underflow (wrapping). Just ensure it doesn't panic.
        let proxy = TcpProxy::new(make_config(vec!["a:80"], 0));
        proxy.release_connection();
        // Active connections wrapped to u32::MAX — acquire should still work
        // because max_connections is 0 (unlimited)
        assert!(proxy.try_acquire_connection());
    }

    // ── Select target with SNI + no default targets ──────────────────

    #[test]
    fn select_target_sni_match_no_default_targets() {
        let mut sni_routes = std::collections::HashMap::new();
        sni_routes.insert("api.example.com".to_string(), vec!["api:443".to_string()]);
        let config = TcpServiceConfig {
            listen: "0.0.0.0:443".to_string(),
            targets: vec![], // no default targets
            sni_routes,
            connect_timeout: "5s".to_string(),
            proxy_protocol: false,
            max_connections: 0,
        };
        let proxy = TcpProxy::new(config);
        // SNI match works
        assert_eq!(
            proxy.select_target(Some("api.example.com")),
            Some("api:443".to_string())
        );
        // No SNI match + no default targets = None
        assert_eq!(proxy.select_target(Some("other.com")), None);
        assert_eq!(proxy.select_target(None), None);
    }
}
