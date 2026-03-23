//! Mail proxy — transparent proxying for SMTP, IMAP, and POP3 protocols.
//!
//! Nginx equivalent: `mail {}` block.
//! Provides L4 proxying with protocol-aware greeting handling and optional
//! STARTTLS interception for mail protocols.
//!
//! Supported protocols:
//! - SMTP (port 25, 465, 587) — email submission/relay
//! - IMAP (port 143, 993) — mailbox access
//! - POP3 (port 110, 995) — mailbox retrieval

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Mail protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailProtocol {
    /// SMTP (Simple Mail Transfer Protocol).
    Smtp,
    /// IMAP (Internet Message Access Protocol).
    Imap,
    /// POP3 (Post Office Protocol).
    Pop3,
}

impl MailProtocol {
    /// Default greeting banner for this protocol.
    fn default_greeting(&self, hostname: &str) -> String {
        match self {
            Self::Smtp => format!("220 {hostname} ESMTP fluxo mail proxy\r\n"),
            Self::Imap => format!("* OK [{hostname}] fluxo IMAP proxy ready\r\n"),
            Self::Pop3 => format!("+OK {hostname} fluxo POP3 proxy ready\r\n"),
        }
    }
}

/// Configuration for a mail proxy service.
#[derive(Debug, Clone, Deserialize)]
pub struct MailProxyConfig {
    /// Listen address (e.g., "0.0.0.0:25" for SMTP).
    pub listen: String,

    /// Mail protocol: smtp, imap, or pop3.
    pub protocol: MailProtocol,

    /// Upstream mail server targets (address:port).
    pub targets: Vec<String>,

    /// Server hostname used in protocol greetings.
    #[serde(default = "default_hostname")]
    pub hostname: String,

    /// Connection timeout to upstream. Default: "10s".
    #[serde(default = "default_mail_timeout")]
    pub connect_timeout: String,

    /// Maximum concurrent connections. 0 = unlimited.
    #[serde(default)]
    pub max_connections: u32,

    /// Whether to replace the upstream greeting with our own. Default: true.
    /// When true, the proxy sends its own greeting before connecting upstream.
    /// When false, the upstream greeting is forwarded to the client.
    #[serde(default = "default_replace_greeting")]
    pub replace_greeting: bool,
}

fn default_hostname() -> String {
    "localhost".to_string()
}

fn default_mail_timeout() -> String {
    "10s".to_string()
}

fn default_replace_greeting() -> bool {
    true
}

/// A running mail proxy service.
pub struct MailProxy {
    config: MailProxyConfig,
    connect_timeout: Duration,
    next_target: std::sync::atomic::AtomicUsize,
    active_connections: std::sync::atomic::AtomicU32,
}

impl MailProxy {
    pub fn new(config: MailProxyConfig) -> Self {
        let connect_timeout = crate::config::parse_duration(&config.connect_timeout)
            .unwrap_or(Duration::from_secs(10));
        Self {
            config,
            connect_timeout,
            next_target: std::sync::atomic::AtomicUsize::new(0),
            active_connections: std::sync::atomic::AtomicU32::new(0),
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

    /// Check and acquire a connection slot.
    fn try_acquire_connection(&self) -> bool {
        let max = self.config.max_connections;
        if max == 0 {
            self.active_connections
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }
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

    /// Handle a single mail proxy connection.
    async fn handle_connection(
        self: &Arc<Self>,
        mut downstream: TcpStream,
        client_addr: SocketAddr,
    ) -> io::Result<()> {
        let Some(target) = self.select_target() else {
            warn!(client = %client_addr, "no mail upstream target available");
            return Ok(());
        };

        debug!(
            client = %client_addr,
            target,
            protocol = ?self.config.protocol,
            "mail proxy connecting"
        );

        // Connect to upstream
        let mut upstream =
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(target)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    warn!(target, error = %e, "mail upstream connect failed");
                    return Ok(());
                }
                Err(_) => {
                    warn!(target, "mail upstream connect timeout");
                    return Ok(());
                }
            };

        if self.config.replace_greeting {
            // Send our greeting to the client
            let greeting = self.config.protocol.default_greeting(&self.config.hostname);
            downstream.write_all(greeting.as_bytes()).await?;

            // Read and discard the upstream greeting
            let mut greeting_buf = vec![0u8; 4096];
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                upstream.read(&mut greeting_buf),
            )
            .await;
        }

        // After greeting, just do bidirectional byte copy (protocol-transparent)
        let (mut down_read, mut down_write) = downstream.into_split();
        let (mut up_read, mut up_write) = upstream.into_split();

        let client_to_server = tokio::io::copy(&mut down_read, &mut up_write);
        let server_to_client = tokio::io::copy(&mut up_read, &mut down_write);

        tokio::select! {
            result = client_to_server => {
                if let Err(e) = result {
                    debug!(error = %e, "mail client -> server copy ended");
                }
            }
            result = server_to_client => {
                if let Err(e) = result {
                    debug!(error = %e, "mail server -> client copy ended");
                }
            }
        }

        Ok(())
    }

    /// Start the mail proxy listener.
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let listener = TcpListener::bind(&self.config.listen).await?;
        info!(
            address = %self.config.listen,
            protocol = ?self.config.protocol,
            "mail proxy listening"
        );

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    if !self.try_acquire_connection() {
                        warn!(
                            client = %addr,
                            max = self.config.max_connections,
                            "mail proxy max connections reached"
                        );
                        drop(stream);
                        continue;
                    }
                    let proxy = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_connection(stream, addr).await {
                            error!(error = %e, "mail proxy connection error");
                        }
                        proxy.release_connection();
                    });
                }
                Err(e) => {
                    error!(error = %e, "mail proxy accept error");
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
        let config = MailProxyConfig {
            listen: "0.0.0.0:25".to_string(),
            protocol: MailProtocol::Smtp,
            targets: vec!["mx1:25".to_string(), "mx2:25".to_string()],
            hostname: "mail.example.com".to_string(),
            connect_timeout: "10s".to_string(),
            max_connections: 0,
            replace_greeting: true,
        };
        let proxy = MailProxy::new(config);
        assert_eq!(proxy.select_target(), Some("mx1:25"));
        assert_eq!(proxy.select_target(), Some("mx2:25"));
        assert_eq!(proxy.select_target(), Some("mx1:25"));
    }

    #[test]
    fn select_target_empty() {
        let config = MailProxyConfig {
            listen: "0.0.0.0:25".to_string(),
            protocol: MailProtocol::Smtp,
            targets: vec![],
            hostname: "mail.example.com".to_string(),
            connect_timeout: "10s".to_string(),
            max_connections: 0,
            replace_greeting: true,
        };
        let proxy = MailProxy::new(config);
        assert_eq!(proxy.select_target(), None);
    }

    #[test]
    fn smtp_greeting() {
        let greeting = MailProtocol::Smtp.default_greeting("mail.example.com");
        assert!(greeting.starts_with("220 "));
        assert!(greeting.contains("ESMTP"));
        assert!(greeting.ends_with("\r\n"));
    }

    #[test]
    fn imap_greeting() {
        let greeting = MailProtocol::Imap.default_greeting("imap.example.com");
        assert!(greeting.starts_with("* OK"));
        assert!(greeting.ends_with("\r\n"));
    }

    #[test]
    fn pop3_greeting() {
        let greeting = MailProtocol::Pop3.default_greeting("pop.example.com");
        assert!(greeting.starts_with("+OK"));
        assert!(greeting.ends_with("\r\n"));
    }

    #[test]
    fn parse_protocol_from_str() {
        let smtp: MailProtocol = serde_json::from_str(r#""smtp""#).unwrap();
        assert_eq!(smtp, MailProtocol::Smtp);
        let imap: MailProtocol = serde_json::from_str(r#""imap""#).unwrap();
        assert_eq!(imap, MailProtocol::Imap);
        let pop3: MailProtocol = serde_json::from_str(r#""pop3""#).unwrap();
        assert_eq!(pop3, MailProtocol::Pop3);
    }

    #[test]
    fn max_connections_enforcement() {
        let config = MailProxyConfig {
            listen: "0.0.0.0:25".to_string(),
            protocol: MailProtocol::Smtp,
            targets: vec!["mx:25".to_string()],
            hostname: "mail.example.com".to_string(),
            connect_timeout: "10s".to_string(),
            max_connections: 2,
            replace_greeting: true,
        };
        let proxy = MailProxy::new(config);
        assert!(proxy.try_acquire_connection()); // 1
        assert!(proxy.try_acquire_connection()); // 2
        assert!(!proxy.try_acquire_connection()); // 3 - rejected
        proxy.release_connection();
        assert!(proxy.try_acquire_connection()); // 2 again - ok
    }
}
