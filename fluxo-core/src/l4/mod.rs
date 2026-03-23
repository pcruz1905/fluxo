//! Layer 4 (TCP/UDP) proxy module.
//!
//! Provides transparent TCP and UDP proxying with optional SNI-based routing,
//! FastCGI proxying, and mail protocol proxying (SMTP/IMAP/POP3).
//! Nginx equivalent: `stream {}` + `mail {}` blocks.
//! Traefik equivalent: TCP/UDP routers.

pub mod config;
pub mod fastcgi;
pub mod mail_proxy;
pub mod proxy;
pub mod udp_proxy;

pub use config::L4Config;
pub use fastcgi::FastCgiConfig;
pub use mail_proxy::{MailProxy, MailProxyConfig};
pub use proxy::TcpProxy;
pub use udp_proxy::UdpProxy;
