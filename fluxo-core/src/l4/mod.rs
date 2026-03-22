//! Layer 4 (TCP/UDP) proxy module.
//!
//! Provides transparent TCP proxying with optional SNI-based routing.
//! Nginx equivalent: `stream {}` block.
//! Traefik equivalent: TCP/UDP routers.

pub mod config;
pub mod proxy;

pub use config::L4Config;
pub use proxy::TcpProxy;
