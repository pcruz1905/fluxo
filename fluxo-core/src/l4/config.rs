//! L4 proxy configuration types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level L4 proxy configuration (sits alongside HTTP services).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct L4Config {
    /// Named TCP services.
    #[serde(default)]
    pub tcp_services: HashMap<String, TcpServiceConfig>,
}

/// A TCP service — listens on an address and forwards to upstream targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpServiceConfig {
    /// Listen address (e.g., "0.0.0.0:3306" for `MySQL` proxy).
    pub listen: String,

    /// Upstream targets (address:port).
    pub targets: Vec<String>,

    /// SNI-based routing rules. When present, the TLS `ClientHello` SNI
    /// is inspected to route to different upstreams.
    /// Key: SNI hostname pattern, Value: upstream target addresses.
    #[serde(default)]
    pub sni_routes: HashMap<String, Vec<String>>,

    /// Connection timeout to upstream. Default: "5s".
    #[serde(default = "default_tcp_connect_timeout")]
    pub connect_timeout: String,

    /// Proxy protocol support (v1/v2). Default: false.
    #[serde(default)]
    pub proxy_protocol: bool,

    /// Maximum concurrent connections. 0 = unlimited.
    #[serde(default)]
    pub max_connections: u32,
}

fn default_tcp_connect_timeout() -> String {
    "5s".to_string()
}

/// Compiled TCP routing rule.
#[derive(Debug, Clone)]
pub struct CompiledTcpRoute {
    /// SNI hostname pattern (exact match or wildcard).
    pub sni_pattern: Option<String>,
    /// Target addresses.
    pub targets: Vec<String>,
}

impl L4Config {
    /// Whether any L4 services are configured.
    pub fn is_empty(&self) -> bool {
        self.tcp_services.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn empty_config() {
        let cfg = L4Config::default();
        assert!(cfg.is_empty());
    }

    #[test]
    fn parse_tcp_service() {
        let toml_str = r#"
            listen = "0.0.0.0:3306"
            targets = ["db1:3306", "db2:3306"]
            connect_timeout = "10s"
        "#;
        let cfg: TcpServiceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:3306");
        assert_eq!(cfg.targets.len(), 2);
        assert_eq!(cfg.connect_timeout, "10s");
        assert!(!cfg.proxy_protocol);
    }

    #[test]
    fn parse_sni_routes() {
        let toml_str = r#"
            listen = "0.0.0.0:443"
            targets = ["default:443"]
            [sni_routes]
            "api.example.com" = ["api:443"]
            "web.example.com" = ["web:443"]
        "#;
        let cfg: TcpServiceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.sni_routes.len(), 2);
        assert!(cfg.sni_routes.contains_key("api.example.com"));
    }

    #[test]
    fn default_values() {
        let toml_str = r#"
            listen = "0.0.0.0:5432"
            targets = ["pg:5432"]
        "#;
        let cfg: TcpServiceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.connect_timeout, "5s");
        assert!(!cfg.proxy_protocol);
        assert_eq!(cfg.max_connections, 0);
    }
}
