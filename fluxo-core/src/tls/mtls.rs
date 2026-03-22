//! Mutual TLS — client certificate verification.
//!
//! Validates client certificates against a CA certificate pool.
//! Traefik-inspired: supports multiple auth types (none, request, require, verify).

use std::path::Path;
use std::str::FromStr;

/// Client authentication mode for mTLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthType {
    /// No client certificate requested.
    None,
    /// Client certificate requested but not required.
    Request,
    /// Client certificate required but not validated against CA.
    Require,
    /// Client certificate required and must be valid against the CA pool.
    Verify,
}

impl FromStr for ClientAuthType {
    type Err = String;

    /// Parse from config string (case-insensitive).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "request" => Ok(Self::Request),
            "require" => Ok(Self::Require),
            "verify" | "require_and_verify" => Ok(Self::Verify),
            other => Err(format!(
                "unknown client auth type: '{other}' (valid: none, request, require, verify)"
            )),
        }
    }
}

/// Parsed mTLS configuration ready for use.
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// Client authentication mode.
    pub auth_type: ClientAuthType,
    /// Path to CA certificate file (PEM format).
    pub ca_path: Option<String>,
}

impl MtlsConfig {
    /// Build from TLS config values. Validates that CA path is provided when needed.
    pub fn build(client_auth_type: &str, client_ca_path: Option<&str>) -> Result<Self, String> {
        let auth_type: ClientAuthType = client_auth_type.parse()?;

        // Verify CA path is provided for verify mode
        if auth_type == ClientAuthType::Verify && client_ca_path.is_none() {
            return Err(
                "client_ca_path is required when client_auth_type is 'verify'".to_string(),
            );
        }

        // Verify CA file exists if provided
        if let Some(path) = client_ca_path {
            if !Path::new(path).exists() {
                return Err(format!("client CA certificate file not found: {path}"));
            }
        }

        Ok(Self {
            auth_type,
            ca_path: client_ca_path.map(String::from),
        })
    }

    /// Whether mTLS is active (anything other than None).
    pub fn is_active(&self) -> bool {
        self.auth_type != ClientAuthType::None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parse_auth_type_none() {
        assert_eq!(
            "none".parse::<ClientAuthType>().unwrap(),
            ClientAuthType::None
        );
    }

    #[test]
    fn parse_auth_type_request() {
        assert_eq!(
            "request".parse::<ClientAuthType>().unwrap(),
            ClientAuthType::Request
        );
    }

    #[test]
    fn parse_auth_type_require() {
        assert_eq!(
            "require".parse::<ClientAuthType>().unwrap(),
            ClientAuthType::Require
        );
    }

    #[test]
    fn parse_auth_type_verify() {
        assert_eq!(
            "verify".parse::<ClientAuthType>().unwrap(),
            ClientAuthType::Verify
        );
    }

    #[test]
    fn parse_auth_type_case_insensitive() {
        assert_eq!(
            "VERIFY".parse::<ClientAuthType>().unwrap(),
            ClientAuthType::Verify
        );
        assert_eq!(
            "Request".parse::<ClientAuthType>().unwrap(),
            ClientAuthType::Request
        );
    }

    #[test]
    fn parse_auth_type_unknown() {
        assert!("unknown".parse::<ClientAuthType>().is_err());
    }

    #[test]
    fn build_none_without_ca() {
        let cfg = MtlsConfig::build("none", None).unwrap();
        assert!(!cfg.is_active());
    }

    #[test]
    fn build_verify_without_ca_fails() {
        let err = MtlsConfig::build("verify", None).unwrap_err();
        assert!(err.contains("client_ca_path is required"));
    }

    #[test]
    fn build_require_without_ca_ok() {
        // require doesn't need CA (cert required but not validated)
        let cfg = MtlsConfig::build("require", None).unwrap();
        assert!(cfg.is_active());
    }

    #[test]
    fn parse_require_and_verify_alias() {
        assert_eq!(
            "require_and_verify".parse::<ClientAuthType>().unwrap(),
            ClientAuthType::Verify
        );
    }
}
