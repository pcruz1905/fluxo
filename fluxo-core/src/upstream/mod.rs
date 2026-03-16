//! Upstream management — groups, peer selection, and health tracking.

pub mod peer;

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during upstream operations.
#[derive(Debug, Error)]
pub enum UpstreamError {
    /// No healthy backends are available in the upstream group.
    #[error("no healthy backends in upstream '{0}'")]
    NoHealthyBackends(UpstreamName),

    /// An upstream address failed to parse.
    #[error("invalid upstream address '{address}': {reason}")]
    InvalidAddress {
        /// The address string that failed to parse.
        address: String,
        /// Why the address is invalid.
        reason: String,
    },

    /// An unknown load balancing strategy was specified.
    #[error("unknown load balancing strategy '{0}'. Valid: round_robin, random, fnv_hash, consistent_hash")]
    InvalidStrategy(String),
}

/// A named upstream group (e.g., "api-servers").
///
/// Newtype wrapper to prevent mixing upstream names with arbitrary strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UpstreamName(pub String);

impl fmt::Display for UpstreamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for UpstreamName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for UpstreamName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}
