//! Upstream management — groups, peer selection, and health tracking.

pub mod circuit_breaker;
pub mod peer;

use std::fmt;
use std::sync::Arc;

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
    #[error(
        "unknown load balancing strategy '{0}'. Valid: round_robin, random, fnv_hash, consistent_hash"
    )]
    InvalidStrategy(String),
}

/// A named upstream group (e.g., "api-servers").
///
/// Newtype wrapper using `Arc<str>` for zero-cost cloning on the hot path.
/// Cloning an `UpstreamName` is a refcount bump, not a heap allocation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamName(pub Arc<str>);

impl fmt::Display for UpstreamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for UpstreamName {
    fn from(s: String) -> Self {
        Self(Arc::from(s.as_str()))
    }
}

impl From<&str> for UpstreamName {
    fn from(s: &str) -> Self {
        Self(Arc::from(s))
    }
}

impl Serialize for UpstreamName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UpstreamName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from(s))
    }
}
