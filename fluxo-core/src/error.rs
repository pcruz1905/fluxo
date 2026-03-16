//! Error types for the fluxo-core crate.
//!
//! Each module defines its own error type. `FluxoError` composes them
//! via `#[from]` for automatic conversion when errors bubble up.

use thiserror::Error;

use crate::config::ConfigError;
use crate::routing::RoutingError;
use crate::upstream::UpstreamError;

/// Top-level error type for fluxo-core operations.
#[derive(Debug, Error)]
pub enum FluxoError {
    /// Configuration error (parsing, validation, I/O).
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Routing error (invalid patterns).
    #[error("routing error: {0}")]
    Routing(#[from] RoutingError),

    /// Upstream error (no backends, invalid addresses).
    #[error("upstream error: {0}")]
    Upstream(#[from] UpstreamError),

    /// Error from Pingora internals.
    #[error("pingora error: {0}")]
    Pingora(#[from] Box<pingora_core::Error>),
}
