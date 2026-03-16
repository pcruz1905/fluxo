//! Configuration system — TOML parsing, validation, defaults, and merging.

mod defaults;
mod types;

pub use types::*;

use thiserror::Error;

/// Errors that can occur during configuration loading and validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read the config file from disk.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse TOML content.
    #[error("failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),

    /// Semantic validation failed.
    #[error("validation error: {0}")]
    Validation(String),

    /// A route references an upstream that doesn't exist.
    #[error("unknown upstream '{0}' referenced in route")]
    UnknownUpstream(String),
}
