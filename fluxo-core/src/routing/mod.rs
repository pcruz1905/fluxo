//! Routing — route table compilation and request matching.

pub mod matcher;

use thiserror::Error;

/// Errors that can occur during route compilation.
#[derive(Debug, Error)]
pub enum RoutingError {
    /// An invalid glob pattern was specified.
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob {
        /// The pattern that failed to compile.
        pattern: String,
        /// The underlying glob error.
        source: glob::PatternError,
    },

    /// An invalid regex pattern was specified.
    #[error("invalid regex '{pattern}': {source}")]
    InvalidRegex {
        /// The pattern that failed to compile.
        pattern: String,
        /// The underlying regex error.
        source: regex::Error,
    },
}
