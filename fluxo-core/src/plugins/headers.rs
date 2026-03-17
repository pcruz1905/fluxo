//! Headers plugin — add, set, and remove request/response headers.

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub struct HeadersConfig {
    /// Headers to set on upstream requests.
    #[serde(default)]
    pub request_set: HashMap<String, String>,
    /// Headers to remove from upstream requests.
    #[serde(default)]
    pub request_remove: Vec<String>,
    /// Headers to set on downstream responses.
    #[serde(default)]
    pub response_set: HashMap<String, String>,
    /// Headers to remove from downstream responses.
    #[serde(default)]
    pub response_remove: Vec<String>,
}

#[derive(Debug)]
pub struct HeadersPlugin {
    pub config: HeadersConfig,
}

impl HeadersPlugin {
    pub fn new(config: HeadersConfig) -> Self {
        Self { config }
    }
}
