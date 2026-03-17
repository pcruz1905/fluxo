//! CORS plugin — Cross-Origin Resource Sharing headers.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    pub max_age: Option<u64>,
    #[serde(default)]
    pub allow_credentials: bool,
    #[serde(default)]
    pub expose_headers: Vec<String>,
}

#[derive(Debug)]
pub struct CorsPlugin {
    pub config: CorsConfig,
}

impl CorsPlugin {
    pub fn new(config: CorsConfig) -> Self {
        Self { config }
    }
}
