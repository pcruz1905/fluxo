//! DNS provider abstraction for ACME DNS-01 challenges.
//!
//! Supports creating and cleaning up TXT records for domain validation.
//! Currently implements: Cloudflare API.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Errors from DNS provider operations.
#[derive(Debug, thiserror::Error)]
pub enum DnsProviderError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error: {0}")]
    Api(String),

    #[error("unknown provider: {0}")]
    UnknownProvider(String),
}

/// DNS-01 challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcmeDnsConfig {
    /// DNS provider name: "cloudflare".
    pub provider: String,

    /// API token for the DNS provider.
    pub api_token: Option<String>,

    /// Cloudflare zone ID (optional — auto-detected from domain if omitted).
    pub zone_id: Option<String>,

    /// Propagation wait time before notifying ACME server. Default: "30s".
    #[serde(default = "default_propagation_wait")]
    pub propagation_wait: String,
}

fn default_propagation_wait() -> String {
    "30s".to_string()
}

/// Trait for DNS providers that can manage TXT records.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create a TXT record for the ACME DNS-01 challenge.
    ///
    /// - `domain`: the domain being validated (e.g., "example.com")
    /// - `record_name`: full record name (e.g., "_acme-challenge.example.com")
    /// - `record_value`: the TXT record content (base64url-encoded key authorization hash)
    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        record_value: &str,
    ) -> Result<String, DnsProviderError>;

    /// Remove the TXT record after validation completes.
    async fn delete_txt_record(&self, record_id: &str) -> Result<(), DnsProviderError>;
}

/// Create a DNS provider from config.
pub fn create_provider(config: &AcmeDnsConfig) -> Result<Box<dyn DnsProvider>, DnsProviderError> {
    match config.provider.as_str() {
        "cloudflare" => {
            let token = config
                .api_token
                .as_deref()
                .ok_or_else(|| DnsProviderError::Api("cloudflare requires api_token".into()))?;
            Ok(Box::new(CloudflareProvider::new(
                token,
                config.zone_id.clone(),
            )))
        }
        other => Err(DnsProviderError::UnknownProvider(other.to_string())),
    }
}

/// Cloudflare DNS provider.
pub struct CloudflareProvider {
    client: reqwest::Client,
    zone_id: Option<String>,
}

impl CloudflareProvider {
    fn new(api_token: &str, zone_id: Option<String>) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {api_token}")) {
            headers.insert(reqwest::header::AUTHORIZATION, val);
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self { client, zone_id }
    }

    /// Auto-detect the Cloudflare zone ID for a domain.
    async fn resolve_zone_id(&self, domain: &str) -> Result<String, DnsProviderError> {
        if let Some(ref zone_id) = self.zone_id {
            return Ok(zone_id.clone());
        }

        // Try progressively shorter domain suffixes to find the zone
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 0..parts.len().saturating_sub(1) {
            let candidate = parts[i..].join(".");
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones?name={candidate}&status=active"
            );

            let resp: CloudflareResponse<Vec<CloudflareZone>> =
                self.client.get(&url).send().await?.json().await?;

            if resp.success {
                if let Some(zone) = resp.result.as_deref().and_then(<[CloudflareZone]>::first) {
                    debug!(
                        zone_id = zone.id,
                        zone_name = zone.name,
                        "resolved Cloudflare zone"
                    );
                    return Ok(zone.id.clone());
                }
            }
        }

        Err(DnsProviderError::Api(format!(
            "could not find Cloudflare zone for domain: {domain}"
        )))
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        record_value: &str,
    ) -> Result<String, DnsProviderError> {
        let zone_id = self.resolve_zone_id(domain).await?;

        let url = format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records");

        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": record_value,
            "ttl": 120
        });

        let resp: CloudflareResponse<CloudflareDnsRecord> = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            let errors: Vec<String> = resp.errors.iter().map(|e| e.message.clone()).collect();
            return Err(DnsProviderError::Api(format!(
                "Cloudflare create TXT failed: {}",
                errors.join(", ")
            )));
        }

        let raw_id = resp.result.map(|r| r.id).unwrap_or_default();

        // Encode zone_id:record_id so delete_txt_record can extract both
        let composite_id = format!("{zone_id}:{raw_id}");

        debug!(
            record_id = raw_id,
            record_name, "created Cloudflare TXT record"
        );

        Ok(composite_id)
    }

    async fn delete_txt_record(&self, record_id: &str) -> Result<(), DnsProviderError> {
        // We need the zone_id to delete. Store it from the create call.
        // For simplicity, parse it from the record_id format or re-resolve.
        // Cloudflare record IDs are globally unique, but the API requires zone_id.
        // We'll encode zone_id:record_id in the returned record_id.
        let parts: Vec<&str> = record_id.splitn(2, ':').collect();
        let (zone_id, real_record_id) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            warn!(
                record_id,
                "cannot delete TXT record — missing zone_id prefix"
            );
            return Ok(());
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{real_record_id}"
        );

        let resp = self.client.delete(&url).send().await?;
        if resp.status().is_success() {
            debug!(record_id = real_record_id, "deleted Cloudflare TXT record");
        } else {
            warn!(
                status = %resp.status(),
                "failed to delete Cloudflare TXT record"
            );
        }

        Ok(())
    }
}

// -- Cloudflare API types --

#[derive(Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<CloudflareError>,
}

#[derive(Deserialize)]
struct CloudflareError {
    message: String,
}

#[derive(Deserialize)]
struct CloudflareZone {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct CloudflareDnsRecord {
    id: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn unknown_provider_error() {
        let config = AcmeDnsConfig {
            provider: "unknown".to_string(),
            api_token: None,
            zone_id: None,
            propagation_wait: "30s".to_string(),
        };
        let result = create_provider(&config);
        let err = result.err().unwrap();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn cloudflare_requires_token() {
        let config = AcmeDnsConfig {
            provider: "cloudflare".to_string(),
            api_token: None,
            zone_id: None,
            propagation_wait: "30s".to_string(),
        };
        let result = create_provider(&config);
        assert!(result.err().unwrap().to_string().contains("api_token"));
    }

    #[test]
    fn cloudflare_provider_with_token() {
        let config = AcmeDnsConfig {
            provider: "cloudflare".to_string(),
            api_token: Some("test-token".to_string()),
            zone_id: Some("zone123".to_string()),
            propagation_wait: "30s".to_string(),
        };
        assert!(create_provider(&config).is_ok());
    }

    #[test]
    fn default_propagation_wait() {
        let config = AcmeDnsConfig::default();
        assert_eq!(config.propagation_wait, "");
        // When deserialized with serde default, it would be "30s"
    }

    #[test]
    fn dns_provider_error_display() {
        let err = DnsProviderError::Api("test error".into());
        assert!(err.to_string().contains("test error"));

        let err = DnsProviderError::UnknownProvider("foo".into());
        assert!(err.to_string().contains("foo"));
    }
}
