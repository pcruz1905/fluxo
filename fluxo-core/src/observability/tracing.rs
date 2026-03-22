//! OpenTelemetry tracing integration.
//!
//! Provides distributed tracing via OpenTelemetry with OTLP export.
//! Traefik equivalent: native OTLP tracing with W3C trace context propagation.
//!
//! Spans are created at three levels:
//! - Entry point (server span): incoming request
//! - Router (internal span): routing decision
//! - Upstream (client span): outgoing request to backend

use serde::{Deserialize, Serialize};

/// OpenTelemetry tracing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelTracingConfig {
    /// Whether tracing is enabled. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// OTLP endpoint (e.g., `http://localhost:4318` for HTTP, `http://localhost:4317` for gRPC).
    #[serde(default = "default_otlp_endpoint")]
    pub endpoint: String,

    /// Export protocol: "http" or "grpc". Default: "http".
    #[serde(default = "default_otlp_protocol")]
    pub protocol: String,

    /// Service name reported in traces. Default: "fluxo".
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Sampling rate (0.0 - 1.0). Default: 1.0 (sample everything).
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,

    /// Additional resource attributes (key=value pairs).
    #[serde(default)]
    pub resource_attributes: std::collections::HashMap<String, String>,

    /// Request headers to capture in spans.
    #[serde(default)]
    pub captured_request_headers: Vec<String>,

    /// Response headers to capture in spans.
    #[serde(default)]
    pub captured_response_headers: Vec<String>,
}

fn default_otlp_endpoint() -> String {
    "http://localhost:4318".to_string()
}

fn default_otlp_protocol() -> String {
    "http".to_string()
}

fn default_service_name() -> String {
    "fluxo".to_string()
}

fn default_sample_rate() -> f64 {
    1.0
}

impl Default for OtelTracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otlp_endpoint(),
            protocol: default_otlp_protocol(),
            service_name: default_service_name(),
            sample_rate: default_sample_rate(),
            resource_attributes: std::collections::HashMap::new(),
            captured_request_headers: Vec::new(),
            captured_response_headers: Vec::new(),
        }
    }
}

/// Trace context extracted from incoming request headers.
/// Supports W3C Trace Context (`traceparent` / `tracestate` headers).
#[derive(Debug, Clone, Default)]
pub struct TraceContext {
    /// W3C traceparent header value.
    pub traceparent: Option<String>,
    /// W3C tracestate header value.
    pub tracestate: Option<String>,
}

impl TraceContext {
    /// Extract trace context from request headers.
    pub fn from_headers(headers: &pingora_http::RequestHeader) -> Self {
        Self {
            traceparent: headers
                .headers
                .get("traceparent")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            tracestate: headers
                .headers
                .get("tracestate")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
        }
    }

    /// Inject trace context into upstream request headers.
    pub fn inject_into(&self, headers: &mut pingora_http::RequestHeader) {
        if let Some(tp) = &self.traceparent {
            let _ = headers.insert_header("traceparent", tp);
        }
        if let Some(ts) = &self.tracestate {
            let _ = headers.insert_header("tracestate", ts);
        }
    }

    /// Whether any trace context is present.
    pub fn is_active(&self) -> bool {
        self.traceparent.is_some()
    }
}

/// Parse a W3C traceparent header into its components.
/// Format: `{version}-{trace_id}-{parent_id}-{trace_flags}`
/// Example: `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`
#[derive(Debug, Clone)]
pub struct ParsedTraceparent {
    pub version: String,
    pub trace_id: String,
    pub parent_id: String,
    pub trace_flags: String,
}

impl ParsedTraceparent {
    /// Parse a traceparent string.
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        // Validate lengths: version=2, trace_id=32, parent_id=16, flags=2
        if parts[0].len() != 2 || parts[1].len() != 32 || parts[2].len() != 16 || parts[3].len() != 2 {
            return None;
        }

        Some(Self {
            version: parts[0].to_string(),
            trace_id: parts[1].to_string(),
            parent_id: parts[2].to_string(),
            trace_flags: parts[3].to_string(),
        })
    }

    /// Whether this trace is sampled (flags bit 0 set).
    pub fn is_sampled(&self) -> bool {
        u8::from_str_radix(&self.trace_flags, 16)
            .map(|f| f & 0x01 != 0)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn default_config() {
        let cfg = OtelTracingConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoint, "http://localhost:4318");
        assert_eq!(cfg.service_name, "fluxo");
        assert!((cfg.sample_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_traceparent_valid() {
        let tp = ParsedTraceparent::parse(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .unwrap();
        assert_eq!(tp.version, "00");
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(tp.parent_id, "00f067aa0ba902b7");
        assert_eq!(tp.trace_flags, "01");
        assert!(tp.is_sampled());
    }

    #[test]
    fn parse_traceparent_not_sampled() {
        let tp = ParsedTraceparent::parse(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
        )
        .unwrap();
        assert!(!tp.is_sampled());
    }

    #[test]
    fn parse_traceparent_invalid() {
        assert!(ParsedTraceparent::parse("invalid").is_none());
        assert!(ParsedTraceparent::parse("00-short-00f067aa0ba902b7-01").is_none());
        assert!(ParsedTraceparent::parse("").is_none());
    }

    #[test]
    fn trace_context_extract_inject() {
        let mut req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .unwrap();
        req.insert_header("tracestate", "congo=t61rcWkgMzE").unwrap();

        let ctx = TraceContext::from_headers(&req);
        assert!(ctx.is_active());
        assert!(ctx.traceparent.as_ref().unwrap().contains("4bf92f35"));

        // Inject into a new request
        let mut upstream_req = pingora_http::RequestHeader::build("GET", b"/api", None).unwrap();
        ctx.inject_into(&mut upstream_req);
        assert!(upstream_req.headers.get("traceparent").is_some());
        assert!(upstream_req.headers.get("tracestate").is_some());
    }

    #[test]
    fn trace_context_empty() {
        let req = pingora_http::RequestHeader::build("GET", b"/", None).unwrap();
        let ctx = TraceContext::from_headers(&req);
        assert!(!ctx.is_active());
    }

    #[test]
    fn config_deserialize() {
        let json = serde_json::json!({
            "enabled": true,
            "endpoint": "http://otel:4317",
            "protocol": "grpc",
            "service_name": "my-proxy",
            "sample_rate": 0.5,
            "resource_attributes": {"env": "prod"},
            "captured_request_headers": ["X-Request-ID"],
        });
        let cfg: OtelTracingConfig = serde_json::from_value(json).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoint, "http://otel:4317");
        assert_eq!(cfg.protocol, "grpc");
        assert_eq!(cfg.service_name, "my-proxy");
        assert!((cfg.sample_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(cfg.resource_attributes.get("env").unwrap(), "prod");
        assert_eq!(cfg.captured_request_headers, vec!["X-Request-ID"]);
    }
}
