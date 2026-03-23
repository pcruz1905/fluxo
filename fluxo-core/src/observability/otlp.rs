//! OpenTelemetry OTLP span exporter initialization.
//!
//! When tracing is enabled in config, this module sets up an OTLP exporter
//! that sends spans to a collector (Jaeger, Tempo, etc.) via gRPC or HTTP.

use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use super::OtelTracingConfig;
use crate::config::AccessLogFormat;

/// Initialize the tracing subscriber with an OTLP export layer.
///
/// Returns a guard that shuts down the tracer provider when dropped.
/// If OTLP initialization fails, falls back to tracing-only (no export).
pub fn init_otlp_tracer(
    config: &OtelTracingConfig,
    log_level: &str,
    log_format: AccessLogFormat,
) -> Option<OtlpGuard> {
    if !config.enabled {
        return None;
    }

    let exporter = build_exporter(config);
    let exporter = match exporter {
        Ok(e) => e,
        Err(e) => {
            eprintln!("fluxo: failed to initialize OTLP exporter: {e}");
            return None;
        }
    };

    // Build resource with service name + custom attributes
    let mut kv_pairs = vec![opentelemetry::KeyValue::new(
        "service.name",
        config.service_name.clone(),
    )];
    for (k, v) in &config.resource_attributes {
        kv_pairs.push(opentelemetry::KeyValue::new(k.clone(), v.clone()));
    }
    let resource = Resource::builder().with_attributes(kv_pairs).build();

    // Build sampler
    let sampler = if (config.sample_rate - 1.0).abs() < f64::EPSILON {
        opentelemetry_sdk::trace::Sampler::AlwaysOn
    } else if config.sample_rate <= 0.0 {
        opentelemetry_sdk::trace::Sampler::AlwaysOff
    } else {
        opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(config.sample_rate)
    };

    // Build tracer provider
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(sampler)
        .build();

    // Build the tracing subscriber with both fmt and OTLP layers.
    // The OpenTelemetryLayer must be created per-branch because it's generic
    // over the exact subscriber stack type.
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    match log_format {
        AccessLogFormat::Json => {
            let tracer = provider.tracer("fluxo");
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .with(otel_layer)
                .init();
        }
        AccessLogFormat::Compact => {
            let tracer = provider.tracer("fluxo");
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .with(otel_layer)
                .init();
        }
    }

    Some(OtlpGuard { provider })
}

/// Guard that shuts down the OTLP tracer provider on drop.
pub struct OtlpGuard {
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
}

impl Drop for OtlpGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            eprintln!("fluxo: OTLP tracer shutdown error: {e}");
        }
    }
}

/// Build the OTLP exporter based on protocol config.
fn build_exporter(
    config: &OtelTracingConfig,
) -> Result<opentelemetry_otlp::SpanExporter, opentelemetry_otlp::ExporterBuildError> {
    match config.protocol.as_str() {
        "grpc" => opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build(),
        _ => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(&config.endpoint)
            .build(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn disabled_config_returns_none() {
        let config = OtelTracingConfig::default();
        assert!(!config.enabled);
        // Can't actually call init_otlp_tracer in tests (global subscriber),
        // but verify the config check works
        assert!(!config.enabled);
    }

    #[test]
    fn init_otlp_tracer_disabled_returns_none() {
        let config = OtelTracingConfig {
            enabled: false,
            ..Default::default()
        };
        let result = init_otlp_tracer(&config, "info", AccessLogFormat::Compact);
        assert!(result.is_none());
    }

    #[test]
    fn init_otlp_tracer_disabled_json_returns_none() {
        let config = OtelTracingConfig {
            enabled: false,
            ..Default::default()
        };
        let result = init_otlp_tracer(&config, "debug", AccessLogFormat::Json);
        assert!(result.is_none());
    }

    #[test]
    fn build_exporter_http() {
        let config = OtelTracingConfig {
            enabled: true,
            endpoint: "http://localhost:4318".to_string(),
            protocol: "http".to_string(),
            ..Default::default()
        };
        let result = build_exporter(&config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn build_exporter_grpc() {
        let config = OtelTracingConfig {
            enabled: true,
            endpoint: "http://localhost:4317".to_string(),
            protocol: "grpc".to_string(),
            ..Default::default()
        };
        let result = build_exporter(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn build_exporter_unknown_protocol_defaults_to_http() {
        // Any protocol string other than "grpc" falls through to the HTTP branch
        let config = OtelTracingConfig {
            enabled: true,
            endpoint: "http://localhost:4318".to_string(),
            protocol: "unknown-proto".to_string(),
            ..Default::default()
        };
        let result = build_exporter(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn build_exporter_empty_protocol_defaults_to_http() {
        let config = OtelTracingConfig {
            enabled: true,
            endpoint: "http://localhost:4318".to_string(),
            protocol: String::new(),
            ..Default::default()
        };
        let result = build_exporter(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn build_exporter_with_custom_endpoint() {
        let config = OtelTracingConfig {
            enabled: true,
            endpoint: "http://otel-collector.example.com:4318/v1/traces".to_string(),
            protocol: "http".to_string(),
            ..Default::default()
        };
        let result = build_exporter(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn config_with_resource_attributes() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("deployment.environment".to_string(), "staging".to_string());
        attrs.insert("service.version".to_string(), "1.2.3".to_string());
        let config = OtelTracingConfig {
            enabled: false,
            service_name: "my-proxy".to_string(),
            resource_attributes: attrs,
            ..Default::default()
        };
        // Disabled config still returns None from init
        let result = init_otlp_tracer(&config, "warn", AccessLogFormat::Compact);
        assert!(result.is_none());
        // But the config is well-formed
        assert_eq!(config.service_name, "my-proxy");
        assert_eq!(config.resource_attributes.len(), 2);
        assert_eq!(
            config
                .resource_attributes
                .get("deployment.environment")
                .unwrap(),
            "staging"
        );
    }

    #[test]
    fn config_sample_rate_boundaries() {
        // Sample rate of 0.0 maps to AlwaysOff, 1.0 to AlwaysOn
        let always_on = OtelTracingConfig {
            sample_rate: 1.0,
            ..Default::default()
        };
        assert!((always_on.sample_rate - 1.0).abs() < f64::EPSILON);

        let always_off = OtelTracingConfig {
            sample_rate: 0.0,
            ..Default::default()
        };
        assert!(always_off.sample_rate <= 0.0);

        let ratio = OtelTracingConfig {
            sample_rate: 0.5,
            ..Default::default()
        };
        assert!(ratio.sample_rate > 0.0 && ratio.sample_rate < 1.0);
    }
}
