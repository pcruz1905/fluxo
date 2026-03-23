use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};

/// Shared metrics registry for the entire Fluxo process.
///
/// One instance is created at startup and shared (via Arc) across all
/// proxy callbacks. Metrics are updated in the `logging()` callback
/// after each request completes.
#[derive(Clone)]
pub struct MetricsRegistry {
    registry: Registry,
    requests_total: IntCounterVec,
    request_duration_seconds: HistogramVec,
    active_requests: IntGauge,
    bytes_sent_total: IntCounterVec,
    bytes_received_total: IntCounterVec,
    // Per-upstream metrics (Traefik-inspired: per-server observability wrapping)
    upstream_requests_total: IntCounterVec,
    upstream_duration_seconds: HistogramVec,
    upstream_errors_total: IntCounterVec,
    // Cache metrics (Pingora-native caching)
    cache_hits: prometheus::IntCounter,
    cache_misses: prometheus::IntCounter,
    cache_stale: prometheus::IntCounter,
}

impl MetricsRegistry {
    /// Create a new metrics registry with all Fluxo metrics pre-registered.
    pub fn new() -> Result<Self, String> {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("fluxo_requests_total", "Total number of processed requests"),
            &["service", "route", "method", "status"],
        )
        .map_err(|e| format!("metric creation failed: {e}"))?;

        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "fluxo_request_duration_seconds",
                "Request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["service", "route"],
        )
        .map_err(|e| format!("metric creation failed: {e}"))?;

        let active_requests = IntGauge::new(
            "fluxo_active_requests",
            "Number of currently active requests",
        )
        .map_err(|e| format!("metric creation failed: {e}"))?;

        let bytes_sent_total = IntCounterVec::new(
            Opts::new("fluxo_bytes_sent_total", "Total bytes sent to clients"),
            &["service"],
        )
        .map_err(|e| format!("metric creation failed: {e}"))?;

        let bytes_received_total = IntCounterVec::new(
            Opts::new(
                "fluxo_bytes_received_total",
                "Total bytes received from clients",
            ),
            &["service"],
        )
        .map_err(|e| format!("metric creation failed: {e}"))?;

        let upstream_requests_total = IntCounterVec::new(
            Opts::new(
                "fluxo_upstream_requests_total",
                "Total requests proxied to each upstream",
            ),
            &["upstream", "status"],
        )
        .map_err(|e| format!("metric creation failed: {e}"))?;

        let upstream_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "fluxo_upstream_duration_seconds",
                "Upstream response duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["upstream"],
        )
        .map_err(|e| format!("metric creation failed: {e}"))?;

        let upstream_errors_total = IntCounterVec::new(
            Opts::new(
                "fluxo_upstream_errors_total",
                "Total proxy errors per upstream",
            ),
            &["upstream", "error_type"],
        )
        .map_err(|e| format!("metric creation failed: {e}"))?;

        let cache_hits = prometheus::IntCounter::new("fluxo_cache_hits_total", "Total cache hits")
            .map_err(|e| format!("metric creation failed: {e}"))?;
        let cache_misses =
            prometheus::IntCounter::new("fluxo_cache_misses_total", "Total cache misses")
                .map_err(|e| format!("metric creation failed: {e}"))?;
        let cache_stale =
            prometheus::IntCounter::new("fluxo_cache_stale_total", "Total stale cache serves")
                .map_err(|e| format!("metric creation failed: {e}"))?;

        registry
            .register(Box::new(requests_total.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(request_duration_seconds.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(active_requests.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(bytes_sent_total.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(bytes_received_total.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(upstream_requests_total.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(upstream_duration_seconds.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(upstream_errors_total.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(cache_hits.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(cache_misses.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;
        registry
            .register(Box::new(cache_stale.clone()))
            .map_err(|e| format!("collector registration failed: {e}"))?;

        Ok(Self {
            registry,
            requests_total,
            request_duration_seconds,
            active_requests,
            bytes_sent_total,
            bytes_received_total,
            upstream_requests_total,
            upstream_duration_seconds,
            upstream_errors_total,
            cache_hits,
            cache_misses,
            cache_stale,
        })
    }

    /// Record a completed request in all relevant metrics.
    #[allow(clippy::too_many_arguments)]
    pub fn record_request(
        &self,
        service: &str,
        route: &str,
        method: &str,
        status: u16,
        duration_secs: f64,
        bytes_sent: u64,
        bytes_received: u64,
    ) {
        let status_str = status.to_string();
        self.requests_total
            .with_label_values(&[service, route, method, &status_str])
            .inc();
        self.request_duration_seconds
            .with_label_values(&[service, route])
            .observe(duration_secs);
        self.bytes_sent_total
            .with_label_values(&[service])
            .inc_by(bytes_sent);
        self.bytes_received_total
            .with_label_values(&[service])
            .inc_by(bytes_received);
    }

    /// Record a completed upstream request — per-upstream observability.
    ///
    /// Traefik-inspired: every upstream server gets its own metrics so you can
    /// see request count, latency, and error rate per backend.
    pub fn record_upstream_request(
        &self,
        upstream: &str,
        status: u16,
        duration_secs: f64,
        error_type: Option<&str>,
    ) {
        let status_str = status.to_string();
        self.upstream_requests_total
            .with_label_values(&[upstream, &status_str])
            .inc();
        self.upstream_duration_seconds
            .with_label_values(&[upstream])
            .observe(duration_secs);
        if let Some(err) = error_type {
            self.upstream_errors_total
                .with_label_values(&[upstream, err])
                .inc();
        }
    }

    /// Increment cache hit counter.
    pub fn inc_cache_hits(&self) {
        self.cache_hits.inc();
    }

    /// Increment cache miss counter.
    pub fn inc_cache_misses(&self) {
        self.cache_misses.inc();
    }

    /// Increment cache stale counter.
    pub fn inc_cache_stale(&self) {
        self.cache_stale.inc();
    }

    /// Increment the active requests gauge.
    pub fn inc_active(&self) {
        self.active_requests.inc();
    }

    /// Decrement the active requests gauge.
    pub fn dec_active(&self) {
        self.active_requests.dec();
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn encode(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        let _ = encoder.encode(&metric_families, &mut buffer);
        String::from_utf8(buffer).unwrap_or_default()
    }

    /// Alias for `encode()` — used by Prometheus push mode.
    pub fn export_text(&self) -> String {
        self.encode()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn new_registry_creates_all_metrics() {
        let m = MetricsRegistry::new().unwrap();
        // Touch each metric so it appears in output
        m.record_request("test", "test", "GET", 200, 0.01, 1, 1);
        m.inc_active();
        let output = m.encode();
        assert!(output.contains("fluxo_requests_total"));
        assert!(output.contains("fluxo_request_duration_seconds"));
        assert!(output.contains("fluxo_active_requests"));
        assert!(output.contains("fluxo_bytes_sent_total"));
        assert!(output.contains("fluxo_bytes_received_total"));
    }

    #[test]
    fn record_request_increments_counters() {
        let m = MetricsRegistry::new().unwrap();
        m.record_request("web", "api-v1", "GET", 200, 0.042, 1024, 256);
        m.record_request("web", "api-v1", "GET", 200, 0.038, 512, 128);
        m.record_request("web", "api-v1", "POST", 500, 1.2, 64, 8192);

        let output = m.encode();
        assert!(output.contains(
            r#"fluxo_requests_total{method="GET",route="api-v1",service="web",status="200"} 2"#
        ));
        assert!(output.contains(
            r#"fluxo_requests_total{method="POST",route="api-v1",service="web",status="500"} 1"#
        ));
    }

    #[test]
    fn active_requests_gauge_increments_and_decrements() {
        let m = MetricsRegistry::new().unwrap();
        m.inc_active();
        m.inc_active();
        m.dec_active();
        let output = m.encode();
        assert!(output.contains("fluxo_active_requests 1"));
    }

    #[test]
    fn encode_produces_valid_prometheus_format() {
        let m = MetricsRegistry::new().unwrap();
        m.record_request("web", "index", "GET", 200, 0.01, 100, 50);
        let output = m.encode();
        assert!(output.contains("# HELP fluxo_requests_total"));
        assert!(output.contains("# TYPE fluxo_requests_total counter"));
    }

    #[test]
    fn upstream_metrics_recorded() {
        let m = MetricsRegistry::new().unwrap();
        m.record_upstream_request("backend-api", 200, 0.05, None);
        m.record_upstream_request("backend-api", 200, 0.03, None);
        m.record_upstream_request("backend-api", 502, 1.0, Some("connect"));

        let output = m.encode();
        assert!(output.contains("fluxo_upstream_requests_total"));
        assert!(output.contains(r#"upstream="backend-api"#));
        assert!(output.contains("fluxo_upstream_duration_seconds"));
        assert!(output.contains("fluxo_upstream_errors_total"));
    }

    #[test]
    fn upstream_errors_only_recorded_when_present() {
        let m = MetricsRegistry::new().unwrap();
        m.record_upstream_request("svc", 200, 0.01, None);
        let output = m.encode();
        // No errors recorded → no error labels in output
        assert!(!output.contains(r#"fluxo_upstream_errors_total{upstream="svc"#));

        // Record an error
        m.record_upstream_request("svc", 504, 5.0, Some("timeout"));
        let output = m.encode();
        assert!(output.contains(r#"error_type="timeout"#));
    }
}
