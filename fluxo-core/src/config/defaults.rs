//! Default values for configuration fields.

pub fn admin_addr() -> String {
    "127.0.0.1:2019".to_string()
}

pub fn log_level() -> String {
    "info".to_string()
}

pub fn discovery() -> String {
    "static".to_string()
}

// --- DNS discovery defaults ---

pub fn dns_default_port() -> u16 {
    80
}

pub fn dns_refresh_interval() -> String {
    "30s".to_string()
}

pub fn load_balancing() -> String {
    "round_robin".to_string()
}

pub fn health_check_interval() -> String {
    "10s".to_string()
}

pub fn health_check_timeout() -> String {
    "3s".to_string()
}

pub fn unhealthy_threshold() -> u32 {
    3
}

pub fn healthy_threshold() -> u32 {
    2
}

pub fn health_check_method() -> String {
    "GET".to_string()
}

pub fn health_check_follow_redirects() -> bool {
    true
}

pub fn access_log_format() -> super::types::AccessLogFormat {
    super::types::AccessLogFormat::Json
}

pub fn metrics_enabled() -> bool {
    true
}

// --- Upstream timeout defaults (Nginx-compatible) ---

/// Default TCP connect timeout. Nginx default: 60s, but 5s is safer.
pub fn connect_timeout() -> String {
    "5s".to_string()
}

/// Default upstream read timeout. Nginx default: 60s.
pub fn read_timeout() -> String {
    "60s".to_string()
}

/// Default upstream write timeout. Nginx default: 60s.
pub fn write_timeout() -> String {
    "60s".to_string()
}

// --- Retry defaults ---

pub fn retry_attempts() -> u32 {
    1
}

pub fn retry_on() -> Vec<String> {
    vec!["error".to_string(), "timeout".to_string()]
}

pub fn retry_initial_interval() -> String {
    "100ms".to_string()
}

pub fn retry_max_interval() -> String {
    "1s".to_string()
}

// --- Passive health check defaults ---

pub fn passive_max_fails() -> u32 {
    3
}

pub fn passive_fail_timeout() -> String {
    "30s".to_string()
}

// --- Sticky session defaults ---

pub fn sticky_cookie_name() -> String {
    "FLUXO_STICKY".to_string()
}

pub fn sticky_cookie_http_only() -> bool {
    true
}

// --- Circuit breaker defaults ---

pub fn cb_failure_threshold() -> u32 {
    5
}

pub fn cb_success_threshold() -> u32 {
    3
}

pub fn cb_open_duration() -> String {
    "30s".to_string()
}

// --- Circuit breaker expression defaults ---

pub fn cb_error_ratio_threshold() -> f64 {
    0.5
}

pub fn cb_min_requests() -> u32 {
    10
}

// --- Keepalive defaults ---

pub fn keepalive_timeout() -> String {
    "60s".to_string()
}

pub fn keepalive_pool_size() -> usize {
    128
}

// --- TCP keepalive defaults ---

pub fn tcp_keepalive_idle() -> String {
    "60s".to_string()
}

pub fn tcp_keepalive_interval() -> String {
    "15s".to_string()
}

pub fn tcp_keepalive_count() -> usize {
    5
}

// --- Traffic mirroring defaults ---

pub fn mirror_percent() -> u8 {
    100
}

// --- Cache defaults ---

pub fn cache_default_ttl() -> String {
    "300s".to_string()
}

pub fn cache_max_size() -> String {
    "50mb".to_string()
}

pub fn cache_stale_while_revalidate() -> String {
    "0s".to_string()
}

pub fn cache_stale_if_error() -> String {
    "0s".to_string()
}

pub fn cache_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}

pub fn cache_include_query() -> bool {
    true
}

/// Default disk cache max size: 1 GB.
pub fn cache_max_disk_size() -> String {
    "1gb".to_string()
}

/// Default max access log file size before rotation: 100 MB.
pub fn access_log_max_size() -> String {
    "100mb".to_string()
}

/// Default number of rotated log backups to keep.
pub fn access_log_max_backups() -> u32 {
    5
}

/// Default syslog facility.
pub fn syslog_facility() -> String {
    "local0".to_string()
}

/// Default syslog app name.
pub fn syslog_app_name() -> String {
    "fluxo".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Basic defaults ---

    #[test]
    fn default_admin_addr_is_localhost() {
        assert_eq!(admin_addr(), "127.0.0.1:2019");
    }

    #[test]
    fn default_log_level_is_info() {
        assert_eq!(log_level(), "info");
    }

    #[test]
    fn default_discovery_is_static() {
        assert_eq!(discovery(), "static");
    }

    #[test]
    fn default_load_balancing_is_round_robin() {
        assert_eq!(load_balancing(), "round_robin");
    }

    // --- Health check defaults ---

    #[test]
    fn default_health_check_interval_is_10s() {
        assert_eq!(health_check_interval(), "10s");
    }

    #[test]
    fn default_health_check_timeout_is_3s() {
        assert_eq!(health_check_timeout(), "3s");
    }

    #[test]
    fn default_unhealthy_threshold_is_3() {
        assert_eq!(unhealthy_threshold(), 3);
    }

    #[test]
    fn default_healthy_threshold_is_2() {
        assert_eq!(healthy_threshold(), 2);
    }

    // --- Access log ---

    #[test]
    fn default_access_log_format_is_json() {
        assert!(matches!(
            access_log_format(),
            super::super::types::AccessLogFormat::Json
        ));
    }

    #[test]
    fn default_metrics_enabled_is_true() {
        assert!(metrics_enabled());
    }

    // --- Upstream timeout defaults ---

    #[test]
    fn default_connect_timeout_is_5s() {
        assert_eq!(connect_timeout(), "5s");
    }

    #[test]
    fn default_read_timeout_is_60s() {
        assert_eq!(read_timeout(), "60s");
    }

    #[test]
    fn default_write_timeout_is_60s() {
        assert_eq!(write_timeout(), "60s");
    }

    // --- Retry defaults ---

    #[test]
    fn default_retry_attempts_is_1() {
        assert_eq!(retry_attempts(), 1);
    }

    #[test]
    fn default_retry_on_includes_error_and_timeout() {
        let on = retry_on();
        assert_eq!(on.len(), 2);
        assert!(on.contains(&"error".to_string()));
        assert!(on.contains(&"timeout".to_string()));
    }

    #[test]
    fn default_retry_initial_interval_is_100ms() {
        assert_eq!(retry_initial_interval(), "100ms");
    }

    #[test]
    fn default_retry_max_interval_is_1s() {
        assert_eq!(retry_max_interval(), "1s");
    }

    // --- Passive health check defaults ---

    #[test]
    fn default_passive_max_fails_is_3() {
        assert_eq!(passive_max_fails(), 3);
    }

    #[test]
    fn default_passive_fail_timeout_is_30s() {
        assert_eq!(passive_fail_timeout(), "30s");
    }

    // --- Sticky session defaults ---

    #[test]
    fn default_sticky_cookie_name() {
        assert_eq!(sticky_cookie_name(), "FLUXO_STICKY");
    }

    #[test]
    fn default_sticky_cookie_http_only_is_true() {
        assert!(sticky_cookie_http_only());
    }

    // --- Circuit breaker defaults ---

    #[test]
    fn default_cb_failure_threshold_is_5() {
        assert_eq!(cb_failure_threshold(), 5);
    }

    #[test]
    fn default_cb_success_threshold_is_3() {
        assert_eq!(cb_success_threshold(), 3);
    }

    #[test]
    fn default_cb_open_duration_is_30s() {
        assert_eq!(cb_open_duration(), "30s");
    }

    #[test]
    fn default_cb_error_ratio_threshold_is_half() {
        assert!((cb_error_ratio_threshold() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn default_cb_min_requests_is_10() {
        assert_eq!(cb_min_requests(), 10);
    }

    // --- Keepalive defaults ---

    #[test]
    fn default_keepalive_timeout_is_60s() {
        assert_eq!(keepalive_timeout(), "60s");
    }

    #[test]
    fn default_keepalive_pool_size_is_128() {
        assert_eq!(keepalive_pool_size(), 128);
    }

    // --- TCP keepalive defaults ---

    #[test]
    fn default_tcp_keepalive_idle_is_60s() {
        assert_eq!(tcp_keepalive_idle(), "60s");
    }

    #[test]
    fn default_tcp_keepalive_interval_is_15s() {
        assert_eq!(tcp_keepalive_interval(), "15s");
    }

    #[test]
    fn default_tcp_keepalive_count_is_5() {
        assert_eq!(tcp_keepalive_count(), 5);
    }

    // --- Mirror defaults ---

    #[test]
    fn default_mirror_percent_is_100() {
        assert_eq!(mirror_percent(), 100);
    }

    // --- Cache defaults ---

    #[test]
    fn default_cache_default_ttl_is_300s() {
        assert_eq!(cache_default_ttl(), "300s");
    }

    #[test]
    fn default_cache_max_size_is_50mb() {
        assert_eq!(cache_max_size(), "50mb");
    }

    #[test]
    fn default_cache_stale_while_revalidate_is_0s() {
        assert_eq!(cache_stale_while_revalidate(), "0s");
    }

    #[test]
    fn default_cache_stale_if_error_is_0s() {
        assert_eq!(cache_stale_if_error(), "0s");
    }

    #[test]
    fn default_cache_methods_are_get_and_head() {
        let methods = cache_methods();
        assert_eq!(methods.len(), 2);
        assert!(methods.contains(&"GET".to_string()));
        assert!(methods.contains(&"HEAD".to_string()));
    }

    #[test]
    fn default_cache_include_query_is_true() {
        assert!(cache_include_query());
    }

    // --- Health check extended defaults ---

    #[test]
    fn default_health_check_method_is_get() {
        assert_eq!(health_check_method(), "GET");
    }

    #[test]
    fn default_health_check_follow_redirects_is_true() {
        assert!(health_check_follow_redirects());
    }
}
