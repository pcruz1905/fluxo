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

// --- Passive health check defaults ---

pub fn passive_max_fails() -> u32 {
    3
}

pub fn passive_fail_timeout() -> String {
    "30s".to_string()
}
