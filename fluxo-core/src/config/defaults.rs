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
