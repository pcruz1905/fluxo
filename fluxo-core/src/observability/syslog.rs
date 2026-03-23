//! Syslog output — RFC 5424 over UDP.
//!
//! Sends access log entries to a remote syslog collector. Best-effort delivery
//! (UDP) so log writes never block or crash the proxy.

use std::net::UdpSocket;
use std::sync::OnceLock;

use crate::config::SyslogConfig;

/// Global syslog sender — initialized once at startup.
static SYSLOG: OnceLock<SyslogSender> = OnceLock::new();

/// Syslog severity levels (RFC 5424 §6.2.1).
fn severity_from_status(status: u16) -> u8 {
    match status {
        0..=199 => 6,   // informational
        200..=399 => 6, // informational
        400..=499 => 4, // warning
        _ => 3,         // error (5xx and unknown)
    }
}

/// Parse a syslog facility name to its numeric code (RFC 5424 §6.2.1).
fn parse_facility(name: &str) -> u8 {
    match name.to_lowercase().as_str() {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => 16, // default to local0
    }
}

struct SyslogSender {
    socket: UdpSocket,
    target: String,
    facility: u8,
    app_name: String,
}

/// Initialize the syslog sender. Call once at startup.
pub fn init_syslog(config: &SyslogConfig) {
    // Bind to any available local port for sending
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to bind UDP socket for syslog");
            return;
        }
    };

    // Set non-blocking so sends never block the proxy
    if let Err(e) = socket.set_nonblocking(true) {
        tracing::warn!(error = %e, "failed to set syslog socket non-blocking");
    }

    let facility = parse_facility(&config.facility);

    let sender = SyslogSender {
        socket,
        target: config.address.clone(),
        facility,
        app_name: config.app_name.clone(),
    };

    if SYSLOG.set(sender).is_err() {
        tracing::warn!("syslog already initialized");
        return;
    }

    tracing::info!(
        address = %config.address,
        facility = %config.facility,
        "syslog output initialized"
    );
}

/// Send an access log entry via syslog. Best-effort — errors are silently ignored.
pub fn emit_syslog(json_line: &str, status: u16) {
    let Some(sender) = SYSLOG.get() else {
        return;
    };

    let severity = severity_from_status(status);
    let priority = sender.facility * 8 + severity;
    let timestamp = super::access_log::chrono_now_rfc3339();
    let hostname = "-"; // RFC 5424 NILVALUE — we don't need to resolve our hostname
    let pid = std::process::id();

    // RFC 5424 format:
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    let message = format!(
        "<{priority}>1 {timestamp} {hostname} {app} {pid} - - {json_line}",
        app = sender.app_name,
    );

    // Best-effort UDP send — never block, never crash
    let _ = sender.socket.send_to(message.as_bytes(), &sender.target);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_facility_known_names() {
        assert_eq!(parse_facility("kern"), 0);
        assert_eq!(parse_facility("daemon"), 3);
        assert_eq!(parse_facility("local0"), 16);
        assert_eq!(parse_facility("local7"), 23);
        assert_eq!(parse_facility("LOCAL0"), 16); // case insensitive
    }

    #[test]
    fn parse_facility_unknown_defaults_to_local0() {
        assert_eq!(parse_facility("unknown"), 16);
    }

    #[test]
    fn severity_from_status_values() {
        assert_eq!(severity_from_status(200), 6); // info
        assert_eq!(severity_from_status(301), 6); // info
        assert_eq!(severity_from_status(404), 4); // warning
        assert_eq!(severity_from_status(500), 3); // error
        assert_eq!(severity_from_status(502), 3); // error
    }
}
