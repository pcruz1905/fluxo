use crate::context::RequestContext;
use std::io::Write;
use std::sync::OnceLock;

/// Global file logger — initialized once, writes access logs with optional rotation.
static FILE_LOGGER: OnceLock<parking_lot::Mutex<RotatingFileWriter>> = OnceLock::new();

/// A file writer that rotates log files when they exceed a configured size.
struct RotatingFileWriter {
    path: String,
    writer: std::io::BufWriter<std::fs::File>,
    max_size: u64,
    max_backups: u32,
    current_size: u64,
}

impl RotatingFileWriter {
    fn new(path: &str, max_size: u64, max_backups: u32) -> std::io::Result<Self> {
        let current_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            path: path.to_string(),
            writer: std::io::BufWriter::new(file),
            max_size,
            max_backups,
            current_size,
        })
    }

    /// Write a line and rotate if the file exceeds `max_size`.
    fn write_line(&mut self, line: &str) {
        let bytes = line.len() as u64 + 1; // +1 for newline
        let _ = writeln!(self.writer, "{line}");
        let _ = self.writer.flush();
        self.current_size += bytes;

        // Check rotation (0 = disabled)
        if self.max_size > 0 && self.current_size >= self.max_size {
            self.rotate();
        }
    }

    /// Rotate: current → `.1`, `.1` → `.2`, ..., delete oldest beyond `max_backups`.
    fn rotate(&mut self) {
        // Flush and drop current writer
        let _ = self.writer.flush();

        // Delete oldest backup
        let oldest = format!("{}.{}", self.path, self.max_backups);
        let _ = std::fs::remove_file(&oldest);

        // Shift backups: .{n-1} → .{n}
        for i in (1..self.max_backups).rev() {
            let from = format!("{}.{i}", self.path);
            let to = format!("{}.{}", self.path, i + 1);
            let _ = std::fs::rename(&from, &to);
        }

        // Current → .1
        let backup_1 = format!("{}.1", self.path);
        let _ = std::fs::rename(&self.path, &backup_1);

        // Open new file
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => {
                self.writer = std::io::BufWriter::new(file);
                self.current_size = 0;
                tracing::debug!(path = %self.path, "access log rotated");
            }
            Err(e) => {
                tracing::error!(path = %self.path, error = %e, "failed to open new log file after rotation");
            }
        }
    }
}

/// Initialize the file-based access logger with optional rotation.
///
/// - `path`: log file path (None = file logging disabled)
/// - `max_size`: max file size in bytes before rotation (0 = no rotation)
/// - `max_backups`: number of rotated backups to keep
pub fn init_file_logger(path: Option<&str>, max_size: u64, max_backups: u32) {
    if let Some(path) = path {
        match RotatingFileWriter::new(path, max_size, max_backups) {
            Ok(writer) => {
                let rotation = if max_size > 0 {
                    format!("max_size={max_size}, max_backups={max_backups}")
                } else {
                    "disabled".to_string()
                };
                let _ = FILE_LOGGER.set(parking_lot::Mutex::new(writer));
                tracing::info!(path, rotation = %rotation, "access log file writer initialized");
            }
            Err(e) => {
                tracing::error!(path, error = %e, "failed to open access log file");
            }
        }
    }
}

/// Format a single access log line in JSON format for file output.
pub(crate) fn format_access_log_json(ctx: &RequestContext, status: u16) -> String {
    let duration_ms = ctx.elapsed().as_millis() as u64;
    let route = ctx
        .matched_route
        .as_ref()
        .and_then(|r| r.name.as_deref())
        .unwrap_or("-");
    let upstream = ctx.matched_route.as_ref().map(|r| r.upstream.to_string());
    let upstream = upstream.as_deref().unwrap_or("-");
    let peer = ctx.selected_peer.as_ref().map(|p| p.address.to_string());

    serde_json::json!({
        "timestamp": chrono_now_rfc3339(),
        "request_id": ctx.request_id.to_string(),
        "method": ctx.method.as_deref().unwrap_or("-"),
        "host": ctx.host.as_deref().unwrap_or("-"),
        "path": ctx.path.as_deref().unwrap_or("-"),
        "status": status,
        "duration_ms": duration_ms,
        "route": route,
        "upstream": upstream,
        "upstream_peer": peer.as_deref().unwrap_or("-"),
        "client_ip": ctx.client_ip.as_deref().unwrap_or("-"),
        "bytes_sent": ctx.bytes_sent,
        "bytes_received": ctx.bytes_received,
        "tls_version": ctx.tls_version.as_deref().unwrap_or("-"),
        "http_version": ctx.http_version.as_deref().unwrap_or("-"),
        "user_agent": ctx.user_agent.as_deref().unwrap_or("-"),
        "error": ctx.error_message.as_deref().unwrap_or(""),
        "retries": ctx.retry_count,
    })
    .to_string()
}

/// Minimal RFC 3339 timestamp without pulling in chrono.
pub(crate) fn chrono_now_rfc3339() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Simple UTC timestamp: seconds since epoch → readable format
    // Format: epoch seconds as a number (consumers parse via their own tooling)
    // For a proper ISO 8601 timestamp we compute from epoch:
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Convert days since epoch to date (simplified — covers 1970-2099)
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Emit a single wide-event access log for a completed request.
///
/// This is the canonical log line — one per request, containing all context
/// accumulated during the request lifecycle. Designed for structured log
/// aggregators (Loki, `ClickHouse`, `CloudWatch` Insights).
///
/// Logs to both stdout (via tracing), the configured access log file (if any),
/// and syslog (if configured).
pub fn emit_access_log(ctx: &RequestContext, status: u16) {
    let duration_ms = ctx.elapsed().as_millis() as u64;
    let request_id = ctx.request_id.to_string();

    let route = ctx
        .matched_route
        .as_ref()
        .and_then(|r| r.name.as_deref())
        .unwrap_or("-");

    let upstream = ctx.matched_route.as_ref().map(|r| r.upstream.to_string());
    let upstream = upstream.as_deref().unwrap_or("-");

    let peer = ctx.selected_peer.as_ref().map(|p| p.address.to_string());

    tracing::info!(
        // Request identification
        request_id = %request_id,
        // Request metadata
        method = ctx.method.as_deref().unwrap_or("-"),
        host = ctx.host.as_deref().unwrap_or("-"),
        path = ctx.path.as_deref().unwrap_or("-"),
        status,
        // Timing
        duration_ms,
        upstream_connect_ms = ctx.upstream_connect_ms,
        upstream_response_ms = ctx.upstream_response_ms,
        // Routing
        route,
        upstream,
        upstream_peer = peer.as_deref().unwrap_or("-"),
        // Network
        client_ip = ctx.client_ip.as_deref().unwrap_or("-"),
        bytes_sent = ctx.bytes_sent,
        bytes_received = ctx.bytes_received,
        tls_version = ctx.tls_version.as_deref().unwrap_or("-"),
        http_version = ctx.http_version.as_deref().unwrap_or("-"),
        // Client
        user_agent = ctx.user_agent.as_deref().unwrap_or("-"),
        // Errors
        error = ctx.error_message.as_deref().unwrap_or(""),
        retries = ctx.retry_count,
        // Marker
        "request completed"
    );

    // Format JSON line (shared by file + syslog)
    let json_line = format_access_log_json(ctx, status);

    // Write to file if configured
    if let Some(logger) = FILE_LOGGER.get() {
        let mut writer = logger.lock();
        writer.write_line(&json_line);
    }

    // Write to syslog if configured
    super::syslog::emit_syslog(&json_line, status);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn emit_access_log_does_not_panic_with_empty_context() {
        let ctx = RequestContext::new();
        emit_access_log(&ctx, 200);
    }

    #[test]
    fn emit_access_log_does_not_panic_with_error_status() {
        let mut ctx = RequestContext::new();
        ctx.error_message = Some("upstream timeout".to_string());
        emit_access_log(&ctx, 502);
    }

    #[test]
    fn days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2024-01-01 is day 19723 since epoch
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn format_access_log_json_produces_valid_json() {
        let ctx = RequestContext::new();
        let json = format_access_log_json(&ctx, 200);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], 200);
        assert_eq!(parsed["method"], "-");
    }

    #[test]
    fn rotating_writer_rotates_at_max_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let path_str = path.to_str().unwrap();

        let mut writer = RotatingFileWriter::new(path_str, 50, 3).unwrap();

        // Write enough data to trigger rotation
        for i in 0..10 {
            writer.write_line(&format!("log line {i} with some padding data"));
        }

        // Should have rotated — backup files should exist
        let backup_1 = dir.path().join("test.log.1");
        assert!(backup_1.exists(), "backup .1 should exist after rotation");
    }

    #[test]
    fn rotating_writer_keeps_max_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let path_str = path.to_str().unwrap();

        // Very small max_size to force many rotations, keep only 2 backups
        let mut writer = RotatingFileWriter::new(path_str, 20, 2).unwrap();

        for i in 0..50 {
            writer.write_line(&format!("line {i:03} padding data here"));
        }

        // .1 and .2 should exist, .3 should not
        assert!(dir.path().join("test.log.1").exists());
        assert!(dir.path().join("test.log.2").exists());
        assert!(
            !dir.path().join("test.log.3").exists(),
            ".3 should be deleted"
        );
    }

    #[test]
    fn rotating_writer_no_rotation_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let path_str = path.to_str().unwrap();

        // max_size = 0 means no rotation
        let mut writer = RotatingFileWriter::new(path_str, 0, 5).unwrap();

        for i in 0..100 {
            writer.write_line(&format!("line {i:03} padding data here"));
        }

        // No backup should exist
        assert!(!dir.path().join("test.log.1").exists());
    }
}
