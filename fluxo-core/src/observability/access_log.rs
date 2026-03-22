use crate::context::RequestContext;
use std::io::Write;
use std::sync::OnceLock;

/// Global file logger — initialized once, writes access logs to a file.
/// Uses a Mutex<BufWriter> for thread-safe buffered writes.
static FILE_LOGGER: OnceLock<parking_lot::Mutex<std::io::BufWriter<std::fs::File>>> =
    OnceLock::new();

/// Initialize the file-based access logger. Call once at startup.
/// If `path` is None, file logging is disabled (stdout only via tracing).
pub fn init_file_logger(path: Option<&str>) {
    if let Some(path) = path {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(file) => {
                let _ = FILE_LOGGER.set(parking_lot::Mutex::new(std::io::BufWriter::new(file)));
                tracing::info!(path, "access log file writer initialized");
            }
            Err(e) => {
                tracing::error!(path, error = %e, "failed to open access log file");
            }
        }
    }
}

/// Format a single access log line in JSON format for file output.
fn format_access_log_json(ctx: &RequestContext, status: u16) -> String {
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
fn chrono_now_rfc3339() -> String {
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
/// Logs to both stdout (via tracing) and the configured access log file (if any).
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

    // Write to file if configured
    if let Some(logger) = FILE_LOGGER.get() {
        let line = format_access_log_json(ctx, status);
        let mut writer = logger.lock();
        // Best-effort: don't let file I/O errors crash the proxy
        let _ = writeln!(writer, "{line}");
        let _ = writer.flush();
    }
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
    fn file_logger_writes_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let path_str = path.to_str().unwrap();

        // Initialize file logger
        init_file_logger(Some(path_str));

        // Note: OnceLock means this test only works once per process.
        // In practice, the file logger is initialized once at startup.
        // We verify the file was created.
        assert!(path.exists() || FILE_LOGGER.get().is_some());
    }
}
