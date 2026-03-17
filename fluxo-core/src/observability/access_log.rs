use crate::context::RequestContext;

/// Emit a single wide-event access log for a completed request.
///
/// This is the canonical log line — one per request, containing all context
/// accumulated during the request lifecycle. Designed for structured log
/// aggregators (Loki, ClickHouse, CloudWatch Insights).
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
}

#[cfg(test)]
mod tests {
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
}
