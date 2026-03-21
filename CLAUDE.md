# Fluxo

Reverse proxy built on Cloudflare's Pingora. Rust, TOML config, single binary.

## Tech Stack

- Rust (edition 2024), async via Tokio
- Pingora 0.8 (proxy engine)
- Dual TLS: BoringSSL (default) or Rustls
- ACME via instant-acme
- Prometheus metrics, tracing for logs

## Workspace Crates

- `fluxo-bin` — CLI entry point (clap)
- `fluxo-core` — Proxy engine, routing, plugins, config, admin API, TLS/ACME
- `fluxo-plugin-sdk` — Plugin SDK (placeholder for native plugin ABI)
- `fluxo-plugins` — Additional plugins

## Commands

- Build (rustls): `cargo build --no-default-features --features rustls`
- Build (boringssl): `cargo build` (requires cmake + nasm)
- Test: `cargo test --no-default-features --features rustls`
- Single test: `cargo test --test e2e_proxy --no-default-features --features rustls`
- Clippy: `cargo clippy --no-default-features --features rustls --all-targets`
- Format: `cargo +nightly fmt --all --check`
- Validate config: `cargo run -- --config examples/fluxo.toml --test`

## CI

Runs on push to main. Jobs: fmt, clippy, test, build, config-test, rustdoc. Both TLS backends tested. `RUSTFLAGS="-Dwarnings"` is set — all warnings are errors.

## Architecture

- **Config** (`fluxo-core/src/config/`) — TOML parsing, validation, hot-reload via file watcher + SIGHUP
- **Routing** (`fluxo-core/src/routing/`) — First-match-wins, glob/regex matchers for host/path/method/header
- **Proxy** (`fluxo-core/src/proxy.rs`) — Pingora ProxyHttp implementation, ArcSwap for lock-free state swap
- **Plugins** (`fluxo-core/src/plugins/`) — 17 built-in, enum dispatch (no trait objects), 4 lifecycle phases
- **Upstream** (`fluxo-core/src/upstream/`) — Peer selection, health tracking, circuit breaker, EDF load balancing
- **TLS/ACME** (`fluxo-core/src/tls/`) — Certificate management, HTTP-01 challenges, background renewal
- **Admin** (`fluxo-core/src/admin/`) — Hyper-based REST API (health, metrics, config, reload, cache purge)
- **Observability** (`fluxo-core/src/observability/`) — Prometheus counters/histograms, structured access logs

## Code Conventions

- No `unsafe` in application code
- Enum-based plugin dispatch, not trait objects
- ArcSwap for hot-reload (lock-free reads on hot path)
- Config changes are atomic (full swap or nothing)
- E2E tests use custom harness with mock Axum upstreams (`fluxo-core/tests/`)
- Feature-gated TLS: `#[cfg(feature = "rustls")]` / `#[cfg(feature = "boringssl")]`
- Unix-only code guarded with `#[cfg(unix)]`

## Testing

E2E tests in `fluxo-core/tests/` use `harness = false` (Pingora spawns threads that don't cleanly exit). Tests boot a real proxy + mock upstream, send HTTP requests, and assert responses. Run all with `cargo test --no-default-features --features rustls`.

## Important

- Default feature is `boringssl`, but local dev on Windows/Mac is easier with `--features rustls`
- Pingora calls `run_forever()` which never returns — test runner calls `std::process::exit(0)`
- Config file search order: `--config` flag > `./fluxo.toml` > `/etc/fluxo/fluxo.toml`
