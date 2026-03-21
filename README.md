<h1 align="center">Fluxo</h1>

<p align="center">
  <strong>The fast, simple, memory-safe reverse proxy.</strong><br>
  Built on Cloudflare's <a href="https://github.com/cloudflare/pingora">Pingora</a>. Configured in TOML. Ships as a single binary.
</p>

<p align="center">
  <a href="https://github.com/pcruz1905/fluxo/actions/workflows/ci.yml"><img src="https://github.com/pcruz1905/fluxo/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/pcruz1905/fluxo/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
</p>

---

Fluxo is a reverse proxy you download as a single binary, configure in TOML, and run. It handles TLS certificates automatically via ACME, routes traffic to your services, and gets out of the way — while using less memory and producing lower tail latency than alternatives written in Go or C.

Under the hood, Fluxo is powered by [Pingora](https://github.com/cloudflare/pingora), the Rust framework Cloudflare built to replace Nginx across their global network (1 trillion+ requests/day in production).

## Features

- **Automatic HTTPS** — Let's Encrypt certificates via ACME, obtained and renewed automatically
- **TOML configuration** — Human-readable, strongly typed, validated at load time
- **Hot reload** — Config changes applied without restart (file-watch + SIGHUP + admin API)
- **Load balancing** — Round-robin, weighted, random, consistent hashing, and earliest-deadline-first
- **Health checks** — Active HTTP probes with configurable thresholds
- **Circuit breaker** — Per-upstream circuit breaker (open / half-open / closed)
- **HTTP caching** — Pingora-native response cache with TTL, stale-while-revalidate, and cache purge API
- **17 built-in plugins** — Rate limiting, CORS, compression (gzip/brotli/zstd), basic auth, security headers, path rewriting, and more
- **Observability** — Prometheus metrics, structured JSON or compact access logs
- **Admin API** — `/health`, `/metrics`, `/config`, `/reload`, `/cache/purge`
- **HTTP/2** — Full support on both client and upstream connections
- **Dual TLS backends** — BoringSSL (default) or Rustls (pure Rust, zero native deps)
- **Single binary** — No runtime dependencies, no containers required

## Quick start

```bash
# Download (or build from source — see Installation below)
./fluxo --upstream localhost:3000
```

This starts Fluxo on port 8080 and proxies all traffic to `localhost:3000`.

For production, create a config file:

```toml
[global]
admin = "127.0.0.1:2019"
log_level = "info"

[services.web]
[[services.web.listeners]]
address = "0.0.0.0:443"
offer_h2 = true

[services.web.tls]
acme = true
acme_email = "you@example.com"

[[services.web.routes]]
name = "app"
match_host = ["app.example.com"]
upstream = "backend"

[upstreams.backend]
discovery = "static"
targets = ["127.0.0.1:3000"]
```

```bash
fluxo --config fluxo.toml
```

## Installation

### Pre-built binaries

Download from [GitHub Releases](https://github.com/pcruz1905/fluxo/releases). Binaries are available for:

| Platform | TLS backend |
|---|---|
| Linux x86_64 | BoringSSL, Rustls |
| Linux aarch64 | Rustls |
| macOS x86_64 | Rustls |
| macOS aarch64 (Apple Silicon) | Rustls |

### Build from source

```bash
git clone https://github.com/pcruz1905/fluxo.git
cd fluxo

# Rustls (recommended — no native build dependencies)
cargo build --release --no-default-features --features rustls

# BoringSSL (requires cmake + nasm)
cargo build --release
```

The binary is at `target/release/fluxo`.

## Configuration

Fluxo uses TOML. Config is loaded from (in priority order):

1. `--config <path>` CLI flag
2. `./fluxo.toml` in the current directory
3. `/etc/fluxo/fluxo.toml`

See [examples/fluxo.toml](examples/fluxo.toml) for a fully commented example covering services, routes, upstreams, TLS, plugins, and health checks.

### Validate without starting

```bash
fluxo --config fluxo.toml --test
```

### Generate default config

```bash
fluxo --init
```

## Built-in plugins

Plugins are configured per-route or globally in TOML:

| Plugin | Description |
|---|---|
| `rate_limit` | Token-bucket rate limiting per client IP |
| `cors` | CORS preflight handling and header injection |
| `compression` | gzip, brotli, and zstd response compression |
| `basic_auth` | HTTP Basic authentication |
| `security_headers` | HSTS, X-Content-Type-Options, X-Frame-Options |
| `request_id` | Inject unique request ID header |
| `headers` | Add/remove request and response headers |
| `redirect` | HTTP redirects (permanent/temporary) |
| `static_response` | Return static response without hitting upstream |
| `strip_prefix` | Remove path prefix before forwarding |
| `add_prefix` | Add path prefix before forwarding |
| `path_rewrite` | Regex-based path rewriting |
| `ip_restrict` | IP allow/deny lists |
| `body_filter` | Response body transformation |

```toml
[[services.web.routes]]
name = "api"
match_path = ["/api/*"]
upstream = "backend"

[services.web.routes.plugins.rate_limit]
requests_per_second = 100
burst = 50

[services.web.routes.plugins.cors]
allowed_origins = ["https://app.example.com"]
allowed_methods = ["GET", "POST"]
max_age = 3600
```

## Admin API

Default: `127.0.0.1:2019`

```bash
curl localhost:2019/health            # Health check
curl localhost:2019/metrics           # Prometheus metrics
curl localhost:2019/config            # Current config (JSON)
curl -X POST localhost:2019/reload    # Hot-reload config from disk
curl -X POST localhost:2019/cache/purge  # Purge response cache
```

## Architecture

```
┌──────────────────────────────────────┐
│         Fluxo Binary (CLI)           │
│   Config loading · Signals · Boot    │
├──────────────────────────────────────┤
│         Fluxo Core Library           │
│  Routing · Plugins · Admin API       │
│  TLS/ACME · Caching · Observability  │
├──────────────────────────────────────┤
│         Pingora Engine               │
│  Async runtime · Connection pooling  │
│  HTTP parsing · TLS · Work-stealing  │
└──────────────────────────────────────┘
```

Fluxo is a Cargo workspace with four crates:

| Crate | Purpose |
|---|---|
| `fluxo-bin` | CLI binary, bootstrap, signal handling |
| `fluxo-core` | Proxy engine, routing, plugins, config, admin API |
| `fluxo-plugin-sdk` | Plugin SDK (foundation for native plugins) |
| `fluxo-plugins` | Additional plugin implementations |

## Why Fluxo?

| | Nginx | Caddy | Traefik | Fluxo |
|---|---|---|---|---|
| Language | C | Go | Go | Rust |
| Memory safety | No | GC | GC | Ownership |
| Auto HTTPS | No | Yes | Yes | Yes |
| Config format | nginx.conf | Caddyfile/JSON | YAML+labels | TOML/JSON API |
| GC pauses | N/A | Yes | Yes | None |
| Connection pooling | Per-worker | Per-worker | Per-worker | Cross-thread |
| Memory footprint | 15-50 MB | 30-100 MB | 50-200 MB | ~15-40 MB |

## License

[Apache-2.0](LICENSE)
