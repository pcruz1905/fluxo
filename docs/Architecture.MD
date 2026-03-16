# Fluxo — Architecture

This document describes HOW Fluxo is built, bridging the components provided by Pingora and the implementation goals for a production-ready reverse proxy. It is intended for implementers and contributors to clarify scope, plan work, and understand the design rationale.

For WHAT Fluxo is and why it exists, refer to [VISION.md](./VISION.md).

> The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
> "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY",
> and "OPTIONAL" in this document are to be interpreted as described
> in [BCP 14] [RFC2119] [RFC8174] when, and only when, they appear
> in all capitals, as shown here.

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC2119]: https://datatracker.ietf.org/doc/html/rfc2119
[RFC8174]: https://datatracker.ietf.org/doc/html/rfc8174

---

## 1 — System overview

Fluxo is a layered system. Each layer has a clear boundary of responsibility.

```text
┌─────────────────────────────────────────────────────────────┐
│                     Fluxo Binary (CLI)                      │
│  Arg parsing · Bootstrap · Signal handling · Daemonization  │
├─────────────────────────────────────────────────────────────┤
│                     Fluxo Application                       │
│  Config system · Admin API · TLS/ACME · Plugin runtime      │
│  Service registry · Observability · Graceful upgrade        │
├─────────────────────────────────────────────────────────────┤
│                     Pingora Engine                          │
│  Server · Services · ProxyHttp trait · Connection pooling   │
│  HTTP/1.1 · HTTP/2 · TLS (OpenSSL/BoringSSL) · Listeners   │
│  Work-stealing async runtime · Graceful restart primitives  │
├─────────────────────────────────────────────────────────────┤
│                  Operating System                           │
│  TCP/UDP sockets · Unix domain sockets · io_uring (future)  │
└─────────────────────────────────────────────────────────────┘
```

**Pingora Engine** is a library dependency. Fluxo does not fork, patch, or vendor Pingora. All integration happens through Pingora's public API surface, primarily the `ProxyHttp` trait, the `Server` lifecycle, and the `Service` abstraction. When Pingora adds capabilities (HTTP/3, improved caching), Fluxo inherits them by updating the dependency version.

**Fluxo Application** is the product layer. It translates operator intent (expressed as configuration) into Pingora constructs (Services, HttpPeers, filter callbacks). This is where the vast majority of Fluxo-specific code lives.

**Fluxo Binary** is a thin CLI wrapper. It parses arguments, loads configuration, bootstraps the Pingora Server, and handles OS signals. The binary itself SHOULD contain minimal logic.

---

## 2 — Relationship with Pingora

### 2.1 — What Pingora provides

Pingora provides the core networking primitives that would take years to build correctly:

1. **Server process management** — daemonization, worker thread pools, signal handling, graceful restart via listener handoff (SIGQUIT + upgrade socket)
2. **Service abstraction** — each Service owns a Tokio runtime with configurable thread count; multiple Services can run in one Server
3. **HTTP proxy engine** — the `ProxyHttp` trait with ~30 callback hooks covering the full request lifecycle
4. **Connection pooling** — cross-thread connection reuse via a shared pool (unlike Nginx's per-worker isolation), with configurable idle timeouts and pool sizes
5. **TLS termination** — OpenSSL and BoringSSL backends, ALPN negotiation, certificate hot-swapping
6. **Load balancing** — round robin, weighted, consistent hashing, and random selection via `pingora-load-balancing`
7. **HTTP caching** — a cache framework with pluggable storage backends, cache lock coordination, and stale-while-revalidate support
8. **Work-stealing scheduler** — when a worker thread runs out of work, it steals tasks from other workers' queues; this distributes load without centralized coordination and avoids Nginx's problem of one overloaded worker while others sit idle

### 2.2 — What Pingora does NOT provide

The following are explicitly out of scope for Pingora and MUST be implemented by Fluxo:

1. **Configuration** — Pingora has no config file format, no config parser, and no config API; it expects the application to construct all types programmatically
2. **Automatic HTTPS** — no ACME client, no Let's Encrypt integration, no certificate storage or renewal
3. **Routing** — `upstream_peer()` is a blank callback; Pingora does not match hosts, paths, headers, or methods to upstreams
4. **Plugin system** — Pingora's extensibility is through Rust trait implementation; there is no dynamic plugin loading
5. **Admin API** — no HTTP management API, no runtime config changes, no health/metrics endpoints
6. **Service discovery** — no DNS polling, no Docker label discovery, no SRV record resolution
7. **Observability** — Pingora provides hooks for logging (the `logging()` callback) but no structured logger, no Prometheus exporter, no OpenTelemetry integration
8. **User-facing documentation** — Pingora's docs are developer-oriented; Fluxo needs operator docs

### 2.3 — The ProxyHttp trait

The `ProxyHttp` trait is the heart of Fluxo's integration with Pingora. It defines callback hooks at each phase of a proxied request's lifecycle. Fluxo implements this trait once and dispatches to its internal routing, plugin, and middleware systems from within each callback.

The following table lists the key callbacks available in Pingora's `ProxyHttp` trait (as of v0.7.0) and how Fluxo uses each:

| Phase | Pingora callback | Fluxo usage |
|---|---|---|
| Context creation | `new_ctx()` | **REQUIRED.** Allocate per-request state: trace ID, start time, matched route, plugin chain |
| Downstream modules | `init_downstream_modules()` | Register downstream modules (e.g., PROXY protocol parser, response compression) |
| Pre-filter | `early_request_filter()` | IP deny lists, connection-level rate limiting — runs before any other logic |
| Request arrival | `request_filter()` | Route matching, authentication, per-route rate limiting, request validation, header normalization. Return `Ok(true)` to short-circuit with a direct response |
| Peer selection | `upstream_peer()` | **REQUIRED.** Resolve matched route → upstream group → select specific peer via load balancing strategy, considering health check state |
| Connected to peer | `connected_to_upstream()` | Record which upstream was selected (for logging and metrics) |
| Request forwarding | `upstream_request_filter()` | Mutate request headers before sending upstream: set Host, add X-Forwarded-For/X-Real-IP, inject auth tokens, remove internal headers |
| Response arrival | `upstream_response_filter()` | Inspect upstream response. Modify status/headers. Decide caching eligibility |
| Response to client | `response_filter()` | Final header mutation before streaming to client: add CORS, security headers, Server header, compression hints |
| Request body | `request_body_filter()` | Inspect or transform request body chunks (e.g., request size limits, body logging) |
| Response body | `response_body_filter()` | Inspect or transform response body chunks (e.g., content injection, response size tracking) |
| Completion | `logging()` | Emit access log entry. Update Prometheus metrics. Record latency, status code, bytes, upstream selection |
| Error handling | `fail_to_proxy()` | Generate error response pages. Log errors. Update upstream health state based on failure type |
| Error suppression | `suppress_error_log()` | Suppress noisy errors (e.g., client disconnect) from the error log while keeping them in metrics |
| Error summary | `request_summary()` | Customize error log context: include route name, upstream, trace ID |
| Cache (future) | `cache_*` callbacks | Pingora's cache framework — hooks for cache key generation, hit/miss decisions, storage |

### 2.4 — Request lifecycle

```text
  Client                                                          Upstream
    │                                                                │
    │──── TCP connect ────▶┌──────────────────────┐                  │
    │                      │ TLS Termination       │                  │
    │◀── TLS handshake ───▶│ (Pingora internal)    │                  │
    │                      └──────────┬───────────┘                  │
    │                                 │                              │
    │──── HTTP request ───▶┌──────────▼───────────┐                  │
    │                      │ early_request_filter  │                  │
    │                      │ IP deny? Rate limit?  │                  │
    │                      └──────────┬───────────┘                  │
    │                                 │                              │
    │                      ┌──────────▼───────────┐                  │
    │                      │   request_filter      │                  │
    │                      │ Route match           │                  │
    │                      │ Auth check            │                  │
    │                      │ Per-route rate limit   │                  │
    │                      │ Header normalization   │                  │
    │                      └──────────┬───────────┘                  │
    │                                 │                              │
    │                      ┌──────────▼───────────┐                  │
    │                      │   upstream_peer       │                  │
    │                      │ Select upstream group │                  │
    │                      │ Load balance → pick   │                  │
    │                      │ peer, check health    │                  │
    │                      └──────────┬───────────┘                  │
    │                                 │                              │
    │                      ┌──────────▼───────────┐                  │
    │                      │ upstream_request_     │                  │
    │                      │ filter                │──── request ───▶│
    │                      │ Set Host, XFF, etc.   │                  │
    │                      └──────────────────────┘                  │
    │                                                                │
    │                      ┌──────────────────────┐                  │
    │                      │ response_filter       │◀── response ────│
    │◀── HTTP response ────│ CORS, security hdrs   │                  │
    │                      └──────────┬───────────┘                  │
    │                                 │                              │
    │                      ┌──────────▼───────────┐                  │
    │                      │   logging             │                  │
    │                      │ Access log, metrics   │                  │
    │                      └──────────────────────┘                  │
```

**Error paths:** If any filter returns `Err`, Pingora calls `fail_to_proxy()`. Fluxo generates an error response page, logs the error with context from `request_summary()`, and updates metrics. Connection and upstream errors also flow through `fail_to_proxy()`, where Fluxo can update passive health check state.

**Short-circuit paths:** If `request_filter()` returns `Ok(true)`, the request is considered handled (e.g., Fluxo sent a 429 rate limit response or a 301 redirect). No upstream connection is made.

---

## 3 — Configuration system

### 3.1 — Design philosophy

Fluxo borrows Caddy's foundational insight: **configuration is a single, structured document treated as an immutable, atomic unit.** Either the whole config is replaced, or nothing changes. This eliminates the need to synchronize access to individual parameters in hot paths.

However, Fluxo diverges from Caddy in format choice:

| | Caddy | Fluxo |
|---|---|---|
| Native format | JSON | Rust structs (internal) |
| Primary human format | Caddyfile (custom DSL) | TOML |
| Secondary formats | JSON, YAML, TOML, Nginx (via adapters) | JSON (via Admin API) |
| Dynamic config | REST API on localhost:2019 | REST API on localhost:2019 |

The rationale: TOML is more readable than JSON for hand-edited config files, is well-supported by Rust's serde ecosystem, and does not require building a custom parser (as Caddy did for the Caddyfile).

### 3.2 — Configuration requirements

1. Fluxo MUST support configuration of all options via a human-editable TOML file
2. Fluxo MUST support emitting a default configuration file as a CLI command: `fluxo config init`
3. Fluxo MUST support a subset of options via command line flags
4. Fluxo MUST support a subset of options via environment variables
5. Fluxo MUST give priority: CLI flags > env vars > config file
6. Fluxo MUST validate the entire configuration before applying it
7. Fluxo MUST support runtime changes via the Admin API without restarting
8. Fluxo MUST treat config changes as atomic: entire new config applies, or old config remains

### 3.3 — Configuration lifecycle

```text
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│  fluxo.toml  │────▶│  Deserialize │────▶│   FluxoConfig    │
│  (on disk)   │     │  (serde)     │     │  (typed struct)  │
└──────────────┘     └──────────────┘     └────────┬─────────┘
                                                   │
                     ┌──────────────┐     ┌────────▼─────────┐
                     │  CLI flags + │────▶│     Merge &      │
                     │  env vars    │     │    Validate      │
                     └──────────────┘     └────────┬─────────┘
                                                   │
                     ┌──────────────┐     ┌────────▼─────────┐
                     │  Admin API   │────▶│  Build Pingora   │
                     │  (JSON PATCH)│     │  Services        │
                     └──────────────┘     └────────┬─────────┘
                                                   │
                                                   ▼
                                          ┌──────────────────┐
                                          │  Atomic swap:    │
                                          │  old config →    │
                                          │  new config      │
                                          └──────────────────┘
```

On reload: new config is parsed and validated. New Services are provisioned. If provisioning succeeds, listeners transfer from old to new via Pingora's upgrade socket. In-flight requests complete on old config. If provisioning fails, old config remains active.

### 3.4 — Example configuration

```toml
# fluxo.toml

[global]
admin = "127.0.0.1:2019"
threads = 0                # 0 = auto-detect CPU count
pid_file = "/var/run/fluxo.pid"
upgrade_socket = "/var/run/fluxo.sock"
log_level = "info"

[services.web]

  [[services.web.listeners]]
  address = "0.0.0.0:443"
  offer_h2 = true

  [[services.web.listeners]]
  address = "0.0.0.0:80"

  [services.web.tls]
  acme = true
  acme_email = "ops@example.com"

  [[services.web.routes]]
  match_host = ["api.example.com"]
  match_path = ["/v1/*"]
  upstream = "api-servers"
  [services.web.routes.plugins.rate_limit]
  requests_per_second = 50
  burst = 20

  [[services.web.routes]]
  match_host = ["example.com"]
  upstream = "web-servers"

[upstreams.api-servers]
discovery = "static"
targets = ["10.0.1.1:8080", "10.0.1.2:8080", "10.0.1.3:8080"]
load_balancing = "least_connections"
[upstreams.api-servers.health_check]
path = "/healthz"
interval = "10s"
timeout = "3s"
unhealthy_threshold = 3
healthy_threshold = 2

[upstreams.web-servers]
discovery = "dns"
hostname = "web.internal.example.com"
port = 3000
dns_ttl = "30s"

[plugins.compression]
algorithms = ["zstd", "br", "gzip"]
min_size = 256

[plugins.security_headers]
hsts_max_age = 31536000

# External native plugin (shared library)
[[plugins.external]]
name = "custom_auth"
path = "/etc/fluxo/plugins/libcustom_auth.so"
config = '{"jwt_secret": "..."}'
phase = "request"
```

---

## 4 — Admin REST API

The Admin API MUST run on a configurable address (default `127.0.0.1:2019`). It MUST be localhost-only by default.

| Method | Path | Description |
|---|---|---|
| `GET` | `/config` | Export full running config as JSON |
| `POST` | `/config` | Replace entire config (atomic swap) |
| `PATCH` | `/config/{path...}` | Update a section (internally: read full config → patch → validate → swap) |
| `GET` | `/config/{path...}` | Read a specific section |
| `GET` | `/health` | Process health: uptime, version, config hash |
| `GET` | `/metrics` | Prometheus-format metrics |
| `GET` | `/upstreams` | All upstreams with health status per peer |
| `POST` | `/reload` | Trigger config file re-read and apply |
| `POST` | `/stop` | Graceful shutdown with configurable drain timeout |

---

## 5 — Downstream: listeners and protocols

1. Fluxo MUST accept connections via TCP sockets (IPv4 and IPv6)
2. Fluxo MUST accept connections via Unix domain sockets
3. Fluxo MUST support TLS termination with configurable cipher suites and minimum TLS version (default: TLS 1.2)
4. Fluxo MUST support HTTP/1.0, HTTP/1.1, and HTTP/2
5. Fluxo SHOULD support HTTP/3 (QUIC) when Pingora adds native support; in the interim, Fluxo MAY integrate `tokio-quiche` for experimental HTTP/3
6. Fluxo MUST support the PROXY protocol (v1 and v2)
7. Fluxo MUST support X-Forwarded-For, X-Real-IP, and Forwarded headers

### HTTP/3 strategy

HTTP/3 adoption is accelerating (~75% of Meta's traffic runs over QUIC). Cloudflare has open-sourced `tokio-quiche`, an async Rust wrapper around their `quiche` QUIC implementation.

- **v0.1–v0.5:** No HTTP/3. Focus on HTTP/1.1 and HTTP/2.
- **v0.6+:** Experimental HTTP/3 via `tokio-quiche`. Separate QUIC listener, translate to HTTP/2 internally.
- **Long term:** Adopt Pingora's native HTTP/3 when available.

---

## 6 — Upstream: connection, discovery, and health

### 6.1 — Connection

1. Fluxo MUST support configurable timeouts: connection, request, idle keepalive
2. Fluxo MUST support cross-thread connection pooling (via Pingora)
3. Fluxo MUST support HTTP/1.1 and HTTP/2 to upstreams
4. Fluxo MUST support TLS to upstreams (including mTLS)
5. Fluxo MUST support PROXY protocol (v1/v2) to upstreams
6. Fluxo MUST support configurable retry: count, conditions, backoff

### 6.2 — Service discovery

1. Fluxo MUST support static upstream lists
2. Fluxo MUST support DNS (A/AAAA) discovery with configurable poll interval
3. Fluxo MUST support DNS SRV records
4. Fluxo MUST support DNS TTL as poll interval
5. Fluxo SHOULD support Docker label-based discovery
6. Fluxo MAY support Consul/etcd in future

### 6.3 — Health checking

**Active:** periodic HTTP probes with configurable path, interval, timeout, and healthy/unhealthy thresholds.

**Passive:** track upstream failures during normal proxying. Distinguish connection errors from HTTP 5xx from latency spikes — these are different signals. Connection errors use consecutive-failure rules; latency uses windowed spike detection.

### 6.4 — Load balancing

| Strategy | Description |
|---|---|
| `round_robin` | Default. Sequential rotation among healthy peers |
| `weighted` | Round robin with per-peer weights |
| `random` | Uniform random among healthy peers |
| `consistent_hash` | Hash on configurable key (IP, header, cookie) |
| `least_connections` | Route to peer with fewest active connections |

---

## 7 — Request path control

### 7.1 — Routing

1. Fluxo MUST match on: host (exact, wildcard), path (exact, prefix, glob), HTTP method, headers (exact, regex)
2. Routes MUST be evaluated in config order, first match wins
3. Fluxo MUST return configurable error (default: 404) when no route matches

### 7.2 — Modification

1. Fluxo MUST support header addition and removal (glob/regex)
2. Fluxo MUST support URI normalization
3. Fluxo MUST support HTTP→HTTPS redirect
4. Fluxo MUST support proxy headers: X-Forwarded-For, X-Forwarded-Proto, X-Real-IP, X-Request-ID

### 7.3 — Rate limiting

1. Token bucket with configurable rate and burst
2. Scoped to: global, per-service, per-route, per-client-IP
3. Combinable scopes
4. Returns HTTP 429 with Retry-After

### 7.4 — Access control

1. CIDR-based IP allow/deny lists (evaluated in `early_request_filter()`)
2. HTTP Basic auth
3. JWT/OAuth2 validation (via external plugin)

---

## 8 — Plugin system

### 8.1 — Design philosophy

Fluxo's plugin system follows Nginx's proven model: native shared libraries loaded via `dlopen` at startup. A plugin is a `.so` (Linux) or `.dylib` (macOS) file that exports functions matching a stable C ABI. This means plugins can be written in **C, C++, Rust, Zig**, or any language that can export C-compatible symbols.

The C ABI is the most universal calling convention in computing. A plugin call is a direct function call — zero overhead, no serialization, no sandbox boundary crossing. This is the same trust model Nginx has used for 20 years: the operator who loads a plugin is responsible for its correctness.

### 8.2 — Two tiers of plugins

```text
┌─────────────────────────────────────────────────────────────┐
│                  Fluxo Plugin Pipeline                      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Built-in plugins (Rust, compiled into binary)      │    │
│  │  rate_limit · compression · cors · headers · ...    │    │
│  │  Zero overhead. Part of the Fluxo binary.           │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  External plugins (C ABI, loaded via dlopen)        │    │
│  │  libcustom_auth.so · libmetrics.so · ...            │    │
│  │  Zero overhead. Written in C/C++/Rust/Zig.          │    │
│  │  Loaded at startup from configured paths.           │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Built-in plugins** are Rust code compiled into the Fluxo binary. They implement a Fluxo-internal `Plugin` trait. All standard middleware ships this way. They have full access to Pingora's `Session` type and can do anything the core can do.

**External plugins** are shared libraries loaded at startup. They export C ABI functions that Fluxo calls at the configured phase. They interact with request/response data through a set of host functions that Fluxo provides via function pointers.

### 8.3 — C ABI contract

The plugin ABI is defined by a C header file (`fluxo_plugin.h`) that ships with Fluxo. It consists of two halves:

**Functions the plugin implements** (Fluxo calls these):

```c
// fluxo_plugin.h — the plugin contract

#define FLUXO_CONTINUE  0   // proceed to next phase
#define FLUXO_STOP      1   // request handled, stop pipeline

// Lifecycle
int  fluxo_plugin_init(const char *config_json);   // called once at load
void fluxo_plugin_deinit(void);                     // called at unload

// Request phase hooks (implement the ones you need)
int  on_request(fluxo_request_t *req);              // early filtering, auth, routing overrides
int  on_upstream_request(fluxo_request_t *req);     // modify request before forwarding
int  on_response(fluxo_request_t *req, fluxo_response_t *resp);  // modify response
void on_log(fluxo_request_t *req, fluxo_response_t *resp);       // logging, metrics
```

**Functions Fluxo provides** (plugin calls these via function pointers passed during init):

```c
// Read request data
const char* fluxo_get_path(fluxo_request_t *req);
const char* fluxo_get_method(fluxo_request_t *req);
const char* fluxo_get_header(fluxo_request_t *req, const char *name);
const char* fluxo_get_client_ip(fluxo_request_t *req);
const char* fluxo_get_query(fluxo_request_t *req);

// Modify request
void fluxo_set_request_header(fluxo_request_t *req, const char *name, const char *value);
void fluxo_remove_request_header(fluxo_request_t *req, const char *name);

// Modify response
void fluxo_set_response_header(fluxo_response_t *resp, const char *name, const char *value);
void fluxo_remove_response_header(fluxo_response_t *resp, const char *name);

// Short-circuit: send a response directly, skip upstream
void fluxo_respond(fluxo_request_t *req, int status, const char *body);

// Logging
void fluxo_log(int level, const char *message);
```

### 8.4 — Plugin loading and execution

1. Fluxo MUST load external plugins at startup via `dlopen` (Linux) / `dlsym`
2. Fluxo MUST call `fluxo_plugin_init()` with the plugin's config JSON after loading
3. Fluxo MUST call `fluxo_plugin_deinit()` during graceful shutdown
4. Fluxo MUST call plugin hooks at the configured phase within the Pingora callback pipeline
5. Fluxo MUST skip plugins that do not export a given hook function (hooks are optional)
6. Fluxo MUST document the C ABI and provide `fluxo_plugin.h` as part of the release
7. Fluxo SHOULD provide example plugins in C and Rust to serve as templates

### 8.5 — Plugin configuration

```toml
# Load an external plugin
[[plugins.external]]
name = "custom_auth"                           # display name for logs
path = "/etc/fluxo/plugins/libcustom_auth.so"  # path to .so / .dylib
config = '{"jwt_secret": "abc123"}'            # passed to fluxo_plugin_init()
phase = "request"                              # when to call on_request()
priority = 10                                  # execution order (lower = earlier)

[[plugins.external]]
name = "custom_metrics"
path = "/etc/fluxo/plugins/libcustom_metrics.so"
phase = "log"
```

### 8.6 — Built-in plugins

The following plugins MUST ship compiled into the Fluxo binary:

| Plugin | Phase | Description |
|---|---|---|
| `rate_limit` | early_request_filter | Token bucket per IP/route/header |
| `ip_restrict` | early_request_filter | CIDR allow/deny |
| `basic_auth` | request_filter | HTTP Basic auth |
| `redirect` | request_filter | HTTP→HTTPS, path redirects |
| `headers` | request/response_filter | Add/remove/modify headers |
| `compression` | response_filter | gzip, brotli, zstd |
| `cors` | response_filter | CORS headers |
| `security_headers` | response_filter | HSTS, X-Frame-Options, CSP |
| `request_id` | upstream_request_filter | Unique request ID injection |
| `static_response` | request_filter | Fixed responses (health, maintenance) |

---

## 9 — TLS and ACME

1. ACME v2 protocol for Let's Encrypt / ZeroSSL
2. HTTP-01 and TLS-ALPN-01 challenges
3. Auto-renewal 30 days before expiry (configurable)
4. Wildcard domains (requires DNS-01)
5. Certificates stored on disk, private keys encrypted at rest
6. OCSP stapling
7. Manual certs via cert_path / key_path
8. SNI-based certificate selection
9. Hot-swap without connection interruption

---

## 10 — Observability

### Structured logging
JSON access logs per-request. Configurable levels. Output to stdout/stderr/file.

### Prometheus metrics
Exposed at `GET /metrics`: requests total, duration histogram, active connections, upstream health, cert expiry, config reloads, bytes sent/received.

### Distributed tracing
OpenTelemetry (OTLP) export. W3C Trace Context headers. Spans for each proxy phase.

---

## 11 — Graceful operations

### Restart
Zero-downtime via Pingora listener handoff (SIGQUIT + upgrade socket). Configurable drain timeout (default: 60s).

### Hot reload
Triggered by: filesystem watch, SIGHUP, or Admin API. Validates before applying. Never drops connections.

### Process management
Daemonization. Privilege drop (two-stage execution). Linux primary, macOS for dev. No root required with `CAP_NET_BIND_SERVICE`.

---

## 12 — Crate structure

```
fluxo/
├── Cargo.toml                    # Workspace root
├── fluxo-bin/                    # CLI binary (thin)
│   └── src/main.rs
├── fluxo-core/                   # Core application logic
│   └── src/
│       ├── lib.rs
│       ├── config/               # TOML parsing, validation, merge, defaults
│       ├── proxy.rs              # ProxyHttp implementation (central file)
│       ├── routing/              # Route table: match host, path, headers
│       ├── upstream/             # Groups, discovery, health, LB
│       ├── tls/                  # ACME, cert storage, renewal
│       ├── admin/                # REST API server
│       ├── plugins/              # Plugin trait, registry, pipeline, dlopen loader
│       └── observability/        # Access log, Prometheus, OTLP
├── fluxo-plugins/                # Built-in native plugins
│   └── src/
│       ├── rate_limit.rs
│       ├── compression.rs
│       ├── cors.rs
│       ├── headers.rs
│       ├── ip_restrict.rs
│       ├── basic_auth.rs
│       ├── redirect.rs
│       ├── security_headers.rs
│       ├── request_id.rs
│       └── static_response.rs
├── fluxo-plugin-sdk/             # C header + Rust FFI helpers for plugin authors
│   ├── include/
│   │   └── fluxo_plugin.h        # The C ABI contract
│   └── src/
│       └── lib.rs                # Rust helpers for writing plugins in Rust
├── examples/
│   ├── plugin-c/                 # Example plugin in C
│   │   ├── auth_plugin.c
│   │   └── Makefile              # gcc -shared -o libauth.so auth_plugin.c
│   └── plugin-rust/              # Example plugin in Rust
│       ├── src/lib.rs
│       └── Cargo.toml            # cdylib crate type
└── tests/
    ├── config/
    ├── routing/
    ├── plugins/                  # Plugin loading, ABI correctness
    ├── e2e/
    └── benchmarks/
```

---

## 13 — Development practices

### Testing
Unit tests for config, routing, plugins. Integration tests with real Fluxo instances. Plugin ABI tests (load example .so, verify callbacks). Benchmark suite (criterion) tracking latency/throughput/memory. Comparison benchmarks vs Nginx/Caddy/Traefik.

### CI/CD
All merges: `cargo fmt`, `cargo clippy`, `cargo test`, doc build. Cross-compile all targets. Build example plugins in C and Rust as CI step. Benchmarks on schedule. Docker images on release.

### Documentation
Complete rustdoc (`#![deny(missing_docs)]`). User-facing mdbook: installation, config reference, quick-start, plugin development guide (C and Rust examples), migration guides from Nginx/Caddy/Traefik. Auto-published per release.

---

## 14 — Milestone roadmap

| Milestone | Scope | Est. |
|---|---|---|
| **v0.1** | Pingora integration, static upstreams, manual TLS, TOML config, basic routing | 4w |
| **v0.2** | Full routing, round robin + least conn, active health checks, access logging | 3w |
| **v0.3** | ACME (HTTP-01), Let's Encrypt, cert storage, HTTP→HTTPS redirect | 3w |
| **v0.4** | Admin REST API, Prometheus metrics, structured logs | 3w |
| **v0.5** | Built-in plugins (rate limit, compression, CORS, headers, IP restrict, etc.) | 3w |
| **v0.6** | External plugin system: C ABI, dlopen loader, `fluxo_plugin.h`, example plugins | 3w |
| **v0.7** | DNS discovery, Docker labels, passive health, graceful upgrade, daemonization | 3w |
| **v0.8** | Hardening: fuzz testing, security audit, benchmark suite, comparison benchmarks | 3w |
| **v1.0** | Stable release: API + ABI stability commitment, complete docs, migration guides | 2w |

**Total: ~27 weeks solo.** Parallelizable with a second contributor from v0.3.

HTTP/3 support (experimental, via `tokio-quiche`) is planned for a post-v1.0 release.

---

## 15 — Future considerations

These are not committed but architecturally preserved:

**HTTP/3 via tokio-quiche** — Experimental QUIC listener as a post-v1.0 feature. Separate UDP listener that terminates QUIC and translates to HTTP/2 internally. Adopt Pingora's native HTTP/3 when available.

**io_uring** — Kernel-bypassing async I/O for further syscall reduction. Adoptable transparently through Tokio/Pingora when mature.

**eBPF acceleration** — XDP-level packet filtering for DDoS mitigation. Complementary to Fluxo (sits below in the stack). Fluxo MAY provide companion eBPF programs.

**QUIC-aware proxying** — IETF MASQUE draft for forwarding QUIC connections without terminating them. Worth tracking for v2.x.

**Declarative policy engine** — CEL or OPA/Rego-style policy language for complex access control without writing compiled plugins. A natural evolution if operators need more expressive rules than config-driven plugins allow.

**Multi-cluster config sync** — Control plane for synchronizing config across Fluxo instances via etcd/Consul. Commercial feature candidate.