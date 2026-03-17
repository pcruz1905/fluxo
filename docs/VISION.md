# Fluxo

**The fast, simple, memory-safe reverse proxy.**

Built on Cloudflare's Pingora. Designed for humans.

---

## What is Fluxo?

Fluxo is a reverse proxy that you download as a single binary, configure in TOML, and run. It handles TLS certificates automatically, routes traffic to your services, and gets out of the way — while using less CPU, less memory, and producing lower tail latency than alternatives written in Go or C.

Under the hood, Fluxo is powered by Pingora, the Rust networking framework that Cloudflare built to replace Nginx across their global network. Pingora handles over 1 trillion requests per day in production. It is not a reverse proxy — it is a *library* for building network services. It provides the async runtime, the connection pooling, the TLS termination, the HTTP parsing, and the work-stealing scheduler. What it does not provide is anything an operator would recognize: no config files, no routing, no automatic HTTPS, no management API, no plugin system.

Fluxo is the product built on top of that engine. It is the thing you actually install, configure, and operate.

For the technical architecture of how Fluxo integrates with Pingora, see [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Why Fluxo exists

Every significant deployment on the internet puts a reverse proxy in front of its services. The proxy terminates TLS, routes requests, balances load, and serves as the first line of defense. The three dominant options today each have a fundamental limitation:

### Nginx

Nginx is fast. It's written in C, it's been battle-tested for two decades, and it handles concurrency efficiently through an event-driven architecture. But its process-per-worker model means connections cannot be shared between workers — each worker maintains its own connection pool to upstream servers, leading to unnecessary TLS handshakes and wasted resources. Its configuration language is powerful but verbose (a task that takes 4 lines in Caddy takes 30 in Nginx). It has no automatic HTTPS. Config changes require a reload signal. And its C codebase carries inherent memory safety risks that grow with every custom module.

Cloudflare replaced Nginx with Pingora specifically because of these limitations. Their engineering team found that Nginx's architecture could not efficiently share connections across workers, and its C codebase made custom development error-prone.

### Caddy

Caddy solved the developer experience problem. Its Caddyfile syntax is radically simple. Automatic HTTPS works out of the box. Its JSON-native config with a REST API enables dynamic, runtime changes without restarts. Its architecture is genuinely elegant — configs are treated as immutable atomic units, modules follow a clean lifecycle (load → provision → validate → use → cleanup), and the plugin system is powerful.

But Caddy is written in Go. Go's garbage collector creates unpredictable P99 latency spikes under load. Its goroutine scheduler adds relay steps between packet arrival and handler execution. Its memory usage grows with goroutine count and GC pressure. For most deployments, this doesn't matter. For high-traffic production environments where tail latency translates directly to user experience and revenue, it does. And Caddy's plugin model requires recompiling the entire binary to add extensions — there is no way to load a plugin at runtime without rebuilding Caddy from source with `xcaddy`.

### Traefik

Traefik excels in container-orchestrated environments. Its label-based auto-discovery for Docker and Kubernetes is genuinely powerful. But it is also Go (same performance ceiling as Caddy), its configuration model is complex, and its resource footprint is the highest of the three (50–200MB baseline due to service discovery components).

### The gap

No production-ready reverse proxy today combines:

1. The raw performance and memory efficiency of a Rust async runtime (no GC, deterministic memory, work-stealing scheduler)
2. The simplicity and automatic HTTPS that made Caddy beloved
3. A plugin system that allows writing extensions in C, C++, or Rust — loaded at runtime without recompilation, with zero overhead via native shared libraries

Fluxo fills this gap.

---

## North star

> **Can someone go from zero to production-ready reverse proxy in under 5 minutes — with automatic HTTPS, load balancing, and observability — while running on half the resources of Caddy?**

Every design decision flows from this question. If a feature makes the product harder to understand in 5 minutes, it needs to earn its place. If an architecture choice adds latency or memory, it needs extraordinary justification.

---

## Principles

### 1. Zero-config should be production-ready

Running `fluxo --upstream localhost:3000` with no config file MUST give you: automatic HTTPS via Let's Encrypt, sensible security headers, request normalization, and graceful error handling. The operator who does nothing gets a secure, performant proxy. Configuration exists for tuning, not for basic operation.

### 2. Single binary, zero dependencies

Fluxo ships as one statically-linked binary. No runtime dependencies. No libc (musl builds). No container required. Download it, run it. This is a constraint inherited from Caddy's philosophy and it is non-negotiable — it is one of the most-cited reasons developers choose Caddy over Nginx.

### 3. Configuration is data, not code

Fluxo's human-authored format is TOML. Its internal representation is typed Rust structs. Its API speaks JSON. Configuration changes are atomic — either the entire new config is validated and applied, or nothing changes. This design, proven by Caddy at scale, eliminates fine-grained locking on hot paths and ensures consistency.

We chose TOML over Caddy's approach (custom DSL + JSON native) because TOML is readable without learning a new syntax, has excellent Rust ecosystem support (serde), and doesn't require building and maintaining a custom parser. The tradeoff is that TOML is slightly more verbose than a Caddyfile for simple cases — but it's universally understood and tooling-friendly.

### 4. Performance is inherited, not chased

We don't write custom networking code. We don't chase benchmarks. Pingora's async runtime, connection pooling, and work-stealing scheduler — battle-tested at 1 trillion requests per day — provide the performance foundation. Fluxo's advantage over Go proxies is a natural consequence of the runtime: no GC pauses, deterministic memory management, cross-thread connection reuse, and zero-cost async. The measurable outcomes are: lower P99 latency, lower memory footprint, lower CPU usage per request.

### 5. Memory safety without compromise

The entire proxy stack runs in safe Rust. Pingora handles TLS termination, HTTP parsing, and connection management in memory-safe code. Fluxo's application layer is memory-safe. There is no `unsafe` in application code and no manual memory management in the core. External plugins (loaded as shared libraries) are the operator's responsibility — same trust model as Nginx modules, which has worked for 20 years.

### 6. Extend with native code, not sandboxed runtimes

Caddy requires recompiling the binary to add plugins. Nginx loads C shared libraries via `dlopen`. Fluxo takes Nginx's approach: plugins compile to native shared libraries (`.so` / `.dylib`) using a stable C ABI. This means plugins can be written in C, C++, Rust, Zig, or any language that exports C-compatible functions — and loaded at runtime without recompiling Fluxo.

The C ABI is the most universal contract in computing. It's proven, zero-overhead (a plugin call is just a function call), and accessible to the largest possible developer base. No WASM runtimes, no sandboxing overhead, no complex host/guest memory management. Just a header file (`fluxo_plugin.h`) and a `gcc -shared` command.

---

## What Fluxo is NOT

**Not a web framework.** Fluxo does not serve dynamic content from application code.

**Not a service mesh.** Fluxo does not manage service-to-service communication inside a cluster (though it can sit at the edge of one).

**Not a CDN.** Fluxo does not cache content at edge locations worldwide (though it integrates Pingora's caching framework for origin-level caching).

**Not a framework.** Unlike Pingora, you do not write Rust code to use Fluxo. You configure it and run it.

---

## Target users

### First wave: developers and self-hosters

People running personal projects, homelab setups, and small SaaS products. They want something that works immediately with automatic HTTPS. They're currently using Caddy or Nginx Proxy Manager. Fluxo wins them with: *just as simple, noticeably faster, less RAM.*

Adoption path: `curl -sSL install.fluxo.dev | sh` → `fluxo --upstream localhost:3000` → working HTTPS in under a minute.

### Second wave: startup and mid-size production teams

Teams running 10–100 services behind a reverse proxy. They need load balancing, health checks, dynamic config, and observability. They're on Nginx, Caddy, or Traefik. Fluxo wins them with: *measurable latency and resource improvements, better operational experience than Nginx, native plugin extensibility, Prometheus metrics out of the box.*

Adoption path: Replace `nginx.conf` or `Caddyfile` with `fluxo.toml`. Verify lower P99 in staging. Roll to production.

### Third wave: high-traffic infrastructure teams

Companies processing millions of requests per second where tail latency directly impacts revenue. They're on Nginx, HAProxy, or custom solutions. Fluxo wins them with: *Pingora-class performance in a productized package, without maintaining custom Rust code. Native plugin system for custom logic at zero overhead.*

Adoption path: Evaluate benchmark results. Run shadow traffic comparison. Migrate incrementally by service.

---

## Competitive positioning

| | Nginx | Caddy | Traefik | Pingap | Fluxo |
|---|---|---|---|---|---|
| Language | C | Go | Go | Rust (Pingora) | Rust (Pingora) |
| Memory safety | No | Yes (GC) | Yes (GC) | Yes (ownership) | Yes (ownership) |
| Auto HTTPS | No | Yes | Yes | Yes | Yes |
| Config format | nginx.conf | Caddyfile / JSON | YAML + labels | TOML + Web UI | TOML / JSON API |
| Dynamic config API | No (OSS) | Yes (REST) | Yes (labels) | Yes (Web UI) | Yes (REST) |
| Plugin model | C .so (dlopen) | Go (recompile) | Go middleware | Rust (built-in only) | C ABI .so (dlopen) + Rust built-in |
| P99 latency | Excellent | Good | Good | Excellent | Excellent |
| Memory footprint | 15–50 MB | 30–100 MB | 50–200 MB | ~15–40 MB | ~15–40 MB |
| GC pauses | N/A | Yes | Yes | None | None |
| Connection pooling | Per-worker | Per-worker | Per-worker | Cross-thread | Cross-thread |
| HTTP/3 | Partial | Yes | Yes | Planned | Planned |
| GitHub stars | 26K+ | 70K+ | 54K+ | 1.1K | — |

**Pingap is the closest competitor.** Also built on Pingora, already has a web UI, 20+ plugins, and production features. But it's maintained primarily by a single Chinese developer, has limited English documentation, doesn't accept PRs, and has no external plugin system (all plugins are built-in Rust only). Fluxo differentiates with: config-file-first workflow (familiar to Nginx/Caddy users), native shared library plugins (C/C++/Rust), English-first community, and open contribution model.

**Nginx has the same plugin architecture** (C shared libraries via dlopen), which means Fluxo's plugin model is immediately familiar to the Nginx ecosystem. The difference is everything else: automatic HTTPS, TOML config, Rust memory safety, cross-thread connection pooling, and a management API.

---

## The window of opportunity

Three factors create an unusually clear opening:

**River is stalled.** The "official" Pingora-based reverse proxy — backed by ISRG (Let's Encrypt), Cloudflare, and Shopify — paused development at v0.5.0 in August 2024. The project used KDL (a niche config format), had only 4 contributors, and explicitly states "no expectation of stability." If River resumes, it will be a collaborator or a competitor — but today, the space is open.

**Cloudflare keeps investing in the ecosystem.** In late 2025, Cloudflare open-sourced `tokio-quiche`, an async QUIC/HTTP3 library wrapping their `quiche` implementation with the Tokio runtime. Pingora continues active development (v0.7.0 in 2026). The Rust proxy ecosystem is maturing fast.

**Developers are actively switching proxies.** Community discussions show a clear migration pattern: Nginx → Caddy for simplicity, Caddy → Traefik for container orchestration. The conversation has shifted from "which is fastest" to "which has the best developer experience." Fluxo enters at the moment when DX is the deciding factor — and offers DX *plus* performance.

---

## Business model

Fluxo is open-source under the Apache 2.0 license. The core proxy — including all features needed for production deployment — is and will always be free.

Revenue comes from complementary commercial offerings:

**Fluxo Cloud** — Managed reverse proxy service. We run and monitor Fluxo instances. Dashboard with analytics, alerting, and config management. Priced per-instance per-month.

**Fluxo Enterprise** — Self-hosted with enterprise features: SSO/SAML, audit logging, multi-cluster config sync, dedicated support, and SLA guarantees. Priced per-node per-year.

The model follows the Astral playbook (Ruff/uv): build genuinely useful open-source tools → gain widespread adoption → monetize complementary services.

---

## Risks and honest challenges

**Distribution is the real risk, not engineering.** Building Fluxo is achievable. Getting people to switch from Caddy (70K stars, massive community, excellent docs) is the hard part. Ruff succeeded because it was 1000x faster and replaced 20 tools. Fluxo's performance advantage over Caddy is real but less dramatic (2–5x on P99, 2–3x on memory). The DX story needs to be at least as good as Caddy's, not just "comparable."

**Community matters more than features.** Pingap has more features than Fluxo will have at v1.0. It hasn't captured mindshare because it lacks English docs, community engagement, and a familiar workflow. Fluxo's success depends as much on documentation quality and community building as on code quality.

**Caddy may adopt Rust components.** If the Caddy team decides to address their Go performance ceiling, Fluxo's differentiation narrows. Unlikely in the near term (Caddy's architecture is deeply Go-idiomatic) but worth monitoring.

**Pingora's roadmap is Cloudflare's roadmap.** Fluxo depends on Pingora as a library. If Cloudflare deprioritizes open-source Pingora development, Fluxo is affected. Mitigation: integrate through stable public APIs (the ProxyHttp trait), not internals. Apache 2.0 license allows forking as a last resort.

---

## Success metrics

**v0.1 milestone (month 1):**
Working proxy with Pingora integration — TOML config, static upstreams, manual TLS, basic routing.

**v0.5 milestone (month 3–4):**
Feature-complete for self-hosters: auto HTTPS, health checks, load balancing, admin API, core built-in plugins. Publish benchmark comparisons.

**Year 1 targets:**

- 5,000+ GitHub stars
- Published benchmarks showing measurable P99 and memory advantage over Caddy
- 100+ production deployments (self-reported)
- First community-contributed native plugin
- First paying Fluxo Cloud customer

**Year 2 targets:**

- 15,000+ GitHub stars
- Mentioned in proxy comparison posts alongside Caddy and Traefik
- $100K ARR from Cloud + Enterprise
- HTTP/3 support stable
- Conference talks / blog posts from production users

---

## The name

**Fluxo** (Portuguese: "flow") — traffic flows through it. Simple, memorable, international. The domain and GitHub org availability should be verified before committing.

---

## Let's move

The engine exists. The window is open. The architecture is documented. The first milestone is 4 weeks of focused work.

Start with `cargo init`, add `pingora` as a dependency, implement `ProxyHttp`, and make the first request flow through.
