//! Benchmarks for hot-path operations.
//!
//! Run with: `cargo bench --no-default-features --features rustls -p fluxo-core`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use fluxo_core::config::FluxoConfig;
use fluxo_core::routing::RouteTable;

/// Build a TOML config string with N routes for benchmarking.
fn build_toml_config(num_routes: usize) -> String {
    let mut toml = String::from(
        r#"
[global]
admin = "127.0.0.1:2019"
"#,
    );

    // Upstreams
    for i in 0..num_routes {
        toml.push_str(&format!(
            r#"
[upstreams.upstream_{i}]
targets = ["127.0.0.1:{}"]
"#,
            3000 + i
        ));
    }

    // Service with all routes
    toml.push_str(
        r#"
[services.web]
listeners = [{ address = "0.0.0.0:80" }]
"#,
    );

    // Routes (inline in service)
    toml.push_str("routes = [\n");
    for i in 0..num_routes {
        toml.push_str(&format!(
            r#"  {{ match_host = ["host{i}.example.com"], match_path = ["/api/v{i}/*"], upstream = "upstream_{i}" }},
"#,
        ));
    }
    toml.push_str("]\n");

    toml
}

/// No-op header lookup for benchmarks.
struct EmptyHeaders;

impl fluxo_core::routing::matcher::RequestHeaders for EmptyHeaders {
    fn get_header(&self, _name: &str) -> Option<&str> {
        None
    }
}

fn bench_route_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_matching");

    for &count in &[10, 100, 500] {
        let toml_str = build_toml_config(count);
        let config: FluxoConfig = toml::from_str(&toml_str).expect("parse config");
        let table = RouteTable::build(&config).expect("route table build");
        let headers = EmptyHeaders;

        // Best case: match first route
        group.bench_function(format!("{count}_routes_first_match"), |b| {
            b.iter(|| {
                table.match_route_full(
                    black_box(Some("host0.example.com")),
                    black_box("/api/v0/users"),
                    black_box("GET"),
                    black_box(&headers),
                    black_box(None),
                    black_box(None),
                    black_box(None),
                )
            });
        });

        // Worst case: match last route
        let last = count - 1;
        let last_host = format!("host{last}.example.com");
        let last_path = format!("/api/v{last}/users");
        group.bench_function(format!("{count}_routes_last_match"), |b| {
            b.iter(|| {
                table.match_route_full(
                    black_box(Some(&last_host)),
                    black_box(&last_path),
                    black_box("GET"),
                    black_box(&headers),
                    black_box(None),
                    black_box(None),
                    black_box(None),
                )
            });
        });

        // Miss case: no route matches
        group.bench_function(format!("{count}_routes_no_match"), |b| {
            b.iter(|| {
                table.match_route_full(
                    black_box(Some("unknown.example.com")),
                    black_box("/nonexistent"),
                    black_box("GET"),
                    black_box(&headers),
                    black_box(None),
                    black_box(None),
                    black_box(None),
                )
            });
        });
    }

    group.finish();
}

fn bench_cache_key_generation(c: &mut Criterion) {
    use pingora_cache::CacheKey;

    c.bench_function("cache_key_generation", |b| {
        b.iter(|| {
            let primary = format!(
                "{}{}{}",
                black_box("GET"),
                black_box("api.example.com"),
                black_box("/api/v1/users?page=1&limit=50")
            );
            CacheKey::new("fluxo", primary, "")
        });
    });
}

fn bench_config_parsing(c: &mut Criterion) {
    let toml_str = r#"
[global]
admin = "127.0.0.1:2019"
log_level = "info"

[upstreams.backend]
targets = ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"]
load_balancing = "round_robin"

[upstreams.static_servers]
targets = ["10.0.1.1:80"]

[services.web]
listeners = [{ address = "0.0.0.0:80" }]
routes = [
    { match_host = ["api.example.com"], match_path = ["/api/*"], upstream = "backend" },
    { match_host = ["cdn.example.com"], match_path = ["/*"], upstream = "static_servers" },
]
"#;

    c.bench_function("config_parse_toml", |b| {
        b.iter(|| {
            let _config: FluxoConfig = toml::from_str(black_box(toml_str)).expect("parse");
        });
    });
}

fn bench_disk_cache_hash(c: &mut Criterion) {
    c.bench_function("disk_cache_sha256_hash", |b| {
        use sha2::{Digest, Sha256};
        let key = "GETapi.example.com/api/v1/users?page=1&limit=50";
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(key).as_bytes());
            let result = hasher.finalize();
            let _ = format!("{result:064x}");
        });
    });
}

criterion_group!(
    benches,
    bench_route_matching,
    bench_cache_key_generation,
    bench_config_parsing,
    bench_disk_cache_hash,
);
criterion_main!(benches);
