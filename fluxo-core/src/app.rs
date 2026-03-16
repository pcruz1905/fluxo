//! `FluxoApp` — top-level orchestrator that wires config, proxy, and server together.
//!
//! This is a thin coordination layer. For v0.1, it simply constructs a `FluxoProxy`
//! with a hardcoded upstream. Later steps will add `FluxoState`, ArcSwap, etc.

use crate::proxy::FluxoProxy;

/// The top-level Fluxo application.
pub struct FluxoApp {
    proxy: FluxoProxy,
}

impl FluxoApp {
    /// Create a new FluxoApp that proxies to the given upstream address.
    pub fn new(upstream_addr: String) -> Self {
        let proxy = FluxoProxy::new(upstream_addr);
        Self { proxy }
    }

    /// Get a reference to the proxy for registering with Pingora.
    pub fn proxy(&self) -> &FluxoProxy {
        &self.proxy
    }
}
