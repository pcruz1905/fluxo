//! `FluxoApp` — top-level orchestrator that wires config, proxy, and server together.

use crate::config::FluxoConfig;
use crate::error::FluxoError;
use crate::proxy::{FluxoProxy, FluxoState};

/// The top-level Fluxo application.
pub struct FluxoApp {
    config: FluxoConfig,
    proxy: FluxoProxy,
}

impl FluxoApp {
    /// Create a new FluxoApp from a validated config.
    ///
    /// Builds the pre-computed `FluxoState` (compiled routes, initialized load
    /// balancers) and wraps it in a `FluxoProxy` with ArcSwap.
    pub fn from_config(config: FluxoConfig) -> Result<Self, FluxoError> {
        let state = FluxoState::try_from_config(config.clone())?;
        let proxy = FluxoProxy::new(state);
        Ok(Self { config, proxy })
    }

    /// Get a clone of the proxy for registering with Pingora services.
    ///
    /// `FluxoProxy` is cheap to clone (it's an `Arc<ArcSwap<FluxoState>>`).
    pub fn proxy(&self) -> FluxoProxy {
        self.proxy.clone()
    }

    /// Get a reference to the original config.
    pub fn config(&self) -> &FluxoConfig {
        &self.config
    }

    /// Reload the proxy with a new config.
    ///
    /// Builds a new `FluxoState` and atomically swaps it into the proxy.
    /// Returns an error if the new config is invalid; the old config remains active.
    pub fn reload(&self, new_config: FluxoConfig) -> Result<(), FluxoError> {
        let new_state = FluxoState::try_from_config(new_config)?;
        self.proxy.reload(new_state);
        Ok(())
    }
}
