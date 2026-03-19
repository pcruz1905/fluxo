//! Fluxo Core — the proxy engine for the Fluxo reverse proxy.
//!
//! This crate contains all proxy logic: configuration, routing, upstream
//! management, the Pingora `ProxyHttp` implementation, and plugin infrastructure.

pub mod admin;
pub mod app;
pub mod config;
pub mod context;
pub mod error;
pub mod observability;
pub mod plugins;
pub mod proxy;
pub mod proxy_protocol;
pub mod routing;
pub mod tls;
pub mod upstream;

pub use app::FluxoApp;
pub use context::RequestContext;
pub use error::FluxoError;
pub use proxy::{FluxoBuild, FluxoProxy, FluxoState};
pub use tls::{CertStore, ChallengeState};
