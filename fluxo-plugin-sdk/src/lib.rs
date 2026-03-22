//! Fluxo Plugin SDK — defines the ABI for external Wasm plugins.
//!
//! Plugins are compiled to WebAssembly (`.wasm`) and loaded at runtime.
//! The host (Fluxo) calls exported functions at each request lifecycle phase.
//!
//! # Plugin Lifecycle
//!
//! 1. `on_request` — Called when a request arrives. Can modify headers or short-circuit.
//! 2. `on_upstream_request` — Called before forwarding to upstream. Can modify headers.
//! 3. `on_response` — Called when upstream responds. Can modify response headers.
//!
//! # Memory Model
//!
//! The host provides memory import functions for the guest to read/write headers:
//! - `host_get_request_header(name_ptr, name_len) -> (ptr, len)` — read a request header
//! - `host_set_request_header(name_ptr, name_len, val_ptr, val_len)` — set a request header
//! - `host_get_response_header(name_ptr, name_len) -> (ptr, len)` — read a response header
//! - `host_set_response_header(name_ptr, name_len, val_ptr, val_len)` — set a response header
//!
//! # Example Plugin (Rust → Wasm)
//!
//! ```rust,ignore
//! use fluxo_plugin_sdk::*;
//!
//! #[no_mangle]
//! pub extern "C" fn on_request() -> PluginResult {
//!     let ua = get_request_header("user-agent").unwrap_or_default();
//!     if ua.contains("bot") {
//!         return PluginResult::Handled(403);
//!     }
//!     PluginResult::Continue
//! }
//! ```

/// Result of a plugin phase execution.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginResult {
    /// Continue to the next plugin / proxy phase.
    Continue = 0,
    /// Short-circuit with an HTTP status code.
    Handled = 1,
}

/// Plugin metadata — returned by the `plugin_info` export.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin name (UTF-8, null-terminated).
    pub name: &'static str,
    /// Plugin version (semver).
    pub version: &'static str,
    /// Minimum SDK version required.
    pub min_sdk_version: &'static str,
}

/// Plugin configuration key-value pair.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    pub key: *const u8,
    pub key_len: u32,
    pub value: *const u8,
    pub value_len: u32,
}

/// ABI version — plugins must export a function returning this.
pub const ABI_VERSION: u32 = 1;

/// Maximum plugin config size in bytes.
pub const MAX_CONFIG_SIZE: usize = 65536;

/// Maximum header value size in bytes.
pub const MAX_HEADER_SIZE: usize = 8192;

/// Host function signatures that the Wasm runtime imports into the guest.
///
/// These are the functions available to plugin authors for interacting
/// with the request/response lifecycle.
pub mod host_functions {
    /// Get a request header value by name.
    /// Returns 0 on success, -1 if header not found.
    pub type GetRequestHeader = extern "C" fn(
        name_ptr: *const u8,
        name_len: u32,
        value_out_ptr: *mut u8,
        value_out_len: *mut u32,
    ) -> i32;

    /// Set a request header.
    pub type SetRequestHeader = extern "C" fn(
        name_ptr: *const u8,
        name_len: u32,
        value_ptr: *const u8,
        value_len: u32,
    ) -> i32;

    /// Get a response header value by name.
    pub type GetResponseHeader = extern "C" fn(
        name_ptr: *const u8,
        name_len: u32,
        value_out_ptr: *mut u8,
        value_out_len: *mut u32,
    ) -> i32;

    /// Set a response header.
    pub type SetResponseHeader = extern "C" fn(
        name_ptr: *const u8,
        name_len: u32,
        value_ptr: *const u8,
        value_len: u32,
    ) -> i32;

    /// Get the client IP address as a string.
    pub type GetClientIp = extern "C" fn(ip_out_ptr: *mut u8, ip_out_len: *mut u32) -> i32;

    /// Get the request path.
    pub type GetRequestPath = extern "C" fn(path_out_ptr: *mut u8, path_out_len: *mut u32) -> i32;

    /// Get the request method.
    pub type GetRequestMethod =
        extern "C" fn(method_out_ptr: *mut u8, method_out_len: *mut u32) -> i32;

    /// Log a message from the plugin.
    pub type Log = extern "C" fn(
        level: u32, // 0=trace, 1=debug, 2=info, 3=warn, 4=error
        msg_ptr: *const u8,
        msg_len: u32,
    );
}

/// Guest export signatures — functions that plugins must implement.
pub mod guest_exports {
    /// Returns the ABI version (must match `ABI_VERSION`).
    pub const ABI_VERSION_FUNC: &str = "fluxo_abi_version";

    /// Returns plugin metadata.
    pub const PLUGIN_INFO_FUNC: &str = "fluxo_plugin_info";

    /// Called with plugin configuration JSON.
    pub const CONFIGURE_FUNC: &str = "fluxo_configure";

    /// Request phase handler.
    pub const ON_REQUEST_FUNC: &str = "fluxo_on_request";

    /// Upstream request phase handler.
    pub const ON_UPSTREAM_REQUEST_FUNC: &str = "fluxo_on_upstream_request";

    /// Response phase handler.
    pub const ON_RESPONSE_FUNC: &str = "fluxo_on_response";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_stable() {
        assert_eq!(ABI_VERSION, 1);
    }

    #[test]
    fn plugin_result_values() {
        assert_eq!(PluginResult::Continue as u32, 0);
        assert_eq!(PluginResult::Handled as u32, 1);
    }

    #[test]
    fn export_names_are_prefixed() {
        assert!(guest_exports::ON_REQUEST_FUNC.starts_with("fluxo_"));
        assert!(guest_exports::ON_RESPONSE_FUNC.starts_with("fluxo_"));
        assert!(guest_exports::CONFIGURE_FUNC.starts_with("fluxo_"));
    }
}
