//! HTTP-01 challenge state — shared between the ACME client and the proxy.
//!
//! During ACME certificate acquisition, the ACME server verifies domain
//! ownership by requesting a token at `/.well-known/acme-challenge/{token}`.
//! This module holds the in-flight challenge tokens so `request_filter` can
//! serve them.

use std::collections::HashMap;
use std::sync::RwLock;

/// Shared state for in-flight ACME HTTP-01 challenges.
///
/// Thread-safe: stored in `FluxoState` and read from `request_filter` on the
/// hot path. Writes happen only during cert acquisition (rare).
#[derive(Debug, Default)]
pub struct ChallengeState {
    /// Maps challenge token → key authorization string.
    tokens: RwLock<HashMap<String, String>>,
}

impl ChallengeState {
    /// Create a new empty challenge state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pending challenge token.
    pub fn set(&self, token: String, key_authorization: String) {
        self.tokens
            .write()
            .expect("challenge state lock poisoned")
            .insert(token, key_authorization);
    }

    /// Look up a challenge token. Returns the key authorization if found.
    pub fn get(&self, token: &str) -> Option<String> {
        self.tokens
            .read()
            .expect("challenge state lock poisoned")
            .get(token)
            .cloned()
    }

    /// Remove a challenge token after validation completes.
    pub fn remove(&self, token: &str) {
        self.tokens
            .write()
            .expect("challenge state lock poisoned")
            .remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_remove() {
        let state = ChallengeState::new();

        assert!(state.get("token1").is_none());

        state.set("token1".to_string(), "auth1".to_string());
        assert_eq!(state.get("token1"), Some("auth1".to_string()));

        state.remove("token1");
        assert!(state.get("token1").is_none());
    }

    #[test]
    fn multiple_tokens() {
        let state = ChallengeState::new();

        state.set("a".to_string(), "auth-a".to_string());
        state.set("b".to_string(), "auth-b".to_string());

        assert_eq!(state.get("a"), Some("auth-a".to_string()));
        assert_eq!(state.get("b"), Some("auth-b".to_string()));
    }
}
