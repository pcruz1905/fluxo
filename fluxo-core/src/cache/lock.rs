//! Cache stampede protection — prevents thundering herd on cache misses.
//!
//! When a cached entry expires and multiple requests arrive simultaneously,
//! only the first request fetches from upstream while others wait (or are served stale).
//! Inspired by Nginx `proxy_cache_lock` and Pingap's cache lock.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::broadcast;

/// Cache lock manager — coordinates concurrent requests for the same cache key.
pub struct CacheLockManager {
    locks: Mutex<HashMap<String, Arc<CacheLockEntry>>>,
    /// Maximum time to wait for a lock before bypassing cache. Default: 3s.
    pub lock_timeout: Duration,
}

struct CacheLockEntry {
    /// When this lock was acquired.
    created: Instant,
    /// Broadcast channel — waiters subscribe, the fetcher sends when done.
    notify: broadcast::Sender<()>,
}

/// Result of attempting to acquire a cache lock.
pub enum CacheLockResult {
    /// This request should fetch from upstream (first one in).
    Fetch,
    /// Another request is already fetching — wait for it.
    Wait(broadcast::Receiver<()>),
    /// Lock timed out — bypass cache and fetch directly.
    Bypass,
}

impl CacheLockManager {
    /// Create a new cache lock manager.
    pub fn new(lock_timeout: Duration) -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
            lock_timeout,
        }
    }

    /// Try to acquire a lock for the given cache key.
    pub fn try_lock(&self, key: &str) -> CacheLockResult {
        let mut locks = self.locks.lock();

        if let Some(entry) = locks.get(key) {
            // Check if the existing lock has timed out
            if entry.created.elapsed() > self.lock_timeout {
                // Lock expired — remove it and let this request through
                locks.remove(key);
            } else {
                // Another request is fetching — subscribe and wait
                let rx = entry.notify.subscribe();
                return CacheLockResult::Wait(rx);
            }
        }

        // No existing lock — this request will fetch
        let (tx, _) = broadcast::channel(1);
        let entry = Arc::new(CacheLockEntry {
            created: Instant::now(),
            notify: tx,
        });
        locks.insert(key.to_string(), entry);
        CacheLockResult::Fetch
    }

    /// Release the lock for the given cache key, notifying all waiters.
    pub fn unlock(&self, key: &str) {
        let mut locks = self.locks.lock();
        if let Some(entry) = locks.remove(key) {
            // Notify all waiters (ignore send errors — no receivers is fine)
            let _ = entry.notify.send(());
        }
    }

    /// Clean up expired locks (call periodically from a background task).
    pub fn cleanup_expired(&self) {
        let mut locks = self.locks.lock();
        let timeout = self.lock_timeout;
        locks.retain(|_, entry| entry.created.elapsed() <= timeout);
    }

    /// Number of active locks (for metrics/debugging).
    pub fn active_locks(&self) -> usize {
        self.locks.lock().len()
    }
}

impl Default for CacheLockManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(3))
    }
}

impl std::fmt::Debug for CacheLockManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheLockManager")
            .field("lock_timeout", &self.lock_timeout)
            .field("locks", &self.active_locks())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn first_request_gets_fetch() {
        let mgr = CacheLockManager::default();
        assert!(matches!(mgr.try_lock("key1"), CacheLockResult::Fetch));
    }

    #[test]
    fn second_request_gets_wait() {
        let mgr = CacheLockManager::default();
        let _first = mgr.try_lock("key1");
        assert!(matches!(mgr.try_lock("key1"), CacheLockResult::Wait(_)));
    }

    #[test]
    fn different_keys_both_get_fetch() {
        let mgr = CacheLockManager::default();
        assert!(matches!(mgr.try_lock("key1"), CacheLockResult::Fetch));
        assert!(matches!(mgr.try_lock("key2"), CacheLockResult::Fetch));
    }

    #[test]
    fn unlock_allows_new_fetch() {
        let mgr = CacheLockManager::default();
        let _first = mgr.try_lock("key1");
        mgr.unlock("key1");
        assert!(matches!(mgr.try_lock("key1"), CacheLockResult::Fetch));
    }

    #[test]
    fn active_locks_count() {
        let mgr = CacheLockManager::default();
        assert_eq!(mgr.active_locks(), 0);
        let _first = mgr.try_lock("key1");
        assert_eq!(mgr.active_locks(), 1);
        let _second = mgr.try_lock("key2");
        assert_eq!(mgr.active_locks(), 2);
        mgr.unlock("key1");
        assert_eq!(mgr.active_locks(), 1);
    }

    #[test]
    fn expired_lock_allows_bypass() {
        let mgr = CacheLockManager::new(Duration::from_millis(1));
        let _first = mgr.try_lock("key1");
        // Wait for lock to expire
        std::thread::sleep(Duration::from_millis(5));
        // Expired lock should be removed, allowing a new fetch
        assert!(matches!(mgr.try_lock("key1"), CacheLockResult::Fetch));
    }

    #[test]
    fn cleanup_removes_expired() {
        let mgr = CacheLockManager::new(Duration::from_millis(1));
        let _first = mgr.try_lock("key1");
        std::thread::sleep(Duration::from_millis(5));
        mgr.cleanup_expired();
        assert_eq!(mgr.active_locks(), 0);
    }
}
