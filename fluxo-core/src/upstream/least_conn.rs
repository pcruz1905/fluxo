//! Least Connections load balancing scheduler.
//!
//! Selects the backend with the fewest active connections. Uses atomic counters
//! per target for lock-free reads and minimal contention.
//! Ties are broken by round-robin (index rotation).

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// A target in the least-connections scheduler.
#[derive(Debug)]
struct LcTarget {
    address: String,
    /// Number of currently active connections to this target.
    active: AtomicU64,
}

/// Least-connections load balancer.
///
/// Selection is O(n) scan over targets, but N is typically small (<100).
/// Thread-safe via atomic counters — no locks on the selection hot path.
pub struct LeastConnScheduler {
    targets: Vec<LcTarget>,
    /// Tie-breaker rotation to avoid always picking the first target.
    rotation: AtomicUsize,
}

impl LeastConnScheduler {
    /// Create a new scheduler from target addresses.
    pub fn new(addresses: Vec<String>) -> Self {
        let targets = addresses
            .into_iter()
            .map(|address| LcTarget {
                address,
                active: AtomicU64::new(0),
            })
            .collect();
        Self {
            targets,
            rotation: AtomicUsize::new(0),
        }
    }

    /// Select the target with the fewest active connections.
    ///
    /// Returns `(index, address)`. Caller must call `release(index)` when the
    /// request completes to decrement the active count.
    pub fn select(&self) -> Option<(usize, &str)> {
        if self.targets.is_empty() {
            return None;
        }

        let n = self.targets.len();
        let offset = self.rotation.fetch_add(1, Ordering::Relaxed) % n;

        let mut best_idx = offset;
        let mut best_count = self.targets[offset].active.load(Ordering::Relaxed);

        for i in 1..n {
            let idx = (offset + i) % n;
            let count = self.targets[idx].active.load(Ordering::Relaxed);
            if count < best_count {
                best_count = count;
                best_idx = idx;
            }
        }

        self.targets[best_idx].active.fetch_add(1, Ordering::Relaxed);
        Some((best_idx, &self.targets[best_idx].address))
    }

    /// Release a connection slot for the given target index.
    ///
    /// Must be called when the request to this target completes.
    pub fn release(&self, index: usize) {
        if index < self.targets.len() {
            self.targets[index].active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Get the number of targets.
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Check if the scheduler has no targets.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

impl std::fmt::Debug for LeastConnScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeastConnScheduler")
            .field(
                "targets",
                &self
                    .targets
                    .iter()
                    .map(|t| &t.address)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn selects_target_with_fewest_connections() {
        let scheduler = LeastConnScheduler::new(vec![
            "a:8080".into(),
            "b:8080".into(),
            "c:8080".into(),
        ]);

        // First selection — all at 0, picks based on rotation
        let (idx0, _) = scheduler.select().unwrap();
        // idx0 now has 1 active

        // Next selection should pick a different target (0 active)
        let (idx1, _) = scheduler.select().unwrap();
        assert_ne!(idx0, idx1, "should pick different target with fewer connections");

        // Release first, now idx0 is back to 0
        scheduler.release(idx0);

        // Third selection — idx0 is 0, idx1 is 1, should not pick idx1
        let (idx2, _) = scheduler.select().unwrap();
        assert_ne!(idx2, idx1, "should avoid the target with most connections");
    }

    #[test]
    fn empty_scheduler() {
        let scheduler = LeastConnScheduler::new(vec![]);
        assert!(scheduler.select().is_none());
        assert!(scheduler.is_empty());
    }

    #[test]
    fn single_target_always_selected() {
        let scheduler = LeastConnScheduler::new(vec!["only:8080".into()]);
        for _ in 0..5 {
            let (idx, addr) = scheduler.select().unwrap();
            assert_eq!(idx, 0);
            assert_eq!(addr, "only:8080");
        }
        // Release all
        for _ in 0..5 {
            scheduler.release(0);
        }
    }

    #[test]
    fn release_decrements_count() {
        let scheduler = LeastConnScheduler::new(vec!["a:8080".into(), "b:8080".into()]);

        let (idx, _) = scheduler.select().unwrap();
        // Active count is now 1 for idx
        assert_eq!(scheduler.targets[idx].active.load(Ordering::Relaxed), 1);

        scheduler.release(idx);
        assert_eq!(scheduler.targets[idx].active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn distributes_evenly_when_released() {
        let scheduler = LeastConnScheduler::new(vec![
            "a:8080".into(),
            "b:8080".into(),
            "c:8080".into(),
        ]);

        let mut counts = [0u32; 3];
        for _ in 0..300 {
            let (idx, _) = scheduler.select().unwrap();
            counts[idx] += 1;
            scheduler.release(idx); // release immediately — all stay at 0
        }
        // Should be roughly equal distribution
        assert!(counts[0] == 100 && counts[1] == 100 && counts[2] == 100);
    }
}
