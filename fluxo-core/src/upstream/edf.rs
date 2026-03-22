//! Earliest Deadline First (EDF) weighted scheduler.
//!
//! Traefik-inspired: uses a min-heap to distribute requests proportionally to weights.
//! Each target's next deadline is `current + 1.0/weight`. The target with the
//! earliest deadline is always selected next, achieving precise weighted distribution.
//!
//! Advantages over weight-by-repetition (Pingora's default WRR):
//! - O(log n) selection instead of O(1) but with O(N*W) memory
//! - No memory waste for large weights (weight=1000 doesn't create 1000 copies)
//! - Mathematically precise distribution

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// An entry in the EDF scheduler's min-heap.
#[derive(Debug, Clone)]
struct EdfEntry {
    /// Virtual deadline — lower means "due sooner".
    deadline: f64,
    /// Index into the targets array.
    index: usize,
}

impl PartialEq for EdfEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.index == other.index
    }
}

impl Eq for EdfEntry {}

// Reverse ordering for min-heap behavior (BinaryHeap is max-heap by default).
impl PartialOrd for EdfEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EdfEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse: smaller deadline = higher priority
        other
            .deadline
            .partial_cmp(&self.deadline)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.index.cmp(&self.index))
    }
}

/// A target with its weight and address.
#[derive(Debug, Clone)]
pub struct EdfTarget {
    pub address: String,
    pub weight: u32,
}

/// EDF-based weighted scheduler.
///
/// Thread-safe via `parking_lot::Mutex` — selection is O(log n) so contention is minimal.
pub struct EdfScheduler {
    targets: Vec<EdfTarget>,
    heap: parking_lot::Mutex<BinaryHeap<EdfEntry>>,
}

impl EdfScheduler {
    /// Create a new EDF scheduler from weighted targets.
    ///
    /// Each target starts with deadline `1.0 / weight`.
    pub fn new(targets: Vec<EdfTarget>) -> Self {
        let mut heap = BinaryHeap::with_capacity(targets.len());
        for (i, target) in targets.iter().enumerate() {
            let weight = f64::from(target.weight).max(1.0);
            heap.push(EdfEntry {
                deadline: 1.0 / weight,
                index: i,
            });
        }
        Self {
            targets,
            heap: parking_lot::Mutex::new(heap),
        }
    }

    /// Select the next target. Returns the target address and index.
    ///
    /// O(log n) — pops the min-deadline entry, computes next deadline, pushes back.
    pub fn select(&self) -> Option<(usize, &str)> {
        let idx = {
            let mut heap = self.heap.lock();
            let entry = heap.pop()?;
            let weight = f64::from(self.targets[entry.index].weight).max(1.0);
            let index = entry.index;

            // Schedule next deadline for this target
            heap.push(EdfEntry {
                deadline: entry.deadline + 1.0 / weight,
                index,
            });

            drop(heap);
            index
        };

        Some((idx, &self.targets[idx].address))
    }

    /// Select the next healthy target, skipping unhealthy ones.
    ///
    /// The `is_healthy` predicate receives a peer address and returns `true` if
    /// the peer should receive traffic. Tries up to N targets (one full cycle)
    /// before giving up.
    pub fn select_healthy<F>(&self, is_healthy: F) -> Option<(usize, &str)>
    where
        F: Fn(&str) -> bool,
    {
        let n = self.targets.len();
        for _ in 0..n {
            let (idx, addr) = self.select()?;
            if is_healthy(addr) {
                return Some((idx, addr));
            }
            // Unhealthy — the entry was already re-pushed by select(), so the
            // next call will pick the next-deadline target automatically.
        }
        // All targets unhealthy — fall back to returning whatever EDF picks
        // (better to send traffic somewhere than drop it entirely).
        self.select()
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

impl std::fmt::Debug for EdfScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdfScheduler")
            .field("targets", &self.targets)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn equal_weights_round_robin() {
        let scheduler = EdfScheduler::new(vec![
            EdfTarget {
                address: "a".into(),
                weight: 1,
            },
            EdfTarget {
                address: "b".into(),
                weight: 1,
            },
            EdfTarget {
                address: "c".into(),
                weight: 1,
            },
        ]);

        // With equal weights, should cycle through all targets
        let mut counts = [0u32; 3];
        for _ in 0..300 {
            let (idx, _) = scheduler.select().unwrap();
            counts[idx] += 1;
        }
        // Each should get exactly 100
        assert_eq!(counts, [100, 100, 100]);
    }

    #[test]
    fn weighted_distribution() {
        let scheduler = EdfScheduler::new(vec![
            EdfTarget {
                address: "a".into(),
                weight: 3,
            },
            EdfTarget {
                address: "b".into(),
                weight: 1,
            },
        ]);

        let mut counts = [0u32; 2];
        for _ in 0..400 {
            let (idx, _) = scheduler.select().unwrap();
            counts[idx] += 1;
        }
        // 3:1 ratio → 300:100
        assert_eq!(counts[0], 300);
        assert_eq!(counts[1], 100);
    }

    #[test]
    fn single_target() {
        let scheduler = EdfScheduler::new(vec![EdfTarget {
            address: "only".into(),
            weight: 5,
        }]);

        for _ in 0..10 {
            let (idx, addr) = scheduler.select().unwrap();
            assert_eq!(idx, 0);
            assert_eq!(addr, "only");
        }
    }

    #[test]
    fn empty_scheduler() {
        let scheduler = EdfScheduler::new(vec![]);
        assert!(scheduler.select().is_none());
        assert!(scheduler.is_empty());
    }

    #[test]
    fn large_weight_difference() {
        let scheduler = EdfScheduler::new(vec![
            EdfTarget {
                address: "heavy".into(),
                weight: 100,
            },
            EdfTarget {
                address: "light".into(),
                weight: 1,
            },
        ]);

        let mut counts = [0u32; 2];
        for _ in 0..1010 {
            let (idx, _) = scheduler.select().unwrap();
            counts[idx] += 1;
        }
        // 100:1 ratio → ~1000:10
        assert_eq!(counts[0], 1000);
        assert_eq!(counts[1], 10);
    }

    #[test]
    fn select_healthy_skips_unhealthy() {
        let scheduler = EdfScheduler::new(vec![
            EdfTarget {
                address: "a".into(),
                weight: 1,
            },
            EdfTarget {
                address: "b".into(),
                weight: 1,
            },
            EdfTarget {
                address: "c".into(),
                weight: 1,
            },
        ]);

        // Mark "a" as unhealthy
        let is_healthy = |addr: &str| addr != "a";

        let mut counts = std::collections::HashMap::new();
        for _ in 0..100 {
            let (_, addr) = scheduler.select_healthy(is_healthy).unwrap();
            *counts.entry(addr.to_string()).or_insert(0u32) += 1;
        }
        // "a" should never be selected
        assert_eq!(
            counts.get("a"),
            None,
            "unhealthy peer 'a' should be skipped"
        );
        assert!(
            counts.get("b").unwrap_or(&0) > &0,
            "'b' should receive traffic"
        );
        assert!(
            counts.get("c").unwrap_or(&0) > &0,
            "'c' should receive traffic"
        );
    }

    #[test]
    fn select_healthy_all_unhealthy_falls_back() {
        let scheduler = EdfScheduler::new(vec![
            EdfTarget {
                address: "a".into(),
                weight: 1,
            },
            EdfTarget {
                address: "b".into(),
                weight: 1,
            },
        ]);

        // All unhealthy — should still return something (fallback)
        let none_healthy = |_: &str| false;
        let result = scheduler.select_healthy(none_healthy);
        assert!(
            result.is_some(),
            "should fall back to a peer when all are unhealthy"
        );
    }

    #[test]
    fn select_healthy_all_healthy_preserves_distribution() {
        let scheduler = EdfScheduler::new(vec![
            EdfTarget {
                address: "a".into(),
                weight: 3,
            },
            EdfTarget {
                address: "b".into(),
                weight: 1,
            },
        ]);

        // All healthy — should behave like normal weighted distribution
        let all_healthy = |_: &str| true;
        let mut counts = [0u32; 2];
        for _ in 0..400 {
            let (idx, _) = scheduler.select_healthy(all_healthy).unwrap();
            counts[idx] += 1;
        }
        // 3:1 ratio should still hold
        assert_eq!(counts[0], 300);
        assert_eq!(counts[1], 100);
    }
}
