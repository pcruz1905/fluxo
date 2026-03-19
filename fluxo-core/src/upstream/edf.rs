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
            let weight = (target.weight as f64).max(1.0);
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
        let mut heap = self.heap.lock();
        let entry = heap.pop()?;
        let target = &self.targets[entry.index];
        let weight = (target.weight as f64).max(1.0);

        // Schedule next deadline for this target
        heap.push(EdfEntry {
            deadline: entry.deadline + 1.0 / weight,
            index: entry.index,
        });

        Some((entry.index, &target.address))
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
            .finish()
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
}
