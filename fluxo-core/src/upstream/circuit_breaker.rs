//! Circuit breaker — per-upstream failure tracking with 3-state machine.
//!
//! States: Closed (normal) → Open (reject all) → HalfOpen (probe) → Closed.
//!
//! Inspired by Traefik's circuit breaker and Netflix Hystrix.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::config::CircuitBreakerConfig;
use crate::upstream::UpstreamName;

/// Circuit breaker status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitStatus {
    /// Normal operation — requests flow through.
    Closed,
    /// Failures exceeded threshold — all requests rejected.
    Open,
    /// Probing — allow a limited number of requests to test recovery.
    HalfOpen,
}

/// Sliding window for tracking request outcomes over time.
/// Used for error ratio calculation (Traefik-style NetworkErrorRatio).
struct SlidingWindow {
    /// Ring buffer of (timestamp, is_failure) entries.
    entries: Vec<(Instant, bool)>,
    /// Window duration — only entries within this window count.
    window: Duration,
}

impl SlidingWindow {
    fn new(window: Duration) -> Self {
        Self {
            entries: Vec::with_capacity(256),
            window,
        }
    }

    fn record(&mut self, failure: bool) {
        let now = Instant::now();
        self.entries.push((now, failure));
        // Evict expired entries periodically
        if self.entries.len() > 200 {
            let cutoff = now - self.window;
            self.entries.retain(|(t, _)| *t > cutoff);
        }
    }

    /// Error ratio in [0.0, 1.0]. Returns 0.0 if no data.
    fn error_ratio(&self) -> f64 {
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut total = 0u32;
        let mut failures = 0u32;
        for (t, is_fail) in &self.entries {
            if *t > cutoff {
                total += 1;
                if *is_fail {
                    failures += 1;
                }
            }
        }
        if total == 0 {
            0.0
        } else {
            failures as f64 / total as f64
        }
    }

    fn total_in_window(&self) -> u32 {
        let cutoff = Instant::now() - self.window;
        self.entries.iter().filter(|(t, _)| *t > cutoff).count() as u32
    }
}

/// Per-upstream circuit breaker state.
struct CircuitState {
    status: CircuitStatus,
    failure_count: u32,
    success_count: u32,
    last_failure: Option<Instant>,
    config: CircuitBreakerConfig,
    open_duration: Duration,
    /// Sliding window for error ratio tracking.
    window: SlidingWindow,
}

impl CircuitState {
    fn new(config: CircuitBreakerConfig) -> Self {
        let open_duration = crate::config::parse_duration(&config.open_duration)
            .unwrap_or(Duration::from_secs(30));
        Self {
            status: CircuitStatus::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure: None,
            // Sliding window matches the open_duration for ratio calculation
            window: SlidingWindow::new(open_duration),
            config,
            open_duration,
        }
    }

    /// Check if the circuit allows a request. Returns the current status.
    fn check(&mut self) -> CircuitStatus {
        match self.status {
            CircuitStatus::Closed => CircuitStatus::Closed,
            CircuitStatus::Open => {
                // Check if we should transition to half-open
                if let Some(last) = self.last_failure {
                    if last.elapsed() >= self.open_duration {
                        self.status = CircuitStatus::HalfOpen;
                        self.success_count = 0;
                        return CircuitStatus::HalfOpen;
                    }
                }
                CircuitStatus::Open
            }
            CircuitStatus::HalfOpen => CircuitStatus::HalfOpen,
        }
    }

    /// Current error ratio from the sliding window.
    fn error_ratio(&self) -> f64 {
        self.window.error_ratio()
    }

    /// Record a successful request.
    fn record_success(&mut self) {
        self.window.record(false);
        match self.status {
            CircuitStatus::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.config.success_threshold {
                    // Recovered — close the circuit
                    self.status = CircuitStatus::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            }
            CircuitStatus::Closed => {
                // Reset consecutive failure count on success
                self.failure_count = 0;
            }
            CircuitStatus::Open => {}
        }
    }

    /// Record a failed request.
    fn record_failure(&mut self) {
        self.window.record(true);
        self.last_failure = Some(Instant::now());
        match self.status {
            CircuitStatus::Closed => {
                self.failure_count += 1;
                // Open circuit if consecutive failures OR error ratio exceeds threshold
                // Minimum 10 requests in window before ratio-based trip
                let ratio_trip = self.window.total_in_window() >= 10
                    && self.window.error_ratio() > 0.5;
                if self.failure_count >= self.config.failure_threshold || ratio_trip {
                    self.status = CircuitStatus::Open;
                }
            }
            CircuitStatus::HalfOpen => {
                // Any failure in half-open → back to open
                self.status = CircuitStatus::Open;
                self.success_count = 0;
            }
            CircuitStatus::Open => {}
        }
    }
}

/// Shared circuit breaker tracker — thread-safe, persists across config reloads.
pub struct CircuitBreakerTracker {
    states: DashMap<UpstreamName, Mutex<CircuitState>>,
}

impl Default for CircuitBreakerTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreakerTracker {
    pub fn new() -> Self {
        Self {
            states: DashMap::new(),
        }
    }

    /// Register or update circuit breaker config for an upstream.
    pub fn register(&self, name: UpstreamName, config: CircuitBreakerConfig) {
        self.states
            .entry(name)
            .or_insert_with(|| Mutex::new(CircuitState::new(config)));
    }

    /// Check if the circuit for an upstream allows requests.
    /// Returns `None` if no circuit breaker is configured for this upstream.
    pub fn check(&self, name: &UpstreamName) -> Option<CircuitStatus> {
        self.states
            .get(name)
            .map(|entry| entry.value().lock().check())
    }

    /// Record a successful request for an upstream.
    pub fn record_success(&self, name: &UpstreamName) {
        if let Some(entry) = self.states.get(name) {
            entry.value().lock().record_success();
        }
    }

    /// Record a failed request for an upstream.
    pub fn record_failure(&self, name: &UpstreamName) {
        if let Some(entry) = self.states.get(name) {
            entry.value().lock().record_failure();
        }
    }

    /// Get the current error ratio for an upstream (0.0-1.0).
    /// Returns `None` if no circuit breaker is configured.
    pub fn error_ratio(&self, name: &UpstreamName) -> Option<f64> {
        self.states
            .get(name)
            .map(|entry| entry.value().lock().error_ratio())
    }
}

/// Passive health tracker — tracks consecutive failures per peer address.
pub struct PassiveHealthTracker {
    /// Map of peer address → (consecutive_failures, last_failure_time)
    failures: DashMap<String, (AtomicU32, Mutex<Option<Instant>>)>,
}

impl Default for PassiveHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PassiveHealthTracker {
    pub fn new() -> Self {
        Self {
            failures: DashMap::new(),
        }
    }

    /// Record a failure for a peer. Returns the new consecutive failure count.
    pub fn record_failure(&self, peer_addr: &str) -> u32 {
        let entry = self.failures.entry(peer_addr.to_string()).or_insert_with(|| {
            (AtomicU32::new(0), Mutex::new(None))
        });
        let count = entry.value().0.fetch_add(1, Ordering::Relaxed) + 1;
        *entry.value().1.lock() = Some(Instant::now());
        count
    }

    /// Record a success for a peer — resets its failure count.
    pub fn record_success(&self, peer_addr: &str) {
        if let Some(entry) = self.failures.get(peer_addr) {
            entry.value().0.store(0, Ordering::Relaxed);
        }
    }

    /// Check if a peer is considered unhealthy (failures >= max_fails within fail_timeout).
    pub fn is_unhealthy(&self, peer_addr: &str, max_fails: u32, fail_timeout: Duration) -> bool {
        if let Some(entry) = self.failures.get(peer_addr) {
            let count = entry.value().0.load(Ordering::Relaxed);
            if count >= max_fails {
                // Check if within the fail_timeout window
                if let Some(last) = *entry.value().1.lock() {
                    if last.elapsed() < fail_timeout {
                        return true;
                    }
                    // Timeout expired — reset
                    entry.value().0.store(0, Ordering::Relaxed);
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CircuitBreakerConfig;
    use crate::upstream::UpstreamName;

    fn test_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            open_duration: "1s".to_string(),
        }
    }

    #[test]
    fn circuit_starts_closed() {
        let tracker = CircuitBreakerTracker::new();
        let name = UpstreamName::from("test");
        tracker.register(name.clone(), test_config());

        assert_eq!(tracker.check(&name), Some(CircuitStatus::Closed));
    }

    #[test]
    fn circuit_opens_after_threshold_failures() {
        let tracker = CircuitBreakerTracker::new();
        let name = UpstreamName::from("test");
        tracker.register(name.clone(), test_config());

        tracker.record_failure(&name);
        tracker.record_failure(&name);
        assert_eq!(tracker.check(&name), Some(CircuitStatus::Closed));

        tracker.record_failure(&name);
        assert_eq!(tracker.check(&name), Some(CircuitStatus::Open));
    }

    #[test]
    fn circuit_transitions_to_half_open_after_timeout() {
        let tracker = CircuitBreakerTracker::new();
        let name = UpstreamName::from("test");
        let mut config = test_config();
        config.open_duration = "1ms".to_string();
        tracker.register(name.clone(), config);

        // Open the circuit
        for _ in 0..3 {
            tracker.record_failure(&name);
        }
        assert_eq!(tracker.check(&name), Some(CircuitStatus::Open));

        // Wait for open_duration to elapse
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(tracker.check(&name), Some(CircuitStatus::HalfOpen));
    }

    #[test]
    fn circuit_closes_after_success_in_half_open() {
        let tracker = CircuitBreakerTracker::new();
        let name = UpstreamName::from("test");
        let mut config = test_config();
        config.open_duration = "1ms".to_string();
        tracker.register(name.clone(), config);

        // Open the circuit
        for _ in 0..3 {
            tracker.record_failure(&name);
        }

        // Wait for half-open
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(tracker.check(&name), Some(CircuitStatus::HalfOpen));

        // Successes in half-open → closed
        tracker.record_success(&name);
        tracker.record_success(&name);
        assert_eq!(tracker.check(&name), Some(CircuitStatus::Closed));
    }

    #[test]
    fn failure_in_half_open_reopens_circuit() {
        let tracker = CircuitBreakerTracker::new();
        let name = UpstreamName::from("test");
        let mut config = test_config();
        config.open_duration = "1ms".to_string();
        tracker.register(name.clone(), config);

        // Open → wait → half-open
        for _ in 0..3 {
            tracker.record_failure(&name);
        }
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(tracker.check(&name), Some(CircuitStatus::HalfOpen));

        // Failure in half-open → back to open
        tracker.record_failure(&name);
        assert_eq!(tracker.check(&name), Some(CircuitStatus::Open));
    }

    #[test]
    fn success_resets_failure_count_in_closed() {
        let tracker = CircuitBreakerTracker::new();
        let name = UpstreamName::from("test");
        tracker.register(name.clone(), test_config());

        tracker.record_failure(&name);
        tracker.record_failure(&name);
        tracker.record_success(&name); // resets count
        tracker.record_failure(&name);
        tracker.record_failure(&name);
        // Should still be closed (count was reset)
        assert_eq!(tracker.check(&name), Some(CircuitStatus::Closed));
    }

    #[test]
    fn passive_health_tracks_failures() {
        let tracker = PassiveHealthTracker::new();
        assert!(!tracker.is_unhealthy("127.0.0.1:3000", 3, Duration::from_secs(30)));

        tracker.record_failure("127.0.0.1:3000");
        tracker.record_failure("127.0.0.1:3000");
        assert!(!tracker.is_unhealthy("127.0.0.1:3000", 3, Duration::from_secs(30)));

        tracker.record_failure("127.0.0.1:3000");
        assert!(tracker.is_unhealthy("127.0.0.1:3000", 3, Duration::from_secs(30)));
    }

    #[test]
    fn passive_health_resets_on_success() {
        let tracker = PassiveHealthTracker::new();
        for _ in 0..5 {
            tracker.record_failure("127.0.0.1:3000");
        }
        assert!(tracker.is_unhealthy("127.0.0.1:3000", 3, Duration::from_secs(30)));

        tracker.record_success("127.0.0.1:3000");
        assert!(!tracker.is_unhealthy("127.0.0.1:3000", 3, Duration::from_secs(30)));
    }
}
