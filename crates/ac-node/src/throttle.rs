use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// A rate limit on bytes, shared by everything moving them in one direction.
#[derive(Debug)]
pub struct Throttle {
    bucket: Option<Mutex<Bucket>>,
    /// Every byte that passed through, limit or no limit.
    moved: AtomicU64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl Throttle {
    /// No limit. Every call returns without waiting.
    pub fn none() -> Self {
        Self {
            bucket: None,
            moved: AtomicU64::new(0),
        }
    }

    /// `bytes_per_second` bytes a second, with a burst of `burst` bytes.
    pub fn new(bytes_per_second: u64, burst: u64) -> Self {
        let rate = bytes_per_second.max(1) as f64;
        Self {
            bucket: Some(Mutex::new(Bucket {
                tokens: 0.0,
                rate,
                burst: (burst as f64).max(rate),
                last: Instant::now(),
            })),
            moved: AtomicU64::new(0),
        }
    }

    /// From config: `None` is no limit.
    pub fn from_config(bytes_per_second: Option<u64>, burst: u64) -> Self {
        match bytes_per_second {
            Some(rate) => Self::new(rate, burst),
            None => Self::none(),
        }
    }

    /// Whether there is a cap
    pub fn is_limited(&self) -> bool {
        self.bucket.is_some()
    }

    /// Bytes that have passed through since this node started.
    pub fn moved(&self) -> u64 {
        self.moved.load(Ordering::Relaxed)
    }

    /// Wait until `n` bytes may move, then account for them.
    pub async fn consume(&self, n: usize) {
        self.moved.fetch_add(n as u64, Ordering::Relaxed);
        let mut owed = n as f64;
        while let Some(wait) = self.take(&mut owed) {
            tokio::time::sleep(wait).await;
        }
    }

    /// The same, for a caller with no runtime to await in.
    ///
    /// The CLI's import is one: `main` is not async, and the pump runs on the thread that
    /// typed the command. Sleeping it is the whole intent — there is nothing else on it.
    pub fn consume_blocking(&self, n: usize) {
        self.moved.fetch_add(n as u64, Ordering::Relaxed);
        let mut owed = n as f64;
        while let Some(wait) = self.take(&mut owed) {
            std::thread::sleep(wait);
        }
    }

    /// Spend what the bucket holds against `owed`, and say how long until it is worth asking
    /// again. `None` once nothing is owed, which is immediately when there is no limit.
    ///
    /// Split out so the waiting is the only thing the two callers above do differently: the
    /// lock is never held across either sleep.
    fn take(&self, owed: &mut f64) -> Option<Duration> {
        if *owed <= 0.0 {
            return None;
        }
        let bucket = self.bucket.as_ref()?;

        let mut b = bucket.lock().unwrap_or_else(|e| e.into_inner());
        b.refill();

        let taken = owed.min(b.tokens);
        b.tokens -= taken;
        *owed -= taken;

        if *owed <= 0.0 {
            return None;
        }

        let bite = owed.min(b.burst);
        Some(Duration::from_secs_f64((bite - b.tokens).max(0.0) / b.rate))
    }
}

impl Bucket {
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_limit_never_waits() {
        let t = Throttle::none();
        let start = Instant::now();
        for _ in 0..1000 {
            t.consume(1024 * 1024).await;
        }
        assert!(!t.is_limited());
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "unlimited should be free"
        );
    }

    #[tokio::test]
    async fn bytes_are_counted_even_with_no_limit_to_apply() {
        let t = Throttle::none();
        t.consume(1000).await;
        t.consume(24).await;

        assert_eq!(t.moved(), 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn a_limited_throttle_counts_the_same_bytes_it_delays() {
        let t = Throttle::new(1024, 1024);
        t.consume(4096).await;

        assert_eq!(t.moved(), 4096);
    }

    #[tokio::test(start_paused = true)]
    async fn bytes_take_the_time_the_rate_says() {
        let t = Throttle::new(1024, 1024);
        let start = Instant::now();
        t.consume(4096).await;
        let took = start.elapsed();

        assert!(
            took >= Duration::from_secs(3) && took <= Duration::from_secs(5),
            "4 KiB at 1 KiB/s should take about four seconds, took {took:?}"
        );
    }

    /// Deliberately not a `tokio::test`: the CLI's import runs under a plain `fn main`, and
    /// the point of this path is that it needs no runtime to wait in. Time cannot be paused
    /// without one, so the numbers are small enough to wait out for real.
    #[test]
    fn a_blocking_caller_waits_without_a_runtime() {
        let t = Throttle::new(4096, 4096);
        let start = std::time::Instant::now();
        t.consume_blocking(1024);
        let took = start.elapsed();

        assert!(
            took >= Duration::from_millis(150) && took < Duration::from_secs(2),
            "1 KiB at 4 KiB/s should take about a quarter second, took {took:?}"
        );
        assert_eq!(t.moved(), 1024, "and it is counted like any other byte");
    }

    /// The other half: no limit means no wait, and still no runtime.
    #[test]
    fn a_blocking_caller_with_no_limit_never_waits() {
        let t = Throttle::none();
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            t.consume_blocking(1024 * 1024);
        }

        assert!(start.elapsed() < Duration::from_millis(50));
        assert_eq!(t.moved(), 1000 * 1024 * 1024);
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_is_spent_before_the_rate_applies() {
        let t = Throttle::new(1024, 64 * 1024);
        // Let the bucket fill to its ceiling.
        tokio::time::sleep(Duration::from_secs(120)).await;

        let start = Instant::now();
        t.consume(64 * 1024).await;
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "a full bucket should hand over its burst at once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_burst_is_never_less_than_a_second_of_rate() {
        // Asking for a burst below the rate would make a full second's worth unspendable.
        let t = Throttle::new(1024 * 1024, 1024);
        tokio::time::sleep(Duration::from_secs(5)).await;

        let start = Instant::now();
        t.consume(1024 * 1024).await;
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "one second of rate should be spendable in one go"
        );
    }
}
