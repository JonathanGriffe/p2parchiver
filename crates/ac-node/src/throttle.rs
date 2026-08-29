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

    #[cfg(test)]
    pub fn is_limited(&self) -> bool {
        self.bucket.is_some()
    }

    /// Bytes that have passed through since this node started.
    pub fn moved(&self) -> u64 {
        self.moved.load(Ordering::Relaxed)
    }

    /// Wait until `n` bytes may move, then account for them.
    pub async fn consume(&self, n: usize) {
        // Counted above the early return, so an unthrottled node still has a total. Nothing
        // reads this often enough for the ordering to matter.
        self.moved.fetch_add(n as u64, Ordering::Relaxed);

        let Some(bucket) = &self.bucket else {
            return;
        };

        let mut owed = n as f64;
        while owed > 0.0 {
            let wait = {
                // Not held across the await below: the sleep happens outside this block.
                let mut b = bucket.lock().unwrap_or_else(|e| e.into_inner());
                b.refill();

                let taken = owed.min(b.tokens);
                b.tokens -= taken;
                owed -= taken;

                if owed <= 0.0 {
                    return;
                }

                let bite = owed.min(b.burst);
                Duration::from_secs_f64((bite - b.tokens).max(0.0) / b.rate)
            };
            tokio::time::sleep(wait).await;
        }
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

    /// The total is what the Status page shows, so it has to keep counting on the nodes that
    /// set no limit — which is most of them.
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
