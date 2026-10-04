//! Token buckets refilled by monotonic time (quick-protocol §5.2.1).

use nsshared_proto::relay::budget::RateLimit;
use std::time::Instant;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// A token bucket that starts full; tokens are kept in nano-token units so refills of
/// any elapsed time are exact.
#[derive(Clone, Debug)]
pub(crate) struct TokenBucket {
    limit: RateLimit,
    nano_tokens: u128,
    last: Instant,
}

impl TokenBucket {
    pub(crate) fn new(limit: RateLimit, now: Instant) -> Self {
        Self {
            limit,
            nano_tokens: u128::from(limit.burst) * NANOS_PER_SECOND,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_nanos();
        let capacity = u128::from(self.limit.burst) * NANOS_PER_SECOND;
        self.nano_tokens = self
            .nano_tokens
            .saturating_add(elapsed.saturating_mul(u128::from(self.limit.per_second)))
            .min(capacity);
        self.last = self.last.max(now);
    }

    /// Returns true when `amount` tokens are available at `now`, without taking them.
    pub(crate) fn has(&mut self, now: Instant, amount: u64) -> bool {
        self.refill(now);
        self.nano_tokens >= u128::from(amount) * NANOS_PER_SECOND
    }

    /// Takes `amount` tokens; call after [`Self::has`] returned true.
    pub(crate) fn take(&mut self, amount: u64) {
        self.nano_tokens = self
            .nano_tokens
            .saturating_sub(u128::from(amount) * NANOS_PER_SECOND);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_bursts_then_refills() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(
            RateLimit {
                per_second: 2,
                burst: 3,
            },
            start,
        );
        for _ in 0..3 {
            assert!(bucket.has(start, 1));
            bucket.take(1);
        }
        assert!(!bucket.has(start, 1));
        assert!(bucket.has(start + Duration::from_millis(500), 1));
        bucket.take(1);
        assert!(!bucket.has(start + Duration::from_millis(500), 1));
        assert!(bucket.has(start + Duration::from_secs(60), 3));
        assert!(!bucket.has(start + Duration::from_secs(60), 4));
    }
}
