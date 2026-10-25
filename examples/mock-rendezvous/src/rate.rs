//! Keyed rate limiters for the rendezvous §6 and quick-v2 §7.4 rate limits.
//!
//! Each key gets a fixed window that starts at the first request admitted after the
//! previous window ended and lasts `window_ms`; at most `limit` requests are admitted
//! per window. Anchoring the window on the first request makes `limit = 1` an exact
//! minimum interval, so the same limiter serves per-source-IP per minute, global per
//! second (key `()`), per-connection per second and per-identity minimum interval.
//!
//! Time is `now_ms`, Unix milliseconds, passed by the caller. Memory is bounded: a full
//! limiter prunes expired keys on use and refuses new keys while still full, and
//! [`RateLimiter::prune`] drops expired keys explicitly.

use nsshared_rendezvous::error::ErrorCode;
use std::{collections::HashMap, hash::Hash};

/// Milliseconds in a second.
pub const SECOND_MS: u64 = 1000;
/// Milliseconds in a minute.
pub const MINUTE_MS: u64 = 60 * SECOND_MS;

/// One key's current window.
#[derive(Clone, Copy, Debug)]
struct Window {
    start_ms: u64,
    count: u32,
}

/// A keyed fixed-window rate limiter.
#[derive(Clone, Debug)]
pub struct RateLimiter<K> {
    limit: u32,
    window_ms: u64,
    max_keys: usize,
    windows: HashMap<K, Window>,
}

impl<K: Eq + Hash> RateLimiter<K> {
    /// At most `limit` requests per key per `window_ms`, tracking at most `max_keys` keys.
    #[must_use]
    pub fn new(limit: u32, window_ms: u64, max_keys: usize) -> Self {
        Self {
            limit,
            window_ms,
            max_keys,
            windows: HashMap::new(),
        }
    }

    /// At most `limit` requests per key per minute, e.g. per source IP.
    #[must_use]
    pub fn per_minute(limit: u32, max_keys: usize) -> Self {
        Self::new(limit, MINUTE_MS, max_keys)
    }

    /// At most `limit` requests per key per second, e.g. per connection or, with key
    /// `()`, globally.
    #[must_use]
    pub fn per_second(limit: u32, max_keys: usize) -> Self {
        Self::new(limit, SECOND_MS, max_keys)
    }

    /// At least `interval_ms` between admitted requests of a key, e.g. per identity.
    #[must_use]
    pub fn min_interval(interval_ms: u64, max_keys: usize) -> Self {
        Self::new(1, interval_ms, max_keys)
    }

    /// Admits and counts one request of `key` at `now_ms`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::RateLimited`] when the key's window is used up, or when the key is
    /// new and the limiter tracks `max_keys` unexpired keys. A refused request is not
    /// counted.
    pub fn check(&mut self, key: K, now_ms: u64) -> Result<(), ErrorCode> {
        if !self.windows.contains_key(&key) && self.windows.len() >= self.max_keys {
            self.prune(now_ms);
            if self.windows.len() >= self.max_keys {
                return Err(ErrorCode::RateLimited);
            }
        }
        let window_ms = self.window_ms;
        let window = self.windows.entry(key).or_insert(Window {
            start_ms: now_ms,
            count: 0,
        });
        if now_ms.saturating_sub(window.start_ms) >= window_ms {
            *window = Window {
                start_ms: now_ms,
                count: 0,
            };
        }
        if window.count >= self.limit {
            return Err(ErrorCode::RateLimited);
        }
        window.count += 1;
        Ok(())
    }

    /// Drops every key whose window has ended by `now_ms`.
    pub fn prune(&mut self, now_ms: u64) {
        let window_ms = self.window_ms;
        self.windows
            .retain(|_, window| now_ms.saturating_sub(window.start_ms) < window_ms);
    }

    /// Number of tracked keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    /// Whether no key is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{MINUTE_MS, RateLimiter, SECOND_MS};
    use nsshared_rendezvous::error::ErrorCode;
    use std::net::{IpAddr, Ipv4Addr};

    const T: u64 = 1_800_000_000_000;

    #[test]
    fn per_ip_per_minute() {
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let mut limiter = RateLimiter::per_minute(12, 16);
        for i in 0..12 {
            assert_eq!(limiter.check(a, T + i), Ok(()));
        }
        assert_eq!(limiter.check(a, T + 30_000), Err(ErrorCode::RateLimited));
        assert_eq!(limiter.check(b, T + 30_000), Ok(()));
        assert_eq!(
            limiter.check(a, T + MINUTE_MS - 1),
            Err(ErrorCode::RateLimited)
        );
        assert_eq!(limiter.check(a, T + MINUTE_MS), Ok(()));
    }

    #[test]
    fn global_per_second() {
        let mut limiter = RateLimiter::per_second(100, 1);
        for _ in 0..100 {
            assert_eq!(limiter.check((), T), Ok(()));
        }
        assert_eq!(limiter.check((), T + 999), Err(ErrorCode::RateLimited));
        assert_eq!(limiter.check((), T + SECOND_MS), Ok(()));
    }

    #[test]
    fn per_connection_per_second() {
        let mut limiter = RateLimiter::per_second(10, 16);
        for _ in 0..10 {
            assert_eq!(limiter.check(7_u64, T), Ok(()));
        }
        assert_eq!(limiter.check(7, T + 500), Err(ErrorCode::RateLimited));
        assert_eq!(limiter.check(8, T + 500), Ok(()));
        assert_eq!(limiter.check(7, T + 1000), Ok(()));
    }

    #[test]
    fn per_identity_minimum_interval() {
        let mut limiter = RateLimiter::min_interval(60 * SECOND_MS, 16);
        assert_eq!(limiter.check([1_u8; 32], T), Ok(()));
        assert_eq!(
            limiter.check([1; 32], T + 59_999),
            Err(ErrorCode::RateLimited)
        );
        assert_eq!(limiter.check([2; 32], T + 1), Ok(()));
        assert_eq!(limiter.check([1; 32], T + 60_000), Ok(()));
        assert_eq!(
            limiter.check([1; 32], T + 60_001),
            Err(ErrorCode::RateLimited)
        );
    }

    #[test]
    fn zero_limit_refuses_everything() {
        let mut limiter = RateLimiter::per_second(0, 1);
        assert_eq!(limiter.check((), T), Err(ErrorCode::RateLimited));
    }

    #[test]
    fn memory_is_bounded_and_pruned() {
        let mut limiter = RateLimiter::per_second(5, 2);
        assert_eq!(limiter.check(1_u32, T), Ok(()));
        assert_eq!(limiter.check(2, T), Ok(()));
        assert_eq!(limiter.check(3, T + 10), Err(ErrorCode::RateLimited));
        assert_eq!(limiter.len(), 2);
        assert_eq!(limiter.check(1, T + 10), Ok(()));
        assert_eq!(limiter.check(3, T + SECOND_MS), Ok(()));
        assert_eq!(limiter.len(), 1);

        limiter.prune(T + 2 * SECOND_MS);
        assert!(limiter.is_empty());
    }
}
