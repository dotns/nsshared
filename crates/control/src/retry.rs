//! Bounded exponential-backoff retry harness for cold-boot operations.
//!
//! NSN and NSC fail hard if NSD's HTTP listener has not finished accepting
//! when the binary first dials it (TCP `Connection refused`). Docker restart
//! policies mask the user-visible failure but each NSD slow-boot triggers an
//! exit/restart cycle. Wrapping the register call sites in this helper turns
//! the cold-boot race into a bounded retry that honours shutdown signals.
//!
//! The helper deliberately bounds attempts (≈61s ceiling at the default
//! policy) so a stuck NSD eventually surfaces a `RetryExhausted` error rather
//! than spamming logs forever. Indefinite reconnects belong to the
//! steady-state control plane, not to the boot path.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{error, info, warn};

use crate::Error;

// The retry harness is parameterised over an `AsyncFnMut` so callers can pass
// closures that re-borrow `&mut state` per attempt without the
// "captured variable cannot escape FnMut closure body" lifetime trap that
// affects plain `FnMut() -> impl Future` shapes when the closure body borrows
// from its captures. `AsyncFnMut` lets the compiler stitch the captured-borrow
// lifetime back through the returned future on each call.

/// Backoff schedule for [`retry_with_boot_backoff`].
#[derive(Debug, Clone, Copy)]
pub struct BootRetryPolicy {
    /// First sleep interval before the second attempt.
    pub initial_backoff: Duration,
    /// Upper bound on a single sleep interval.
    pub max_backoff: Duration,
    /// Total attempt budget, including the first attempt.
    pub max_attempts: u32,
    /// Symmetric jitter window as a percentage of the computed backoff
    /// (0..=100). `20` means each sleep is multiplied by a factor in
    /// `[0.8, 1.2]`. Non-cryptographic — only spreads retries across a
    /// flock of binaries restarting in lockstep.
    pub jitter_pct: u8,
}

impl Default for BootRetryPolicy {
    fn default() -> Self {
        // 1s → 2s → 4s → 8s → 16s → 30s (capped) ≈ 61s deterministic ceiling.
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            max_attempts: 6,
            jitter_pct: 20,
        }
    }
}

/// Run `operation` up to `policy.max_attempts` times with jittered
/// exponential backoff between attempts.
///
/// On success returns the operation's `Ok` value. On max-attempts exhaustion
/// returns [`Error::RetryExhausted`]. If `shutdown` resolves at any point —
/// before the first attempt, while driving an attempt, or mid-sleep — the
/// helper returns [`Error::Cancelled`] promptly without polling the operation
/// again.
///
/// `op_name` is a static label included in every log breadcrumb so operators
/// can grep retry activity per-site.
///
/// The `shutdown` future must be `Unpin` so the caller controls pinning;
/// the typical shape is `Box::pin(shutdown_signal())`. The helper assumes
/// `shutdown` is not re-polled after returning `Ready` (it returns immediately
/// in that case), so callers do not need to wrap it in a `Fuse`.
pub async fn retry_with_boot_backoff<F, T, E>(
    op_name: &'static str,
    policy: BootRetryPolicy,
    mut shutdown: impl Future<Output = ()> + Unpin,
    mut operation: F,
) -> Result<T, Error>
where
    F: AsyncFnMut() -> Result<T, E>,
    E: fmt::Display,
{
    let mut backoff = policy.initial_backoff;
    let mut last_error: Option<String> = None;

    for attempt in 1..=policy.max_attempts {
        // Peek at shutdown before invoking the operation so a pre-resolved
        // signal short-circuits without ever calling `operation()`.
        if peek_shutdown(&mut shutdown).await {
            return Err(Error::Cancelled);
        }

        let op_fut = operation();
        tokio::pin!(op_fut);

        let result = tokio::select! {
            biased;
            () = &mut shutdown => return Err(Error::Cancelled),
            r = &mut op_fut => r,
        };

        match result {
            Ok(value) => {
                if attempt > 1 {
                    info!(op = op_name, attempt, "retry succeeded");
                }
                return Ok(value);
            }
            Err(e) => {
                let msg = e.to_string();
                last_error = Some(msg.clone());
                if attempt < policy.max_attempts {
                    let sleep = jittered(backoff, policy.jitter_pct);
                    warn!(
                        op = op_name,
                        attempt,
                        backoff_ms = sleep.as_millis() as u64,
                        error = %msg,
                        "attempt failed; backing off",
                    );
                    tokio::select! {
                        biased;
                        () = &mut shutdown => return Err(Error::Cancelled),
                        () = tokio::time::sleep(sleep) => {}
                    }
                    backoff = (backoff * 2).min(policy.max_backoff);
                } else {
                    warn!(op = op_name, attempt, error = %msg, "attempt failed");
                }
            }
        }
    }

    let last_error = last_error.unwrap_or_else(|| "no failure recorded".to_string());
    error!(
        op = op_name,
        attempts = policy.max_attempts,
        last_error = %last_error,
        "retry exhausted",
    );
    Err(Error::RetryExhausted {
        op: op_name.to_string(),
        attempts: policy.max_attempts,
        last_error,
    })
}

/// Drive a single poll of `shutdown`. Returns `true` if `shutdown` is already
/// resolved. Never blocks; never re-polls after `Ready` (the caller returns).
async fn peek_shutdown(shutdown: &mut (impl Future<Output = ()> + Unpin)) -> bool {
    poll_fn(|cx| match Pin::new(&mut *shutdown).poll(cx) {
        Poll::Ready(()) => Poll::Ready(true),
        Poll::Pending => Poll::Ready(false),
    })
    .await
}

/// Apply ±`jitter_pct`% jitter to `base`. Seeded from the system clock so
/// independent binaries hitting the same NSD cold-boot scatter across the
/// retry window.
fn jittered(base: Duration, jitter_pct: u8) -> Duration {
    if jitter_pct == 0 || base.is_zero() {
        return base;
    }
    let pct = jitter_pct.min(100) as i64;
    let span = (2 * pct + 1) as u128;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let offset = (nanos % span) as i64 - pct;
    let base_millis = base.as_millis() as i64;
    let delta = base_millis.saturating_mul(offset) / 100;
    let scaled = (base_millis + delta).max(0) as u64;
    Duration::from_millis(scaled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::oneshot;

    fn fast_policy() -> BootRetryPolicy {
        // Compact schedule keeps tests fast under `tokio::time::pause`:
        // 10ms → 20ms → 40ms (capped) across 5 attempts.
        BootRetryPolicy {
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(40),
            max_attempts: 5,
            jitter_pct: 0,
        }
    }

    fn never_shutdown() -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(std::future::pending::<()>())
    }

    #[tokio::test]
    async fn succeeds_immediately_on_first_attempt() {
        let calls = Arc::new(AtomicU32::new(0));
        let result: Result<u32, Error> =
            retry_with_boot_backoff("noop", fast_policy(), never_shutdown(), async || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<u32, &'static str>(7)
            })
            .await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn succeeds_after_n_failures() {
        let calls = Arc::new(AtomicU32::new(0));
        let result: Result<&'static str, Error> =
            retry_with_boot_backoff("flaky", fast_policy(), never_shutdown(), async || {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    Err::<&'static str, String>(format!("transient {n}"))
                } else {
                    Ok("ok")
                }
            })
            .await;
        assert_eq!(result.unwrap(), "ok");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn exhausts_after_max_attempts() {
        let calls = Arc::new(AtomicU32::new(0));
        let result: Result<(), Error> =
            retry_with_boot_backoff("always-bad", fast_policy(), never_shutdown(), async || {
                let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                Err::<(), String>(format!("boom {n}"))
            })
            .await;
        match result {
            Err(Error::RetryExhausted {
                op,
                attempts,
                last_error,
            }) => {
                assert_eq!(op, "always-bad");
                assert_eq!(attempts, fast_policy().max_attempts);
                assert!(
                    last_error.starts_with("boom "),
                    "last_error preserved: {last_error}",
                );
            }
            other => panic!("expected RetryExhausted, got {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), fast_policy().max_attempts);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_preempts_sleep() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_ref = calls.clone();
        let (tx, rx) = oneshot::channel::<()>();
        let shutdown = Box::pin(async move {
            let _ = rx.await;
        });

        let task = tokio::spawn(async move {
            retry_with_boot_backoff(
                "wait-for-cancel",
                BootRetryPolicy {
                    initial_backoff: Duration::from_secs(60),
                    max_backoff: Duration::from_secs(60),
                    max_attempts: 10,
                    jitter_pct: 0,
                },
                shutdown,
                async move || {
                    calls_ref.fetch_add(1, Ordering::SeqCst);
                    Err::<(), &'static str>("fail")
                },
            )
            .await
        });

        // Let the first attempt run and enter the 60s sleep.
        tokio::time::advance(Duration::from_millis(1)).await;
        // Trip shutdown mid-sleep.
        tx.send(()).ok();
        // The helper should return Cancelled long before the 60s sleep expires.
        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("helper did not exit promptly on shutdown")
            .expect("task panicked");
        assert!(matches!(result, Err(Error::Cancelled)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_preempts_immediate_first_attempt() {
        let calls = Arc::new(AtomicU32::new(0));
        // Already-resolved shutdown.
        let shutdown = Box::pin(std::future::ready(()));
        let result: Result<(), Error> =
            retry_with_boot_backoff("already-cancelled", fast_policy(), shutdown, async || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), &'static str>("never reached")
            })
            .await;
        assert!(matches!(result, Err(Error::Cancelled)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_is_bounded() {
        // Force jitter off so the schedule is exactly 10 + 20 + 40 + 40 = 110ms
        // across 5 failing attempts.
        let policy = BootRetryPolicy {
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(40),
            max_attempts: 5,
            jitter_pct: 0,
        };
        let start = tokio::time::Instant::now();
        let result: Result<(), Error> =
            retry_with_boot_backoff("bounded", policy, never_shutdown(), async || {
                Err::<(), &'static str>("nope")
            })
            .await;
        assert!(matches!(result, Err(Error::RetryExhausted { .. })));
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(110),
            "elapsed {elapsed:?} should cover the deterministic schedule",
        );
        // Upper bound: deterministic schedule + a generous slack for select
        // scheduling under `tokio::time::pause`.
        assert!(
            elapsed <= Duration::from_millis(500),
            "elapsed {elapsed:?} exceeded the bounded ceiling",
        );
    }
}
