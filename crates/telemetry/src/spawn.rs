//! Panic-supervised replacement for bare [`tokio::spawn`].
//!
//! Use [`spawn_supervised`] for **long-lived** tasks (loops, background
//! reconcilers, IO driver tasks). It wraps `tokio::spawn` with:
//!
//! 1. A `nsn_tasks_spawned_total{task}` counter on entry.
//! 2. A `nsn_task_panics_total{task}` counter when the inner future panics.
//! 3. A structured `tracing::error!` log carrying the panic payload.
//!
//! # When not to use
//!
//! Short-lived per-connection tasks (one per accepted TCP conn, one per
//! datagram reply, etc.) should **not** go through this helper — the label
//! `task` would explode into high cardinality and the counter value would
//! dwarf the rest of the metric. Keep `tokio::spawn` for those cases.
//!
//! # API shape
//!
//! `task: &'static str` is enforced to keep labels low-cardinality. Any
//! dynamic per-instance discrimination must live in span fields, not in
//! label values.

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use tokio::task::{AbortHandle, JoinHandle};
use tracing::error;

use crate::labels::LABEL_TASK;
use crate::meter::{counter_u64, meter};

struct SpawnInstruments {
    spawned: Counter<u64>,
    panics: Counter<u64>,
}

fn instruments() -> &'static SpawnInstruments {
    static INSTRUMENTS: OnceLock<SpawnInstruments> = OnceLock::new();
    INSTRUMENTS.get_or_init(|| {
        let m = meter("nsn.telemetry.spawn");
        SpawnInstruments {
            spawned: counter_u64(
                &m,
                "nsn_tasks_spawned_total",
                "Long-lived supervised tasks spawned",
            ),
            panics: counter_u64(
                &m,
                "nsn_task_panics_total",
                "Long-lived supervised tasks that exited via panic",
            ),
        }
    })
}

/// Spawn a long-lived task onto the current tokio runtime with panic
/// supervision.
///
/// Semantics identical to [`tokio::spawn`] for the happy path — the returned
/// [`JoinHandle`] completes with `Ok(output)`.  On panic the outer task
/// completes with `Err(JoinError)` (the caller can still observe cancellation
/// or abort semantics) but the panic is additionally logged and counted.
pub fn spawn_supervised<F>(task: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let inst = instruments();
    inst.spawned.add(1, &[KeyValue::new(LABEL_TASK, task)]);

    tokio::spawn(async move {
        let mut handle = tokio::spawn(fut);
        // Propagate outer cancellation to the inner task. Dropping a
        // `JoinHandle` only detaches the task, so without this guard an
        // `.abort()` on the handle returned by `spawn_supervised` (e.g. the
        // tunnel manager aborting the status poller / conntrack GC on
        // re-config) would leave the inner task running forever. The guard
        // aborts `handle` if this wrapper future is dropped before the inner
        // task finishes; on normal completion the abort is a no-op.
        let _abort_on_drop = AbortOnDrop(handle.abort_handle());
        match (&mut handle).await {
            Ok(out) => out,
            Err(join_err) => {
                if join_err.is_panic() {
                    let panic_obj = join_err.into_panic();
                    let panic_msg = panic_payload_to_string(&panic_obj);
                    error!(
                        task = task,
                        panic = %panic_msg,
                        "supervised task panicked"
                    );
                    instruments()
                        .panics
                        .add(1, &[KeyValue::new(LABEL_TASK, task)]);
                    std::panic::resume_unwind(panic_obj);
                } else {
                    // Cancellation — not a panic, propagate silently.
                    std::panic::resume_unwind(Box::new("supervised task cancelled".to_owned()));
                }
            }
        }
    })
}

/// Aborts the wrapped task when dropped.
///
/// Used inside [`spawn_supervised`] so that cancelling the supervisor handle
/// also cancels the supervised inner task instead of detaching it.
struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn panic_payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn supervised_task_returns_value_on_success() {
        let h = spawn_supervised("test-success", async { 42u32 });
        let v = h.await.expect("join ok");
        assert_eq!(v, 42);
    }

    #[tokio::test]
    async fn supervised_task_reports_panic_and_propagates() {
        let h = spawn_supervised("test-panic", async {
            panic!("boom");
        });
        let res = h.await;
        // Outer join: our wrapper calls `resume_unwind`, so the outer
        // tokio::spawn converts that into another JoinError::is_panic.
        assert!(res.is_err(), "outer join should surface as error");
        let err = res.unwrap_err();
        assert!(err.is_panic(), "outer error should be a panic");
    }

    #[tokio::test]
    async fn aborting_supervisor_handle_cancels_inner_task() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // The inner task flips `ran_to_completion` only if it is allowed to
        // run to the end. Aborting the supervisor handle must cancel the inner
        // task before it can do so (regression for the double-spawn detach).
        let ran_to_completion = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran_to_completion);
        let handle = spawn_supervised("test-abort", async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            flag.store(true, Ordering::SeqCst);
        });

        // Give the wrapper a chance to spawn the inner task, then abort.
        tokio::task::yield_now().await;
        handle.abort();
        let _ = handle.await;

        // Allow any leaked inner task a moment to (wrongly) complete.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !ran_to_completion.load(Ordering::SeqCst),
            "inner task must be cancelled, not detached"
        );
    }

    #[tokio::test]
    async fn panic_payload_to_string_extracts_static_str() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("static panic");
        assert_eq!(panic_payload_to_string(&payload), "static panic");
    }

    #[tokio::test]
    async fn panic_payload_to_string_extracts_owned_string() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("owned panic".to_string());
        assert_eq!(panic_payload_to_string(&payload), "owned panic");
    }

    #[tokio::test]
    async fn panic_payload_to_string_falls_back_for_unknown_types() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(123u32);
        assert_eq!(
            panic_payload_to_string(&payload),
            "<non-string panic payload>"
        );
    }
}
